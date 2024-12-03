import socket
import logging
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from scapy.contrib.mqtt import *  # Ensure that Scapy's MQTT module is available
import time
import threading
import select

# Setup logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s:%(levelname)s:%(message)s",
    handlers=[
        logging.FileHandler("mqtt_server.log"),  # Log to this file
        logging.StreamHandler()  # Also log to the console (optional)
    ]
)

# MQTT Packet Types
CONNECT_PACKET = 1
CONNACK_PACKET = 2
PUBLISH_PACKET = 3
PUBACK_PACKET = 4
PUBREC_PACKET = 5
PUBREL_PACKET = 6
PUBCOMP_PACKET = 7
SUBSCRIBE_PACKET = 8
SUBACK_PACKET = 9
UNSUBSCRIBE_PACKET = 10
UNSUBACK_PACKET = 11
PINGREQ_PACKET = 12
PINGRESP_PACKET = 13
DISCONNECT_PACKET = 14

# 全局字典存储客户端活动状态
client_activity = {}  # {client_socket: {"last_active": timestamp, "keep_alive": seconds}}
# 维护订阅信息
subscriptions = {}  # {topic: [client_socket, ...]}
client_subscriptions = {}  # {client_socket: {topic: qos, ...}}


def update_client_activity(client_socket, keep_alive):
    """更新客户端活动时间"""
    client_activity[client_socket] = {
        "last_active": time.time(),
        "keep_alive": keep_alive
    }


def check_heartbeat():
    """后台任务：定期检查客户端活动状态"""
    while True:
        current_time = time.time()
        for client_socket, info in list(client_activity.items()):
            last_active = info["last_active"]
            keep_alive = info["keep_alive"]

            # 超时检测：如果超过 1.5 倍 Keep Alive 时间未活动，则断开连接
            if current_time - last_active > 1.5 * keep_alive:
                logging.warning(f"客户端 {client_socket.getpeername()} 心跳超时，断开连接")
                client_socket.close()
                del client_activity[client_socket]
        time.sleep(5)  # 每隔 5 秒检查一次


def handle_pingreq(client_socket, addr):
    """处理 PINGREQ 报文"""
    try:
        if client_socket not in client_activity:
            logging.error(f"Client {client_socket} not found in activity list during PINGREQ handling.")
            return
        logging.info(f"Received PINGREQ from {addr}")
        # 发送 PINGRESP 报文
        pingresp = bytes([0xD0, 0x00])  # 固定格式的 PINGRESP 报文
        client_socket.send(pingresp)
        logging.info(f"Sent PINGRESP to {addr}")
        update_client_activity(client_socket, client_activity[client_socket]["keep_alive"])
    except Exception as e:
        logging.error(f"Error handling PINGREQ from {addr}: {e}")
        traceback.print_exc()


def send_pingresp(client_socket, addr):
    """ Send PINGRESP to the client to keep the connection alive """
    response = bytearray([0xD0, 0x00])  # PINGRESP message (Fixed header: 0xD0, Remaining length: 0)
    try:
        client_socket.send(response)
        logging.info(f"Sent PINGRESP to {addr}")
    except Exception as e:
        logging.error(f"Error sending PINGRESP to {addr}: {str(e)}")

        # MQTT Response Functions


def send_connack(client_socket, addr, code):
    """手动构造并发送 CONNACK 报文"""
    # 固定头部
    fixed_header = bytes([0x20, 0x02])  # 报文类型为 CONNACK，剩余长度为 2

    session_present = 0

    # 可变头部
    session_present_byte = 0x01 if session_present else 0x00  # 根据 session_present 设置标志位
    variable_header = bytes([session_present_byte, code])  # 添加返回码

    # 合成完整报文
    connack_packet = fixed_header + variable_header

    # 发送报文
    client_socket.send(connack_packet)
    logging.info(f"Sent CONNACK response to {addr}, session present: {session_present}, return code: {code}")


# 假设存在一个模拟的“数据库”来存储客户端的状态
client_sessions = {}
connection_attempts = {}
MAX_CONNECTION_ATTEMPTS = 3
CONNECTION_WINDOW = 10  # Time window in seconds


def handle_connect(client_socket, addr, msg):
    """ Handle the CONNECT packet in a more realistic way with better error handling """
    try:
        current_time = time.time()

        # Ensure the message is long enough before trying to parse it
        if len(msg) < 10:  # CONNECT packet is at least 10 bytes long (fixed header + protocol name + version)
            logging.warning(f"Received invalid CONNECT packet from {addr}, packet too short ({len(msg)} bytes)")
            send_connack(client_socket, addr, 5)  # Internal server error
            return

        # Extract the MQTT protocol version (first two bytes after the fixed header)
        remain_len = msg[1]
        protocol_name_len = (msg[2] << 8) + msg[3]
        protocol_name_end = 4 + protocol_name_len

        # Ensure message is long enough to extract protocol name and version
        if len(msg) < protocol_name_end + 1:
            logging.warning(f"Invalid CONNECT packet from {addr}, incomplete protocol name or version")
            send_connack(client_socket, addr, 5)  # Internal server error
            return

        # Extract protocol name and version
        protocol_name = msg[4:4 + protocol_name_len].decode("utf-8", errors='ignore')
        protocol_version = msg[protocol_name_end]

        logging.info(f"Received CONNECT packet from {addr}, protocol: {protocol_name}, version: {protocol_version}")

        # Validate protocol name and version
        if protocol_name != "MQTT":
            logging.warning(f"Invalid protocol name from {addr}: {protocol_name}")
            send_connack(client_socket, addr, 1)  # Protocol error
            return

        if protocol_version != 4:  # Assuming we only support MQTT 3.1.1 (version 4)
            logging.warning(f"Unsupported protocol version from {addr}: {protocol_version}")
            send_connack(client_socket, addr, 1)  # Protocol version error
            return

        flags_pos = protocol_name_end + 1
        flags = msg[flags_pos]

        username_flag = (flags >> 7) & 0x01  # 第7位
        password_flag = (flags >> 6) & 0x01  # 第6位
        will_retain = (flags >> 5) & 0x01  # 第5位
        will_qos = (flags >> 3) & 0x03  # 第4和第3位（2位用于 QoS）
        will_flag = (flags >> 2) & 0x01  # 第2位
        clean_session = (flags >> 1) & 0x01  # 第1位
        reserved = flags & 0x01  # 第0位（保留位）

        # 检查保留标志位是否为 0
        if reserved != 0:
            logging.info("协议违规: 保留位不为0，服务端应断开连接")
            return
        else:
            logging.info("保留位为 0，连接合法")

        logging.info(f"Username Flag: {username_flag}, Password Flag: {password_flag}, "
                     f"Will Retain: {will_retain}, Will QoS: {will_qos}, Will Flag: {will_flag}, "
                     f"Clean Session: {clean_session}, Reserved: {reserved}")

        # Extract keep alive value (2 bytes)
        if len(msg) < flags_pos + 3:
            logging.warning(f"Invalid CONNECT packet from {addr}, missing keep alive field")
            send_connack(client_socket, addr, 5)  # Internal server error
            return

        keep_alive = (msg[flags_pos + 1] << 8) + msg[flags_pos + 2]
        client_activity[client_socket] = {
            "keep_alive": keep_alive,
            "last_seen": time.time()
        }

        # Ensure there's enough data to extract client ID length and client ID
        if len(msg) < flags_pos + 7 and clean_session == 0:
            logging.warning(f"Invalid CONNECT packet from {addr}, missing client_id_len field")
            send_connack(client_socket, addr, 5)  # Internal server error
            return

        # Extract client_id_len (2 bytes) and client_id
        client_id_len = (msg[flags_pos + 3] << 8) + (msg[flags_pos + 4])
        client_id_pos = flags_pos + 5

        # Handle zero-length ClientId
        if client_id_len == 0:
            if clean_session == 0:
                # Reject if clean session is not set
                logging.warning(f"ClientId is zero-length but clean session is not set, rejecting {addr}")
                send_connack(client_socket, addr, 2)  # Identifier rejected
                client_socket.close()
                return
            else:
                # Assign a unique ClientId
                client_id = str(uuid.uuid4())
                logging.info(f"Assigned unique ClientId {client_id} to client at {addr}")
        else:
            client_id = msg[client_id_pos:client_id_pos + client_id_len].decode("utf-8", errors='ignore')

            # Validate ClientId format
            if not (1 <= len(client_id) <= 23 and client_id.isalnum()):
                logging.warning(f"Invalid ClientId format for client {addr}: {client_id}")
                send_connack(client_socket, addr, 2)  # Identifier rejected
                client_socket.close()
                return

        logging.info(f"Validated ClientId: {client_id} from {addr}")

        # Handle Will Message if flag is set
        will_message = None
        will_message_pos = client_id_pos + client_id_len + 2
        will_message_len = -2
        if will_flag:
            logging.info(f"Will message will be stored for client")
            # Extract Will Topic (UTF-8 string)
            will_topic_len = (msg[client_id_pos + client_id_len] << 8) + msg[client_id_pos + 1 + client_id_len]
            will_topic = msg[
                         client_id_pos + 2 + client_id_len: client_id_pos + 2 + client_id_len + will_topic_len].decode(
                "utf-8", errors='ignore')
            logging.info(f"Will Topic: {will_topic}")

            # Extract Will Message (length + payload)
            will_message_len = (msg[client_id_pos + 2 + client_id_len + will_topic_len] << 8) + msg[
                client_id_pos + 3 + client_id_len + will_topic_len]
            will_message_payload = msg[
                                   flags_pos + 9 + client_id_len + will_topic_len: flags_pos + 9 + client_id_len + will_topic_len + will_message_len]
            will_message = (will_topic, will_message_payload)

            logging.info(f"Will message: {will_message}")

        username_pos = will_message_pos + will_message_len + 2
        username_len = -2
        # Check username and password if flags are set
        if username_flag:

            username_len = (msg[will_message_pos + will_message_len] << 8) + msg[
                will_message_pos + will_message_len + 1]
            username = msg[username_pos: username_pos + username_len].decode("utf-8", errors='ignore')
            logging.info(f"Username received: {username}")

            if username != "datacon":
                logging.warning(f"Invalid username from {addr}: {username}")
                send_connack(client_socket, addr, 4)  # Invalid username
                return
        else:
            send_connack(client_socket, addr, 5)
            return

        password_pos = username_pos + username_len + 2
        password_len = -2
        if password_flag:
            password_len = (msg[username_pos + username_len] << 8) + msg[username_pos + username_len + 1]
            password = msg[password_pos: password_pos + password_len].decode("utf-8", errors='ignore')
            logging.info(f"Password received: {password}")

            if password != "datacon":
                logging.warning(f"Invalid password from {addr}: {password}")
                send_connack(client_socket, addr, 4)  # Invalid password
                return
        else:
            send_connack(client_socket, addr, 5)
            return

        # Respond with CONNACK based on validation
        send_connack(client_socket, addr, 0)  # Success response
        logging.info(f"Connection established for {client_id} from {addr}")

    except Exception as e:
        logging.error(f"Error handling CONNECT packet from {addr}: {e}")
        send_connack(client_socket, addr, 5)
        traceback.print_exc()


# Server setup
def start_mqtt_server(host='0.0.0.0', port=1883):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    logging.info(f"MQTT server listening on {host}:{port}")

    # 启动心跳检测线程
    # threading.Thread(target=check_heartbeat, daemon=True).start()

    with ThreadPoolExecutor(max_workers=10) as executor:
        while True:
            client_socket, addr = server_socket.accept()
            logging.info(f"New connection from {addr}")
            executor.submit(handle_client, client_socket, addr)


def handle_publish(client_socket, addr, msg):
    """处理 PUBLISH 报文并将消息分发给所有订阅的客户端"""
    try:
        logging.debug(f"Received PUBLISH message from {addr}: {msg.hex()}")

        # 提取报文类型和标志位
        packet_type = msg[0] >> 4
        if packet_type != 3:  # PUBLISH 报文的类型应该是 3
            logging.warning(f"Received non-PUBLISH packet from {addr}, ignoring.")
            return

        # 提取剩余长度
        remaining_length = msg[1]

        # 提取主题长度和主题名
        topic_len = (msg[2] << 8) + msg[3]
        topic = msg[4:4 + topic_len].decode("utf-8", errors="ignore")

        # 提取 QoS
        qos = (msg[0] & 0x06) >> 1
        payload_start = 4 + topic_len + (2 if qos > 0 else 0)

        # 提取载荷
        payload = msg[payload_start:4 + topic_len + remaining_length].decode("utf-8", errors="ignore")

        logging.info(f"Received PUBLISH packet from {addr}: Topic = '{topic}', Payload = '{payload}'")

        # 对 QoS 为 1 的报文发送 PUBACK
        if qos == 1:
            send_puback(client_socket, addr, msg)
        elif qos == 2:
            send_pubrec(client_socket, addr, msg)

        # 如果有客户端订阅该主题，则将消息推送给所有订阅者
        if topic in subscriptions:
            for subscriber_socket in subscriptions[topic]:
                # if subscriber_socket != client_socket:  # 排除发送消息的客户端
                send_publish(subscriber_socket, topic, payload)

    except Exception as e:
        logging.error(f"Error processing PUBLISH from {addr}: {e}")
        traceback.print_exc()


def encode_remaining_length(length):
    """编码 MQTT 报文中的剩余长度"""
    encoded = bytearray()
    while length > 0:
        encoded_byte = length % 128
        length //= 128
        if length > 0:
            encoded_byte |= 0x80
        encoded.append(encoded_byte)
    return encoded


def send_publish(client_socket, topic, payload):
    """发送 PUBLISH 报文给订阅者"""
    try:
        # 如果套接字已经关闭，则跳过发送
        if client_socket.fileno() == -1:
            logging.warning(f"Socket {client_socket.getpeername()} is closed, skipping send.")
            return

        fixed_header = 0x30  # PUBLISH 固定报头
        try:
            # 计算剩余长度：主题长度 + 主题内容 + 有效负载
            remaining_length = 2 + len(topic) + len(payload)
        except Exception as e:
            logging.error(f"Error calculating remaining length: {e}")
            return

        packet = bytearray()

        # 构造 PUBLISH 报文
        packet.append(fixed_header)
        packet.extend(encode_remaining_length(remaining_length))
        packet.extend(len(topic).to_bytes(2, 'big'))  # 2字节表示主题长度
        packet.extend(topic.encode('utf-8'))  # 编码主题为 UTF-8
        packet.extend(payload.encode('utf-8'))  # 编码有效负载为 UTF-8

        # 尝试发送报文，捕获可能的异常
        try:
            client_socket.send(packet)  # 发送报文
            logging.info(f"Sent PUBLISH message to {client_socket.getpeername()} on topic '{topic}'")
        except OSError as e:
            logging.error(f"OSError when sending PUBLISH to {client_socket.getpeername()}: {e}")
            handle_invalid_socket(client_socket)

    except Exception as e:
        logging.error(f"Unexpected error while preparing PUBLISH: {e}")
        traceback.print_exc()


def handle_invalid_socket(client_socket):
    """处理无效的套接字，关闭并移除客户端"""
    try:
        # 关闭套接字并从订阅列表中移除
        logging.info(f"Closing socket {client_socket.getpeername()} due to invalid state.")
        client_socket.close()
    except Exception as close_e:
        logging.error(f"Error closing socket {client_socket.getpeername()}: {close_e}")

    # 从订阅列表中移除无效客户端
    remove_invalid_client(client_socket)


def remove_invalid_client(client_socket):
    """从订阅列表中移除无效的客户端"""
    for topic, subscribers in subscriptions.items():
        if client_socket in subscribers:
            subscribers.remove(client_socket)
            logging.info(f"Removed {client_socket.getpeername()} from subscription list for topic '{topic}'")


def send_pubrec(client_socket, addr, msg):
    """发送 PUBREC 响应"""
    try:
        # 提取报文标识符 (packet_id)
        topic_length = (msg[2] << 8) + msg[3]  # 获取主题长度
        packet_id = (msg[4 + topic_length] << 8) + msg[5 + topic_length]  # 获取报文标识符

        # 构造 PUBREC 报文
        # PUBREC 控制报文类型是 0x50，剩余长度是 2，packet_id 是 2 字节
        pubrec_packet = bytes([0x50, 0x02]) + packet_id.to_bytes(2, byteorder='big')

        # 发送 PUBREC 响应
        client_socket.send(pubrec_packet)
        logging.info(f"Sent PUBREC response to {addr} for packet ID {packet_id}")

    except Exception as e:
        logging.error(f"Error sending PUBREC: {e}")


def send_puback(client_socket, addr, msg):
    """发送 PUBACK 响应"""
    try:
        # 提取报文标识符
        # 假设 msg[2:4] 是主题的长度，msg[4:4+len(topic)] 是主题内容
        topic_length = (msg[2] << 8) + msg[3]  # 获取主题长度
        packet_id = (msg[4 + topic_length] << 8) + msg[5 + topic_length]  # 获取报文标识符

        # 构造 PUBACK 报文
        puback_packet = bytes([0x40, 0x02]) + packet_id.to_bytes(2, byteorder='big')  # 0x40 是 PUBACK 类型，0x02 是剩余长度
        client_socket.send(puback_packet)
        logging.info(f"Sent PUBACK response to {addr} for packet ID {packet_id}")
    except Exception as e:
        logging.error(f"Error sending PUBACK: {e}")


def handle_disconnect(client_socket, addr):
    """处理 DISCONNECT 报文"""
    try:
        logging.info(f"Received DISCONNECT from {addr}")
        client_socket.close()
        # 从活动字典中删除客户端
        if client_socket in client_activity:
            del client_activity[client_socket]
        logging.info(f"Connection to {addr} closed successfully.")
    except Exception as e:
        logging.error(f"Error handling DISCONNECT from {addr}: {e}")
        traceback.print_exc()


def handle_subscribe(client_socket, addr, msg):
    """处理 SUBSCRIBE 报文"""
    try:
        logging.debug(f"Received SUBSCRIBE message from {addr}: {msg.hex()}")

        # 确保报文长度足够进行解析
        if len(msg) < 4:
            logging.warning(f"Received SUBSCRIBE message too short from {addr}: {msg.hex()}")
            return

        # 提取报文标识符
        packet_id = (msg[2] << 8) + msg[3]
        current_pos = 4  # 订阅主题从第 4 字节开始

        subscriptions_for_client = {}

        # 确保剩余长度足够进行解析
        while current_pos + 2 <= len(msg):  # 至少需要 2 字节主题长度
            topic_len = (msg[current_pos] << 8) + msg[current_pos + 1]
            current_pos += 2

            # 确保主题长度不会超出剩余报文
            if current_pos + topic_len > len(msg):
                logging.warning(
                    f"Invalid SUBSCRIBE message (topic length exceeds remaining data) from {addr}: {msg.hex()}")
                return

            topic = msg[current_pos:current_pos + topic_len].decode("utf-8", errors="ignore")
            current_pos += topic_len

            # 确保有 QoS 数据
            if current_pos + 1 > len(msg):
                logging.warning(f"Invalid SUBSCRIBE message (missing QoS) from {addr}: {msg.hex()}")
                return

            qos = msg[current_pos]
            current_pos += 1

            subscriptions_for_client[topic] = qos

            # 更新 subscriptions 和 client_subscriptions
            if topic not in subscriptions:
                subscriptions[topic] = []
            subscriptions[topic].append(client_socket)

        # 更新 client_subscriptions
        client_subscriptions[client_socket] = subscriptions_for_client

        # 生成 SUBACK 报文并发送
        send_suback(client_socket, addr, packet_id, [qos for _, qos in subscriptions_for_client.items()])

    except Exception as e:
        logging.error(f"Error processing SUBSCRIBE from {addr}: {e}")


def send_suback(client_socket, addr, packet_id, granted_qos_levels):
    """发送 SUBACK 报文"""
    try:
        # SUBACK 报文格式：固定报头（2 字节）+ 报文标识符（2 字节）+ 返回码列表
        suback = bytearray()
        suback.append((SUBACK_PACKET << 4))  # 报文类型为 SUBACK，标志位为 0
        suback.append(2 + len(granted_qos_levels))  # 剩余长度
        suback.append((packet_id >> 8) & 0xFF)  # 报文标识符高字节
        suback.append(packet_id & 0xFF)  # 报文标识符低字节
        suback.extend(granted_qos_levels)  # 返回码列表

        client_socket.sendall(suback)
        logging.info(f"Sent SUBACK to {addr} for Packet ID {packet_id} with QoS {granted_qos_levels}")

    except Exception as e:
        logging.error(f"Error sending SUBACK to {addr}: {e}")
        traceback.print_exc()


# 定义报文处理函数的映射表
packet_handlers = {
    1: handle_connect,  # CONNECT
    3: handle_publish,  # PUBLISH
    8: handle_subscribe,  # SUBSCRIBE
    12: handle_pingreq,  # PINGREQ
    14: handle_disconnect  # DISCONNECT
}


def handle_packet(client_socket, addr, packet_type, packet_data):
    handler = packet_handlers.get(packet_type)
    if handler:

        if packet_type == 14:  # DISCONNECT
            handler(client_socket, addr)
            logging.info(f"Client {addr} disconnected")
        else:
            handler(client_socket, addr, packet_data)
    else:
        logging.warning(f"Unsupported packet type {packet_type} from {addr}")


def handle_client(client_socket, addr):
    try:
        # 将 socket 设置为阻塞模式（默认行为）
        client_socket.setblocking(True)

        while True:
            try:
                # 阻塞接收数据，直到接收到数据
                data = client_socket.recv(1024)
                if not data:
                    logging.warning(f"Connection closed by {addr}")
                    break  # 连接关闭

                logging.debug(f"Received data from {addr}: {data.hex()}")

                # 解析数据包（假设数据包是很小且每次能完整接收）
                packet_type = data[0] >> 4  # 假设报文类型位于第一个字节的高4位
                handle_packet(client_socket, addr, packet_type, data)

            except socket.error as e:
                logging.error(f"Socket error while reading from {addr}: {e}")
                break
            except Exception as e:
                logging.error(f"Error processing data from {addr}: {e}")
                break

    except Exception as e:
        logging.error(f"Error handling client {addr}: {e}")
    finally:
        # 确保关闭连接
        try:
            client_socket.close()
            logging.info(f"Connection with {addr} closed")
        except Exception as close_e:
            logging.error(f"Error closing socket with {addr}: {close_e}")


# Start the server
if __name__ == "__main__":
    start_mqtt_server()