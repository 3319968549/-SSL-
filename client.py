# 客户端 - 终端版本
import socket
import threading
import SSL
import sqlite3
import hashlib
import binascii
import os
import sys
import time
from need_module import json
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

key = b'\x00' * 32

"""
参数：
    sock：定义一个实例化socket对象
    server：传递的服务器IP和端口
"""
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 使用udp传输方式
server = ("localhost", 9999)  # 默认服务器地址，可根据需要修改


class SymmetricCipher:
    def __init__(self, key):
        self.key = key
        # AES 的分组大小为 16 字节，CFB8 模式的 IV 长度必须为 16 字节
        self.iv = os.urandom(16)

    def encrypt(self, plaintext):
        # 使用 PKCS7 填充
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(
            algorithms.AES(self.key), modes.CFB8(self.iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return b64encode(self.iv + ciphertext).decode("utf-8")

    def decrypt(self, ciphertext):
        # 从密文中提取 IV
        iv = b64decode(ciphertext)[:16]

        # 使用 PKCS7 反填充
        unpadder = padding.PKCS7(128).unpadder()

        cipher = Cipher(
            algorithms.AES(self.key), modes.CFB8(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = (
            decryptor.update(b64decode(ciphertext)[16:]) + decryptor.finalize()
        )
        plaintext = unpadder.update(padded_data) + unpadder.finalize()

        return plaintext.decode("utf-8")


class ChatClient:
    def __init__(self, name, passwd):
        self.name = name
        self.symmetric_key = None
        self.online_users = set([name])  # 在线用户列表
        self.symmetric_cipher = None
        self.running = True
        
        # 执行SSL握手
        self.client_perform_ssl_handshake(name, passwd)
        
        # 初始化对称加密
        global key
        self.symmetric_cipher = SymmetricCipher(key)

    def client_perform_ssl_handshake(self, name, passwd):
        client = SSL.Client(name, passwd)
        client_hello = client.send_client_hello(name)

        message = {"client_hello": client_hello}
        jsondata = json.dumps(message, ensure_ascii=False)
        sock.sendto(jsondata.encode("utf-8"), server)
        print("\033[32m[+]\033[0m客户端握手消息发送成功")

        # 等待服务端收到握手消息
        while True:
            data = sock.recv(1024)
            if len(data) != 0:
                break
        json_data = json.loads(data.decode("utf-8"))
        server_hello = json_data["server_hello"]
        print("\033[32m[+]\033[0m收到Server的握手消息")

        # 验证服务端证书
        while True:
            data, _ = sock.recvfrom(4096)
            server_crt_data = data.decode("utf-8")
            if len(server_crt_data) != 0:
                break
        with open(f"./{name}_req.crt", "r") as file:
            client_crt_data = file.read()
        with open("Server_req.crt", "w") as server_crt:
            server_crt.write(server_crt_data)

        # 验证服务端证书
        if client.verify_server_certificate():
            with open(f"./{name}_req.crt", "r") as file:
                client_crt_data = file.read()
            client_crt_data_encrypt = SSL.encrypt_message(
                client_crt_data, server_crt_data
            )
            sock.sendto(client_crt_data_encrypt, server)  # 发送客户端证书，服务端公钥加密
            print(f"\033[32m[+]\033[0m{name}客户端证书发送完成!")

            shared_key = client.process_server_hello(server_hello)
            print("\033[32m[+]\033[0m共享密钥:", shared_key)
            self.symmetric_key = binascii.unhexlify(shared_key)
            shared_secret_encrypt = SSL.encrypt_message(
                str(shared_key), server_crt_data
            )
            sock.sendto(shared_secret_encrypt, server)  # 发送共享密钥，服务端公钥加密
            print("\033[32m[+]\033[0mSSL握手完成！")
        else:
            sock.sendto("NOT_PASS_VERIFY".encode("utf-8"), server)
            print(f"\033[31m[-]\033[0m证书验证失败，本次连接请求结束")
            sys.exit(1)

    def send_group_message(self, msg):
        """发送群聊消息"""
        if msg != "":
            plaintext = msg.encode("utf-8")
            encrypted_msg = self.symmetric_cipher.encrypt(plaintext)
            
            message = {}
            message["chat_type"] = "normal"
            message["message_type"] = "text"
            message["send_user"] = self.name
            message["content"] = encrypted_msg.strip()
            jsondata = json.dumps(message, ensure_ascii=False)
            sock.sendto(jsondata.encode("utf-8"), server)
            
            now_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print(f"\033[36m[{now_time}] 你: {msg}\033[0m")

    def send_private_message(self, recv_user, msg):
        """发送私聊消息"""
        if recv_user not in self.online_users:
            print(f"\033[31m[-]\033[0m用户 '{recv_user}' 不在线或不存在")
            return False
        
        plaintext = msg.encode("utf-8")
        encrypted_msg = self.symmetric_cipher.encrypt(plaintext)
        
        message = {}
        message["chat_type"] = "private"
        message["message_type"] = "text"
        message["send_user"] = self.name
        message["recv_user"] = recv_user
        message["content"] = encrypted_msg.strip()
        jsondata = json.dumps(message, ensure_ascii=False)
        sock.sendto(jsondata.encode("utf-8"), server)
        
        now_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        print(f"\033[35m[{now_time}] 你 -> {recv_user}: {msg}\033[0m")
        return True

    def send_file(self, recv_user, file_path):
        """发送文件"""
        if recv_user not in self.online_users:
            print(f"\033[31m[-]\033[0m用户 '{recv_user}' 不在线或不存在")
            return False
        
        if not os.path.exists(file_path):
            print(f"\033[31m[-]\033[0m文件不存在: {file_path}")
            return False
        
        fpath, tempfilename = os.path.split(file_path)
        fname, extension = os.path.splitext(tempfilename)
        
        # 确定文件类型
        if extension in (".py", ".doc", ".txt", ".docx"):
            file_type = "normal-file"
        elif extension in (".jpg", ".png"):
            file_type = "image"
        elif extension in (".avi", ".mp4"):
            file_type = "video"
        else:
            file_type = "normal-file"
        
        message = {}
        message["chat_type"] = "private"
        message["message_type"] = "ask-file"
        message["file_type"] = file_type
        message["file_name"] = tempfilename
        message["send_user"] = self.name
        message["recv_user"] = recv_user
        message["content"] = file_path
        jsondata = json.dumps(message, ensure_ascii=False)
        sock.sendto(jsondata.encode("utf-8"), server)
        
        print(f"\033[33m[!]\033[0m正在请求发送文件 '{tempfilename}' 给 {recv_user}...")
        return True

    def recv(self):
        """接收消息的线程函数"""
        # 发送初始化消息
        message = {}
        message["message_type"] = "init_message"
        message["content"] = self.name
        json_str = json.dumps(message, ensure_ascii=False)
        sock.sendto(json_str.encode("utf-8"), server)
        
        while self.running:
            try:
                data = sock.recv(1024)
                if not data:
                    continue
                
                json_data = json.loads(data.decode("utf-8"))
                now_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                
                if json_data["message_type"] == "init_message":
                    user_list = eval(json_data["online_user"])
                    self.online_users = set(user_list)
                    print(f"\033[33m[!]\033[0m {json_data['content']} 进入了聊天室")
                    print(f"\033[33m[!]\033[0m 当前在线用户: {', '.join(user_list)}")
                
                elif json_data["message_type"] == "leave_message":
                    if json_data["content"] in self.online_users:
                        self.online_users.remove(json_data["content"])
                    print(f"\033[33m[!]\033[0m {json_data['content']} 离开了聊天室")
                    print(f"\033[33m[!]\033[0m 当前在线用户: {', '.join(self.online_users)}")
                
                elif json_data["chat_type"] == "normal":
                    if json_data["message_type"] == "text":
                        try:
                            decrypted_content = self.symmetric_cipher.decrypt(
                                json_data["content"]
                            )
                            print(f"\033[36m[{now_time}] {json_data['send_user']}: {decrypted_content}\033[0m")
                        except Exception as e:
                            print(f"\033[31m[-]\033[0m消息解密失败: {e}")
                    
                    elif json_data["message_type"] == "stickers":
                        print(f"\033[33m[!]\033[0m {json_data['send_user']} 发送了表情包: {json_data['content']}")
                
                elif json_data["chat_type"] == "private":
                    if json_data["message_type"] == "text":
                        try:
                            # 私聊消息是加密的字符串
                            plain_text = self.symmetric_cipher.decrypt(
                                json_data["content"]
                            )
                            print(f"\033[35m[{now_time}] {json_data['send_user']} -> 你 (私聊): {plain_text}\033[0m")
                        except Exception as e:
                            print(f"\033[31m[-]\033[0m私聊消息解密失败: {e}")
                            print(f"\033[31m[-]\033[0m原始内容: {json_data['content'][:50]}...")
                    
                    elif json_data["message_type"] == "ask-file":
                        file_type = json_data["file_type"]
                        file_name = json_data["file_name"]
                        send_user = json_data["send_user"]
                        print(f"\033[33m[!]\033[0m {send_user} 想要发送文件 '{file_name}' ({file_type}) 给你")
                        response = input("是否接收? (y/n): ").strip().lower()
                        
                        json_data["message_type"] = "isRecv"
                        json_data["isRecv"] = "true" if response == 'y' else "false"
                        jsondata = json.dumps(json_data, ensure_ascii=False)
                        sock.sendto(jsondata.encode("utf-8"), server)
                        
                        if response == 'y':
                            print(f"\033[32m[+]\033[0m等待接收文件...")
                        else:
                            print(f"\033[31m[-]\033[0m已拒绝接收文件")
                    
                    elif json_data["message_type"] == "file-data":
                        filename = json_data["file_name"]
                        data_size = int(json_data["file_length"])
                        print(f"\033[32m[+]\033[0m正在接收文件 '{filename}' (大小: {data_size} 字节)...")
                        
                        recvd_size = 0
                        data_total = b""
                        j = 0
                        while recvd_size < data_size:
                            j += 1
                            data, addr = sock.recvfrom(1024)
                            recvd_size += len(data)
                            data_total += data
                            print(f"\033[33m[!]\033[0m 已接收 {recvd_size}/{data_size} 字节 ({j} 次)")
                        
                        # 保存文件
                        with open(filename, "wb") as f:
                            f.write(data_total)
                        print(f"\033[32m[+]\033[0m文件 '{filename}' 接收完成！")
                        
                        # 发送接收确认
                        message = {}
                        message["chat_type"] = "private"
                        message["message_type"] = "Recv_msg"
                        message["Recv_msg"] = "true"
                        message["file_length"] = json_data["file_length"]
                        message["file_name"] = json_data["file_name"]
                        message["send_user"] = json_data["recv_user"]
                        message["recv_user"] = json_data["send_user"]
                        jsondata = json.dumps(message, ensure_ascii=False)
                        sock.sendto(jsondata.encode("utf-8"), server)
                    
                    elif json_data["message_type"] == "isRecv":
                        if json_data["isRecv"] == "true":
                            file_path = json_data["content"]
                            if os.path.exists(file_path):
                                with open(file_path, "rb") as f:
                                    file_data = f.read()
                                fhead = len(file_data)
                                
                                message = {}
                                message["chat_type"] = "private"
                                message["message_type"] = "file-data"
                                message["file_length"] = str(fhead)
                                message["file_name"] = json_data["file_name"]
                                message["send_user"] = json_data["send_user"]
                                message["recv_user"] = json_data["recv_user"]
                                message["content"] = ""
                                jsondata = json.dumps(message, ensure_ascii=False)
                                sock.sendto(jsondata.encode("utf-8"), server)
                                
                                # 分片发送文件
                                print(f"\033[32m[+]\033[0m开始发送文件数据...")
                                for i in range(fhead // 1024 + 1):
                                    time.sleep(0.0000000001)
                                    if 1024 * (i + 1) > fhead:
                                        sock.sendto(file_data[1024 * i:], server)
                                    else:
                                        sock.sendto(file_data[1024 * i: 1024 * (i + 1)], server)
                                    print(f"\033[33m[!]\033[0m 已发送 {min(1024 * (i + 1), fhead)}/{fhead} 字节")
                                print(f"\033[32m[+]\033[0m文件发送完成！")
                        else:
                            print(f"\033[31m[-]\033[0m对方拒绝接收文件")
                    
                    elif json_data["message_type"] == "Recv_msg":
                        if json_data["Recv_msg"] == "true":
                            filename = json_data["file_name"]
                            recv_user = json_data["recv_user"]
                            print(f"\033[32m[+]\033[0m文件 '{filename}' 已成功发送给 {recv_user}")
                            
            except Exception as e:
                if self.running:
                    print(f"\033[31m[-]\033[0m接收消息时出错: {e}")
                    import traceback
                    traceback.print_exc()

    def leave(self):
        """离开聊天室"""
        self.running = False
        message = {}
        message["message_type"] = "leave_message"
        message["content"] = self.name
        jsondata = json.dumps(message, ensure_ascii=False)
        sock.sendto(jsondata.encode("utf-8"), server)
        print("\033[33m[!]\033[0m 已离开聊天室")


def print_help():
    """打印帮助信息"""
    print("\n" + "="*60)
    print("聊天室命令帮助")
    print("="*60)
    print("  /help              - 显示此帮助信息")
    print("  /users             - 显示在线用户列表")
    print("  /msg <用户> <消息> - 发送私聊消息")
    print("  /file <用户> <路径> - 发送文件")
    print("  /quit 或 /exit     - 退出聊天室")
    print("  直接输入消息        - 发送群聊消息")
    print("="*60 + "\n")


def register_user():
    """用户注册"""
    print("\n" + "="*60)
    print("用户注册")
    print("="*60)
    
    username = input("用户名 (不超过8个字符): ").strip()
    if len(username) > 8:
        print("\033[31m[-]\033[0m 用户名不能超过8个字符")
        return None, None
    
    password = input("密码 (至少8位): ").strip()
    if len(password) < 8:
        print("\033[31m[-]\033[0m 密码长度不能少于8个字符")
        return None, None
    
    confirm_password = input("确认密码: ").strip()
    if password != confirm_password:
        print("\033[31m[-]\033[0m 两次输入的密码不一致")
        return None, None
    
    # 连接数据库
    conn = sqlite3.connect("yonghu.db")
    cursor = conn.cursor()
    cursor.execute(
        "create table if not exists user(username varchar(20),password varchar(64))"
    )
    
    # 检查用户是否已存在
    cursor.execute("select username from user where username=?", (username,))
    if cursor.fetchone():
        print("\033[31m[-]\033[0m 用户名已存在")
        cursor.close()
        conn.close()
        return None, None
    
    # 注册新用户
    hashed_pwd = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute(
        "insert into user (username, password) values (?, ?)",
        (username, hashed_pwd),
    )
    conn.commit()
    cursor.close()
    conn.close()
    
    print("\033[32m[+]\033[0m 注册成功！")
    return username, password


def login_user():
    """用户登录"""
    print("\n" + "="*60)
    print("用户登录")
    print("="*60)
    
    failed_attempts = 0
    max_failed_attempts = 3
    lock_duration = 60
    locked_until = 0
    
    while True:
        if locked_until > time.time():
            remaining_time = int(locked_until - time.time())
            print(f"\033[31m[-]\033[0m 账号已被锁定，请在 {remaining_time} 秒后重试！")
            time.sleep(1)
            continue
        
        username = input("用户名: ").strip()
        password = input("密码: ").strip()
        
        if username == "" or password == "":
            print("\033[31m[-]\033[0m 用户名和密码不能为空")
            continue
        
        conn = sqlite3.connect("yonghu.db")
        cursor = conn.cursor()
        
        cursor.execute("SELECT password FROM user WHERE username=?", (username,))
        hashed_pwd = cursor.fetchone()
        
        if hashed_pwd:
            # 尝试明文密码验证（兼容旧数据）
            if password == hashed_pwd[0]:
                print("\033[32m[+]\033[0m 登录成功！")
                cursor.close()
                conn.close()
                return username, password
            
            # 尝试哈希密码验证
            hashed_input_pwd = hashlib.sha256(password.encode()).hexdigest()
            if hashed_input_pwd == hashed_pwd[0]:
                print("\033[32m[+]\033[0m 登录成功！")
                cursor.close()
                conn.close()
                return username, password
            else:
                failed_attempts += 1
                if failed_attempts >= max_failed_attempts:
                    locked_until = time.time() + lock_duration
                    failed_attempts = 0
                    print("\033[31m[-]\033[0m 失败次数过多，账号已被锁定60秒！")
                else:
                    print(f"\033[31m[-]\033[0m 用户名或密码错误！ (剩余尝试次数: {max_failed_attempts - failed_attempts})")
        else:
            print("\033[31m[-]\033[0m 没有该用户！")
        
        cursor.close()
        conn.close()


def main():
    """主函数"""
    print("\n" + "="*60)
    print("基于SSL/TLS双向认证的聊天室 - 终端版")
    print("="*60)
    
    # 选择登录或注册
    while True:
        choice = input("\n请选择: [1] 登录  [2] 注册  [q] 退出: ").strip()
        if choice == '1':
            username, password = login_user()
            if username:
                break
        elif choice == '2':
            username, password = register_user()
            if username:
                break
        elif choice.lower() == 'q':
            print("再见！")
            sys.exit(0)
        else:
            print("\033[31m[-]\033[0m 无效选择，请重新输入")
    
    # 创建客户端并执行SSL握手
    try:
        client = ChatClient(username, password)
    except Exception as e:
        print(f"\033[31m[-]\033[0m 连接失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # 启动接收消息线程
    recv_thread = threading.Thread(target=client.recv, daemon=True)
    recv_thread.start()
    
    # 等待一下让初始化消息发送
    time.sleep(0.5)
    
    print("\n" + "="*60)
    print("已进入聊天室！输入 /help 查看命令帮助")
    print("="*60 + "\n")
    
    # 主循环：处理用户输入
    try:
        while client.running:
            try:
                user_input = input().strip()
                
                if not user_input:
                    continue
                
                # 处理命令
                if user_input.startswith('/'):
                    parts = user_input.split(None, 2)
                    cmd = parts[0].lower()
                    
                    if cmd == '/help':
                        print_help()
                    
                    elif cmd == '/users':
                        print(f"\033[33m[!]\033[0m 当前在线用户: {', '.join(client.online_users)}")
                    
                    elif cmd == '/msg' or cmd == '/private':
                        if len(parts) < 3:
                            print("\033[31m[-]\033[0m 用法: /msg <用户名> <消息>")
                        else:
                            recv_user = parts[1]
                            msg = parts[2]
                            client.send_private_message(recv_user, msg)
                    
                    elif cmd == '/file':
                        if len(parts) < 3:
                            print("\033[31m[-]\033[0m 用法: /file <用户名> <文件路径>")
                        else:
                            recv_user = parts[1]
                            file_path = parts[2]
                            client.send_file(recv_user, file_path)
                    
                    elif cmd == '/quit' or cmd == '/exit':
                        client.leave()
                        print("再见！")
                        break
                    
                    else:
                        print(f"\033[31m[-]\033[0m 未知命令: {cmd}，输入 /help 查看帮助")
                
                else:
                    # 普通消息（群聊）
                    client.send_group_message(user_input)
            
            except KeyboardInterrupt:
                print("\n\n\033[33m[!]\033[0m 收到中断信号，正在退出...")
                client.leave()
                break
            except EOFError:
                print("\n\n\033[33m[!]\033[0m 输入结束，正在退出...")
                client.leave()
                break
            except Exception as e:
                print(f"\033[31m[-]\033[0m 处理输入时出错: {e}")
    
    except KeyboardInterrupt:
        print("\n\n\033[33m[!]\033[0m 正在退出...")
        client.leave()
    
    print("程序已退出")


if __name__ == "__main__":
    main()
