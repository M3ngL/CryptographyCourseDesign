import json
import socket
from Crypto.Util.number import *
import uuid
import gmpy2
import random
from AES import AES
from sha256 import sha256
import os

def padding(text):
    text = text + chr(16 - len(text) % 16).encode() * (16 - len(text) % 16)
    return text

# 密钥协商部分的函数定义
def Get_ID():
    return str(uuid.uuid3(uuid.NAMESPACE_DNS, 'Client_B'))

def Sign_key():
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    e = getPrime(20)
    fai_n = (p - 1) * (q - 1)
    d = gmpy2.invert(e,fai_n)
    return (n, e ,d)

def get_hash(s):
    return bytes_to_long(sha256(s.encode()))

# 交互部分的函数定义
def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def my_send(msg):
    if msg == 'exit':
        socket_B.close()
    msg = json.dumps(msg)
    socket_B.send(bytes(msg.encode('utf-8')))

def my_receive():
    msg = json.loads(socket_B.recv(2048))
    return msg

def encode(msg):
    msg =  bytes(json.dumps(msg).encode('utf-8'))
    return msg

# 初始化套接字
socket_B = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# host = '172.27.75.93'
host = get_host_ip()
port = 12345
socket_B.connect((host, port))


# 发送数字证书部分
ID_B = Get_ID()
n, e, d = Sign_key()
pubkey_B = (e, n)
cert = [ID_B, pubkey_B, "Server"]
my_send(cert)
C_B = my_receive()
# print(C_B)
print("成功接收证书!")

# 接收从服务端（第三方）生成的p, g
p, g = my_receive()
# 第一步
y_A = my_receive()[0]

# 第二步
b = random.randrange(2, p - 2)
y_B = pow(g, b, p)
k = pow(y_A, b, p)
sign_B = pow(get_hash(str((y_A, y_B))), d, n)

aes = AES(long_to_bytes(k))
sign_B = padding(long_to_bytes(sign_B)) 
E_B = bytes_to_long(aes.encrypt(sign_B))

# 第三步
cert = [C_B, y_B, E_B, "Client_A"] # 发送的变量内容不能是字节类型
my_send(cert)

# 第七步
# 验证C_A的有效性
C_A, E_A = my_receive()
C_A = eval(C_A)
cert = [C_A[0], "Server"]
my_send(cert)
e_A, n_A = my_receive()
if  get_hash(str((C_A[0], C_A[1]))) == pow(C_A[2], e_A, n_A):
    print("对发送方A的身份验证成功!")
else:
    print("验证失败!请谨慎交互!")
    os._exit(1)

# 对sign_A的有效性进行验证
sign_A = aes.decrypt(long_to_bytes(E_A))
sign_A = bytes_to_long(sign_A[:-int(sign_A[-1])])
if pow(sign_A, C_A[1][0], C_A[1][1]) == get_hash(str((y_A, y_B))):
    print("对A的签名验证成功!")
else:
    print("验证失败!请谨慎交互!")
    os._exit(1)

print("密钥协商过程结束!")
print("进入实际交互模式:")


while True:
    try:
        socket_B.settimeout(1)
        msg = my_receive()[0]
        print("接收到的密文:{}".format(msg))
        msg = aes.decrypt(eval(msg))
        print("明文:{}".format(msg[:-msg[-1]].decode()))
    except:
        msg = input(">>>")
        if msg == '':
            continue
        msg = aes.encrypt(msg.encode())
        cert = [str(msg), "Client_A"]
        my_send(cert)


