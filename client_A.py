import json
import random
import socket
from Crypto.Util.number import *
import uuid
import gmpy2
from AES import AES
from sha256 import sha256
import os

def padding(text):
    text = text + chr(16 - len(text) % 16).encode() * (16 - len(text) % 16)
    return text

# 密钥协商部分的函数定义
def Get_ID():
    return str(uuid.uuid3(uuid.NAMESPACE_DNS, 'Client_A'))

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
def my_send(msg):
    if msg == 'exit':
        socket_A.close()
    msg = json.dumps(msg)
    socket_A.send(bytes(msg.encode('utf-8')))

def my_receive():
    msg = json.loads(socket_A.recv(2048))
    return msg

def encode(msg):
    msg =  bytes(json.dumps(msg).encode('utf-8'))
    return msg

def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

# 初始化套接字
socket_A = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# host = '172.27.75.93'
host = get_host_ip()
port = 14725
socket_A.connect((host, port))

# 发送数字证书部分
ID_A = Get_ID()
n, e, d = Sign_key()
pubkey_A = (e, n)
cert = [ID_A, pubkey_A, "Server"]
my_send(cert)
C_A = my_receive()
# print(C_A)
print("成功接收证书!")

# 接收从服务端（第三方）生成的p, g
p, g = my_receive()
a = random.randrange(2, p - 2)

# A生成y_A，并发送给B
y_A = pow(g, a, p)
cert = [y_A, "Client_B"]
my_send(cert)

# A接收来自B的信息
C_B, y_B, E_B = my_receive()
# 验证C_B的有效性
C_B = eval(C_B)
cert = [C_B[0], "Server"]
my_send(cert)
e_B, n_B = my_receive()
if get_hash(str((C_B[0],C_B[1]))) == pow(C_B[2], e_B, n_B):
    print("对发送方B的身份验证成功!")
else:
    print("验证失败!请谨慎交互!")
    os._exit(1)
    
# 继续第四步, 验证sign_B的有效性
k = long_to_bytes(pow(y_B, a, p))
aes = AES(k)
sign_B = aes.decrypt(long_to_bytes(E_B))
sign_B = bytes_to_long(sign_B[:-int(sign_B[-1])]) # 去掉padding的部分

if pow(sign_B, C_B[1][0], C_B[1][1]) == get_hash(str((y_A, y_B))):
    print("对B的签名验证成功!")
else:
    print("验证失败!请谨慎交互!")
    os._exit(1)
    
# 第五步
sign_A = pow(get_hash(str((y_A, y_B))), d, n)
sign_A = padding(long_to_bytes(sign_A))
E_A = bytes_to_long(aes.encrypt(sign_A))

cert = [C_A, E_A, "Client_B"]
my_send(cert)

print("密钥协商过程结束!")
print("进入实际交互模式:")

while True:
    try:
        socket_A.settimeout(1)
        msg = my_receive()[0]
        print("接收到的密文:{}".format(msg))
        msg = aes.decrypt(eval(msg))
        print("明文{}".format(msg[:-msg[-1]].decode()))
    except:
        msg = input(">>>")
        if msg == '':
            continue
        msg = aes.encrypt(msg.encode())
        cert = [str(msg), "Client_B"]
        my_send(cert)

