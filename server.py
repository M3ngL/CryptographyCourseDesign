import json
import socket
from Crypto.Util.number import *
import time
import gmpy2
from sha256 import sha256
import os

# 密钥协商部分函数
def generator_gen():
    while True:
        fac = getPrime(127)
        p = fac * 2 + 1
        if isPrime(p) and p.bit_length() == 128:
            break
    g = 2
    while True:
        if pow(g, fac, p) != 1 and pow(g, 2, p) != 1:
            break
        else:
            g += 1
    return p, g

def Sign_key():
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    e = getPrime(20)
    fai_n = (p - 1) * (q - 1)
    d = gmpy2.invert(e,fai_n)
    return (n, e ,d)

def get_hash(s):
    return bytes_to_long(sha256(s.encode())) # 得到hash转十进制值

# 网络通信部分函数
def encode(msg):
    msg =  bytes(json.dumps(msg).encode('utf-8'))
    return msg

def transmit_from_A():
    cert = json.loads(A.recv(2048))
    if cert[-1] == "Client_B":
        msg = bytes(json.dumps(cert[:-1]).encode('utf-8'))
        B.send(msg)
        return True
    elif cert[-1] == "Server":
        return cert[:-1]
    else:
        return False

def transmit_from_B():
    cert = json.loads(B.recv(2048))
    if cert[-1] == "Client_A":
        msg = bytes(json.dumps(cert[:-1]).encode('utf-8'))
        A.send(msg)
        return True
    elif cert[-1] == "Server":
        return cert[:-1]
    else:
        return False

def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

# 初始化服务端套接字
socket1 = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
socket2 = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

# 绑定客户端运行端口
host = get_host_ip()
port1 = 12345
port2 = 14725
socket1.bind((host, port1))
socket2.bind((host, port2))

socket1.listen(5)
socket2.listen(5)

print("连接中...")
time.sleep(1)
B, addr1 = socket1.accept()
A, addr2 = socket2.accept()
print("成功连接!")
print("连接地址：", addr1)
print("接收端：", addr2)


# 发送数字证书
ID_A, pubkey_A = transmit_from_A()
ID_B, pubkey_B = transmit_from_B()
n_A, e_A, d_A = Sign_key()
n_B, e_B, d_B = Sign_key()
sign_TA_A = pow(get_hash(str((ID_A, pubkey_A))), d_A, n_A)
sign_TA_B = pow(get_hash(str((ID_B, pubkey_B))), d_B, n_B)
A.send(encode(str((ID_A, pubkey_A, int(sign_TA_A)))))
B.send(encode(str((ID_B, pubkey_B, int(sign_TA_B)))))
# 密钥协商
p, g = generator_gen()
A.send(encode((p, g)))
B.send(encode((p, g)))

# 第一轮交互,A发送y_A给B
if transmit_from_A():
    print("接收并转发成功!")

if transmit_from_B():
    print("接收并转发成功!")

request_ID = transmit_from_A()[0]
if request_ID == ID_B:
    A.send(encode((e_B, n_B))) # 发送服务端对B进行签名时用的公钥
    print("成功发送!")

if transmit_from_A():
    print("接收并转发成功!")

request_ID = transmit_from_B()[0]
if request_ID == ID_A:
    B.send(encode((e_A, n_A))) # 发送服务端对A进行签名时用的公钥
    print("成功发送!")

print("密钥协商过程结束!")

while True:
    try:
        A.settimeout(0.1)
        transmit_from_A()
    except: 
        try:
            B.settimeout(0.1)
            transmit_from_B()
        except:
            continue