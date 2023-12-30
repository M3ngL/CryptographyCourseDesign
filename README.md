# CryptographyCourseDesign
Course design of cryptography, developing that communication encryption system to achieve the purpose of encrypted communication between two independent network hosts in the local area network with Python. Diffie-Hellman key negotiation algorithm is used to ensure the confidentiality of key transmission, sha256 hash algorithm is used to generate simple digital certificates, and RSA algorithm is used to encrypt and decrypt communication data in general.

Open three command-line CMDS on the local host, using the Python3 environment, and run `server.py`，`client_B.py`，`client_A.py` one by one.

Test screenshots are available below.

# 密码学课程设计

使用 Python 开发通信加密系统以达到实现局域网内，两个独立的网络主机之间可以进行加密通信的目的。使用 Diffie-Hellman 密钥协商算法过程来保证密钥传递的保密性，使用 sha256 散列算法生成简单数字证书，总体上使用 RSA 算法实现通信数据的加密与解密。

在本地主机打开三个命令行cmd，使用Python3环境，依次运行`server.py`，`client_B.py`，`client_A.py`

`server.py`回显

![image-20231230170952107](https://cdn.jsdelivr.net/gh/Meng1in/Picture/img/image-20231230170952107.png)

`client_A.py`回显

![image-20231230171038572](https://cdn.jsdelivr.net/gh/Meng1in/Picture/img/image-20231230171038572.png)

---

开始进行交互，输入信息后回车，在接收端按下回车以接收发送端的消息

`Client_A.py`首先作为发送端

![image-20231230171157130](https://cdn.jsdelivr.net/gh/Meng1in/Picture/img/image-20231230171157130.png)

`Client_B.py`首先作为接收端

![image-20231230171202636](https://cdn.jsdelivr.net/gh/Meng1in/Picture/img/image-20231230171202636.png)
