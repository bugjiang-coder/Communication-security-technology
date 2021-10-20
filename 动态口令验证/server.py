from socket import *
import time
import hashlib

serverPort = 12000
serverSocket = socket(AF_INET, SOCK_STREAM)  # 创建TCP欢迎套接字，使用IPv4协议
serverSocket.bind(('127.0.0.1', serverPort))  # 将TCP欢迎套接字绑定到指定端口
serverSocket.listen(1)  # 最大连接数为1
print("The server in ready to receive")

# PIN 都是key的hash值
user0 = {"id": "yjr", "seed": "19300240012", "PIN": "2c70e12b7a0646f92279f427c7b38e7334d8e5389cff167a1dc30e73f826b683"}
user1 = {"id": "yjr1", "seed": "19300240013", "PIN": "2c70e12b7a0646f92279f427c7b38e7334d8e5389cff167a1dc30e73f826b683"}
user2 = {"id": "yjr2", "seed": "19300240014", "PIN": "2c70e12b7a0646f92279f427c7b38e7334d8e5389cff167a1dc30e73f826b683"}

user = [user0, user1, user2]


def token(user):
    # 获取时间
    current_time = time.time()
    md5 = hashlib.md5()

    # hash运算
    md5.update((user["seed"] + str(int(current_time/60))).encode('utf-8'))
    hashAns = md5.hexdigest()
    # 将运算结果保留装换为整数 取末尾6个数字
    return (int(hashAns, 16) % 1000000)

def authentication(id,Certified_value):
    sha256 = hashlib.sha256()
    for u in user:
        if u["id"] == id:
            time_token = token(u) 
            print(time_token)
            print(u["PIN"])
            identify_value = (u["PIN"] +  str(time_token)).encode('utf-8')
            sha256.update(identify_value)
            identify_value = sha256.hexdigest()
            if identify_value == Certified_value:
                return True
    return False

times =3

while times:
    connectionSocket, addr = serverSocket.accept()  # 接收到客户连接请求后，建立新的TCP连接套接字
    print('Accept new connection from %s:%s...' % addr)

    id = connectionSocket.recv(1024).decode()  # 获取客户发送的字符串
    print("收到：",id)
    connectionSocket.send("Start certification".encode())

    Certified_value = connectionSocket.recv(1024).decode()
    print("收到验证值：",Certified_value)
    if authentication(id,Certified_value):
        connectionSocket.send("OK".encode())  # 向用户发送OK
    else:
        connectionSocket.send("Error".encode())
    connectionSocket.close()  # 关闭TCP连接套接字

    times -= 1
