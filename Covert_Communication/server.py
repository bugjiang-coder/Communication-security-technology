import socket
import time
import hashlib
import mySSL

serverPort = 12000


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建TCP欢迎套接字，使用IPv4协议
sock.bind(('127.0.0.1', serverPort))
sock.listen(1)                          # 最大连接数为1

print("服务启动")

# PIN 都是key的hash值 所有的用户密码都是key
# 这里存储用户数据
user0 = {"id": "yjr", "seed": "19300240012",
         "PIN": "2c70e12b7a0646f92279f427c7b38e7334d8e5389cff167a1dc30e73f826b683"}
user1 = {"id": "yjr1", "seed": "19300240013",
         "PIN": "2c70e12b7a0646f92279f427c7b38e7334d8e5389cff167a1dc30e73f826b683"}
user2 = {"id": "yjr2", "seed": "19300240014",
         "PIN": "2c70e12b7a0646f92279f427c7b38e7334d8e5389cff167a1dc30e73f826b683"}

USERS = [user0, user1, user2]

# 获取对应用户的时间令牌


def token(user):
    # 获取时间
    current_time = time.time()
    md5 = hashlib.md5()
    # hash运算
    md5.update((user["seed"] + str(int(current_time/60))).encode('utf-8'))
    hashAns = md5.hexdigest()
    # 将运算结果保留装换为整数 取末尾6个数字
    return ((str(int(hashAns, 16) % 1000000)).zfill(6))

# 对用户进行验证


def authentication(u, Certified_value):
    sha256 = hashlib.sha256()

    time_token = token(u)
    # 服务端本地生成用户的认证码
    identify_value = (u["PIN"] + str(time_token)).encode('utf-8')
    sha256.update(identify_value)
    identify_value = sha256.hexdigest()
    # 本地认证码和用户发来的认证码进行比对
    if identify_value == Certified_value:
        return True
    return False

# 查找是否有该用户


def findUser(userID):
    for u in USERS:
        # 如果存在该用户id 进行验证 否则直接返回false
        if u["id"] == userID:
            return (True, u)
    return (False, None)


times = 6

while times:
    # 使用自己模拟 SSL进行连接
    context = mySSL.SSLContext()
    serverSocket = context.wrap_socket(sock, True)

    connectionSocket, addr = serverSocket.accept()  # 接收到客户连接请求后，建立新的TCP连接套接字
    print('收到来自%s:%s的请求' % addr)

    id = connectionSocket.recv(1024).decode()  # 获取客户发送的id
    print("收到来自用户 %s 的请求" % id)

    judge, user = findUser(id)
    # 如果没有这个用户 发送错误消息 断开连接
    if not judge:
        connectionSocket.send("There is no such user.".encode())
        connectionSocket.close()  # 关闭TCP连接套接字
        continue
    # 用户存在发送 确认信息
    connectionSocket.send("Start certification".encode())

    # 接收用户发送的认证码
    Certified_value = connectionSocket.recv(1024).decode()
    # print("收到验证值：", Certified_value)
    if authentication(user, Certified_value):
        connectionSocket.send("OK".encode())  # 向用户发送OK
        print("用户%s认证成功" % id)
    else:
        connectionSocket.send("Error".encode())
        print("用户%s认证失败" % id)

    connectionSocket.close()  # 关闭TCP连接套接字

    times -= 1
