from socket import *
import hashlib
serverName = '127.0.0.1' # 指定服务器IP地址
serverPort = 12000
clientSocket = socket(AF_INET, SOCK_STREAM) # 建立TCP套接字，使用IPv4协议
clientSocket.connect((serverName,serverPort)) # 向服务器发起连接
sha256 = hashlib.sha256()

id = input('输入用户名：').encode() # 用户输入信息，并编码为bytes以便发送
print("用户名为：",id.decode())

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~下面未完成
clientSocket.send(id) # 将信息发送到服务器
print("发送id成功")
feedback = clientSocket.recvfrom(1024) # 从服务器接收信息
print(feedback[0].decode())

if feedback[0] == "Start certification".encode():
    # 如果获得服务器正常的响应
    PIN = input('请输入PIN')
    # 先本地对PIN进行hash
    PIN = PIN.encode('utf-8')
    sha256_forPIN = hashlib.sha256()
    sha256_forPIN.update(PIN)
    PIN = sha256_forPIN.hexdigest()
    print(PIN)


    seed = input('请输入令牌上显示的数组')
    identify_value = (PIN + str(seed)).encode('utf-8')
    sha256.update(identify_value)
    identify_value = sha256.hexdigest()
    clientSocket.send(identify_value.encode())
    print("发送验证：",identify_value)

feedback2 = clientSocket.recvfrom(1024)
print(feedback2[0].decode())


clientSocket.close() # 关闭套接字

