from socket import *
import hashlib
serverName = 'www.baidu.com' # 指定服务器地址
serverPort = 80
clientSocket = socket(AF_INET, SOCK_STREAM) # 建立TCP套接字，使用IPv4协议
clientSocket.connect((serverName,serverPort)) # 向服务器发起连接
sha256 = hashlib.sha256()


