import socket
import mySSL

host = '127.0.0.1'
serverPort = 12000


context = mySSL.SSLContext()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((host,serverPort))
sock.listen(1)

ssock = context.wrap_socket(sock, True)


connectionSocket, addr = ssock.accept()  # 接收到客户连接请求后，建立新的TCP连接套接字
print('收到来自%s:%s的请求' % addr)

data = connectionSocket.recv(1024).decode()
print('收到client的数据:\t%s' % data)

print("发送：\tConnection succeeded")
connectionSocket.send("Connection succeeded".encode())

ssock.close()