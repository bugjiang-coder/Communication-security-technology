import socket
import mySSL

host = '127.0.0.1'
serverPort = 12000


context = mySSL.SSLContext()
# 加载服务器所用证书和私钥
# context.load_cert_chain('./server/server.crt', './server/server.key')


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((host,serverPort))
sock.listen(1)

# ssock = sock
ssock = context.wrap_socket(sock, True)


connectionSocket, addr = ssock.accept()  # 接收到客户连接请求后，建立新的TCP连接套接字
print('收到来自%s:%s的请求' % addr)
data = connectionSocket.recv(1024).decode()
print('收到client的数据:%s' % data)
connectionSocket.send("Connection succeeded".encode())

ssock.close()