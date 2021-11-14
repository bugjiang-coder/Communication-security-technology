import socket
import mySSL

host = '127.0.0.1'
port = 12000

# 生成SSL上下文
context = mySSL.SSLContext()


sock = socket.create_connection((host, port))

ssock = context.wrap_socket(sock, False)

print("发送：\tclient connecting")
ssock.send("client connecting".encode())

data = ssock.recv(1024).decode()
print('收到server的数据:\t%s' % data)

ssock.close()
