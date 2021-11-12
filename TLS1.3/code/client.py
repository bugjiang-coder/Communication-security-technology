import socket
import mySSL

host = '127.0.0.1'
hostname = '19300240012'
port = 12000

# 生成SSL上下文
context = mySSL.SSLContext()
# # 加载信任根证书
# context.load_verify_locations('./ca/ca.crt')



sock = socket.create_connection((host, port))
# ssock = sock
ssock = context.wrap_socket(sock, False)


ssock.send("client connecting".encode())
data = ssock.recv(1024).decode()
print('收到server的数据:%s' % data)

ssock.close()
