import socket 
import hashlib
import ssl




serverName = '127.0.0.1' # 指定服务器IP地址
serverPort = 12000


# 生成SSL上下文
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
# 加载信任根证书
context.load_verify_locations('./ca/ca.crt')
ssr = []

#与服务端建立socket连接
with socket.create_connection((serverName,serverPort)) as sock:
    # 将socket打包成SSL socket
    # 一定要注意的是这里的server_hostname不是指服务端IP，而是指服务端证书中设置的CN
    with context.wrap_socket(sock, server_hostname='19300240012') as ssock:
        ssr = ssock.session
        sha256 = hashlib.sha256()

        id = input('输入用户名：\n').encode() # 用户输入信息，并编码为bytes以便发送
        print("用户名为：",id.decode())

        # 将信息发送到服务器
        ssock.send(id)
        # 从服务器接收信息
        feedback = ssock.recv(1024) 
        # 打印服务器的反馈
        print(feedback.decode())

        if feedback == "Start certification".encode():
            # 如果获得服务器正常的响应
            PIN = input('请输入PIN：\n')
            
            # 先本地对PIN进行hash
            PIN = PIN.encode('utf-8')
            sha256_forPIN = hashlib.sha256()
            sha256_forPIN.update(PIN)
            PIN = sha256_forPIN.hexdigest()

            # 对时间令牌和PIN的hash结果合并后再hash
            seed = input('请输入令牌上显示的数组:\n')
            identify_value = (PIN + str(seed)).encode('utf-8')
            sha256.update(identify_value)
            identify_value = sha256.hexdigest()
            ssock.send(identify_value.encode())

        # 打印服务器的反馈
        feedback2 = ssock.recv(1024)
        print(feedback2.decode())


        ssock.close() # 关闭套接字
input("wait")
sock2 = socket.create_connection((serverName, serverPort))
ssock2 = context.wrap_socket(sock2, server_hostname="19300240012", session=ssr)
print(ssock2.session_reused) # True , if server support it
input("wait")