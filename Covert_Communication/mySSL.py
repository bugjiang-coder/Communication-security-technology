import base64
import hmac
import json
from enum import IntEnum

import numpy
import rsa

import AEScbc
import PRF


# 整个请求会和阶段使用Python的列表进行请求的认证
class TLSVersion(IntEnum):
    SSLv3 = 0
    TLSv1 = 1
    TLSv1_1 = 2
    TLSv1_2 = 3
    TLSv1_3 = 4
    MINIMUM_SUPPORTED = 4
    MAXIMUM_SUPPORTED = 4


class TLSContentType(IntEnum):
    """Content types (record layer)

    See RFC 8446, section B.1
    """
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23


class TLSMessageType(IntEnum):
    """Message types (handshake protocol)

    See RFC 8446, section B.3
    """
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    HELLO_VERIFY_REQUEST = 3
    NEWSESSION_TICKET = 4
    END_OF_EARLY_DATA = 5
    HELLO_RETRY_REQUEST = 6
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    CERTIFICATE_URL = 21
    CERTIFICATE_STATUS = 22
    SUPPLEMENTAL_DATA = 23
    KEY_UPDATE = 24
    NEXT_PROTO = 67
    MESSAGE_HASH = 254
    CHANGE_CIPHER_SPEC = 0x0101
# https://www.rfc-editor.org/rfc/rfc8446.txt


class TLSCipherSuites(IntEnum):
    TLS_AES_128_GCM_SHA256 = 1
    TLS_AES_256_GCM_SHA384 = 2
    TLS_CHACHA20_POLY1305_SHA256 = 3
    TLS_AES_128_CCM_SHA256 = 4
    TLS_AES_128_CCM_8_SHA256 = 5
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x3D


class SSLerror(RuntimeError):
    def __init__(self, arg):
        self.args = arg


def packet(pkt):
    # 为测试使用
    # print(TLSContentType(20)._name_)
    print("[*]TLSContentType:\t"+TLSContentType(pkt[0])._name_)
    print("[*]TLSMessageType:\t"+TLSMessageType(pkt[1][0])._name_)
    print("[*]TLSMessage length:\t"+str(pkt[1][1]))
    print("------------------------")
    print("[*]TLSVersion:\t"+TLSVersion(pkt[1][2][0])._name_)
    print("[*]Random:")
    print(base64.b64decode(pkt[1][2][1]))
    print("[*]session ID:")
    print(pkt[1][2][2])
    print("[*]TLSCipherSuites:")
    print([TLSCipherSuites(i).name for i in pkt[1][2][3]])
    print("[*]Compression Methods:")
    print(pkt[1][2][4])


class SSLSocket:
    def __init__(self):
        self.socket = None
        # 是否连接成功
        self.is_connect = False
        self.version = None
        # 是否是服务端
        self.server_side = False
        # 客户端随机数
        self.clientRandom = b''
        # 服务端随机数
        self.serverRandom = b''

        # 预备主密钥
        self.pre_master_secret = b''
        # 主密钥
        self.master_secret = b''
        # 服务器写MAC密钥
        self.server_mac_secret = b''
        # 客户端写MAC密钥
        self.client_mac_secret = b''
        # 服务器写密钥
        self.server_write_secret = b''
        # 客户端写密钥
        self.client_write_secret = b''

        # 偏移量 先定义为固定值
        self.iv = bytes(16)

        # server的rsa公钥
        self.pubkey = None
        # server的rsa私钥
        self.privkey = None

    def client_hello(self):
        # 生成28字节的随机数
        self.clientRandom = numpy.random.bytes(28)

        # 初始化会话ID为0 表示是在简历新的连接
        self.sessionID = 0

        # 生成client_hello报文内容
        CLIENT_HELLO = [TLSVersion.TLSv1_2, base64.b64encode(self.clientRandom).decode(),
                        self.sessionID, [i.value for i in TLSCipherSuites], None]
        clientRequest = [TLSMessageType.CLIENT_HELLO,
                         len(CLIENT_HELLO), CLIENT_HELLO]
        TLSContent = [TLSContentType.HANDSHAKE, clientRequest]

        print("[*]\t--->\t发送CLIENT_HELLO")

        # 发送CLIENT_HELLO
        self.socket.send(json.dumps(TLSContent).encode())

    def server_hello_rcev(self):
        # 接收client的消息
        data = json.loads(self.socket.recv(1024))

        print("[*]\t<---\t接收CLIENT_HELLO")

        # 先检查TLSContentType和TLSMessageType是否正确
        if data[0] == TLSContentType.HANDSHAKE:
            if data[1][0] == TLSMessageType.CLIENT_HELLO:
                # 获取client 随机数
                self.clientRandom = base64.b64decode(data[1][2][1])

                # 检查：client是否实现了支持的套件
                for i in data[1][2][3]:
                    if i == TLSCipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA256:
                        # 设置会话ID
                        self.sessionID = data[1][2][2]

                        print("[#]\t \t选择密钥套件TLS_RSA_WITH_AES_256_CBC_SHA256")

                        # 设置密码套件
                        self.cipherSuites = TLSCipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA256

                        return

        # 如果有一项不满足就抛出错误
        raise SSLerror("server hello rcev error")

    def server_hello_response(self):
        # 生成服务端随机数
        self.serverRandom = numpy.random.bytes(28)

        # 生成RSA密钥对 并且在CERTIFICATE部分发送
        (self.pubkey, self.privkey) = rsa.newkeys(1024)

        # 生成SERVER_HELLO报文
        SERVER_HELLO = [TLSVersion.TLSv1_2, base64.b64encode(self.serverRandom).decode(),
                        0, TLSCipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA256, None]
        serverResponse = [TLSMessageType.SERVER_HELLO,
                          len(SERVER_HELLO), SERVER_HELLO]
        TLSContent = [TLSContentType.HANDSHAKE, serverResponse]

        print("[*]\t--->\t发送SERVER_HELLO")

        # 要发送证书 证书内包含 server的公钥 这里简化实现不进行签名认证，直接发送server的公钥
        CERTIFICATE = [TLSVersion.TLSv1_2,
                       base64.b64encode(self.pubkey.save_pkcs1()).decode()]
        certificate = [TLSMessageType.CERTIFICATE,
                       len(CERTIFICATE), CERTIFICATE]
        TLSContent1 = [TLSContentType.HANDSHAKE, certificate]

        print("[*]\t--->\t发送CERTIFICATE")

        # 生成SERVER_DONE报文
        SERVER_DONE = [TLSVersion.TLSv1_2]
        helloDone = [TLSMessageType.SERVER_DONE, len(SERVER_DONE), SERVER_DONE]
        TLSContent2 = [TLSContentType.HANDSHAKE, helloDone]

        print("[*]\t--->\t发送SERVER_DONE")

        self.socket.send(json.dumps(
            [TLSContent, TLSContent1, TLSContent2]).encode())

    def client_hello_rcev(self):
        # 接收server的消息
        data = json.loads(self.socket.recv(1024))

        # 判断收到的3个包是否是HANDSHAKE
        if data[0][0] == TLSContentType.HANDSHAKE and data[2][0] == TLSContentType.HANDSHAKE:
            # 两个包的类型否是SERVER_HELLO 和 SERVER_DONE
            if data[0][1][0] == TLSMessageType.SERVER_HELLO and data[2][1][0] == TLSMessageType.SERVER_DONE:
                # 包的类型符合
                print("[*]\t<---\t接收SERVER_HELLO")
                print("[*]\t<---\t接收CERTIFICATE")
                print("[*]\t<---\t接收SERVER_DONE")

                # 获取server随机数
                self.serverRandom = base64.b64decode(data[0][1][2][1])

                # 获取server的RSA公钥
                self.pubkey = rsa.PublicKey.load_pkcs1(
                    base64.b64decode(data[1][1][2][1]))

                print("[#]\t \t使用密钥套件TLS_RSA_WITH_AES_256_CBC_SHA256")
                # 将密码套件设置为服务器选择的密码套件
                self.cipherSuites = data[0][1][2][3]

                return

        raise SSLerror("client hello rcev error")

    def keySend(self):
        # 生成预备主密钥
        self.pre_master_secret = numpy.random.bytes(48)

        print("[#]\t \t生成pre_master_secret\t对称密钥生成完毕")

        # 用公钥加密预备主密钥
        crypto = rsa.encrypt(self.pre_master_secret, self.pubkey)

        # 生成clientKeyExchange报文
        CLIENT_KEY_EXCHANGE = [TLSVersion.TLSv1_2,
                               base64.b64encode(crypto).decode()]
        clientKeyExchange = [TLSMessageType.CLIENT_KEY_EXCHANGE,
                             len(CLIENT_KEY_EXCHANGE), CLIENT_KEY_EXCHANGE]
        TLSContent = [TLSContentType.HANDSHAKE, clientKeyExchange]
        print("[*]\t--->\t发送CLIENT_KEY_EXCHANGE")

        # 生成CHANGE_CIPHER_SPEC报文
        TLSContent1 = [TLSContentType.CHANGE_CIPHER_SPEC,
                       TLSMessageType.CHANGE_CIPHER_SPEC, TLSVersion.TLSv1_2]
        print("[*]\t--->\t发送CHANGE_CIPHER_SPEC")

        # 这里是生成对称密钥
        self.change_cipher()

        # 发送CLIENT_HELLO
        self.socket.send(json.dumps([TLSContent, TLSContent1]).encode())

    def recvKey(self):
        # 接收client预备主密钥
        data = json.loads(self.socket.recv(2048))

        # 接收预备主密钥
        if data[0][0] == TLSContentType.HANDSHAKE and data[0][1][0] == TLSMessageType.CLIENT_KEY_EXCHANGE:
            pre_master_secret = base64.b64decode(data[0][1][2][1])
        else:
            # 如果没有正确接收就抛出错误
            raise SSLerror("server recvKey error")

        # 对密钥还进行解密！！
        self.pre_master_secret = rsa.decrypt(pre_master_secret, self.privkey)

        # 生成对称密钥
        self.change_cipher()

        print("[*]\t<---\t收到CLIENT_KEY_EXCHANGE")
        print("[*]\t<---\t收到CHANGE_CIPHER_SPEC")
        print("[#]\t \t收到pre_master_secret\t对称密钥生成完毕")

    def server_finish(self):
        TLSContent = [TLSContentType.CHANGE_CIPHER_SPEC,
                      TLSMessageType.CHANGE_CIPHER_SPEC, TLSVersion.TLSv1_2]
        print("[*]\t--->\t发送CHANGE_CIPHER_SPEC")

        # 发送CHANGE_CIPHER_SPEC
        self.socket.send(json.dumps([TLSContent]).encode())
    
    def client_finish(self):
        # 接收server预备主密钥
        data = json.loads(self.socket.recv(2048))

        if data[0][0] == TLSContentType.CHANGE_CIPHER_SPEC and data[0][1] == TLSMessageType.CHANGE_CIPHER_SPEC:
            print("[*]\t<---\t收到CHANGE_CIPHER_SPEC")
            return
        else:
            # 如果没有正确接收就抛出错误
            raise SSLerror("client finish error: server probably not CHANGE CIPHER SPEC")


    def change_cipher(self):
        # 生成48字节的主密钥
        self.master_secret = PRF.prf(
            self.pre_master_secret, b"master secret", self.serverRandom+self.clientRandom).output(48)
        # 服务器写MAC密钥
        self.server_mac_secret = PRF.prf(
            self.master_secret, b"server mac secret", self.serverRandom+self.clientRandom).output(48)
        # 客户端写MAC密钥
        self.client_mac_secret = PRF.prf(
            self.master_secret, b"client mac secret", self.serverRandom+self.clientRandom).output(48)
        # 服务器写密钥
        self.server_write_secret = PRF.prf(
            self.master_secret, b"server write secret", self.serverRandom+self.clientRandom).output(32)
        # 客户端写密钥
        self.client_write_secret = PRF.prf(
            self.master_secret, b"client write secret", self.serverRandom+self.clientRandom).output(32)

    def client_do_handshake(self):
        # 客户端向服务器hello
        self.client_hello()

        # 接收server的回复
        self.client_hello_rcev()

        # 向server发送预备主密钥
        self.keySend()

        # 接收回复看服务器是否更换密钥
        self.client_finish()

        # 连接成功
        self.is_connect = True

    def server_do_handshake(self):
        # 服务器进行握手必须先接受一个连接
        connectionSocket, addr = self.socket.accept()

        # 连接成功后 服务端就把socket换为 连接上的client的套接字
        self.socket = connectionSocket

        # 服务器接受 client 的hello
        self.server_hello_rcev()

        # 服务响应给client
        self.server_hello_response()

        # 接收客户端的发送的钥匙
        self.recvKey()

        # 发送CHANGE_CIPHER_SPEC接收握手过程
        self.server_finish()

        # 连接成功
        self.is_connect = True

        # 返回包装好的套接字
        return (self, addr)

    def create(self, sock, server_side):
        self.socket = sock
        if server_side:
            self.server_side = True
        return self

    def accept(self):
        if (self.server_side) and (not self.is_connect):
            # 如果要调用 accept 一定是服务端 且一定是没有完成tls连接 必须先完成handshake
            return self.server_do_handshake()
        else:
            return False

    def recv(self, size):
        if not self.is_connect:
            if self.server_side:
                self.server_do_handshake()
            else:
                self.client_do_handshake()

        data = self.socket.recv(2048)
        
        if not self.server_side:
            recvData = AEScbc.decrypt(
                data, self.server_write_secret, self.iv)
            MAC = hmac.new(self.server_mac_secret, recvData[0:-32],
                           digestmod='sha256').digest()

        else:
            recvData = AEScbc.decrypt(
                data, self.client_write_secret, self.iv)
            MAC = hmac.new(self.client_mac_secret, recvData[0:-32],
                           digestmod='sha256').digest()

        recvMAC = recvData[-32:]

        data = recvData[0:-32]

        # 核对密钥是否正确
        if recvMAC == MAC:
            return data[0:size]
        else:
            raise SSLerror("recv data MAC error")


    def send(self, data):
        if not self.is_connect:
            if self.server_side:
                self.server_do_handshake()
            else:
                self.client_do_handshake()

        if self.server_side:
            # 服务端加密
            sendMAC = hmac.new(self.server_mac_secret, data,
                               digestmod='sha256').digest()
            data += sendMAC
            sendData = AEScbc.encrypt(data, self.server_write_secret, self.iv)
        else:
            # 客户端加密
            sendMAC = hmac.new(self.client_mac_secret, data,
                               digestmod='sha256').digest()
            data += sendMAC
            sendData = AEScbc.encrypt(data, self.client_write_secret, self.iv)
        
        self.socket.send(sendData)

    def close(self):
        self.is_connect = False
        self.socket.close()
        print("[*]\t--x--\t连接CLOSE")

    def viewKey(self):
        # 供测试使用
        print("········密钥：")
        print(self.pre_master_secret,"\n",
        self.master_secret,"\n",
        self.server_mac_secret,"\n",
        self.client_mac_secret,"\n",
        self.server_write_secret,"\n",
        self.client_write_secret)


class SSLContext:
    sslsocket_class = None

    def wrap_socket(self, sock, server_side):
        return self.sslsocket_class.create(sock, server_side)


SSLContext.sslsocket_class = SSLSocket()

if __name__ == "__main__":
    pass
    # print(random.randint(0,9))
    # print(numpy.random.bytes(28))
    # print([i.value for i in TLSCipherSuites])
    # bytes = numpy.random.bytes(28)
    # print(bytes)
    # print([int(i) for i in bytes])

    # print(str(int(bytes[0])))
    # randomNum = ''
    # for i in range(0, len(bytes), 4):
    #     randomNum += str(int(bytes[i:i + 4], 2))


#     # --------------------------------------------------------------
    CLIENT_HELLO = [TLSVersion.TLSv1_2, base64.b64encode(numpy.random.bytes(28)).decode(),
                    0, [i.value for i in TLSCipherSuites], None]
    clientRequest = [TLSMessageType.CLIENT_HELLO,
                     len(CLIENT_HELLO), CLIENT_HELLO]
    TLSContent = [TLSContentType.HANDSHAKE, clientRequest]
    data = json.dumps(TLSContent)

    # print(data.encode())
    data2 = json.loads(data.encode())
    # print(data2)
    packet(data2)
# # --------------------------------------------------------------

    # --------------------------------------------------------------
    # iv = bytes(16)

    # recvData = AEScbc.decrypt(
    #             data[0:-32], self.client_write_secret, iv)
