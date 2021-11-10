from enum import IntEnum
import random
import numpy
from Crypto.Cipher import AES
import json
import base64
import rsa
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


'''
4.2.7.  Supported Groups

   When sent by the client, the "supported_groups" extension indicates
   the named groups which the client supports for key exchange, ordered
   from most preferred to least preferred.

   Note: In versions of TLS prior to TLS 1.3, this extension was named
   "elliptic_curves" and only contained elliptic curve groups.  See
   [RFC8422] and [RFC7919].  This extension was also used to negotiate
   ECDSA curves.  Signature algorithms are now negotiated independently
   (see Section 4.2.3).

   The "extension_data" field of this extension contains a
   "NamedGroupList" value:

      enum {

          /* Elliptic Curve Groups (ECDHE) */
          secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
          x25519(0x001D), x448(0x001E),

          /* Finite Field Groups (DHE) */
          ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
          ffdhe6144(0x0103), ffdhe8192(0x0104),

          /* Reserved Code Points */
          ffdhe_private_use(0x01FC..0x01FF),
          ecdhe_private_use(0xFE00..0xFEFF),
          (0xFFFF)
      } NamedGroup;

      struct {
          NamedGroup named_group_list<2..2^16-1>;
      } NamedGroupList;
'''


class SupportedGroup(IntEnum):
    # 这里只实现了协议中的3个
    secp256r1 = 0x0017
    secp384r1 = 0x0018
    secp521r1 = 0x0019


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
        self.version
        # 是否是服务端
        self.server_side = False
        # 客户端随机数
        self.clientRandom
        # 服务端随机数
        self.serverRandom
        # 预备主密钥
        self.pre_master_secret
        # server的rsa公钥
        self.pubkey
        # server的rsa私钥
        self.privkey

    def client_hello(self):
        self.clientRandom = numpy.random.bytes(28)
        # 由于json无法发送bytes流 clientRandom使用base64编码
        CLIENT_HELLO = [TLSVersion.TLSv1_3, str(base64.b64encode(self.clientRandom)),
                        0, [i.value for i in TLSCipherSuites], None]
        clientRequest = [TLSMessageType.CLIENT_HELLO,
                         len(CLIENT_HELLO), CLIENT_HELLO]
        TLSContent = [TLSContentType.HANDSHAKE, clientRequest]
        print("[*]\t 发送CLIENT_HELLO")

        # 发送CLIENT_HELLO
        self.socket.send(json.dumps(TLSContent).encode())

    def server_hello_rcev(self):
        data = json.loads(self.socket.recv(1024))
        if data[0] == TLSContentType.HANDSHAKE:
            if data[1][0] == TLSMessageType.CLIENT_HELLO:
                # 获取client 随机数
                self.clientRandom = base64.b64decode(data[1][2][1])
                # 检查 是否有对应的密码套件只实现了该套件
                for i in data[1][2][3]:
                    if i == TLSCipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA256:
                        return True
        return False

    def server_hello_response(self):
        # 由于json无法发送bytes流 clientRandom使用base64编码
        self.serverRandom = numpy.random.bytes(28)
        # 生成RSA密钥对 并且在CERTIFICATE部分发送
        (self.pubkey, self.privkey) = rsa.newkeys(1024)

        # SERVER_HELLO
        SERVER_HELLO = [TLSVersion.TLSv1_3, str(base64.b64encode(self.serverRandom)),
                        0, TLSCipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA256, None]
        serverResponse = [TLSMessageType.SERVER_HELLO,
                          len(SERVER_HELLO), SERVER_HELLO]
        TLSContent = [TLSContentType.HANDSHAKE, serverResponse]
        print("[*]\t 发送SERVER_HELLO")

        # 要发送证书 证书内包含 server的公钥 这里简化实现不进行签名认证，直接发送server的公钥
        CERTIFICATE = [TLSVersion.TLSv1_3,
                       str(base64.b64encode(self.pubkey.save_pkcs1()))]
        certificate = [TLSMessageType.CERTIFICATE,
                       len(CERTIFICATE), CERTIFICATE]
        TLSContent1 = [TLSContentType.HANDSHAKE, certificate]
        print("[*]\t 发送CERTIFICATE")

        # SERVER_DONE 结束hello过程
        SERVER_DONE = [TLSVersion.TLSv1_3]
        helloDone = [TLSMessageType.SERVER_DONE, len(SERVER_DONE), SERVER_DONE]
        TLSContent2 = [TLSContentType.HANDSHAKE, helloDone]
        print("[*]\t 发送SERVER_DONE")

        self.socket.send(json.dumps(
            [TLSContent, TLSContent1, TLSContent2]).encode())

    def client_hello_rcev(self):
        data = json.loads(self.socket.recv(1024))
        # 判断收到的两个包是否是HANDSHAKE
        if data[0][0] == TLSContentType.HANDSHAKE and data[2][0] == TLSContentType.HANDSHAKE:
            # 两个包的类型否是SERVER_HELLO 和 SERVER_DONE
            if data[0][1][0] == TLSMessageType.SERVER_HELLO and data[2][1][0] == TLSMessageType.SERVER_DONE:
                # 获取server随机数
                self.serverRandom = base64.b64decode(data[0][1][2][1])
                # 获取server的RSA公钥
                self.pubkey = rsa.PublicKey.load_pkcs1(base64.b64decode(data[1][1][2][1]))
                # 检查 是否有对应的密码套件只实现了该套件
                if data[0][1][2][3] == TLSCipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA256:
                    return True
        return False

    def keySend(self):
        # 生成预备主密钥
        self.pre_master_secret = numpy.random.bytes(48)
        # 用公钥加密预备主密钥
        crypto = rsa.encrypt(self.pre_master_secret, self.pubkey)

        CLIENT_KEY_EXCHANGE = [TLSVersion.TLSv1_3, str(base64.b64encode(crypto))]
        clientKeyExchange = [TLSMessageType.CLIENT_KEY_EXCHANGE,
                         len(CLIENT_KEY_EXCHANGE), CLIENT_KEY_EXCHANGE]
        TLSContent = [TLSContentType.HANDSHAKE, clientKeyExchange]
        print("[*]\t 发送CLIENT_KEY_EXCHANGE")

        TLSContent1 = [TLSContentType.CHANGE_CIPHER_SPEC, TLSMessageType.CHANGE_CIPHER_SPEC, TLSVersion.TLSv1_3]
        print("[*]\t 发送CHANGE_CIPHER_SPEC")

        # 修改（这里是生成）对称密钥
        self.change_cipher()

        # TLSContent2 = [TLSContentType.CHANGE_CIPHER_SPEC, TLSMessageType.FINISHED,TLSVersion.TLSv1_3]
        print("[*]\t 发送FINISHED")


        # 发送CLIENT_HELLO
        self.socket.send(json.dumps([TLSContent,TLSContent1,TLSContent2]).encode())

    def change_cipher(self):
        pass



    def client_do_handshake(self):
        # 客户端向服务器hello
        self.client_hello()
        # 接收server的回复
        chrFlag = self.client_hello_rcev()

        self.keySend()

        if chrFlag:
            self.is_connect = True

    def server_do_handshake(self):
        # 服务器进行握手必须先接受一个连接
        connectionSocket, addr = self.socket.accept()
        # 服务器接受 client 的hello

        shrFlag = self.server_hello_rcev()
        # 服务响应给client
        self.server_hello_response()

        if shrFlag:
            self.is_connect = True

        if self.is_connect:
            return (connectionSocket, addr)
        else:
            return False

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

    def recv(self):
        if not self.is_connect:
            if self.server_side:
                self.server_do_handshake()
            else:
                self.client_do_handshake()

        pass

    def send(self):
        if not self.is_connect:
            if self.server_side:
                self.server_do_handshake()
            else:
                self.client_do_handshake()

        pass


class SSLContext:
    sslsocket_class = None

    def wrap_socket(self, sock, server_side=False):
        return self.sslsocket_class.create(sock, server_side)


SSLContext.sslsocket_class = SSLSocket

if __name__ == "__main__":
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
    CLIENT_HELLO = [TLSVersion.TLSv1_3, str(base64.b64encode(numpy.random.bytes(28))),
                    0, [i.value for i in TLSCipherSuites], None]
    clientRequest = [TLSMessageType.CLIENT_HELLO,
                     len(CLIENT_HELLO), CLIENT_HELLO]
    TLSContent = [TLSContentType.HANDSHAKE, clientRequest]
    data = json.dumps(TLSContent)

    # print(data.encode())
    data2 = json.loads(data.encode())
    # print(data2)
    packet(data2)
