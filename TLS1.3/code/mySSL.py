from enum import IntEnum
import random
import numpy
from Crypto.Cipher import AES
import json


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


class MyEncoder(json.JSONEncoder):
    # 使用Python的json发送byte流，为了发送结构的美观，没有办法，将byte流转化为int发送
    def default(self, obj):
        if isinstance(obj, bytes):
            return [int(i) for i in obj]
        return json.JSONEncoder.default(self, obj)


def packet(pkt):
    # 为测试使用    
    # print(TLSContentType(20)._name_)
    print("[*]TLSContentType:\t"+TLSContentType(pkt[0])._name_)
    print("[*]TLSMessageType:\t"+TLSMessageType(pkt[1][0])._name_)
    print("[*]TLSMessage length:\t"+str(pkt[1][1]))
    print("------------------------")
    print("[*]TLSVersion:\t"+TLSVersion(pkt[1][2][0])._name_)
    print("[*]Random:")
    print(pkt[1][2][1])
    print("[*]session ID:")
    print(pkt[1][2][2])
    print("[*]TLSCipherSuites:")
    print([TLSCipherSuites(i).name for i in pkt[1][2][3]])
    print("[*]Compression Methods:")
    print(pkt[1][2][4])

class SSLSocket:
    def __init__(self):
        self.socket = None
        self.is_connect = False
        self.version
        self.server_side = False
        self.clientRandom
        self.serverRandom
    



    def client_hello(self):
        self.clientRandom = numpy.random.bytes(28)
        CLIENT_HELLO = [TLSVersion.TLSv1_3, self.clientRandom,
                        0, [i.value for i in TLSCipherSuites], None]
        clientRequest = [TLSMessageType.CLIENT_HELLO,
                         len(CLIENT_HELLO), CLIENT_HELLO]
        TLSContent = [TLSContentType.HANDSHAKE, clientRequest]
        # 发送CLIENT_HELLO
        print("[*]\t 发送CLIENT_HELLO")
        self.socket.send(json.dumps(TLSContent, cls=MyEncoder).encode())

    def server_rcev(self):
        data = json.loads(self.socket.recv(1024))
        if data[0] == TLSContentType.HANDSHAKE:
            if data[1][0] == TLSMessageType.CLIENT_HELLO:
                

        

    def client_do_handshake(self):
        self.client_hello()

        pass

    def server_do_handshake(self):
        connectionSocket, addr = self.socket.accept()
        self.server_rcev()


        if self.is_connect:
            return (connectionSocket, addr)
        else:
            return False

        pass

    def create(self, sock, server_side):
        self.socket = sock

        if server_side:
            self.server_side = True

        return self

    def accept(self):
        if not self.server_side:
            return False
        if not self.is_connect:
            return self.server_do_handshake()

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
    CLIENT_HELLO = [TLSVersion.TLSv1_3, numpy.random.bytes(28),
                    0, [i.value for i in TLSCipherSuites], None]
    clientRequest = [TLSMessageType.CLIENT_HELLO,
                     len(CLIENT_HELLO), CLIENT_HELLO]
    TLSContent = [TLSContentType.HANDSHAKE, clientRequest]
    data = json.dumps(TLSContent, cls=MyEncoder)

    # print(data.encode())
    data2 = json.loads(data.encode())
    # print(data2)
    packet(data2)
