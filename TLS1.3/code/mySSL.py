from enum import IntEnum
import random


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


class SSLSocket:
    def __init__(self):
        self.socket = None
        self.is_connect = False
        self.version

    def do_handshake(self):
        requestContent = [TLSVersion.TLSv1_3, random.randbytes(28), 0, ]
        clientRequest = [TLSMessageType.CLIENT_HELLO,
                         len(requestContent), requestContent]

        pass

    def server_do_handshake(self):
        pass

    def create(self, sock, server_side):
        self.socket = sock
        if server_side:
            self.server_do_handshake()
        else:
            self.do_handshake()
        return self

    def accept():
        pass

    def recv():
        pass

    def send():
        pass


class SSLContext:
    sslsocket_class = None

    def wrap_socket(self, sock, server_side=False):
        return self.sslsocket_class.create(sock, server_side)


SSLContext.sslsocket_class = SSLSocket
