import urllib.request
import socket
import ssl

if __name__ == '__main__':
    # CA_FILE = "ca.crt"

    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    # context.check_hostname = False
    # context.load_verify_locations(CA_FILE)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_default_certs()
    # ssl._create_default_https_context = ssl._create_unverified_context

    context.verify_mode = ssl.CERT_REQUIRED
    try:
        request = urllib.request.Request('https://www.baidu.com')
        res = urllib.request.urlopen(request, context=context)
        print(res.code)
        print("---------------")
        print(res)
        print("---------------")
        print(res.read().decode("utf-8"))
    except Exception as ex:
        print("Found Error in auth phase:%s" % str(ex))

    # hostname = 'www.python.org'
    # # PROTOCOL_TLS_CLIENT requires valid cert chain and hostname
    # context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # context.load_verify_locations('path/to/cabundle.pem')

    # with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    #     with context.wrap_socket(sock, server_hostname=hostname) as ssock:
    #         print(ssock.version())