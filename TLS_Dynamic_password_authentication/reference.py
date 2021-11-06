hostname = 'google.com'
port = 443
resource = '/'

context = ssl.SSLContext(ssl.PROTOCOL_TLS)

sock = socket.create_connection((hostname, port))
ssock = context.wrap_socket(sock, server_hostname=hostname)

#send - receive

ssr = ssock.session
print(ssock.session_reused) # False
ssock.close()



sock = socket.create_connection((hostname, port))
ssock = context.wrap_socket(sock, server_hostname=hostname, session=ssr)

#send - receive

print(ssock.session_reused) # True , if server support it

ssock.close()