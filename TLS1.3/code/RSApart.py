import rsa
import base64
# client 要生成48字节的随机预备主密钥
# server利用私钥解密 并获得值

 
 
if __name__ == "__main__":

    (pubkey, privkey) = rsa.newkeys(1024)
    sendPubKey = base64.b64encode(pubkey.save_pkcs1())
    print("sendPubKey")
    print(sendPubKey)

    # 收到的公钥
    recvPubKey = rsa.PublicKey.load_pkcs1(base64.b64decode(sendPubKey))
    content = "hello".encode()
    # 公钥加密 
    crypto = rsa.encrypt(content, recvPubKey)

    message = rsa.decrypt(crypto, privkey).decode()

    print(message)


