# encoding:utf-8
import base64
from Crypto.Cipher import AES
from Crypto import Random


def encrypt(data, password, iv):
    bs = AES.block_size
    # bs等于16字节 128位

    def pad(s): return s + bytearray((bs - len(s) % bs)*[bs - len(s) % bs])
    cipher = AES.new(key=password, mode=AES.MODE_CBC, iv=iv)
    data = cipher.encrypt(pad(data))

    return (data)


def decrypt(data, password, iv):
    bs = AES.block_size
    if len(data) <= bs:
        return (data)

    def unpad(s): return s[0:-s[-1]]

    cipher = AES.new(key=password, mode=AES.MODE_CBC, iv=iv)
    temp = cipher.decrypt(data)

    data = unpad(temp)
    return (data)


if __name__ == '__main__':
    data = b'd437814d9185a290af2sdfsdfsdfsdf0514d9341b710'
    password = b'78f40f2c57eee727a4be179049cecf89'  # 16,24,32位长的密码
    # iv = Random.new().read(16)
    iv = bytes(16)
    encrypt_data = encrypt(data, password, iv)
    encrypt_data = base64.b64encode(encrypt_data)
    print('encrypt_data:', encrypt_data)

    encrypt_data = base64.b64decode(encrypt_data)
    decrypt_data = decrypt(encrypt_data, password, iv)
    print('decrypt_data:', decrypt_data)
