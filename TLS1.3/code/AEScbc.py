import base64
from Crypto.Cipher import AES


def encrypt(data, password, iv):
    bs = AES.block_size

    # 定义填充函数 数据总是会被填充
    def pad(s): return s + bytearray((bs - len(s) % bs)*[bs - len(s) % bs])

    # 加密
    cipher = AES.new(key=password, mode=AES.MODE_CBC, iv=iv)
    data = cipher.encrypt(pad(data))

    return (data)


def decrypt(data, password, iv):
    bs = AES.block_size
    
    # 如果小于bs是无法解密的
    if len(data) <= bs:
        return (data)

    # 定义去除填充函数
    def unpad(s): return s[0:-s[-1]]

    # 解密
    cipher = AES.new(key=password, mode=AES.MODE_CBC, iv=iv)
    data = cipher.decrypt(data)

    return unpad(data)



