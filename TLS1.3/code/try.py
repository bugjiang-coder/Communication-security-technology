#示例：
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import 

def pad(text):
    """加密文本text必须为16的倍数！
    """
    while len(text) % 16 != 0:
        text += '\0'.encode('utf-8')   # \0 可以被decode()自动清除，并且不会影响本来的字符0
    return text

def encrypt(text):
    cryptor = AES.new(key.encode('utf-8')), AES.MODE_CBC, key.encode('utf-8'))   # 此变量是一次性的(第二次调用值会变)不能作为常量通用
    ciphertext = cryptor.encrypt(pad(text.encode('utf-8')))   # encode()转换是因为十六进制用的是字节码
    return b2a_hex(ciphertext).decode('utf-8')   # 因为AES加密时候得到的字符串不一定是ascii字符集的，所以使用十六进制转换才能print来储存

def decrypt(text):
    cryptor = AES.new(key.encode('utf-8'), AES.MODE_CBC, key.encode('utf-8'))
    plain_text = cryptor.decrypt(a2b_hex(text.encode('utf-8')))
    return plain_text.decode('utf-8').rstrip('\0')   # 去除凑数补全的\0
