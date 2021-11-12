import hmac


class prf:
    def __init__(self, secret, label, seed) -> None:
        self.secret = secret
        self.label = label
        self.seed = seed
        # 直接设置种子由 laber||seed PRF内部就是一个P_hash(secret, seed)函数
        self.seed = self.label + self.seed
        self.A = seed
        # 用于放置输出的随机数的序列
        self.sequence = b''

    def updataA(self):
        hash = hmac.new(self.secret, self.A, digestmod='sha256').digest()
        self.A = hash
        return hash

    # 调用get函数增加随机数的序列 达到想要的大小 可以直接用output获取
    def get(self):
        hash = hmac.new(self.secret, self.updataA() + self.seed,
                        digestmod='sha256').digest()
        self.sequence += hash
        return hash
    
    # 输出想要大小的密钥序列 size 指的是字节数
    def output(self,size):
        if size < 0 :
            return b''
        length = size
        while length:
            self.get()
            length -= 32
            if length <= 0:
                return self.sequence[0:size]





if __name__ == "__main__":
    # 测试代码
    ans = prf(b'hello', b'123', b'123123213')
    print(len(ans.sequence))
    print(ans.sequence)
    ans.get()
    print(len(ans.sequence))
    print(ans.sequence)
    ans.get()
    print(len(ans.sequence))
    print(ans.sequence)
    a = ans.output(50)
    print(len(a))
    print(a)
    

    # message = b'Hello, world!'
    # key = b'secret'
    # h = hmac.new(key, message, digestmod='sha256')
    # # 如果消息很长，可以多次调用h.update(msg)
    # print(h.digest())
