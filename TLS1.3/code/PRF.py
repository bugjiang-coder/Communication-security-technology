import hmac


class PRF:
    def __init__(self, secret, label, seed) -> None:
        self.secret = secret
        self.label = label
        self.seed = seed
        # 直接设置种子由 laber||seed PRF内部就是一个P_hash(secret, seed)函数
        self.seed = self.label + self.seed
        self.A = seed
        self.output = b''

    def updataA(self):
        hash = hmac.new(self.secret, self.A, digestmod='sha256').digest()
        self.A = hash
        return hash

    # 调用get函数增加随机数的序列 达到想要的大小 可以直接用output获取
    def get(self):
        hash = hmac.new(self.secret, self.updataA() + self.seed,
                        digestmod='sha256').digest()
        self.output += hash
        return hash


if __name__ == "__main__":
    ans = PRF(b'hello', b'123', b'123123213')
    print(len(ans.output))
    print(ans.output)
    ans.get()
    print(len(ans.output))
    print(ans.output)
    ans.get()
    print(len(ans.output))
    print(ans.output)

    # message = b'Hello, world!'
    # key = b'secret'
    # h = hmac.new(key, message, digestmod='sha256')
    # # 如果消息很长，可以多次调用h.update(msg)
    # print(h.digest())
