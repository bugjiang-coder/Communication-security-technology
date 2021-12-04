import numpy


def randomNum(secretMessage):
    PrimeNum = 61
    mask = bytearray(b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa')
    if secretMessage:
        random = bytearray(numpy.random.bytes(28))
        massage = bytearray(secretMessage.encode())
        # 将secretMessage补足8位
        if len(massage) < 8:
            massage = bytearray((8-len(massage))*[0]) + massage
        # 将secretMessage用mask异或后放入随机数的头8位
        for i in range(0,8):
            massage[i] = massage[i] ^ mask[i]
            random[i] = massage[i]

        # 修改随机数最后1为将sum可以被选取的质数整除
        remainder = sum(random) % PrimeNum
        if remainder != 0:
            if random[-1] - remainder > 0:
                random[-1] -= remainder
            else:
                random[-1] = random[-1] + 255 - remainder
            return random
        else:
            return random

    else:
        random = bytearray(numpy.random.bytes(28))
        # 保证sum不能被整除
        if sum(random) % PrimeNum == 0:
            if random[-1] > 0:
                random[-1] -= 1
            else:
                random[-1] += 1
            return random
        else:
            return random

def getsecretMessage(secretNum):
    PrimeNum = 61
    mask = bytearray(b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa')
    random = bytearray(secretNum)
    if sum(random) %PrimeNum != 0:
        return "**********"
    else:
        massage = random[0:8]
        begin = -1
        for i in range(0,8):
            massage[i] ^=mask[i]
            # 找到字符串开始的位置
            if massage[i] != 0 and begin == -1:
                begin = i

        return massage[begin:].decode()



if __name__ == "__main__":
    # "hello"
    test = randomNum("hello")

    print(sum(test)%61)

    print(getsecretMessage(test))