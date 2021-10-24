import time
import hashlib


# 获取时间
current_time = time.time()

md5 = hashlib.md5()
# 种子和用户账户一一对应
seed = "19300240012"
# hash运算
md5.update((seed + str(int(current_time/60))).encode('utf-8'))
hashAns = md5.hexdigest()
# 将运算结果保留装换为整数 取末尾6个数字 
print((str(int(hashAns, 16) % 1000000)).zfill(6))
