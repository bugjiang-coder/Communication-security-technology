from PySide2.QtWidgets import QApplication, QMessageBox
from PySide2.QtUiTools import QUiLoader
from PySide2.QtCore import QTimer, QDateTime
import time
import hashlib


class Stats:

    def __init__(self):
        # 从文件中加载UI定义
        # 从 UI 定义中动态 创建一个相应的窗口对象
        # 注意：里面的控件对象也成为窗口对象的属性了
        self.ui = QUiLoader().load('token.ui')
        # 计时器用于更新token
        self.timer = QTimer()
        self.timer.timeout.connect(self.changeToken)  # 这里调用不能有函数括号，不是单纯的运行函数

    def changeToken(self):
        self.ui.plainTextEdit.setPlainText(toke())
        self.timer.start(1000)


def toke():
    # 获取时间
    current_time = time.time()

    md5 = hashlib.md5()
    # 种子和用户账户一一对应
    seed = "19300240012"
    # hash运算
    md5.update((seed + str(int(current_time / 60))).encode('utf-8'))
    hashAns = md5.hexdigest()
    # 将运算结果保留装换为整数 取末尾6个数字
    return((str(int(hashAns, 16) % 1000000)).zfill(6))


app = QApplication([])
stats = Stats()
stats.timer.start(1000)
stats.ui.show()

app.exec_()
