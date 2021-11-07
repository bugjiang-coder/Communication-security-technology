from PySide2.QtWidgets import QApplication, QMessageBox
from PySide2.QtUiTools import QUiLoader
import socket
import ssl
import hashlib

class Stats:


    def __init__(self):
        self.ui = QUiLoader().load('client.ui')
        self.ui.ButtonNO.clicked.connect(self.ButtonNO)
        self.ui.ButtonOK.clicked.connect(self.handleOK)
        # 计数点击次数
        self.clickOK = 0
        # 存储Session
        self.ssr = []
        # 生成SSL上下文
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        # 加载信任根证书
        self.context.load_verify_locations('./ca/ca.crt')

        
    def ButtonNO(self):
        self.ui.key.setText('')
        self.ui.token.setText('')
        self.ui.textEdit.setText('')


    def handleOK(self):
        self.clickOK += 1
        try:
            sock = socket.create_connection((serverName,serverPort))  # 建立TCP套接字，使用IPv4协议

            if self.clickOK % 2:
                ssock = self.context.wrap_socket(sock, server_hostname='19300240012')  # 向服务器发起连接
            else:
                ssock = self.context.wrap_socket(sock, server_hostname='19300240012', session=self.ssr)
        except OSError as error:
            self.ui.textEdit.append(str(error))
        except ConnectionRefusedError as er:
            self.ui.textEdit.append(str(er))

        if self.clickOK % 2:
            self.ssr = ssock.session
        
        self.ui.textEdit.append("使用session连接到服务器:\t"+str(ssock.session_reused))


        sha256 = hashlib.sha256()
        id = self.ui.id.text().encode()
        key = self.ui.key.text()
        token = self.ui.token.text()

        self.ui.textEdit.append(str("用户名为："+id.decode()))
        ssock.send(id)
        # 从服务器接收信息
        feedback = ssock.recv(1024)
        # 打印服务器的反馈
        self.ui.textEdit.append(feedback.decode())

        if feedback == "Start certification".encode():
            # 先本地对PIN进行hash
            PIN = key.encode('utf-8')
            sha256_forPIN = hashlib.sha256()
            sha256_forPIN.update(PIN)
            PIN = sha256_forPIN.hexdigest()

            # 对时间令牌和PIN的hash结果合并后再hash
            identify_value = (PIN + str(token)).encode('utf-8')
            sha256.update(identify_value)
            identify_value = sha256.hexdigest()
            ssock.send(identify_value.encode())
            feedback2 = ssock.recv(1024)
            self.ui.textEdit.append(feedback2.decode())
            if feedback2.decode() == "OK":
                QMessageBox.about(self.ui, '通知', f'''
                登录成功'''
                )
                ssr = ssock.session

            else:
                QMessageBox.about(self.ui, '错误', f'''登录失败
                            ''')

        else:
            QMessageBox.about(self.ui,'错误', f'''登录失败
            ''')

        ssock.close()  # 关闭套接字





serverName = '127.0.0.1' # 指定服务器IP地址
serverPort = 12000

app = QApplication([])

stats = Stats()

stats.ui.show()

app.exec_()



