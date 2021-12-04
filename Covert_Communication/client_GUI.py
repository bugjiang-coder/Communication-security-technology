from PySide2.QtWidgets import QApplication, QMessageBox
from PySide2.QtUiTools import QUiLoader
import socket
import hashlib
import mySSL


class Stats:

    def __init__(self):
        self.ui = QUiLoader().load('client.ui')
        self.ui.ButtonNO.clicked.connect(self.ButtonNO)
        self.ui.ButtonOK.clicked.connect(self.handleOK)

    def ButtonNO(self):
        self.ui.key.setText('')
        self.ui.token.setText('')
        self.ui.textEdit.setText('')
        self.ui.secretMessage.setText('')

    def handleOK(self):
        id = self.ui.id.text().encode()
        key = self.ui.key.text()
        token = self.ui.token.text()
        secretMessage = self.ui.secretMessage.text()

        try:
            context = mySSL.SSLContext()
            sock = socket.create_connection(
                (serverName, serverPort))  # 建立TCP套接字，使用IPv4协议
            clientSocket = context.wrap_socket(sock, False, secretMessage)

        except OSError as error:
            self.ui.textEdit.append(str(error))
        except ConnectionRefusedError as er:
            self.ui.textEdit.append(str(er))

        sha256 = hashlib.sha256()

        self.ui.textEdit.append(str("用户名为："+id.decode()))
        clientSocket.send(id)
        # 从服务器接收信息
        feedback = clientSocket.recv(1024)
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
            clientSocket.send(identify_value.encode())
            feedback2 = clientSocket.recv(1024)
            self.ui.textEdit.append(feedback2.decode())
            if feedback2.decode() == "OK":
                QMessageBox.about(self.ui, '通知', f'''
                登录成功'''
                                  )
            else:
                QMessageBox.about(self.ui, '错误', f'''登录失败
                            ''')

        else:
            QMessageBox.about(self.ui, '错误', f'''登录失败
            ''')

        clientSocket.close()  # 关闭套接字


serverName = '127.0.0.1'  # 指定服务器IP地址
serverPort = 12000

app = QApplication([])

stats = Stats()

stats.ui.show()

app.exec_()
