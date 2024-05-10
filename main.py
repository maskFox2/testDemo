import base64
import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QLabel, QGridLayout, \
    QPlainTextEdit
import rsa


class RSAEncryptDecryptApp(QWidget):
    def __init__(self):
        super().__init__()

        self.pubkey, self.privkey = rsa.newkeys(1024)
        self.initUI()

    def initUI(self):
        self.setWindowTitle('RSA Encrypt/Decrypt')
        self.setGeometry(600, 300, 600, 400)

        # 创建布局和控件
        layout = QVBoxLayout()
        self.setLayout(layout)

        grid_layout = QGridLayout()
        layout.addLayout(grid_layout)

        # 添加p，q，公钥，私钥值为多少
        self.public_key_edit = QPlainTextEdit()
        self.private_key_edit = QPlainTextEdit()

        self.plaintext_edit = QPlainTextEdit()
        self.ciphertext_edit = QPlainTextEdit()
        self.decryptedtext_edit = QPlainTextEdit()

        grid_layout.addWidget(QLabel('消息:'), 0, 0)
        grid_layout.addWidget(self.plaintext_edit, 0, 1)

        grid_layout.addWidget(QLabel('加密/签名:'), 1, 0)
        grid_layout.addWidget(self.ciphertext_edit, 1, 1)

        grid_layout.addWidget(QLabel('解密/Hash:'), 2, 0)
        grid_layout.addWidget(self.decryptedtext_edit, 2, 1)

        grid_layout.addWidget(QLabel('Private_key:'), 3, 0)
        grid_layout.addWidget(self.private_key_edit, 3, 1)
        self.private_key_edit.setPlainText('{}'.format(self.privkey.save_pkcs1().decode("utf-8")))

        grid_layout.addWidget(QLabel('Public_key:'), 4, 0)
        grid_layout.addWidget(self.public_key_edit, 4, 1)
        self.public_key_edit.setPlainText('{}'.format(self.pubkey.save_pkcs1().decode("utf-8")))

        self.encrypt_button = QPushButton('加密')
        self.encrypt_button.clicked.connect(self.encrypt_text)
        layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton('解密')
        self.decrypt_button.clicked.connect(self.decrypt_text)
        layout.addWidget(self.decrypt_button)

        self.encrypt_button_pri = QPushButton('签名')
        self.encrypt_button_pri.clicked.connect(self.encrypt_text_pri)
        layout.addWidget(self.encrypt_button_pri)

        self.decrypt_button_pri = QPushButton('验证')
        self.decrypt_button_pri.clicked.connect(self.decrypt_text_pri)
        layout.addWidget(self.decrypt_button_pri)

    def encrypt_text(self):
        plaintext = self.plaintext_edit.toPlainText()
        ciphertext = rsa.encrypt(plaintext.encode(encoding="utf-8"), self.pubkey)
        self.ciphertext_edit.setPlainText(base64.encodebytes(ciphertext).decode(encoding='utf8'))  # 显示密文的十六进制表示

    def decrypt_text(self):
        ciphertext = self.ciphertext_edit.toPlainText().encode(encoding="utf-8")
        text = rsa.PrivateKey.load_pkcs1(ciphertext)
        try:
            decrypted_text = rsa.decrypt(text, self.privkey).decode(encoding="utf-8")
            self.decryptedtext_edit.setPlainText(decrypted_text)
        except:
            self.decryptedtext_edit.setPlainText("解密失败")

    def encrypt_text_pri(self):
        plaintext = self.plaintext_edit.toPlainText()
        signature = rsa.sign(plaintext.encode(), self.privkey, 'SHA-256')
        self.ciphertext_edit.setPlainText(signature.hex())  # 显示密文的十六进制表示

    def decrypt_text_pri(self):
        plaintext = self.plaintext_edit.toPlainText()
        ciphertext_hex = self.ciphertext_edit.toPlainText()
        ciphertext_bin = bytes.fromhex(ciphertext_hex)

        # 验证签名
        try:
            decrypted_text = rsa.verify(plaintext.encode(), ciphertext_bin, self.pubkey)
            self.decryptedtext_edit.setPlainText(decrypted_text)
        except rsa.VerificationError:
            self.decryptedtext_edit.setPlainText("签名验证失败")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = RSAEncryptDecryptApp()
    ex.show()
    print("pubkey:{}\nprivkey:{}".format(ex.pubkey.save_pkcs1().decode(encoding="utf-8"), ex.privkey.save_pkcs1().decode(encoding="utf-8")))
    sys.exit(app.exec_())
