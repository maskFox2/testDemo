# -*- coding:utf-8 -*-
from tkinter import *
import rsa
import base64


def GenerateKey():
    num = int(bitNum.get("0.0", "end"))
    print(num)
    (public_key, private_key) = rsa.newkeys(num)
    print("\n生成公钥：" + public_key.save_pkcs1().decode('utf8'))
    print("\n生成私钥：" + private_key.save_pkcs1().decode('utf8'))
    publicKeyText.delete(0.0, END)
    publicKeyText.insert(END, public_key.save_pkcs1().decode('utf8'))

    privateKeyText.delete(0.0, END)
    privateKeyText.insert(END, private_key.save_pkcs1().decode('utf8'))


def EncryptionByPublickey():  # 用公钥加密
    public_key_str = publicKeyText.get("0.0", "end").encode(encoding="utf-8")
    public_key = rsa.PublicKey.load_pkcs1(public_key_str)

    entry_str = entryText.get("0.0", "end").encode(encoding="utf-8")

    encrypt_msg = rsa.encrypt(entry_str, public_key)
    print("公钥加密后的文本为：\n" + base64.encodebytes(encrypt_msg).decode('utf8'))
    outputText.delete(0.0, END)
    outputText.insert(END, base64.encodebytes(encrypt_msg).decode('utf8'))


def EncryptionByPrivatekey():
    private_key_str = privateKeyText.get("0.0", "end").encode(encoding="utf-8")
    private_key = rsa.PrivateKey.load_pkcs1(private_key_str)

    entry_str = entryText.get("0.0", "end").encode(encoding="utf-8")

    encrypt_msg = rsa.encrypt(entry_str, private_key)
    print("私钥加密后的文本为：\n" + base64.encodebytes(encrypt_msg).decode('utf8'))
    outputText.delete(0.0, END)
    outputText.insert(END, base64.encodebytes(encrypt_msg).decode('utf8'))


def DeryptionByPublickey():
    public_key_str = privateKeyText.get("0.0", "end").encode(encoding="utf-8")
    public_key = rsa.PrivateKey.load_pkcs1(public_key_str)

    entry_str = entryText.get("0.0", "end").encode(encoding="utf-8")
    encrypt_msg = base64.decodebytes(entry_str)
    outputText.delete(0.0, END)

    try:
        decrypt_msg = rsa.decrypt(encrypt_msg, public_key)
        print("公钥解密后的文本为：\n" + decrypt_msg.decode('utf8'))
        outputText.insert(END, decrypt_msg.decode('utf8'))
    except:
        decrypt_msg = "公钥解密失败"
        print(decrypt_msg)
        outputText.insert(END, decrypt_msg)


def DecryptionByPrivatekey():
    private_key_str = privateKeyText.get("0.0", "end").encode(encoding="utf-8")
    private_key = rsa.PrivateKey.load_pkcs1(private_key_str)

    entry_str = entryText.get("0.0", "end").encode(encoding="utf-8")
    encrypt_msg = base64.decodebytes(entry_str)
    outputText.delete(0.0, END)

    try:
        decrypt_msg = rsa.decrypt(encrypt_msg, private_key)
        print("私钥解密后的文本为：\n" + decrypt_msg.decode('utf8'))
        outputText.insert(END, decrypt_msg.decode('utf8'))
    except:
        decrypt_msg = "私钥解密失败"
        print(decrypt_msg)
        outputText.insert(END, decrypt_msg)


# 添加签名函数
def SignMessageByPrivateKey():
    private_key_str = privateKeyText.get("0.0", "end").encode(encoding="utf-8")
    private_key = rsa.PrivateKey.load_pkcs1(private_key_str)

    entry_str = entryText.get("0.0", "end").encode(encoding="utf-8")

    signature = rsa.sign(entry_str, private_key, 'SHA-256')
    print("签名结果为：\n" + base64.encodebytes(signature).decode('utf8'))
    outputText.delete(0.0, END)
    outputText.insert(END, base64.encodebytes(signature).decode('utf8'))


# 添加验证签名函数
def VerifySignatureByPublicKey():
    public_key_str = publicKeyText.get("0.0", "end").encode(encoding="utf-8")
    public_key = rsa.PublicKey.load_pkcs1(public_key_str)

    signature_base64 = entryText.get("0.0", "end - 1 line").encode(encoding="utf-8")  # 获取待验证的消息文本
    entry_str = entryText.get("end - 1 line", "end").encode(encoding="utf-8")  # 获取签名部分（假设它位于文本末尾）

    # signature_base64 = (signature_base64.decode('utf-8').replace('\n', '')).encode('utf-8')

    print("entry:", entry_str)
    print("signature_base64:", signature_base64)
    outputText.delete(0.0, END)

    try:
        signature_bytes = base64.decodebytes(signature_base64)
        if rsa.verify(entry_str, signature_bytes, public_key):
            print("签名验证成功")
            outputText.delete(0.0, END)
            outputText.insert(END, "签名验证成功")
        else:
            print("签名验证失败")
            outputText.delete(0.0, END)
            outputText.insert(END, "签名验证失败")
    except Exception as e:
        print(f"签名验证过程中发生错误: {e}")
        outputText.delete(0.0, END)
        outputText.insert(END, f"签名验证过程中发生错误: {e}")


window = Tk()
window.title("RSA加密解密软件")

frame = Frame(window)
frame.pack()

label = Label(frame, text="公钥：")
label.grid(row=1, column=1, columnspan=4)

publicKeyText = Text(frame, width=50, height=8)
publicKeyText.grid(row=2, column=1, columnspan=4)

label = Label(frame, text="私钥：")
label.grid(row=3, column=1, columnspan=4)

privateKeyText = Text(frame, width=50, height=12)
privateKeyText.grid(row=4, column=1, columnspan=4)

label = Label(frame, text="位数：")
label.grid(row=5, column=1)

bitNum = Text(frame, width=10, height=2)
bitNum.insert(0.0, "256")
bitNum.grid(row=5, column=2)

btGenerateKey = Button(frame, text="生成公钥/私钥", command=GenerateKey)
btGenerateKey.grid(row=5, column=2, columnspan=4)

label = Label(frame, text="请输入加密/解密的文本:")
label.grid(row=6, column=1, columnspan=4)

entryText = Text(frame, width=50, height=5)
entryText.grid(row=7, column=1, columnspan=4)

btEncryptionByPublickey = Button(frame, text="公钥加密", command=EncryptionByPublickey)
btEncryptionByPublickey.grid(row=8, column=1, pady=10)

btDeryptionByPublickey = Button(frame, text="私钥解密", command=DecryptionByPrivatekey)
btDeryptionByPublickey.grid(row=8, column=2)

btEncryptionByPrivatekey = Button(frame, text="私钥签名", command=SignMessageByPrivateKey)
btEncryptionByPrivatekey.grid(row=8, column=3)

btDecryptionByPrivatekey = Button(frame, text="公钥验证", command=VerifySignatureByPublicKey)
btDecryptionByPrivatekey.grid(row=8, column=4)

outputText = Text(frame, width=50, height=5)
outputText.grid(row=9, column=1, columnspan=4)

GenerateKey()
mainloop()
