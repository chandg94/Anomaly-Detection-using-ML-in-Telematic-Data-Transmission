#!/usr/bin/python3
from Crypto.Cipher import AES


def encrypt_AES_GCM(msg, password, iv):
    aesCipher = AES.new(password, AES.MODE_GCM, iv)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, iv, authTag)


with open('NIST_encrypt', 'r') as f:
    data = []
    for line in f:

        if line.strip() == "#":
            data.clear()
        else:
            bt = line.strip()
            data.append(bytes.fromhex(bt))
        if len(data) == 5:
            encrypt = encrypt_AES_GCM(data[2], data[0], data[1])
            (ciphertext, iv, authTag) = encrypt
            if ciphertext == data[3] and authTag == data[4]:
                print("PASS : Validation test case for Encryption Function ")
            else:
                print("FAIL")
        else:
            pass

