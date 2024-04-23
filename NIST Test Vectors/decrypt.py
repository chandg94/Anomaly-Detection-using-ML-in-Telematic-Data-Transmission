#!/usr/bin/python3
from Crypto.Cipher import AES

def decrypt_AES_GCM(password, iv, ct, tag):
    aesCipher = AES.new(password, AES.MODE_GCM, iv)
    try:
        plaintext = aesCipher.decrypt_and_verify(ct, tag)
        print("No bit manipulation detected")
        return plaintext

    except(ValueError, KeyError):
        print("Bit manipulation detected in Cipher or MAC")
        x = "FAIL"
        return x

with open('NIST_decrypt', 'r') as f:
    data = []
    for line in f:

        if line.strip() == "#":
            data.clear()
        elif line.strip() == "FAIL":
            x = "FAIL"
            data.append(x)

        else:
            bt = line.strip()
            data.append(bytes.fromhex(bt))
        if len(data) == 5:
            decrypt = decrypt_AES_GCM(data[0], data[1], data[2], data[3])
            if decrypt == data[4]:
                print("PASS : Validation Test case for decryption function")
            else:
                print("FAIL")
        else:
            pass
f.close()