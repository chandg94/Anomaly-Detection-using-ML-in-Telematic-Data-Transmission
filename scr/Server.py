#!/usr/bin/python3
# This is the server to which our client/BBB connects
# Importing required modules
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import socket
import struct
import time
import json
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
import scrypt, os, binascii
from csv import writer
import csv
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import datetime as dt
import sys
import random
import threading
import time
import numpy as np
from statsmodels.tsa.arima.model import ARIMA
import warnings
warnings.filterwarnings('ignore')

def key_gen(conn, addr):
    private_key_for_ser = X25519PrivateKey.generate()
    public_key_for_ser = private_key_for_ser.public_key()

    public_pem_key_for_ser = public_key_for_ser.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.send(public_pem_key_for_ser)
    public_pem_key_for_bbb = conn.recv(1024)
    pub_key_bbb = load_pem_public_key(public_pem_key_for_bbb)
    shared_secret = private_key_for_ser.exchange(pub_key_bbb)
    return shared_secret

def ephemeral_key(conn, addr,shared_secret):
    # Generate an ephemeral private key for Server
    e_private_ser = X25519PrivateKey.generate()
    # Extract the public portion of the key
    e_public_ser = e_private_ser.public_key()
    e_public_ser_bytes = e_public_ser.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    f_ser = Fernet(base64.urlsafe_b64encode(shared_secret))
    cipher_text = conn.recv(292)
    # Decrypt the message from BBB and extract the key and salt
    message_from_bbb = f_ser.decrypt(cipher_text)
    salt_from_bbb = message_from_bbb[:32]
    # Server needs to extract the PEM key from BBB
    pem_key_from_bbb = message_from_bbb[32:]
    e_pub_key_from_bbb = load_pem_public_key(pem_key_from_bbb)
    ephemeral_shared_secret = e_private_ser.exchange(e_pub_key_from_bbb)
    cipher_text_for_bbb = f_ser.encrypt(salt_from_bbb + e_public_ser_bytes)
    conn.send(cipher_text_for_bbb)
    return ephemeral_shared_secret

# decryption fucntion to decrypt our arriving packets
def decrypt_AES_GCM(encryptedMsg, password):
    try:
        (kdfSalt, ciphertext, nonce, authTag) = encryptedMsg
        secretKey = scrypt.hash(password, kdfSalt, N=16384, r=8, p=1, buflen=32)
        aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
        plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
        return plaintext
    except(ValueError, KeyError):
        print("Bit manipulation detected in Cipher or MAC")
        return

SPN190_value = []
time_value = []
flag = []
predhighlist = []
predlowlist = []
predlist = []

def predict(SPN190_value, spn190):
    change = abs(SPN190_value[-1] - spn190)
    model = ARIMA(SPN190_value, order=(1,0,1))
    model_fit = model.fit()
    start_index = len(SPN190_value)
    end_index = len(SPN190_value)
    forecast = model_fit.predict(start=start_index, end=end_index)
    predhigh = forecast + 50
    predlow = forecast - 50
    return predhigh,predlow,forecast, change

def recv(count,conn,addr,shared_secret,st):
    while True:
        password = ephemeral_key(conn, addr,shared_secret)
        data = conn.recv(116)  # block until data is available
        message = json.loads(data.decode("utf-8"))
        m1 = base64.b64decode(message['1'])
        m2 = base64.b64decode(message['2'])
        m3 = base64.b64decode(message['3'])
        m4 = base64.b64decode(message['4'])
        encryptedMsg = (m1, m2, m3, m4)
        count = count + 1
        decryptedMsg = decrypt_AES_GCM(encryptedMsg, password)
        val = struct.unpack('<f', decryptedMsg)
        if val[0] == 9999.0:
           print("Finished receiving data")
           break
        spn190 = val[0]
        a = 0
        predhigh=0
        predlow = 0
        t = time.time() - st
        if count > 10:
            predhigh, predlow,forecast, change = predict(SPN190_value,spn190)
            predhigh = predhigh[0]
            predlow = predlow[0]
            if spn190 > predhigh:
                a = spn190
                #print(forecast,change)
            if spn190 < predlow:
                a = spn190
                #print(forecast,change)
            predhighlist.append(predhigh)
            predlowlist.append(predlow)
            predlist.append(a)
        else:
            predlist.append(a)
        flag.append(a)
        SPN190_value.append(spn190)
        time_value.append(t)
        list = [t,spn190,a,predhigh,predlow]
        #print(list)
        if count>10:
            with open('eventdata.csv', 'a', newline='') as f_object:
                # Pass the CSV  file object to the writer() function
                writer_object = writer(f_object)
                writer_object.writerow(list)
                f_object.close()
    return count

def rec_data():
    can_frame_format = "<lB3x8s"
    HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
    PORT = 9009        # Port to listen on (non-privileged ports are > 1023)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    print("Waiting for client to join.....")
    s.listen()
    conn, addr = s.accept()
    print("Connected to client")
    shared_secret = key_gen(conn, addr)
    count = 0
    print("Receiving Data.......please wait")
    st = time.time()
    diclist = []
    for n, j, s, b, c in zip(time_value, SPN190_value, predlist, predhighlist, predlowlist):
        di = {'Time': n, 'SPN': j, 'Flag': s, 'PredHigh': b, 'PredLow': c}
        diclist.append(di)
    with open('eventdata.csv', 'w') as f_object:
        writer = csv.DictWriter(f_object, ['Time', 'SPN', 'Flag','PredHigh', 'PredLow'])
        writer.writeheader()
        for d in diclist:
            writer.writerow(d)
        f_object.close()
    count = recv(count,conn,addr,shared_secret,st)
    end = time.time()
    print(f"TIME taken for receiving data :{end - st}")
    print("Number of packets received : ", count - 1)
    s.close()
    return

rec_data()

print("Closing connection to Client")

