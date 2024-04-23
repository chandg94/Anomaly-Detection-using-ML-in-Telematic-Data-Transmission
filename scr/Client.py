#!/usr/bin/python3
# This is the Client/BBB
# Importing required modules for epheremal key
import os

import random
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import subprocess
import socket
import struct
import time
import json
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
import scrypt, os, binascii
import psutil
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import queue
import threading
import time
import sys
import errno
import matplotlib.pyplot as plt
import numpy

def check_canplayer(file):
    for p in psutil.process_iter():
        if "canplayer" in p.name():
            if file in p.cmdline():
                return True
    return False

def vcan_play():
    if not check_canplayer('dump.txt'):
        subprocess.Popen(["canplayer","-l", "i","-I","/home/test/PycharmProjects/FinalProject/dump.txt","vcan0=can1"], shell=True,)
        print("Started canplayer")
    else:
        print("Canplayer already running")

def key_gen(s):
    private_key_for_bbb = X25519PrivateKey.generate()
    public_key_for_bbb = private_key_for_bbb.public_key()
    public_pem_key_for_bbb = public_key_for_bbb.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    s.send(public_pem_key_for_bbb)
    public_pem_key_for_ser = s.recv(1024)
    pub_key_ser = load_pem_public_key(public_pem_key_for_ser)
    shared_secret = private_key_for_bbb.exchange(pub_key_ser)
    return shared_secret

def ephemeral_key(s):
    e_private_bbb = X25519PrivateKey.generate()
    # Extract the public portion of the key
    e_public_bbb = e_private_bbb.public_key()
    e_public_bbb_bytes = e_public_bbb.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # BBB creates a symmetric cipher based on the shared secret
    f_bbb = Fernet(base64.urlsafe_b64encode(shared_secret))
    # BBB encrypts a 32 byte random salt value and the ephemeral public key
    salt = os.urandom(32)
    cipher_text = f_bbb.encrypt(salt + e_public_bbb_bytes)
    s.send(cipher_text)
    cipher_text_for_bbb = s.recv(292)
    message_from_ser = f_bbb.decrypt(cipher_text_for_bbb)
    salt_from_ser = message_from_ser[:32]
    if (salt != salt_from_ser):
        print("Exception")
    e_pem_from_ser = message_from_ser[32:]
    e_pub_key_from_ser = load_pem_public_key(e_pem_from_ser)
    ephemeral_shared_secret_bbb = e_private_bbb.exchange(e_pub_key_from_ser)
    return ephemeral_shared_secret_bbb


def encrypt_AES_GCM(msg, password):
    kdfSalt = os.urandom(16)
    secretKey = scrypt.hash(password, kdfSalt, N=16384, r=8, p=1, buflen=32)
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (kdfSalt, ciphertext, aesCipher.nonce, authTag)

#Make a CAN reading function
def unpack_CAN(can_packet,display=False):
    can_id, can_dlc, can_data = struct.unpack(can_frame_format, can_packet)
    extended_frame = bool(can_id & socket.CAN_EFF_FLAG)
    if extended_frame:
        can_id &= socket.CAN_EFF_MASK
        can_id_string = "{:08X}".format(can_id)
    else: #Standard Frame
        can_id &= socket.CAN_SFF_MASK
        can_id_string = "{:03X}".format(can_id)
    if display:
        hex_data_string = ' '.join(["{:02X}".format(b) for b in can_data[:can_dlc]])
        print("{} {} [{}] {}".format(interface, can_id_string, can_dlc, hex_data_string))
    return can_id, can_dlc, can_data


# parse J1939 protocol data unit information from the ID using bit masks and shifts
PRIORITY_MASK = 0x1C000000
EDP_MASK = 0x02000000
DP_MASK = 0x01000000
PF_MASK = 0x00FF0000
PS_MASK = 0x0000FF00
SA_MASK = 0x000000FF
PDU1_PGN_MASK = 0x03FF0000
PDU2_PGN_MASK = 0x03FFFF00


def get_j1939_from_id(can_id):
     # priority
     priority = (PRIORITY_MASK & can_id) >> 26

     # Extended Data Page
     edp = (EDP_MASK & can_id) >> 25

     # Data Page
     dp = (DP_MASK & can_id) >> 24

     # Protocol Data Unit (PDU) Format
     PF = (can_id & PF_MASK) >> 16

     # Protocol Data Unit (PDU) Specific
     PS = (can_id & PS_MASK) >> 8

     # Determine the Parameter Group Number and Destination Address
     if PF >= 0xF0:  # 240
          # PDU 2 format, include the PS as a group extension
          DA = 255
          PGN = (can_id & PDU2_PGN_MASK) >> 8
     else:
          PGN = (can_id & PDU1_PGN_MASK) >> 8
          DA = PS
     # Source address
     SA = (can_id & SA_MASK)

     return priority, PGN, DA, SA

print("Connecting to Server.....")
HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 9009        # The port used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
time.sleep(1.0)
s.connect((HOST, PORT))
print("Successfully connected to Server")
shared_secret = key_gen(s)
buffer = queue.Queue()
vcan_play()
# Open a socket and bind to it from SocketCAN
print("Connecting to vcan......")
sock = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
interface = "vcan0"
# Bind to the interface
sock.bind((interface,))
# To match this data structure, the following struct format can be used:
can_frame_format = "<lB3x8s"


def canplay_recv():
    rc = 0
    for i in range(2000):

        msg = sock.recv(16)
        buffer.put(msg)
        rc = rc + 1
    print("CAN frames received : ", rc)

def data_send():
    print("Sending data to server.....please wait")
    count = 0
    can_count = 0
    while not buffer.empty():
        try:
            msg = buffer.get()
            SPN190_value = []
            can_id, can_dlc, can_data = unpack_CAN(msg)
            # Parse the CAN ID into J1939
            priority, pgn, da, sa = get_j1939_from_id(can_id)
            can_count = can_count + 1
            if pgn == 61444 and sa == 0:
                password = ephemeral_key(s)
                count = count + 1
                spn190 = struct.unpack("<H", can_data[3:5])[0] * 0.125 - 0
                SPN190_value.append(spn190)

                zulu = random.uniform(0,1)
                titter = random.uniform(0,1)
                if zulu > 0.96:
                    if titter > 0.3:
                        spn190 = spn190 - (zulu-0.3) * 100
                    else:
                        spn190 = spn190 + (zulu-0.3) * 100
                val = struct.pack('<f', spn190)
                encryptedMsg = encrypt_AES_GCM(val, password)
                message = {
                    '1': base64.b64encode(encryptedMsg[0]).decode('utf-8'),
                    '2': base64.b64encode(encryptedMsg[1]).decode('utf-8'),
                    '3': base64.b64encode(encryptedMsg[2]).decode('utf-8'),
                    '4': base64.b64encode(encryptedMsg[3]).decode('utf-8')
                }
                serializedMsg = json.dumps(message)
                s.send(bytes(serializedMsg, encoding="utf-8"))
                #time.sleep(0.05)
            else:
                pass
        except IOError as e:
            if e.errno == errno.EPIPE:
                pass
    try:
        print("CAN frames processed : ", can_count)
        print("Packets sent : ",count)
        a = 9999.0
        val = struct.pack('<f', a)
        password = ephemeral_key(s)
        encryptedMsg = encrypt_AES_GCM(val, password)
        message = {
            '1': base64.b64encode(encryptedMsg[0]).decode('utf-8'),
            '2': base64.b64encode(encryptedMsg[1]).decode('utf-8'),
            '3': base64.b64encode(encryptedMsg[2]).decode('utf-8'),
            '4': base64.b64encode(encryptedMsg[3]).decode('utf-8')
        }
        serializedMsg = json.dumps(message)
        s.send(bytes(serializedMsg, encoding="utf-8"))

    except IOError as e:
            if e.errno == errno.EPIPE:
                pass


t1 = threading.Thread(target=canplay_recv)
t2 = threading.Thread(target=data_send)
t1.start()
time.sleep(0.5)
t2.start()
t1.join()
t2.join()
print("Closing connection to Server")
s.close()

