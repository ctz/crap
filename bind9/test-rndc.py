import hmac
import hashlib
import struct
import base64
import time
import random
import socket

TYPE_STRING = 0
TYPE_BIN = 1
TYPE_TABLE = 2
TYPE_LIST = 3

VERSION = 1

def marshal_str(s):
    return struct.pack('B', len(s)) + s.encode()

def marshal_value(v):
    if isinstance(v, bytes):
        return with_typelen(v, TYPE_BIN)
    if isinstance(v, dict):
        return with_typelen(marshal_table(v), TYPE_TABLE)
    assert False
    return None

def marshal_table(d):
    body = []
    for k in sorted(d.keys()):
        body.extend(marshal_str(k) + marshal_value(d[k]))
    return bytes(body)

def with_typelen(bb, ty):
    return bytes(
        struct.pack('B', ty) + struct.pack('>I', len(bb)) + bb
    )

def hexbytes(bb):
    return ''.join('%02x' % x for x in bb)

def mkctrl():
    st = lambda x: str(int(x)).encode()
    return dict(_ser = st(random.getrandbits(31)),
                _tim = st(time.time()),
                _exp = st(time.time() + 60))


key = base64.b64decode(b'DfgdVO5eFXJNniysoRIXLA==')

def sign(key, msg):
    data = marshal_table(msg)
    mac = base64.b64encode(hmac.new(key, data, hashlib.md5).digest())
    mac = mac[:-2]
    auth = marshal_table(dict(_auth = dict(hmd5 = mac)))
    return auth + data

def addhdr(payload):
    return struct.pack('>II', len(payload) + 4, VERSION) + payload

msg = dict(_ctrl = mkctrl(),
           _data = dict(type = 'status'.encode()))

send = addhdr(sign(key, msg))
print(hexbytes(send))
s = socket.create_connection(('localhost', 953))
s.send(send)
print(s.recv(512))
