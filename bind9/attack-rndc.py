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
    print(v, type(v))
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
                _exp = st(time.time() + 600))


key = base64.b64decode(b'DfgdVO5eFXJNniysoRIXLA==')

def sign(key, msg):
    data = marshal_table(msg)
    mac = base64.b64encode(hmac.new(key, data, hashlib.md5).digest())
    mac = mac[:-2]
    return mac

def apply_mac(data, mac):
    auth = marshal_table(dict(_auth = dict(hmd5 = mac)))
    return auth + data

def addhdr(payload):
    return struct.pack('>II', len(payload) + 4, VERSION) + payload

msg = dict(_ctrl = mkctrl(),
           _data = dict(type = 'status'.encode()))

base64codes = 'ABCDEFGHIJKLMNOPQRSTUVWXQZabcdefghijklmnopqrstuvwxyz0123456789+/'
assert len(base64codes) == 64
maclen = 22

def time_transact(send):
    s = socket.create_connection(('localhost', 953))
    sendtime = time.time()
    s.send(send)
    r = s.recv(512)
    recvtime = time.time()
    s.close()
    return r, recvtime - sendtime

tests = {}
for i in base64codes:
    testmac = i + base64codes[0] * (maclen - 1)
    testmac = testmac.encode()

    send = addhdr(apply_mac(marshal_table(msg), testmac))
    tests[i] = send

for rounds in (20, 2000):
    results = {}
    times = {}

    for r in range(rounds):
        for code, send in tests.items():
            recv, recvtime = time_transact(send)
            results[code] = results.get(code, 0) + recvtime
            times[code] = times.get(code, []) + [ int(recvtime * 1e9) ]

print(times)

codes_by_time = list(results.keys())
codes_by_time.sort(key = lambda x: results[x])
for code in codes_by_time:
    print(code, ':', results[code])

correctmac = sign(key, msg)
print('correct MAC is', correctmac, '(offset)',
        base64codes.index(correctmac.decode()[0]))
