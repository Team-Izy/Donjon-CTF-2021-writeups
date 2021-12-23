#!/usr/bin/python3s
import numpy as np
import requests
from ecpy.curves import Curve,Point

url = 'http://fine-fine.donjon-ctf.io:6000'

def send_getpubkey(data):
    cmd = {'cmd' : 'getpubkey', 'data': data }
    x = requests.post(url, json = cmd, timeout=3)
    if x.headers["content-type"] == "application/octet-stream":
        trace = np.frombuffer(x.content, dtype=np.uint16)
        return trace
    else:
        return x.json()


cv = Curve.get_curve('secp256r1')
n = cv.order
g = cv.generator

def trace_from_point(p):
    return send_getpubkey(bytes(cv.encode_point(p)[1:]).hex())

Z = Point(0, cv.y_recover(0), cv)

def zeroes(t):
    return t.tolist().count(0)

# number of zeroes found in a "normal" power trace
min_z = zeroes(trace_from_point(g))

s=1
while s.bit_length() < 256:
    s *= 2
    s_inv = pow(s, -1, n) # if s.P=Z, then P=(s^-1).Z
    P = s_inv * Z
    z = zeroes(trace_from_point(P)) - min_z
    if z < 50//2:
        s += 1
    print(s, s.to_bytes(256//8, "little")[::-1])
