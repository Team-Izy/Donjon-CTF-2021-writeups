#!/usr/bin/python3

import numpy as np
from matplotlib import pyplot as plt
import h5py
from lascar import *
from lascar.tools.aes import sbox

# loads date from h5 file
f = h5py.File("./data.h5", "r")
traces = np.array(f["aes"]["traces"])
plaintexts = f["aes"]["plaintext"]

# converts data in a format expected by lascar's containers
value_dtype = np.dtype(
            [("plaintext", np.uint8),]
        )
values = np.zeros((30000,16), value_dtype)
values["plaintext"] = plaintexts

def power_model(value, guess):
    ki = guess & 0xFF
    kj = (guess >> 8) & 0xFF
    pi = value["plaintext"][i]
    pj = value["plaintext"][j]
    return hamming(sbox[pi ^ ki] ^ sbox[pj ^ kj])

def compute_cpa_hamming_two_sboxes(traces, values, i, j):
    # instanciates a container with all the challenge's data
    container = TraceBatchContainer(traces, values, copy=True)
    # applies the center product between all couples of samples in the traces
    container.leakage_processing = CenteredProductProcessing(container, order=2)
    cpa_engine = CpaEngine(name=f"cpa-hamming-sbox-i{i}-j{j}", 
        selection_function=power_model, guess_range=range(256*256))
    session = Session(container, engine=cpa_engine, 
        output_method=ConsoleOutputMethod(cpa_engine))
    session.run(1000)
    return session

N=5000 # actually, we don't need the whole traces
traces = traces[:N]
values = values[:N]
key = bytes()
# for each pair of bytes of the key
for i in range(0,16,2):
    j = (i + 1) % 16
    #run the CPA for each key guess (K[i], K[j])
    s = compute_cpa_hamming_two_sboxes(traces, values, i, j)
    # extract the results from the session
    res = s.engines[f"cpa-hamming-sbox-i{i}-j{j}"].finalize()
    # get the index (=key guess) where the maximum correlation was reached
    # and convert it into 2 bytes 
    key_part = np.abs(res).max(axis=1).argmax().tobytes("C")[:2]
    # add them to what will become the global 16 bytes key, and continue
    key += key_part

from Crypto.Cipher import AES
a = AES.new(bytes(key), mode=AES.MODE_ECB)
with open("./enc_firmware.bin", "rb") as f:
    c = f.read()
print(a.encrypt(c))


