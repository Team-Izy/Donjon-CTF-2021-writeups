from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

from Crypto.PublicKey.RSA import RsaKey
from Crypto.Signature.pss import PSS_SigScheme
from Crypto.Hash import SHA1
from Crypto.Math.Numbers import Integer

from json import loads
from random import randbytes
from base64 import b64decode
from base45 import b45encode

from datetime import datetime
import requests
import cbor
import zlib

# Web

def let_me_in(qrcode):
    """Send the QRCode to the server and returns the response."""

    HOST = "https://crypto-party.donjon-ctf.io:10000"
    URL_LETMEIN = "/api/let_me_in"

    return requests.post(
            HOST + URL_LETMEIN,
            json = {"qrcode": qrcode },
            verify=False,
        ).content

# Crypto

def _decrypt(self, ciphertext):
    """Custom decryption function without optimization."""

    if not 0 <= ciphertext < self._n:
        raise ValueError("Ciphertext too large")
    if not self.has_private():
        raise TypeError("This is not a private key")

    result = pow(Integer(ciphertext), self._d, self._n)
    if ciphertext != pow(result, self._e, self._n):
        raise ValueError("Fault detected in RSA decryption")
    return result

def build_rsa_key(n, e, d):
    """Build a partial RSA key."""

    rsakey = RsaKey(n=n, e=e, d=d, p=1337, q=1337, u=1337)
    rsakey._decrypt = lambda x: _decrypt(rsakey, x)

    return rsakey

def rsa_verify(rsakey, signed_data, signature):
    """Try to verify as the server does."""

    SIG_ALGO = hashes.SHA1()
    PADDING = padding.PSS(mgf=padding.MGF1(SIG_ALGO), salt_length=0)
    public_key = rsa.RSAPublicNumbers(rsakey.e, rsakey.n)
    public_key.public_key().verify(signature, signed_data, PADDING, SIG_ALGO)

def rsa_sign(rsakey, data):
    """Sign data with RSA-PSS"""

    pss = PSS_SigScheme(rsakey, None, 0, randbytes)
    hash = SHA1.new(data)
    signature = pss.sign(hash)

    rsa_verify(rsakey, data, signature)

    return signature

def pack_data_with_signature(algid, certid, rsakey):
    """Pack and sign data."""

    cert_data = int(datetime.utcnow().timestamp()+10000)
    cert = {
        1: algid,
        4: b64decode(certid)
    }

    headers1 = cbor.dumps(cert)
    headers2 = randbytes(32)

    signed_data = cbor.dumps(["Signature1", headers1, headers2, cert_data])

    signature = rsa_sign(rsakey, signed_data)

    cbor_value = headers1, headers2, cert_data, signature
    tag = cbor.Tag(tag=1, value = cbor_value)

    tag_compressed = zlib.compress(cbor.dumps(tag))

    enveloppe = b"LDG:" + b45encode(tag_compressed)

    return enveloppe.decode()
    
if __name__ == "__main__":

    e = 54772973722616689122700859762282578769822156610875026825025566223653351599293
    n = 64231366944007128611348919651104804909435973587058913853892482269232788324041
    d = 24964856803835239775464681118886184024003818538584513246510362993110229374997

    rsakey = build_rsa_key(n, e, d)
    enveloppe = pack_data_with_signature(0, "MDU5MWI1OWM=", rsakey)
    res = let_me_in(enveloppe)
    print(res)