from Crypto.Cipher import AES

import requests
import json

requests.packages.urllib3.disable_warnings() 

URL = "https://magic-otp.donjon-ctf.io:9000"

GET_OTP    = "/api/get_encrypted_otp"
GET_FLAG   = "/api/get_flag"

def get_encrypted_otp(devid):
    """Get an encrypted OTP from the server."""

    return bytes.fromhex(
        json.loads(requests.post(URL + GET_OTP, json = {"deviceid": devid}, verify =
                                    False).text)['encrypted_otp'])

def get_flag(otp):
    """Get the flag from the server."""

    return json.loads(requests.post(URL + GET_FLAG, json = {"otp": otp}, verify =
                                    False).text)["message"]

def decrypt_otp(encrypted_opt):
    """Decrypt the OTP given the shared secret."""

    # Key for deviceid 0
    key = b"\xc2\x13\xed\x25" + b"\x00"*28

    cipher = AES.new(key, AES.MODE_CBC, iv = bytes(16))
    otp = cipher.decrypt(encrypted_opt)

    return otp[:10].decode("utf-8")

encrypted_otp = get_encrypted_otp(0)
otp = decrypt_otp(encrypted_otp)
flag = get_flag(otp)
print(f"Here is the flag: {flag}")