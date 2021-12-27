# 200 - Crypto Party

Task:

```
The famous Elite Crypto Party will happen tonight at 8pm.

The organisers expect every participants to provide a valid QR code to attend the party, unfortunately you aren't part of the happy few. Security guards installed the Crypto Party Scanner app on their Android smartphones to scan participant badges.

The app was found on an underground website. Will you manage to enter the party?
```

## APK analysis

The starting point of this challenge is a link to an Android application named *CryptoPartyScanner.apk* which is -according to the challenge description- installed on the security guards' smartphones to validate the partipant QRcode.

The application is pretty small and only have few custom classes to analyze, we start by analyzing the method called when a QRCode is scanned:

```java
public void scan_qrcode(String qrCode) {
    MainActivity.this.L();
    String simpleName = MainActivity.class.getSimpleName();
    Log.log(simpleName, "QR Code Found: " + qrCode);
    if (CryptoParty.display_sources(MainActivity.this.getApplicationContext(), qrCode)) {
        MainActivity.this.K();
        return;
    }
    Toast.makeText(MainActivity.this.getApplicationContext(), CryptoParty.validate_qrcode(qrCode), 1).show();
    new Handler().postDelayed(new RunnableC0052a(), 3500);
}
```

This method which takes as a parameter a *QRCode* -in a string format- can invoke two interesting methods:
- `CryptoParty.display_sources`: used to display the sources of the verifying server.
- `CryptoParty.validate_qrcode`: used to validate a **QRCode** to enter the party (using a server-side validation).

### Getting the server sources

To get the sources of the server we analyze the following function:

```java
public static boolean display_sources(Context context, String qrCode) {
    if (!encrypt_xor(new byte[]{46, 62, 33, 60, 48, 58, 43, 123, 34, 38, 55, 50, 37, 58, 48, 44, 33, 61, 107, 16}).equals(qrCode)) {
        return false;
    }
    Intent browserIntent = new Intent("android.intent.action.VIEW", Uri.parse(encrypt_xor(URL_INDEX)));
    browserIntent.addFlags(268435456);
    context.startActivity(browserIntent);
    return true;
}
```

This function compares the input QRCode -string format- to an hardcoded *xor-encrypted* string; if both strings are equals then the content of a Web page is displayed an the user interface.

Several strings are *xor-encrypted*, here is the result of the "decryption":

```python
APP_XOR_KEY = b"android.permission.CAMERA"

def xor_encrypt(m, key):
    return bytes([m[i] ^ key[i%len(key)] for i in range(len(m))])

def app_xor_encrypt(b):
    return xor_encrypt(b, APP_XOR_KEY)

msg_e = bytes([46, 62, 33, 60, 48, 58, 43, 123, 34, 38, 55, 50, 37, 58, 48, 44, 33, 61, 107, 16])
LICENCE_MSG = app_xor_encrypt(msg_e).decode("utf-8")
print(f"LICENCE_MSG: {LICENCE_MSG}")
# LICENCE_MSG: OPEN_SOURCE_LICENSES

msg_e = bytes([9, 26, 16, 2, 28, 83, 75, 1, 19, 23, 11, 29, 29, 28, 94, 25, 14, 28, 90, 58, 111, 41, 42, 60, 43, 14, 0, 73, 17, 27, 15, 74, 71, 31, 95, 67, 93, 89, 67, 67, 70, 14, 30, 71, 108, 45, 40, 49, 13, 44, 4, 49, 13, 28])
URL_LETMEIN = app_xor_encrypt(msg_e).decode("utf-8")
print(f"URL_LETMEIN: {URL_LETMEIN}")
# URL_LETMEIN: https://crypto-party.donjon-ctf.io:10000/api/let_me_in

msg_e = bytes([9, 26, 16, 2, 28, 83, 75, 1, 19, 23, 11, 29, 29, 28, 94, 25, 14, 28, 90, 58, 111, 41, 42, 60, 43, 14, 0, 73, 17, 27, 15, 74, 71, 31, 95, 67, 93, 89, 67, 67, 70, 14, 29, 93, 38, 53, 62, 106, 61, 49, 4, 0, 59, 1, 0, 28, 22, 77, 21, 74, 27, 3, 13, 22, 11, 71, 7, 26, 67, 47])
URL_INDEX = app_xor_encrypt(msg_e).decode("utf-8")
print(f"URL_INDEX:   {URL_INDEX}")
# URL_INDEX:   https://crypto-party.donjon-ctf.io:10000/assets/open_source/index.html
```

Finally, by querying the `index URL`, we are able to download the source of the *Python server* which validate the requests.

### QRCode verification

Now that we have access to the source of the validation server we can try to understand (and exploit) the verification process. 

Two interesting endpoints are available on the server and allow to perform the following actions:

- `/api/get_certificates`: this endpoint returns the certificates that are installed on the server and used to verify the validity of the requests submitted and the second API endpoint.
- `/api/let_me_in`: this endpoint is used to verify a QRCode (submitted as a parameter of a POST request).

If we query the first endpoint we get the following result (truncated):

```bash
curl --insecure https://crypto-party.donjon-ctf.io:10000/api/get_certificates | python -m json.tool
{
    "MDU5MWI1OWM=": [
        1,
        [
            64231366944007128611348919651104804909435973587058913853892482269232788324041,
            54772973722616689122700859762282578769822156610875026825025566223653351599293
        ]
    ],
    "MGIwOGUzZGM=": [
        0,
        [
            122866140422466013826785528118621422276782165937835130785806537381269517943199236220629107823703555638672818673422999715302638860711291136523826289175166844856649618910707312388536263738921504610024822114023925075691589276062913223225854523473602389281105109564818657926698862297561918920480184112846229228677,
            65537
        ]
}
```

As we can see, the server send several certificates which have **a name, a type and some parameters**.

The **QRCode** validation process is handled by the function named `verify_qrcode` and is pretty straighforward:
- first, the data sent by the user is decoded and the following information are extracted from the request:
   - *the expiration date*: this is used to verify the validadity of the 
   - *the certificate identifier*: this is used to identify the certificate which has been used to signed the request.
   - *the algorithm identifier*: this is used to identify the algorithm (**RSA** or **ECDSA**) which must be used for the request validation.
   - *the signed data*: this is the signed data.
   - *the signature*: the signature of the signed data.
- then, the signature of the signed data is verified to ensure that it is a legitimate request.

From what we've just seen we can already imagine an exploitable scenario. Actually, it's pretty strange that the certificate identifier and the algorithm identifier are'nt linked together and both provided by the user in different fields. If the server does not check that both are consistent, a **type confusion** could happen.

In order to check this issue, we verify inside the server sources:

```python
def verify_signature(crypto_id):
    cert = Cert(ALGOS[crypto_id.algo_index], CERTS[crypto_id.cert_id][1])
    # [...]

def Cert(algo, public_key):
    klasses = {"rsa": CertRSA, "ec": CertEC}
    return klasses[algo](*public_key)
```

As we can see, the **certificate** instance is created using two parameters; the algorithm and the public key (directly derived from the certificate identifier) which are both provided by the user and used (without valiidation) by the server. No consistensy check is performed to ensure the public key is used in its normal purpose. We can thus try to understand how the certificates are created to see how we could exploit this issue:

```python
class CertRSA(CertABC):

    def __init__(self, n, e=65537):
        self.n, self.e = n, e

class CertEC(CertABC):

    def __init__(self, x, y):
        self.x, self.y = x, y
```

By exploiting this **type confusion**, we could cause the following issues:
- **use a RSA public key as an ECDSA public key**: in this case the modulus and the exponent would be used as an *x-coordinate and y-coordinate* (in affine representation) of a point of the elliptic-curve `SECP256K1`.
- **use an ECDSA public key as a RSA public key**: in this case the *x-coordinate* (resp. *y-coordinate*) of the public key would be used as a modulus (resp. exponent); in this case, there are chances that we can factorise it an thus create a fake signature.

**Note**: depending on the library used (and the checks performed), using a RSA public key as an ECDSA public key isn't always feasible as a "secure library" should verify (this is the case for OpenSSL) that the provided point is a valid of the curve (and thus satisfy the curve equation).

## Building a fake signature

To exploit the **type confusion** I decided to use one of the *ECDSA public keys as a RSA public key*, however, before doing this we must ensure that we can find the associated "private key" to build a valid signature. To find this private key, the first thing to do is to factorize the fake modulus, this is easily achieved using `Sage` or [factor.db](https://factor.db):

```python
sage: factor(64231366944007128611348919651104804909435973587058913853892482269232788324041)
3^4 * 59 * 110647 * 1262927 * 9717632942113556809805909084119 * 9897642244809737193051574181189
```

Moreover, we need to ensure that we can compute `d = e**-1 mod phi(n)` we need to ensure that `e` and `phi(n)` are co-prime:

```python
sage: inverse_mod(e, euler_phi(n))
24964856803835239775464681118886184024003818538584513246510362993110229374997
```

**Note**: to be able to inverse `S = M**e mod n`, we must ensure that M is in the unit-root of the multiplicative group of integer modulo n which is composed of all the integer < n and co-prime with n. Since n, is composite in some case the message isn't inversible and the signature fail.

To build the final signature I used PyCryptodome and modified the `_decrypt` function to perform the decryption using only `d` and `n`:

```python
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

    # We don't care about p, q and u which will never be
    # used here.
    rsakey = RsaKey(n=n, e=e, d=d, p=1337, q=1337, u=1337)
    rsakey._decrypt = lambda x: _decrypt(rsakey, x)

    return rsakey
```

## Packing the result

Finally, we need to pack our result in the format the server is waiting for:

```python
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
```

By chaining all the previous work, we are finally able to get the flag from the server:
```
sage: %run solve.py
b'{"message":"Welcome to the party! Here is your Free Drinks Voucher: CTF{FreeDr1nksForEvery0ne}."}\n'
```