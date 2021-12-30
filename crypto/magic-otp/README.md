# 200- Magic OTP

Task:

```
Bad luck, you lost the hardware device that give access to https://magic-otp.donjon-ctf.io:9000/
```

## One Time Password

In this challenge, we have access to an OTP server and clients through an HTTP interface as well as the sources of the applications. The server can generate token using a [Time-Based One-Time Password Algorithm](https://datatracker.ietf.org/doc/html/rfc6238) and generates 10 digits long token:

```c
static void generate_otp(uint8_t epoch[8], char otp[32])
{
    uint32_t truncated_hash;
    uint8_t hmac_hash[32];
    unsigned int offset;

    cx_hmac_sha256((uint8_t *)OTP_SECRET, sizeof(OTP_SECRET)-1, epoch, 8, hmac_hash, 32);
    offset = hmac_hash[31] & 0x0f;

    truncated_hash = 0;
    truncated_hash |= (hmac_hash[offset+0] & 0x7f) << 24;
    truncated_hash |= hmac_hash[offset+1] << 16;
    truncated_hash |= hmac_hash[offset+2] << 8;
    truncated_hash |= hmac_hash[offset+3] << 0;

    explicit_bzero(hmac_hash, sizeof(hmac_hash));

    memset(otp, 0, 32);
    snprintf(otp, 32, "%010d", truncated_hash);
}
```

The OTP are then *AES encrypted* using a shared secret generated using an Elliptic Curve Diffie-Hellman key exchange and sent to the client which can then decrypt an display the OTP to the end user. The following request can be used to request an OTP for a specific `deviceid` (`0` in this example):

```bash
curl --insecure -X POST https://magic-otp.donjon-ctf.io:9000/api/get_encrypted_otp \
-H 'Content-Type: application/json' \
-d '{"deviceid":0}'
{"encrypted_otp": "9b85d2abc888be0fb1848b6d823776efa37dd538c8cda69f7ec6885bb0605308"}
```

## Vulnerability

After reading carefully the source code, I eventually found the vulnerability which affects the function used to generate the shared secret:

```c
static int get_shared_secret(cx_ecfp_public_key_t *pubkey, uint8_t secret[32])
{
    cx_ecfp_private_key_t privkey;
    uint8_t out[32];
    cx_err_t ret;

    get_own_privkey(&privkey); // [0]
    ret = cx_ecdh_no_throw(&privkey, CX_ECDH_X, pubkey->W, pubkey->W_len,
                           out, sizeof(out)); // [1]

    explicit_bzero(&privkey, sizeof(privkey));
    if (ret != CX_OK) {
        return -1;
    }

    memcpy(secret, out, sizeof(secret)); // [2]

    return 0;
}
```

The secret is generated using an [Elliptic Curve Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) key exchange. Hence, the server private key is retreived in [0] using a call to `get_own_privkey` and the Diffie-Hellman shared secret is computed in [1]. Finally, the computed secret is copied in [2] to the output buffer.
However, there is an issue with this copy since `sizeof(secret)` isn't equivalent to `sizeof(uint8_t secret[32])` but to `sizeof(uint8_t*)` since `secret` is a parameter of the function. This means that only *4 bytes* of the shared key are copied which allow us to perform a **brute force** to retrieve the key.

**Note**: I did not try to build the application during the CTF, however, I guess that the vulnerability can be easily found by looking at the compiler warnings:

```
$ cat main.c
#include <stdio.h>
#include <stdint.h>

void test(uint8_t buffer[32])
{
    printf("sizeof(buffer): %lu\n", sizeof(buffer));
}

int main()
{
  test(NULL);
  return 0;
}
$ gcc main.c
main.c:6:43: warning: sizeof on array function parameter will return size of 'uint8_t *' (aka 'unsigned char *') instead of 'uint8_t [32]' [-Wsizeof-array-argument]
    printf("sizeof(buffer): %lu\n", sizeof(buffer));
                                          ^
main.c:4:19: note: declared here
void test(uint8_t buffer[32])
                  ^
1 warning generated.
```

To be able to perform a brute-force attack we must find a **stop condition** in order to know if the *generated key* is valid or not (without testing directly on the server). If we look at the generated OTP we can see that the block is mostly filled with zeros so we will use that as a stop condition:

```c
static void generate_otp(uint8_t epoch[8], char otp[32])
{
    // [...]
    snprintf(otp, 32, "%010d", truncated_hash);
}
```

## Exploit

To find the right key, I performed a [simple brute-force](./aes-bf.c) loop using `OpenSSL`:

```c
    for (; *i_ptr < BF_MAX_VALUE; *i_ptr+=1)
    {
        if (*i_ptr % PRINT_STEP == 0)
            printf("%#llx\n", (*i_ptr)/PRINT_STEP);

        memset(iv, 0, 0x10);

        AES_set_decrypt_key(user_key, 32*8, &aeskey);
        AES_cbc_encrypt(ciphertext, cleartext, 16, &aeskey, iv, 0);

        if (*(uint32_t*)&cleartext[12] == 0)
        {
            printf("[+] Potential key found:\n");
            hexdump(user_key, 32);
            printf("Cleartext:\n");
            hexdump(cleartext, 32);
        }
    }
```

Compiling and running the script quickly lead to the valid key:

```
$ gcc -lssl -lcrypto -o aes-bf aes-bf.c
$ ./aes-bf
[+] Potential key found:
c2 13 ed 25 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Cleartext:
30 33 36 32 36 32 34 33 32 34 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

We can finally get the flag using this [Python script](./solve.py):

```
$ python solve.py
Here is the flag: Congratulation! Here's the flag: CTF{RustFTW!}.
```