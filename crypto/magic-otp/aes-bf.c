/*
 * gcc -lssl -lcrypto -o aes-bf aes-bf.c
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/aes.h>

#define BF_MAX_VALUE    0x100000000UL
#define PRINT_STEP      0x1000000UL

uint8_t ciphertext[32] = {
    0x23, 0x86, 0xcf, 0xda, 0x6c, 0x40, 0x9b, 0xc2, 0xfd, 0x2e,
    0x9b, 0x82, 0x98, 0xfa, 0x77, 0x64, 0x2b, 0x99, 0x6f, 0x2c,
    0x65, 0xb0, 0x20, 0xe2, 0xca, 0x2f, 0x6d, 0xf6, 0x1f, 0x63,
    0x49, 0xb4
};

void hexdump(uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x%c", data[i], (i % 16 == 15) ? '\n': ' ');
    }

    printf("\n");
}

int brute_force(uint8_t ciphertext[32])
{
    AES_KEY aeskey = {0};
    uint8_t user_key[32]  = {0};
    uint8_t cleartext[32] = {0};
    uint8_t iv[16]        = {0};
    uint64_t *i_ptr = (uint64_t*)&user_key[0];

    for (; *i_ptr < BF_MAX_VALUE; *i_ptr+=1)
    {
        if (*i_ptr % PRINT_STEP == 0)
            printf("%#llx\n", (*i_ptr)/PRINT_STEP);

        memset(iv, 0, 0x10);

        AES_set_decrypt_key(user_key, 32*8, &aeskey);
        AES_cbc_encrypt(ciphertext, cleartext, 16, &aeskey, iv, 0);

#ifdef DEBUG
        printf("Ciphertext:\n");
        hexdump(ciphertext, 32);

        printf("Key:\n");
        hexdump(user_key,   32);

        printf("Cleartext:\n");
        hexdump(cleartext,  32);
#endif

        if (*(uint32_t*)&cleartext[12] == 0)
        {
            printf("[+] Potential key found:\n");
            hexdump(user_key, 32);
            printf("Cleartext:\n");
            hexdump(cleartext, 32);
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    brute_force(ciphertext);
    return 0;
}