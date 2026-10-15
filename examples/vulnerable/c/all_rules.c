#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>

void test_md5() {
    unsigned char digest[MD5_DIGEST_LENGTH];
    const char *message = "Hello, World!";
    MD5((const unsigned char *)message, strlen(message), digest);

    printf("MD5 Digest: ");
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

void test_sha1() {
    unsigned char hash[SHA_DIGEST_LENGTH];
    const char *message = "Hello, World!";
    SHA1((const unsigned char *)message, strlen(message), hash);

    printf("SHA-1 Hash: ");
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

void test_des() {
    DES_cblock key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    DES_key_schedule schedule;
    DES_set_key(&key, &schedule);

    const char *plaintext = "HelloDES";
    char ciphertext[16];
    char decryptedtext[16];

    DES_ecb_encrypt((const_DES_cblock *)plaintext, (DES_cblock *)ciphertext, &schedule, DES_ENCRYPT);
    DES_ecb_encrypt((const_DES_cblock *)ciphertext, (DES_cblock *)decryptedtext, &schedule, DES_DECRYPT);

    printf("DES Plaintext: %s\n", plaintext);
    printf("DES Ciphertext: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", (unsigned char)ciphertext[i]);
    }
    printf("\nDES Decrypted Text: %s\n", decryptedtext);
}

int main() {
    printf("Testing MD5:\n");
    test_md5();

    printf("\nTesting SHA-1:\n");
    test_sha1();

    printf("\nTesting DES:\n");
    test_des();

    return 0;
}