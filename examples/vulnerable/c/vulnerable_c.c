#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

void encrypt_decrypt(const char *input, char *output, const unsigned char *key, int encrypt) {
    AES_KEY aes_key;
    if (encrypt) {
        AES_set_encrypt_key(key, 128, &aes_key);
        AES_encrypt((const unsigned char *)input, (unsigned char *)output, &aes_key);
    } else {
        AES_set_decrypt_key(key, 128, &aes_key);
        AES_decrypt((const unsigned char *)input, (unsigned char *)output, &aes_key);
    }
}

int main() {
    const unsigned char key[16] = "hardcodedkey123"; // Hardcoded Key
    const char *plaintext = "SensitiveData123";
    char encrypted[16];
    char decrypted[16];

    encrypt_decrypt(plaintext, encrypted, key, 1);
    printf("Encrypted: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", (unsigned char)encrypted[i]);
    }
    printf("\n");

    encrypt_decrypt(encrypted, decrypted, key, 0);
    printf("Decrypted: %s\n", decrypted);

    return 0;
}