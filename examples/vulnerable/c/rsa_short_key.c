#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stdio.h>

int main() {
    RSA *rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);
    char plaintext[64] = "Sensitive Data";
    unsigned char encrypted[256];
    unsigned char decrypted[256];

    int encrypted_length = RSA_public_encrypt(strlen(plaintext), (unsigned char *)plaintext, encrypted, rsa, RSA_PKCS1_PADDING);
    printf("Encrypted: ");
    for (int i = 0; i < encrypted_length; i++) {
        printf("%02x", encrypted[i]);
    }
    printf("\n");

    RSA_private_decrypt(encrypted_length, encrypted, decrypted, rsa, RSA_PKCS1_PADDING);
    printf("Decrypted: %s\n", decrypted);

    RSA_free(rsa);
    return 0;
}