#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

int main() {
    const char *message = "Insecure message";
    unsigned char hash[SHA_DIGEST_LENGTH];

    SHA1((const unsigned char *)message, strlen(message), hash);

    printf("SHA-1 Hash: ");
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}