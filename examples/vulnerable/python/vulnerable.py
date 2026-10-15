## Python - Weak Encryption (Use of DES)
# Save this file as "vulnerable_python.py"
from Crypto.Cipher import DES
import os

# Key must be 8 bytes long
key = b'12345678'
cipher = DES.new(key, DES.MODE_ECB)

# Plaintext
plaintext = b'This is a secret!'

# Encryption
def encrypt(plain_text):
    # Padding to make it a multiple of 8
    pad_len = 8 - len(plain_text) % 8
    plain_text += bytes([pad_len]) * pad_len
    ciphertext = cipher.encrypt(plain_text)
    return ciphertext

# Decryption
def decrypt(cipher_text):
    plain_text = cipher.decrypt(cipher_text)
    pad_len = plain_text[-1]
    return plain_text[:-pad_len]

# Test
encrypted = encrypt(plaintext)
print("Encrypted:", encrypted)
decrypted = decrypt(encrypted)
print("Decrypted:", decrypted)
