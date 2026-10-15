from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generate short RSA key (512 bits)
key = RSA.generate(512)
public_key = key.publickey()
cipher = PKCS1_OAEP.new(public_key)

plaintext = b"Sensitive Data"
ciphertext = cipher.encrypt(plaintext)
print("Encrypted:", ciphertext)

# Decrypt
decrypt_cipher = PKCS1_OAEP.new(key)
decrypted = decrypt_cipher.decrypt(ciphertext)
print("Decrypted:", decrypted)
