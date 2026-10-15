from Crypto.Cipher import DES

key = b'12345678'  # Key must be exactly 8 bytes
cipher = DES.new(key, DES.MODE_ECB)

plaintext = b'This is a secret!'  # Input text
# Padding
pad_len = 8 - len(plaintext) % 8
plaintext += bytes([pad_len]) * pad_len

# Encrypt
ciphertext = cipher.encrypt(plaintext)
print("Encrypted:", ciphertext)

# Decrypt
decrypted = cipher.decrypt(ciphertext)
pad_len = decrypted[-1]
decrypted = decrypted[:-pad_len]
print("Decrypted:", decrypted)
