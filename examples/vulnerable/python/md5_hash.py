import hashlib

password = "super_secret_password"
md5_hash = hashlib.md5(password.encode()).hexdigest()
print("MD5 Hash:", md5_hash)
