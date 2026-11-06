from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = bytes.fromhex("...")
blob = bytes.fromhex("...")
plain = AESGCM(key).decrypt(blob[3:15], blob[15:], None)
print(plain.decode("utf-8"))
