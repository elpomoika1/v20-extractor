from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = bytes.fromhex("eb16faa149b3a6c479790a20ab4c7ed3e97059205fdd7e32d3e728fc8dfaf918")
blob = bytes.fromhex(
    "763230808f2ad8fbf2b43fcc38fffbeb808f43c8f535bd564a1a9b6621eb03eab1fd896072da2424"
)
plain = AESGCM(key).decrypt(blob[3:15], blob[15:], None)
print(plain.decode("utf-8"))
