import os
import hashlib

def telegram_kdf(auth_key: bytes, msg_key: bytes, direction: str):
    assert len(auth_key) == 256
    assert len(msg_key) == 16
    assert direction in ['client', 'server']

    if direction == 'client':
        x = 0
    else:
        x = 8

    sha256_a = hashlib.sha256(msg_key + auth_key[x     : x + 36]).digest()
    sha256_b = hashlib.sha256(auth_key[x + 40 : x + 76] + msg_key).digest()

    aes_key = sha256_a[0:8] + sha256_b[8:24] + sha256_a[24:32]
    aes_iv  = sha256_b[0:8] + sha256_a[8:24] + sha256_b[24:32]

    return aes_key, aes_iv

# 🔍 Testovací vstupy
auth_key = os.urandom(256)   # Simulace DH výměny
msg_key  = os.urandom(16)    # Simulovaný SHA256 middle bytes z plaintextu

aes_key_client, aes_iv_client = telegram_kdf(auth_key, msg_key, 'client')
aes_key_server, aes_iv_server = telegram_kdf(auth_key, msg_key, 'server')

# 🖨️ Výstup
print("=== CLIENT TO SERVER ===")
print("AES KEY:", aes_key_client.hex())
print("AES IV :", aes_iv_client.hex())

print("\n=== SERVER TO CLIENT ===")
print("AES KEY:", aes_key_server.hex())
print("AES IV :", aes_iv_server.hex())
