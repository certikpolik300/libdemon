import random
from cryptogalyrex import galyrex
from Crypto.Random import get_random_bytes

def known_plaintext_attack(cipher):
    plaintext = "This is a known plaintext message."
    encrypted_data, mac, nonce = cipher.encrypt(plaintext)
    decrypted_data = cipher.decrypt(encrypted_data, mac, nonce)
    print("Known-plaintext Attack Test:")
    print("Original Plaintext:", plaintext)
    print("Decrypted Plaintext:", decrypted_data)
    print("Attack Successful:", plaintext == decrypted_data)
    print()

if __name__ == "__main__":
    key = get_random_bytes(512)
    cipher = galyrex(key)
    
    known_plaintext_attack(cipher)
