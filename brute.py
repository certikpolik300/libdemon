from cryptogalyrex import galyrex
from Crypto.Random import get_random_bytes
import itertools
import time

def brute_force_attack(ciphertext, known_plaintext, nonce, mac):
    key_len = 32  # Assuming a 32-byte key length for this example
    alphabet = range(256)  # All possible byte values

    start_time = time.time()
    
    for key_tuple in itertools.product(alphabet, repeat=key_len):
        key = bytes(key_tuple)
        cipher = galyrex(key=key)
        try:
            decrypted_text = cipher.decrypt(ciphertext, mac, nonce)
            if known_plaintext in decrypted_text:
                print(f"Key found: {key.hex()}")
                end_time = time.time()
                print(f"Brute force attack duration: {end_time - start_time} seconds")
                return key
        except Exception:
            continue
    
    end_time = time.time()
    print("Key not found within the attempt limit")
    print(f"Brute force attack duration: {end_time - start_time} seconds")
    return None

# Example usage
cipher = galyrex()
plaintext = "This is a test message."
nonce = get_random_bytes(64)
ciphertext, mac, nonce = cipher.encrypt(plaintext, nonce)
brute_force_attack(ciphertext, plaintext[:16], nonce, mac)
