from cryptogalyrex import galyrex
from Crypto.Random import get_random_bytes
import itertools
import time

def brute_force_attack(ciphertext, known_plaintext, nonce, mac, key_len=8, timeout=60):
    # Alphabet now contains only the first 256 possible byte values, i.e., the 8-bit key space
    alphabet = range(256)

    start_time = time.time()

    # Iterate over all possible keys of length `key_len`
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
        except Exception as e:
            # Catch exceptions, could be decryption failure or any other errors
            pass
        
        # Check for timeout
        if time.time() - start_time > timeout:
            print("Timeout reached.")
            break

    end_time = time.time()
    print("Key not found within the attempt limit")
    print(f"Brute force attack duration: {end_time - start_time} seconds")
    return None

# Example usage
cipher = galyrex()
plaintext = "This is a test message."
nonce = get_random_bytes(64)
ciphertext, mac, nonce = cipher.encrypt(plaintext, nonce)

# Brute force with an 8-bit key (just for testing purposes)
brute_force_attack(ciphertext, plaintext[:16], nonce, mac, key_len=8, timeout=60)
