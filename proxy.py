from cryptogalyrex import galyrex
from Crypto.Random import get_random_bytes
import itertools
import time
from concurrent.futures import ProcessPoolExecutor

def decrypt_and_check(key, ciphertext, known_plaintext, nonce, mac):
    try:
        cipher = galyrex(key=key)
        decrypted_text = cipher.decrypt(ciphertext, mac, nonce)
        if known_plaintext in decrypted_text:
            return key
    except Exception:
        pass
    return None

def brute_force_attack(ciphertext, known_plaintext, nonce, mac):
    key_len = 32  # Assuming a 32-byte key length for this example
    alphabet = range(256)  # All possible byte values
    
    # Start timer
    start_time = time.time()
    
    # Parallel brute force with process pool
    with ProcessPoolExecutor() as executor:
        futures = []
        for key_tuple in itertools.product(alphabet, repeat=key_len):
            key = bytes(key_tuple)
            futures.append(executor.submit(decrypt_and_check, key, ciphertext, known_plaintext, nonce, mac))
        
        # Wait for results and check if key is found
        for future in futures:
            result = future.result()
            if result:
                print(f"Key found: {result.hex()}")
                end_time = time.time()
                print(f"Brute force attack duration: {end_time - start_time} seconds")
                return result

    end_time = time.time()
    print("Key not found within the attempt limit")
    print(f"Brute force attack duration: {end_time - start_time} seconds")
    return None

# Example usage
cipher = galyrex()
plaintext = "This is a test message."
nonce = get_random_bytes(64)
ciphertext, mac, nonce = cipher.encrypt(plaintext, nonce)

# Brute-force attack, using first 16 characters of known plaintext for example
brute_force_attack(ciphertext, plaintext[:16], nonce, mac)
