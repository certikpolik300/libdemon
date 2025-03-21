# Test code for cryptogamax encryption algorithm
from cryptogamax import galyrex  # Assuming the class is named galyrex.py

def test_encrypt_decrypt_text():
    # Initialize the galyrex encryption class
    cipher = galyrex()

    # Sample text to encrypt
    plain_text = "This is a test message for Cryptogamax encryption!"

    print("Original Text: ", plain_text)

    # Encrypt the text
    encrypted_data, mac, nonce = cipher.encrypt(plain_text)

    print("\nEncrypted Data (Hex): ", encrypted_data.hex())
    print("MAC (Hex): ", mac.hex())
    print("Nonce (Hex): ", nonce.hex())

    # Decrypt the text
    decrypted_text = cipher.decrypt(encrypted_data, mac, nonce)

    print("\nDecrypted Text: ", decrypted_text)
    assert plain_text == decrypted_text, "Decryption failed!"

if __name__ == "__main__":
    # Run text encryption/decryption test
    test_encrypt_decrypt_text()
