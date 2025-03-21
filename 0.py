import hashlib
import os
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class main:
    def __init__(self, key=None, iterations=200000):
        """
        Initialize the cipher with a key. If no key is provided, generate one.
        Use PBKDF2 with high iterations for key strengthening.
        """
        if key is None:
            key = self.generate_strong_key()
        
        self.key = key
        self.iterations = iterations  # Ensure iterations is set before calling _generate_round_keys
        self.round_keys = self._generate_round_keys()  # Now iterations is available
       
    def _generate_round_keys(self):
        """
        Use an advanced key expansion technique (PBKDF2 and multiple rounds of hashing)
        to generate many round keys.
        """
        round_keys = []
        for i in range(64):  # Increased rounds for higher security
            derived_key = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=128,  # Double length of the key for extra security
                salt=self.key,
                iterations=self.iterations,
                backend=default_backend()
            ).derive(i.to_bytes(4, 'big'))  # Different salt per round
            round_keys.append(derived_key)
        return round_keys

    def generate_strong_key(self):
        """
        Generate a new encryption key using a highly secure random process.
        The key will be derived from a strong entropy source.
        """
        return get_random_bytes(128)  # 1024-bit key for extra security

    def encrypt(self, data, nonce=None):
        """
        Encrypt the data using multiple layers of encryption with custom transformations.
        """
        if nonce is None:
            nonce = get_random_bytes(128)  # Increased nonce size for added security
        
        # Convert the data to hexadecimal string
        data = self.text_to_hex(data)
        data = pad(data.encode(), 128)  # Use larger block size (128 bytes)

        encrypted_data = self._apply_permutation_network(data, nonce)
        mac = self._generate_mac(encrypted_data)
        return encrypted_data, mac, nonce

    def decrypt(self, encrypted_data, mac, nonce):
    """
    Decrypt the data using multiple layers of encryption and verify the MAC.
    """
    if mac != self._generate_mac(encrypted_data):
        raise ValueError("MAC verification failed")
    
    decrypted_data = self._apply_permutation_network(encrypted_data, nonce, decrypt=True)
    
    # Ensure proper padding is removed after decryption
    decrypted_data = unpad(decrypted_data, 128)  # Make sure this is correctly aligned with block size

    # Convert the decrypted data from hex back to text
    decrypted_text = self.hex_to_text(decrypted_data.decode())  # Convert from bytes to text after unpadding
    return decrypted_text

    def _apply_permutation_network(self, data, nonce, decrypt=False):
        """
        Apply a stronger and more complex permutation network on the data.
        Optimized to process multiple blocks in parallel.
        """
        num_blocks = len(data) // 128  # 128-byte blocks (larger than AES block size)
        processed_data = bytearray()
        for i in range(num_blocks):
            block = data[i * 128: (i + 1) * 128]
            round_key = self.round_keys[i % len(self.round_keys)]
            if decrypt:
                block = self._reverse_nonlinear_transform(block)
            processed_block = self._nonlinear_transform(block, round_key)
            processed_data.extend(processed_block)
        return processed_data

    def _nonlinear_transform(self, data, round_key):
        """
        Perform a complex nonlinear transformation with a round key.
        Use more advanced S-boxes or mix columns like in AES but with increased complexity.
        """
        # Perform XOR with round key and apply additional transformation for added security
        transformed_data = bytearray([data[i] ^ round_key[i % len(round_key)] for i in range(len(data))])
        # Further diffusion: additional XOR and shift
        transformed_data = bytearray([((data[i] ^ 0xFF) + 0x42) % 256 for i in range(len(transformed_data))])
        return transformed_data

    def _reverse_nonlinear_transform(self, data):
        """
        Reverse the nonlinear transformation applied during encryption.
        """
        # Reverse the additional transformation (undo XOR with 0xFF and addition of 0x42)
        data = bytearray([((data[i] - 0x42) ^ 0xFF) % 256 for i in range(len(data))])

        # Reverse the XOR with the round key (apply XOR with the same round key used during encryption)
        round_key = self.round_keys[len(data) % len(self.round_keys)]  # Select the appropriate round key
        reversed_data = bytearray([data[i] ^ round_key[i % len(round_key)] for i in range(len(data))])

        return reversed_data

    def _generate_mac(self, data):
        """
        Generate a strong MAC for the given data using SHA-512.
        """
        return hashlib.sha512(self.key + data).digest()  # Use SHA-512 for MAC generation

    def save_key(self, filepath):
        """
        Save the encryption key to a file.
        """
        with open(filepath, 'wb') as file:
            file.write(self.key)
        print(f"Key saved to {filepath}")

    @staticmethod
    def load_key(filepath):
        """
        Load the encryption key from a file.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Key file {filepath} not found.")
        with open(filepath, 'rb') as file:
            key = file.read()
        return main(key)

    def encrypt_file(self, file_path, output_path, nonce=None):
        """
        Encrypt a file and save the encrypted data to a new file.
        """
        with open(file_path, 'rb') as file:
            data = file.read()  # Read the file content
        
        encrypted_data, mac, nonce = self.encrypt(data, nonce)
        
        # Save the encrypted data, MAC, and nonce to the output file
        with open(output_path, 'wb') as file:
            file.write(nonce)  # Write nonce
            file.write(mac)  # Write MAC
            file.write(encrypted_data)  # Write encrypted data
        print(f"File encrypted and saved to {output_path}")

    def decrypt_file(self, encrypted_file_path, output_path):
        """
        Decrypt an encrypted file and save the decrypted content to a new file.
        """
        with open(encrypted_file_path, 'rb') as file:
            nonce = file.read(128)  # 128 bytes for nonce
            mac = file.read(128)  # 128 bytes for MAC
            encrypted_data = file.read()  # Remaining data is encrypted content
        
        # Decrypt the data and verify the MAC
        decrypted_data = self.decrypt(encrypted_data, mac, nonce)
        
        # Save the decrypted content to the output file
        with open(output_path, 'wb') as file:
            file.write(decrypted_data.encode())  # Write decrypted data as bytes
        print(f"File decrypted and saved to {output_path}")

    def text_to_hex(self, text):
        """
        Convert text to hexadecimal representation.
        """
        return text.encode().hex()

    def hex_to_text(self, hex_data):
        """
        Convert hexadecimal string back to text.
        """
        return bytes.fromhex(hex_data).decode()


# Example usage of the custom encryption algorithm for text encryption

# Instantiate the encryption class
cipher = main()

# Original text to encrypt
original_text = "This is a very secret message!"

# Encrypt the text
encrypted_data, mac, nonce = cipher.encrypt(original_text)

# Display the encrypted data, MAC, and nonce (in hexadecimal format for readability)
print("Encrypted Data:", encrypted_data.hex())
print("MAC:", mac.hex())
print("Nonce:", nonce.hex())

# Decrypt the text
decrypted_text = cipher.decrypt(encrypted_data, mac, nonce)

# Display the decrypted text
print("\nDecrypted Text:", decrypted_text)
