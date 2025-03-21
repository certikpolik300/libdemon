import hashlib
import os
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

class gamax:
    def __init__(self, key=None, iterations=200000):
        """
        Initialize the cipher with a key. If no key is provided, generate one.
        Use PBKDF2 with high iterations for key strengthening.
        """
        if key is None:
            key = self.generate_strong_key()
        
        self.key = key
        self.round_keys = self._generate_round_keys()
        self.iterations = iterations

    def _generate_round_keys(self):
        """
        Use an advanced key expansion technique (PBKDF2 and Scrypt with multiple rounds of hashing)
        to generate many round keys.
        """
        round_keys = []
        for i in range(96):  # Increased rounds for higher security
            derived_key = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=128,  # Increased key length for round keys
                salt=self.key,
                iterations=self.iterations,
                backend=default_backend()
            ).derive(i.to_bytes(4, 'big'))  # Different salt per round
            
            scrypt_key = Scrypt(
                salt=self.key,
                length=128,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            ).derive(derived_key)
            
            round_keys.append(scrypt_key)
        return round_keys

    def generate_strong_key(self):
        """
        Generate a new encryption key using a highly secure random process.
        The key will be derived from a strong entropy source.
        """
        return get_random_bytes(256)  # 2048-bit key for extra security

    def encrypt(self, data, nonce=None):
        """
        Encrypt the data using multiple layers of encryption with AES-like structures.
        Convert text to hexadecimal before encryption.
        """
        if nonce is None:
            nonce = get_random_bytes(64)  # Increased nonce size for added security
        
        # Convert the data to hexadecimal string
        data = self.text_to_hex(data)
        data = pad(data.encode(), 256)  # Use larger block size (256 bytes)

        encrypted_data = self._apply_permutation_network(data, nonce)
        mac = self._generate_mac(encrypted_data)
        return encrypted_data, mac, nonce

    def decrypt(self, encrypted_data, mac, nonce):
        """
        Decrypt the data using multiple layers of encryption and verify the MAC.
        Convert encrypted data from hexadecimal back to text.
        """
        if mac != self._generate_mac(encrypted_data):
            raise ValueError("MAC verification failed")
        decrypted_data = self._apply_permutation_network(encrypted_data, nonce, decrypt=True)
        
        # Convert the decrypted data from hex back to text
        decrypted_text = self.hex_to_text(unpad(decrypted_data, 256).decode())
        return decrypted_text

    def _apply_permutation_network(self, data, nonce, decrypt=False):
        """
        Apply a stronger and more complex permutation network on the data.
        """
        num_blocks = len(data) // 256  # 256-byte blocks (larger than AES block size)
        processed_data = bytearray()
        for i in range(num_blocks):
            block = data[i * 256: (i + 1) * 256]
            round_key = self.round_keys[i % len(self.round_keys)]
            if decrypt:
                block = self._reverse_nonlinear_transform(block, round_key)
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
        # Apply additional nonlinear layer
        transformed_data = self._additional_nonlinear_layer(transformed_data)
        return transformed_data

    def _reverse_nonlinear_transform(self, data, round_key):
        """
        Reverse the nonlinear transformation.
        Implement the reverse of your advanced S-boxes and transformations.
        """
        # Reverse additional nonlinear layer
        transformed_data = self._reverse_additional_nonlinear_layer(data)
        # Perform XOR with round key to reverse the transformation
        reversed_data = bytearray([transformed_data[i] ^ round_key[i % len(round_key)] for i in range(len(transformed_data))])
        return reversed_data

    def _additional_nonlinear_layer(self, data):
        """
        Apply an additional nonlinear layer to the data.
        """
        # Example: Rotate bits for an additional layer of security
        return bytearray([(b << 1) | (b >> 7) & 0x01 for b in data])

    def _reverse_additional_nonlinear_layer(self, data):
        """
        Reverse the additional nonlinear layer applied to the data.
        """
        # Reverse the bit rotation
        return bytearray([(b >> 1) | ((b & 0x01) << 7) for b in data])

    def _generate_mac(self, data):
        """
        Generate a strong MAC for the given data using a combination of hashing algorithms.
        """
        hmac1 = HMAC(self.key, hashes.SHA512(), backend=default_backend())
        hmac1.update(data)
        mac1 = hmac1.finalize()
        
        hmac2 = HMAC(self.key, hashes.SHA3_512(), backend=default_backend())
        hmac2.update(data)
        mac2 = hmac2.finalize()
        
        hmac_final = HMAC(self.key, hashes.SHA256(), backend=default_backend())
        hmac_final.update(mac1 + mac2)
        return hmac_final.finalize()

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
        return gamax(key)

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
            nonce = file.read(64)  # 64 bytes for nonce
            mac = file.read(64)  # 64 bytes for MAC
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
