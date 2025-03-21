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
import numpy as np

SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

INVERSE_SBOX = [0] * 256
for i, val in enumerate(SBOX):
    INVERSE_SBOX[val] = i



class main: 
    def __init__(self, key=None, iterations=100000):
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
        Use an advanced key expansion technique (PBKDF2 and multiple rounds of hashing)
        to generate many round keys.
        """
        round_keys = []
        for i in range(48):  # Increased rounds for higher security
            derived_key = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=64,
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
        return get_random_bytes(64)  # 512-bit key for extra security

    def encrypt(self, data, nonce=None):
        """
        Encrypt the data using multiple layers of encryption with AES-like structures.
        Convert text to hexadecimal before encryption.
        """
        if nonce is None:
            nonce = get_random_bytes(32)  # Increased nonce size for added security
        
        # Convert the data to hexadecimal string
        data = self.text_to_hex(data)
        data = pad(data.encode(), 64)  # Use larger block size (64 bytes)

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
        decrypted_text = self.hex_to_text(unpad(decrypted_data, 64).decode())
        return decrypted_text

        def _nonlinear_transform(self, data, round_key):
        data = np.frombuffer(data, dtype=np.uint8)
        round_key = np.frombuffer(round_key, dtype=np.uint8)

        # XOR with round key
        data ^= round_key[:len(data)]

        # Substitution
        data = np.take(SBOX, data)

        # Rotate array for diffusion
        data = np.roll(data, 7)  

        # Lightweight mixing (diffusion) step
        data ^= np.roll(data, 3)

        return data.tobytes()

    def _reverse_nonlinear_transform(self, data, round_key):
        data = np.frombuffer(data, dtype=np.uint8)

        # Reverse lightweight mixing
        data ^= np.roll(data, 3)

        # Reverse rotation
        data = np.roll(data, -7)

        # Inverse substitution
        data = np.take(INVERSE_SBOX, data)

        # XOR with round key
        round_key = np.frombuffer(round_key, dtype=np.uint8)
        data ^= round_key[:len(data)]

        return data.tobytes()


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
            nonce = file.read(32)  # 32 bytes for nonce
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

        # Save the decrypted content to the output file
        with open(output_path, 'wb') as file:
            file.write(decrypted_data.encode())  # Write decrypted data as bytes
        print(f"File decrypted and saved to {output_path}")
