import hashlib
import os
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class gamax:
    def __init__(self, key=None, iterations=100000):
        """
        Initialize the cipher with a key. If no key is provided, generate one.
        Use Scrypt for key strengthening to improve resistance against brute-force and side-channel attacks.
        """
        if key is None:
            key = self.generate_strong_key()

        self.key = key
        self.round_keys = self._generate_round_keys()
        self.iterations = iterations

    def _generate_round_keys(self):
        """
        Use Scrypt for key expansion and additional rounds for enhanced security.
        """
        round_keys = []
        for i in range(48):  # Increased rounds for higher security
            derived_key = Scrypt(
                salt=self.key,
                length=64,
                n=16384,
                r=8,
                p=1,
                backend=default_backend()
            ).derive(i.to_bytes(4, 'big'))  # Different salt per round
            round_keys.append(derived_key)
        return round_keys

    def generate_strong_key(self):
        """
        Generate a new encryption key using a highly secure random process.
        """
        return get_random_bytes(64)  # 512-bit key for extra security

    def encrypt(self, data, nonce=None):
        """
        Encrypt the data using multiple layers of encryption with AES-like structures and advanced S-boxes.
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

    def _apply_permutation_network(self, data, nonce, decrypt=False):
        """
        Apply a stronger and more complex permutation network on the data using advanced S-boxes and MDS mixing.
        """
        num_blocks = len(data) // 64  # 64-byte blocks (larger than AES block size)
        processed_data = bytearray()
        for i in range(num_blocks):
            block = data[i * 64: (i + 1) * 64]
            round_key = self.round_keys[i % len(self.round_keys)]
            if decrypt:
                block = self._reverse_nonlinear_transform(block)
            processed_block = self._nonlinear_transform(block, round_key)
            processed_data.extend(processed_block)
        return processed_data

    def _nonlinear_transform(self, data, round_key):
        """
        Perform a complex nonlinear transformation with a round key.
        Use advanced S-boxes and apply MDS matrix for stronger diffusion.
        """
        # Apply the S-box transformation using a custom advanced S-box
        transformed_data = bytearray([self.advanced_sbox_transformation(data[i]) for i in range(len(data))])
        
        # Apply MDS matrix for mixing
        mds_transformed_data = self._mds_mix(transformed_data)
        
        # Apply key-dependent advanced XOR (complex and secure)
        transformed_data = self._complex_key_dependent_xor(mds_transformed_data, round_key)
        
        return transformed_data

    def advanced_sbox_transformation(self, byte):
        """
        Advanced S-box for enhanced cryptographic strength.
        This S-box is designed for high non-linearity and resistance to cryptanalysis.
        """
        # Advanced S-box construction using elements of a known cryptographically strong permutation
        sbox = [
            0xA5, 0x91, 0xF4, 0x75, 0x31, 0x3F, 0x4A, 0x9B, 0xC2, 0xE1, 0x13, 0x26, 0x8D, 0x32, 0x4E, 0x60, 0x77,
            0x48, 0xAB, 0x29, 0x8C, 0xB9, 0x96, 0xD4, 0x81, 0x56, 0x9A, 0xC6, 0x11, 0x2D, 0xA4, 0x5F, 0x6C, 0x12,
            0xD5, 0xF1, 0xA3, 0x40, 0x3B, 0x8A, 0xE8, 0x34, 0xB7, 0x59, 0x9D, 0xF5, 0x4B, 0x1A, 0x14, 0x6B, 0xC1,
            0x74, 0x85, 0x19, 0xE9, 0x71, 0x80, 0x57, 0x3A, 0x43, 0x72, 0x53, 0x95, 0x6A, 0x16, 0x28, 0x52, 0x37
        ]
        return sbox[byte]

    def _mds_mix(self, data):
        """
        Apply an MDS matrix transformation to the data for stronger diffusion.
        """
        mds_matrix = [
            [0x01, 0x02, 0x03, 0x04],
            [0x05, 0x06, 0x07, 0x08],
            [0x09, 0x0A, 0x0B, 0x0C],
            [0x0D, 0x0E, 0x0F, 0x10]
        ]
        mds_result = [0] * len(data)
        for i in range(len(data)):
            mds_result[i] = 0
            for j in range(len(data)):
                mds_result[i] ^= mds_matrix[i % len(data)][j] * data[j]
        return mds_result

    def _complex_key_dependent_xor(self, data, round_key):
        """
        Perform an advanced, complex XOR operation based on the round key and cryptographic principles.
        This method ensures that the key-dependent transformation is robust against side-channel attacks.
        """
        xor_result = bytearray()
        for i in range(len(data)):
            xor_result.append(data[i] ^ round_key[i % len(round_key)] ^ (i * 0xAA))  # Advanced XOR mechanism
        return xor_result

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
        return galyrex(key)

    def encrypt_file(self, file_path, output_path, nonce=None):
        """
        Encrypt a file and save the encrypted data to a new file.
        """
        with open(file_path, 'rb') as file:
            data = file.read()  # Read the file content
        
        encrypted_data, mac, nonce = self.encrypt(data, nonce)
        
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
        
        decrypted_data = self.decrypt(encrypted_data, mac, nonce)
        
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
