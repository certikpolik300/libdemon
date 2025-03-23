import os
import time
import struct
import hashlib
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hmac

# Constants
AES_KEY_SIZE = 32  # 256-bit
HMAC_KEY_SIZE = 32
NONCE_SIZE = 12
RSA_KEY_SIZE = 4096
TIMESTAMP_TOLERANCE = 30  # Seconds for replay attack protection

class main:
    def __init__(self):
        """Initialize E2EE with ECDH key exchange and RSA encryption."""
        self.ecdh_private_key = ec.generate_private_key(ec.SECP384R1())  # Use a more secure curve
        self.ecdh_public_key = self.ecdh_private_key.public_key()
        self.rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
        self.rsa_public_key = self.rsa_private_key.public_key()

    def get_ecdh_public_key(self):
        """Export ECDH public key."""
        return self.ecdh_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_rsa_public_key(self):
        """Export RSA public key."""
        return self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def derive_shared_secret(self, peer_public_key_pem):
        """Derive shared secret using ECDH."""
        peer_public_key = serialization.load_pem_public_key(peer_public_key_pem)
        shared_secret = self.ecdh_private_key.exchange(ec.ECDH(), peer_public_key)

        # Use HKDF to derive AES and HMAC keys
        kdf = HKDF(algorithm=hashes.SHA256(), length=AES_KEY_SIZE + HMAC_KEY_SIZE, salt=None, info=b'E2EE Key Derivation')
        key_material = kdf.derive(shared_secret)

        self.aes_key = key_material[:AES_KEY_SIZE]
        self.hmac_key = key_material[AES_KEY_SIZE:]
        return base64.b64encode(self.aes_key).decode()

    def sign_message(self, message):
        """Sign the message using RSA to provide authenticity."""
        signature = self.rsa_private_key.sign(
            message.encode(),
            padding.PSS(mgf=padding.MGF1(algorithm=hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def verify_signature(self, message, signature):
        """Verify the signature of a message using RSA."""
        try:
            self.rsa_public_key.verify(
                base64.b64decode(signature),
                message.encode(),
                padding.PSS(mgf=padding.MGF1(algorithm=hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def encrypt(self, plaintext):
        """Encrypts data using AES-256-GCM with integrity protection."""
        nonce = os.urandom(NONCE_SIZE)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

        # Create HMAC for integrity
        mac = hmac.new(self.hmac_key, ciphertext, hashlib.sha256).digest()

        # Include timestamp for replay protection
        timestamp = struct.pack(">Q", int(time.time()))

        return base64.b64encode(nonce + encryptor.tag + timestamp + mac + ciphertext).decode()

    def decrypt(self, encrypted_data):
        """Decrypts data and verifies integrity & freshness."""
        data = base64.b64decode(encrypted_data)

        nonce = data[:NONCE_SIZE]
        tag = data[NONCE_SIZE:NONCE_SIZE+16]
        timestamp = struct.unpack(">Q", data[NONCE_SIZE+16:NONCE_SIZE+24])[0]
        mac = data[NONCE_SIZE+24:NONCE_SIZE+56]
        ciphertext = data[NONCE_SIZE+56:]

        # Replay protection: check timestamp
        if abs(time.time() - timestamp) > TIMESTAMP_TOLERANCE:
            raise Exception("Replay attack detected!")

        # Verify HMAC
        expected_mac = hmac.new(self.hmac_key, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise Exception("Data integrity compromised!")

        # Decrypt
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def encrypt_symmetric_key(self):
        """Encrypt AES key with RSA-4096."""
        encrypted_key = self.rsa_public_key.encrypt(
            self.aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return base64.b64encode(encrypted_key).decode()

    def decrypt_symmetric_key(self, encrypted_key):
        """Decrypt AES key using RSA-4096."""
        decrypted_key = self.rsa_private_key.decrypt(
            base64.b64decode(encrypted_key),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        self.aes_key = decrypted_key
        return base64.b64encode(self.aes_key).decode()

    def encrypt_metadata(self, metadata):
        """Encrypts metadata (IP, port, etc.)."""
        metadata_json = json.dumps(metadata).encode()
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(os.urandom(NONCE_SIZE)))
        encryptor = cipher.encryptor()
        encrypted_metadata = encryptor.update(metadata_json) + encryptor.finalize()
        return base64.b64encode(encrypted_metadata).decode()

    def decrypt_metadata(self, encrypted_metadata):
        """Decrypts metadata."""
        encrypted_metadata = base64.b64decode(encrypted_metadata)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(os.urandom(NONCE_SIZE)))
        decryptor = cipher.decryptor()
        return json.loads(decryptor.update(encrypted_metadata) + decryptor.finalize())
    
    def handshake(self, peer_public_key_pem):
        """Complete the handshake protocol."""
        # Generate and exchange public keys, and derive shared secret
        peer_public_key = serialization.load_pem_public_key(peer_public_key_pem)
        shared_secret = self.derive_shared_secret(peer_public_key_pem)

        # Return the shared secret and the public key for the peer to encrypt the symmetric key
        return {
            "shared_secret": shared_secret,
            "public_key": self.get_rsa_public_key(),
        }

    def secure_message_exchange(self, peer_public_key_pem, message):
        """Exchange a secure message (sign, encrypt, decrypt)."""
        # Handshake to derive shared secret and public keys
        handshake_data = self.handshake(peer_public_key_pem)
        
        # Sign the message before encrypting
        signed_message = self.sign_message(message)
        
        # Encrypt the message
        encrypted_message = self.encrypt(message)
        
        return {
            "signed_message": signed_message,
            "encrypted_message": encrypted_message,
            "handshake_data": handshake_data
        }

    def authenticate_peer(self, peer_public_key_pem, signed_message):
        """Authenticate the peer by verifying their signed message."""
        if self.verify_signature(signed_message, peer_public_key_pem):
            return True
        return False
