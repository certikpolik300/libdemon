import socket
import struct
import asyncio
import zlib
from .encryption import ECDH  # Removed Obfuscation import
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class TCPTransport:
    @staticmethod
    async def send_encrypted_message(sock, encrypted_message, derived_key):
        """Sends an encrypted message over a TCP socket"""
        if encrypted_message is None:
            raise ValueError("Encrypted message cannot be None")
        compressed_message = zlib.compress(encrypted_message)
        message_length = len(compressed_message)
        await sock.sendall(struct.pack("!I", message_length))
        await sock.sendall(compressed_message)

    @staticmethod
    async def receive_encrypted_message(sock, derived_key):
        """Receives an encrypted message over a TCP socket"""
        message_length_data = await sock.recv(4)
        if not message_length_data:
            return None
        message_length = struct.unpack("!I", message_length_data)[0]
        compressed_message = await sock.recv(message_length)
        if not compressed_message:
            return None
        decrypted_message = zlib.decompress(compressed_message)
        return decrypted_message

    @staticmethod
    async def exchange_keys(sock):
        """Exchange public keys and derive shared key"""
        private_key, public_key = ECDH.generate_keypair()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        await sock.sendall(struct.pack("!I", len(public_key_bytes)))
        await sock.sendall(public_key_bytes)

        peer_key_length = struct.unpack("!I", await sock.recv(4))[0]
        peer_key_bytes = await sock.recv(peer_key_length)
        peer_public_key = serialization.load_pem_public_key(peer_key_bytes, backend=default_backend())

        shared_key = ECDH.derive_shared_key(private_key, peer_public_key)
        verification_code, qr_code = ECDH.generate_verification_code(public_key, peer_public_key)
        return shared_key, verification_code, qr_code

    @staticmethod
    async def send_encrypted_file(sock, encrypted_file_data, file_name, derived_key):
        """Sends an encrypted file over a TCP socket"""
        if encrypted_file_data is None:
            raise ValueError("Encrypted file data cannot be None")
        compressed_file_data = zlib.compress(encrypted_file_data)
        file_name_encoded = file_name.encode()
        file_name_length = len(file_name_encoded)
        file_data_length = len(compressed_file_data)

        await sock.sendall(struct.pack("!I", file_name_length))
        await sock.sendall(file_name_encoded)
        await sock.sendall(struct.pack("!Q", file_data_length))
        await sock.sendall(compressed_file_data)

    @staticmethod
    async def receive_encrypted_file(sock, derived_key):
        """Receives an encrypted file over a TCP socket"""
        file_name_length_data = await sock.recv(4)
        if not file_name_length_data:
            return None, None
        file_name_length = struct.unpack("!I", file_name_length_data)[0]
        file_name = (await sock.recv(file_name_length)).decode()

        file_data_length_data = await sock.recv(8)
        file_data_length = struct.unpack("!Q", file_data_length_data)[0]
        compressed_file_data = await sock.recv(file_data_length)
        if not compressed_file_data:
            return None, None

        decrypted_file_data = zlib.decompress(compressed_file_data)
        return file_name, decrypted_file_data


class UDPTransport:
    @staticmethod
    async def send_encrypted_message(sock, encrypted_message, address, derived_key):
        """Sends an encrypted message over a UDP socket"""
        if encrypted_message is None:
            raise ValueError("Encrypted message cannot be None")
        compressed_message = zlib.compress(encrypted_message)
        message_length = len(compressed_message)
        await sock.sendto(struct.pack("!I", message_length) + compressed_message, address)

    @staticmethod
    async def receive_encrypted_message(sock, derived_key):
        """Receives an encrypted message over a UDP socket"""
        message_length_data, _ = await sock.recvfrom(4)
        if not message_length_data:
            return None
        message_length = struct.unpack("!I", message_length_data)[0]
        compressed_message, _ = await sock.recvfrom(message_length)
        if not compressed_message:
            return None
        decrypted_message = zlib.decompress(compressed_message)
        return decrypted_message

    @staticmethod
    async def send_encrypted_file(sock, encrypted_file_data, file_name, address, derived_key):
        """Sends an encrypted file over a UDP socket"""
        if encrypted_file_data is None:
            raise ValueError("Encrypted file data cannot be None")
        compressed_file_data = zlib.compress(encrypted_file_data)
        file_name_encoded = file_name.encode()
        file_name_length = len(file_name_encoded)
        file_data_length = len(compressed_file_data)

        await sock.sendto(
            struct.pack("!I", file_name_length) + file_name_encoded + struct.pack("!Q", file_data_length) + compressed_file_data,
            address
        )

    @staticmethod
    async def receive_encrypted_file(sock, derived_key):
        """Receives an encrypted file over a UDP socket"""
        file_name_length_data, _ = await sock.recvfrom(4)
        if not file_name_length_data:
            return None, None
        file_name_length = struct.unpack("!I", file_name_length_data)[0]
        file_name, _ = await sock.recvfrom(file_name_length)

        file_data_length_data, _ = await sock.recvfrom(8)
        file_data_length = struct.unpack("!Q", file_data_length_data)[0]
        compressed_file_data, _ = await sock.recvfrom(file_data_length)
        if not compressed_file_data:
            return None, None

        decrypted_file_data = zlib.decompress(compressed_file_data)
        return file_name.decode(), decrypted_file_data
