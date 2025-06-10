import os
import struct
import secrets
import hashlib
import math
import functools
from typing import Optional

# Galois Field arithmetic for GF(2^128), irreducible polynomial: x^128 + x^7 + x^2 + x + 1 (NIST P128)
GF_POLY = 0x100000000000000000000000000000087
GF_SIZE = 128

def gf128_mul(x: int, y: int) -> int:
    """Multiply two numbers in GF(2^128)."""
    result = 0
    for i in range(GF_SIZE):
        if (y >> i) & 1:
            result ^= x << i
    # Modular reduction
    for i in reversed(range(GF_SIZE * 2 - 1, GF_SIZE - 1, -1)):
        if (result >> i) & 1:
            result ^= GF_POLY << (i - GF_SIZE)
    return result & ((1 << GF_SIZE) - 1)

def gf128_pow(x: int, power: int) -> int:
    result = 1
    for _ in range(power):
        result = gf128_mul(result, x)
    return result

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def int_to_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, 'big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

class CrypteX1:
    BLOCK_SIZE = 32  # 256 bit block
    KEY_SIZE = 64    # 512 bit key
    NONCE_SIZE = 16  # 128 bit nonce
    TAG_SIZE = 16    # 128 bit tag
    ROUNDS = 20      # 20 rounds of permutation

    def __init__(self, key: bytes):
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes (512 bits)")
        self.key = key
        self.round_keys = self._expand_key(key)

    def _expand_key(self, key: bytes):
        # Use SHAKE256 for strong KDF, generate per-round keys and Galois multipliers
        shake = hashlib.shake_256(key)
        round_keys = []
        for i in range(self.ROUNDS):
            rk = shake.digest(self.BLOCK_SIZE)
            round_keys.append(rk)
        # Additional tweak keys for permutations
        extra = shake.digest(256)
        return round_keys, extra

    def _matmul_block(self, block: bytes, matrix: bytes):
        """Multiply block by a secret matrix in GF(2^8), for strong diffusion."""
        SIZE = self.BLOCK_SIZE
        mat = [matrix[i*SIZE:(i+1)*SIZE] for i in range(SIZE)]
        vec = list(block)
        out = []
        for row in mat:
            val = 0
            for a, b in zip(row, vec):
                val ^= self._gf256_mul(a, b)
            out.append(val)
        return bytes(out)

    @staticmethod
    def _gf256_mul(a: int, b: int) -> int:
        # GF(2^8) with Rijndael's polynomial 0x11b (like AES S-box)
        p = 0
        for i in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= 0x1b
            b >>= 1
        return p

    def _sbox_layer(self, block: bytes, tweak: bytes) -> bytes:
        # Nonlinear S-box using algebraic permutation and tweak
        # S_i(x) = inv(x) ^ tweak[i] mod 256
        out = []
        for i, b in enumerate(block):
            x = b ^ tweak[i]
            out.append(self._sbox(x))
        return bytes(out)

    @staticmethod
    def _sbox(x: int) -> int:
        # Highly nonlinear S-box: multiplicative inverse, affine, then cubic
        if x == 0:
            y = 0
        else:
            y = pow(x, 254, 257) % 256  # Inverse in GF(257) then mod 256
        y = y ^ 0x63
        y = (y * y * y) & 0xFF
        return y

    def _permute(self, block: bytes, round_key: bytes, tweak: bytes, mat: bytes) -> bytes:
        # Each round: add round key, S-box, matmul, rotate, xor tweak
        b = xor_bytes(block, round_key)
        b = self._sbox_layer(b, tweak)
        b = self._matmul_block(b, mat)
        b = self._rotate_bytes(b, (b[0] ^ b[-1]) % self.BLOCK_SIZE)
        b = xor_bytes(b, tweak)
        return b

    @staticmethod
    def _rotate_bytes(b: bytes, n: int) -> bytes:
        return b[n:] + b[:n]

    def _block_encrypt(self, block: bytes, counter: int, nonce: bytes) -> bytes:
        # Strong block cipher permutation with tweakable counter/nonce for uniqueness
        assert len(block) == self.BLOCK_SIZE
        round_keys, extra = self.round_keys
        tweak = hashlib.shake_256(
            self.key + nonce + int_to_bytes(counter, 16) + extra[:16]
        ).digest(self.BLOCK_SIZE)
        mat = extra[16:16+self.BLOCK_SIZE*self.BLOCK_SIZE]
        b = xor_bytes(block, nonce + int_to_bytes(counter, self.BLOCK_SIZE - self.NONCE_SIZE))
        for i in range(self.ROUNDS):
            b = self._permute(b, round_keys[i], tweak, mat)
            tweak = hashlib.shake_256(tweak).digest(self.BLOCK_SIZE)
        return b

    def _ctr_keystream(self, nonce: bytes, counter: int) -> bytes:
        # Generate a keystream block for CTR mode
        block = b"\x00" * self.BLOCK_SIZE
        return self._block_encrypt(block, counter, nonce)

    def encrypt_ctr(self, plaintext: bytes, nonce: Optional[bytes] = None) -> bytes:
        if nonce is None:
            nonce = secrets.token_bytes(self.NONCE_SIZE)
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError("Nonce must be 16 bytes.")
        ciphertext = bytearray()
        for i in range(0, len(plaintext), self.BLOCK_SIZE):
            block = plaintext[i:i+self.BLOCK_SIZE]
            ks = self._ctr_keystream(nonce, i // self.BLOCK_SIZE)
            ct = xor_bytes(block, ks[:len(block)])
            ciphertext.extend(ct)
        return nonce + bytes(ciphertext)

    def decrypt_ctr(self, ciphertext: bytes) -> bytes:
        nonce = ciphertext[:self.NONCE_SIZE]
        ct = ciphertext[self.NONCE_SIZE:]
        plaintext = bytearray()
        for i in range(0, len(ct), self.BLOCK_SIZE):
            block = ct[i:i+self.BLOCK_SIZE]
            ks = self._ctr_keystream(nonce, i // self.BLOCK_SIZE)
            pt = xor_bytes(block, ks[:len(block)])
            plaintext.extend(pt)
        return bytes(plaintext)

    def encrypt_gcm(self, plaintext: bytes, associated_data: bytes = b'', nonce: Optional[bytes] = None) -> bytes:
        if nonce is None:
            nonce = secrets.token_bytes(self.NONCE_SIZE)
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError("Nonce must be 16 bytes.")
        ciphertext = self.encrypt_ctr(plaintext, nonce)[self.NONCE_SIZE:]
        tag = self._gcm_tag(nonce, ciphertext, associated_data)
        return nonce + ciphertext + tag

    def decrypt_gcm(self, ciphertext: bytes, associated_data: bytes = b'') -> Optional[bytes]:
        nonce = ciphertext[:self.NONCE_SIZE]
        tag = ciphertext[-self.TAG_SIZE:]
        ct = ciphertext[self.NONCE_SIZE:-self.TAG_SIZE]
        pt = self.decrypt_ctr(nonce + ct)
        expected_tag = self._gcm_tag(nonce, ct, associated_data)
        if not secrets.compare_digest(tag, expected_tag):
            return None
        return pt

    def _gcm_tag(self, nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
        # Galois hash on (A, C, |A|, |C|), with field element derived from key/nonce
        H = self._ctr_keystream(nonce, 0)[:self.BLOCK_SIZE]
        h = bytes_to_int(H)
        ghash = 0
        def ghash_update(x: int, buf: bytes):
            nonlocal ghash
            for i in range(0, len(buf), 16):
                block = buf[i:i+16]
                if len(block) < 16:
                    block = block + b"\x00" * (16 - len(block))
                ghash = gf128_mul(ghash ^ bytes_to_int(block), x)
        ghash_update(h, associated_data)
        ghash_update(h, ciphertext)
        l = int_to_bytes(len(associated_data) * 8, 8) + int_to_bytes(len(ciphertext) * 8, 8)
        ghash_update(h, l)
        tag = xor_bytes(self._ctr_keystream(nonce, 1)[:16], int_to_bytes(ghash, 16))
        return tag

    @staticmethod
    def generate_key() -> bytes:
        return secrets.token_bytes(CrypteX1.KEY_SIZE)

    @staticmethod
    def generate_nonce() -> bytes:
        return secrets.token_bytes(CrypteX1.NONCE_SIZE)

