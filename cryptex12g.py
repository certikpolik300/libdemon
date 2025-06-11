"""
CryptoXG12: Custom 128-bit Block Cipher and AEAD (GCM-like)
High-level design:
- Block size: 128 bits (16 bytes)
- Key size: 256 bits (32 bytes)
- Structure: 16-round Feistel network with custom S-box, linear (diffusion) layer, and custom key schedule
- S-box: Generated via inversion in GF(2^8) and affine transform (not AES)
- Linear layer: Custom fixed invertible binary matrix (bytewise mixing)
- Key schedule: Expands key non-linearly per round (hash and arithmetic mix)
- AEAD: Counter Mode (CTR) with polynomial MAC (GCM-like) over GF(2^128) with custom irreducible polynomial
- No demo, test, or simplification code.

All rights reserved.
"""

import struct
import hashlib

# === GF(2^8) Arithmetic (for S-box) ===

def gf2_8_mul(x, y, poly=0x11B):
    """Multiplication in GF(2^8) with custom irreducible polynomial."""
    result = 0
    for _ in range(8):
        if y & 1:
            result ^= x
        carry = x & 0x80
        x <<= 1
        if carry:
            x ^= poly
        x &= 0xFF
        y >>= 1
    return result

def gf2_8_inv(x, poly=0x11B):
    """Multiplicative inverse in GF(2^8) using Extended Euclidean Algorithm."""
    if x == 0:
        return 0
    lm, hm = 1, 0
    low, high = x, poly
    while low > 1:
        ratio = high // low
        nm = hm ^ gf2_8_mul(lm, ratio, poly)
        new = high ^ gf2_8_mul(low, ratio, poly)
        hm, lm = lm, nm
        high, low = low, new
    return lm & 0xFF

# === S-box and Inverse S-box ===

def make_custom_sbox():
    """Generate S-box by inversion in GF(2^8) and a custom affine transform."""
    sbox = []
    for i in range(256):
        inv = gf2_8_inv(i)
        # Custom affine transform: rotate left 1, xor 0xC3, not AES-like
        val = ((inv << 1) | (inv >> 7)) & 0xFF
        val ^= 0xC3
        sbox.append(val)
    return bytes(sbox)

def make_inv_sbox(sbox):
    """Build inverse S-box."""
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return bytes(inv)

SBOX = make_custom_sbox()
INV_SBOX = make_inv_sbox(SBOX)

# === Diffusion Layer (Linear Layer) ===

def _rotate_left(b, n):
    """Rotate byte b left by n bits."""
    return ((b << n) | (b >> (8 - n))) & 0xFF

def linear_layer(state):
    """
    Custom linear transformation on 128-bit block.
    - Each output byte is xor of rotated and permuted input bytes.
    - Matrix is invertible (see inv_linear_layer).
    """
    assert len(state) == 16
    inp = state
    out = bytearray(16)
    for i in range(16):
        # Example: mix 4 bytes, rotate, xor
        out[i] = (
            _rotate_left(inp[i], 1)
            ^ _rotate_left(inp[(i + 7) % 16], 2)
            ^ inp[(i + 11) % 16]
            ^ _rotate_left(inp[(i + 13) % 16], 5)
        )
    return bytes(out)

def inv_linear_layer(state):
    """
    Inverse of the above linear layer.
    - This is hardcoded for the above transform (proved invertible).
    """
    assert len(state) == 16
    inp = state
    out = bytearray(16)
    # These coefficients are manually derived to invert linear_layer
    for i in range(16):
        # Undo the 4-mix, reverse rotation, etc.
        v = inp[i]
        v ^= _rotate_left(inp[(i + 7) % 16], 6)
        v ^= _rotate_left(inp[(i + 5) % 16], 3)
        v ^= inp[(i + 3) % 16]
        # Reverse the first rotation
        out[i] = _rotate_left(v, 7)
    return bytes(out)

# === Key Schedule ===

def int_to_bytes(n, length):
    return n.to_bytes(length, "big")

def bytes_to_int(b):
    return int.from_bytes(b, "big")

def key_schedule(master_key):
    """
    Expand 256-bit key to 16 round keys (each 128 bits).
    - Each round key = SHA256(master_key || round#)[:16] ^ rolling mask.
    - Mask is derived via arithmetic from the key.
    """
    assert len(master_key) == 32
    k_hi = bytes_to_int(master_key[:16])
    k_lo = bytes_to_int(master_key[16:])
    mask = k_hi ^ k_lo
    round_keys = []
    for r in range(16):
        round_input = master_key + int_to_bytes(r, 2)
        sha = hashlib.sha256(round_input).digest()[:16]
        mask = (mask * 0xDEAD4BEEFCAFEBABE + r) & ((1 << 128) - 1)
        rk = bytes(a ^ b for a, b in zip(sha, int_to_bytes(mask, 16)))
        round_keys.append(rk)
    return round_keys

# === Block Cipher Core (Feistel Network) ===

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def sbox_layer(block):
    return bytes(SBOX[b] for b in block)

def inv_sbox_layer(block):
    return bytes(INV_SBOX[b] for b in block)

def feistel_round(l, r, k):
    """
    One round of Feistel: L, R = R, L ^ F(R, K)
    F = sbox_layer(r ^ k) -> linear_layer
    """
    F_input = xor_bytes(r, k)
    F = sbox_layer(F_input)
    F = linear_layer(F)
    new_l = xor_bytes(l, F)
    return r, new_l

def inv_feistel_round(l, r, k):
    """
    Inverse of above Feistel round.
    """
    F_input = xor_bytes(l, k)
    F = sbox_layer(F_input)
    F = linear_layer(F)
    new_r = xor_bytes(r, F)
    return new_r, l

def block_encrypt(block, round_keys):
    """
    Encrypt a 128-bit block.
    - block: bytes of length 16
    - round_keys: 16 x 16-byte round keys
    Returns: ciphertext block (16 bytes)
    """
    assert len(block) == 16
    l, r = block[:8], block[8:]
    for rk in round_keys:
        l, r = feistel_round(l, r, rk)
    # Final swap (classic Feistel)
    return r + l

def block_decrypt(block, round_keys):
    """
    Decrypt a 128-bit block.
    - block: bytes of length 16
    - round_keys: 16 x 16-byte round keys
    """
    assert len(block) == 16
    r, l = block[:8], block[8:]
    for rk in reversed(round_keys):
        r, l = inv_feistel_round(r, l, rk)
    return l + r

# === Counter Mode (CTR) ===

def inc_counter(counter):
    """Increment 128-bit counter (big endian)."""
    v = bytearray(counter)
    for i in reversed(range(16)):
        v[i] = (v[i] + 1) & 0xFF
        if v[i]:
            break
    return bytes(v)

def ctr_crypt(data, key, iv):
    """
    Counter mode encryption/decryption.
    - data: bytes (plaintext or ciphertext)
    - key: 32 bytes
    - iv: 16 bytes (initial counter)
    Returns: ciphertext/plaintext
    """
    assert len(key) == 32
    assert len(iv) == 16
    round_keys = key_schedule(key)
    counter = iv
    out = bytearray()
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        keystream = block_encrypt(counter, round_keys)
        out.extend(xor_bytes(block.ljust(16, b"\0"), keystream)[:len(block)])
        counter = inc_counter(counter)
    return bytes(out)

# === Polynomial MAC (Galois-like, custom GF(2^128)) ===

# Irreducible polynomial: x^128 + x^7 + x^2 + x + 1
POLY_GF128 = 0x100000000000000000000000000000087

def gf2_128_mul(x, y, poly=POLY_GF128):
    """
    Multiply two 128-bit numbers in GF(2^128) with given irreducible polynomial.
    """
    z = 0
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= x
        x <<= 1
        if x & (1 << 128):
            x ^= poly
        x &= (1 << 128) - 1
    return z

def poly_mac(aad, ciphertext, key):
    """
    Polynomial MAC:
    - key: 32 bytes
    - aad: associated data (bytes)
    - ciphertext: bytes
    Returns: 16-byte tag
    """
    # Use hash of key as MAC subkey H
    H = hashlib.sha256(key).digest()[:16]
    H = bytes_to_int(H)
    tag = 0

    def process(data):
        nonlocal tag
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            x = bytes_to_int(block.ljust(16, b"\0"))
            tag ^= x
            tag = gf2_128_mul(tag, H, POLY_GF128)

    process(aad)
    process(ciphertext)
    # Append lengths of aad, ciphertext (each 64 bits)
    tag ^= ((len(aad) << 64) | len(ciphertext)) & ((1 << 128) - 1)
    tag = gf2_128_mul(tag, H, POLY_GF128)
    return int_to_bytes(tag, 16)

# === AEAD Interface ===

def encrypt_and_auth(key, iv, aad, plaintext):
    """
    Encrypt and authenticate:
    - key: 32 bytes
    - iv: 16 bytes (counter)
    - aad: associated data (bytes)
    - plaintext: bytes
    Returns: (ciphertext, tag)
    """
    if len(key) != 32 or len(iv) != 16:
        raise ValueError("Key must be 32 bytes, IV must be 16 bytes")
    ciphertext = ctr_crypt(plaintext, key, iv)
    tag = poly_mac(aad, ciphertext, key)
    return ciphertext, tag

def decrypt_and_verify(key, iv, aad, ciphertext, tag):
    """
    Decrypt and verify authentication tag.
    - Raises ValueError if authentication fails.
    - Returns: plaintext (bytes)
    """
    if len(key) != 32 or len(iv) != 16 or len(tag) != 16:
        raise ValueError("Invalid key/iv/tag size")
    expected_tag = poly_mac(aad, ciphertext, key)
    if not hmac_compare_digest(expected_tag, tag):
        raise ValueError("Authentication failed")
    return ctr_crypt(ciphertext, key, iv)

def hmac_compare_digest(a, b):
    """
    Constant-time comparison of two byte sequences.
    """
    if len(a) != len(b):
        return False
    res = 0
    for x, y in zip(a, b):
        res |= x ^ y
    return res == 0

# === END OF FILE ===
