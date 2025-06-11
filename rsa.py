import os
import hashlib
import struct
import time
import math
from typing import Tuple, Optional

# ------------------------
# Cryptographically Secure RNG
# ------------------------
def get_random_bytes(n: int) -> bytes:
    return os.urandom(n)

def get_random_int(bits: int) -> int:
    return int.from_bytes(get_random_bytes((bits + 7) // 8), 'big') | (1 << (bits-1))

# ------------------------
# Miller-Rabin Primality Test (Custom)
# ------------------------
def is_prime(n: int, k: int = 40) -> bool:
    """ Miller-Rabin primality test """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = get_random_int(n.bit_length() - 1) % (n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for __ in range(r-1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            return False
    return True

# ------------------------
# Modular Arithmetic
# ------------------------
def modinv(a: int, m: int) -> int:
    """ Modular inverse using Extended Euclidean Algorithm (Custom) """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError('No modular inverse')
    return x % m

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modexp(base: int, exponent: int, modulus: int) -> int:
    """ Modular exponentiation (square-and-multiply, custom) """
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

# ------------------------
# Prime Generation
# ------------------------
def generate_prime(bits: int) -> int:
    while True:
        p = get_random_int(bits)
        p |= 1  # Ensure odd
        if is_prime(p):
            return p

# ------------------------
# RSA Key Generation
# ------------------------
def generate_rsa_keypair(bits: int = 2048, e: int = 65537) -> Tuple[Tuple[int, int], Tuple[int, int, int, int, int]]:
    """ Returns ((n, e), (n, d, p, q, e)) """
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue
        d = modinv(e, phi)
        return ((n, e), (n, d, p, q, e))

# ------------------------
# OAEP Padding (PKCS#1 v2.2, SHA-256)
# ------------------------
def i2osp(x: int, x_len: int) -> bytes:
    return x.to_bytes(x_len, 'big')

def os2ip(x: bytes) -> int:
    return int.from_bytes(x, 'big')

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def mgf1(seed: bytes, mask_len: int, hash_func=hashlib.sha256) -> bytes:
    """ Mask Generation Function (MGF1) per PKCS#1 v2.2 """
    hLen = hash_func().digest_size
    mask = b''
    for counter in range(0, math.ceil(mask_len / hLen)):
        C = struct.pack(">I", counter)
        mask += hash_func(seed + C).digest()
    return mask[:mask_len]

def oaep_encode(message: bytes, k: int, label: bytes = b'') -> bytes:
    """ OAEP encoding for a message (uses SHA-256) """
    hLen = hashlib.sha256().digest_size
    mLen = len(message)
    if mLen > k - 2 * hLen - 2:
        raise ValueError("Message too long")
    lHash = sha256(label)
    PS = b'\x00' * (k - mLen - 2 * hLen - 2)
    DB = lHash + PS + b'\x01' + message
    seed = get_random_bytes(hLen)
    dbMask = mgf1(seed, k - hLen - 1)
    maskedDB = bytes([db ^ m for db, m in zip(DB, dbMask)])
    seedMask = mgf1(maskedDB, hLen)
    maskedSeed = bytes([s ^ m for s, m in zip(seed, seedMask)])
    return b'\x00' + maskedSeed + maskedDB

def oaep_decode(encoded: bytes, k: int, label: bytes = b'') -> bytes:
    hLen = hashlib.sha256().digest_size
    if len(encoded) != k or encoded[0] != 0:
        raise ValueError("Decryption error")
    maskedSeed = encoded[1:hLen+1]
    maskedDB = encoded[hLen+1:]
    seedMask = mgf1(maskedDB, hLen)
    seed = bytes([ms ^ sm for ms, sm in zip(maskedSeed, seedMask)])
    dbMask = mgf1(seed, k - hLen - 1)
    DB = bytes([md ^ dm for md, dm in zip(maskedDB, dbMask)])
    lHash = sha256(label)
    if DB[:hLen] != lHash:
        raise ValueError("Decryption error")
    # Find the 0x01 separator
    i = hLen
    while i < len(DB):
        if DB[i] == 1:
            break
        elif DB[i] != 0:
            raise ValueError("Decryption error")
        i += 1
    else:
        raise ValueError("Decryption error")
    return DB[i+1:]

# ------------------------
# RSA Encrypt/Decrypt
# ------------------------
def rsa_encrypt_oaep(plaintext: bytes, public_key: Tuple[int, int], k: int, label: bytes = b'') -> bytes:
    n, e = public_key
    padded = oaep_encode(plaintext, k, label)
    m = os2ip(padded)
    c = modexp(m, e, n)
    return i2osp(c, k)

def rsa_decrypt_oaep(ciphertext: bytes, private_key: Tuple[int, int], k: int, label: bytes = b'') -> bytes:
    n, d = private_key
    c = os2ip(ciphertext)
    m = modexp(c, d, n)
    padded = i2osp(m, k)
    return oaep_decode(padded, k, label)

# ------------------------
# PEM/DER Export/Import
# ------------------------
import base64
PEM_PUBLIC_HEADER = "-----BEGIN PUBLIC KEY-----"
PEM_PUBLIC_FOOTER = "-----END PUBLIC KEY-----"
PEM_PRIVATE_HEADER = "-----BEGIN PRIVATE KEY-----"
PEM_PRIVATE_FOOTER = "-----END PRIVATE KEY-----"

def export_public_key_pem(n: int, e: int) -> str:
    from pyasn1.type import univ, namedtype
    from pyasn1.codec.der.encoder import encode as der_encode

    class RSAPublicKey(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('modulus', univ.Integer()),
            namedtype.NamedType('publicExponent', univ.Integer())
        )
    pubkey = RSAPublicKey()
    pubkey.setComponentByName('modulus', n)
    pubkey.setComponentByName('publicExponent', e)
    der = der_encode(pubkey)
    b64 = base64.encodebytes(der).replace(b'\n', b'').decode()
    # Wrap lines at 64 chars
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return PEM_PUBLIC_HEADER + '\n' + '\n'.join(lines) + '\n' + PEM_PUBLIC_FOOTER

def export_private_key_pem(n: int, d: int, e: int, p: int, q: int) -> str:
    from pyasn1.type import univ, namedtype
    from pyasn1.codec.der.encoder import encode as der_encode

    class RSAPrivateKey(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('version', univ.Integer()),
            namedtype.NamedType('modulus', univ.Integer()),
            namedtype.NamedType('publicExponent', univ.Integer()),
            namedtype.NamedType('privateExponent', univ.Integer()),
            namedtype.NamedType('prime1', univ.Integer()),
            namedtype.NamedType('prime2', univ.Integer()),
            namedtype.NamedType('exponent1', univ.Integer()),
            namedtype.NamedType('exponent2', univ.Integer()),
            namedtype.NamedType('coefficient', univ.Integer())
        )
    exp1 = d % (p-1)
    exp2 = d % (q-1)
    coeff = modinv(q, p)
    prikey = RSAPrivateKey()
    prikey.setComponentByName('version', 0)
    prikey.setComponentByName('modulus', n)
    prikey.setComponentByName('publicExponent', e)
    prikey.setComponentByName('privateExponent', d)
    prikey.setComponentByName('prime1', p)
    prikey.setComponentByName('prime2', q)
    prikey.setComponentByName('exponent1', exp1)
    prikey.setComponentByName('exponent2', exp2)
    prikey.setComponentByName('coefficient', coeff)
    der = der_encode(prikey)
    b64 = base64.encodebytes(der).replace(b'\n', b'').decode()
    # Wrap lines at 64 chars
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return PEM_PRIVATE_HEADER + '\n' + '\n'.join(lines) + '\n' + PEM_PRIVATE_FOOTER

# ------------------------
# Timing Metrics
# ------------------------
def benchmark_rsa_oaep(public_key, private_key, k, message, runs=1000):
    enc_times = []
    dec_times = []
    ciphertexts = []
    # Encryption timing
    for _ in range(runs):
        t0 = time.perf_counter()
        c = rsa_encrypt_oaep(message, public_key, k)
        t1 = time.perf_counter()
        enc_times.append(t1-t0)
        ciphertexts.append(c)
    # Decryption timing
    for c in ciphertexts:
        t0 = time.perf_counter()
        m = rsa_decrypt_oaep(c, private_key, k)
        t1 = time.perf_counter()
        dec_times.append(t1-t0)
        assert m == message, "Decryption did not recover original plaintext"
    # Results
    enc_avg = sum(enc_times) / runs
    enc_median = sorted(enc_times)[runs//2]
    dec_avg = sum(dec_times) / runs
    dec_median = sorted(dec_times)[runs//2]
    print(f"Encryption:   avg={enc_avg:.6f}s, median={enc_median:.6f}s")
    print(f"Decryption:   avg={dec_avg:.6f}s, median={dec_median:.6f}s")
    return (enc_avg, enc_median, dec_avg, dec_median)

