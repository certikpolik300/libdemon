"""
aes_gcm_lib.py

A self-contained library for AES and AES-GCM encryption, combining the core AES block cipher
and Galois/Counter Mode (GCM) implementation.

Functions:
    - aes_encryption(data: bytes, key: bytes) -> bytes
    - aes_decryption(cipher: bytes, key: bytes) -> bytes
    - aes_gcm_encrypt(P, K, IV, A, t) -> (ciphertext, tag)
    - aes_gcm_decrypt(C, K, IV, A, T) -> (plaintext, valid)

Usage:
    from aes_gcm_lib import aes_encryption, aes_decryption, aes_gcm_encrypt, aes_gcm_decrypt
"""

import math

# --- AES core implementation ---

s_box_string = (
    '63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76'
    'ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0'
    'b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15'
    '04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75'
    '09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84'
    '53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf'
    'd0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8'
    '51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2'
    'cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73'
    '60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db'
    'e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79'
    'e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08'
    'ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a'
    '70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e'
    'e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df'
    '8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16'
)
s_box = bytearray.fromhex(s_box_string.replace(" ", ""))

def sub_word(word):
    return bytes(s_box[i] for i in word)

def rcon(i):
    rcon_lookup = bytearray.fromhex('01020408102040801b36')
    return bytes([rcon_lookup[i-1], 0, 0, 0])

def xor_bytes(a, b):
    return bytes([x ^ y for (x, y) in zip(a, b)])

def rot_word(word):
    return word[1:] + word[:1]

def state_from_bytes(data):
    return [list(data[i*4:(i+1)*4]) for i in range(4)]

def bytes_from_state(state):
    return bytes([state[r][c] for c in range(4) for r in range(4)])

def key_expansion(key, nb=4):
    nk = len(key) // 4
    key_bit_length = len(key) * 8
    if key_bit_length == 128:
        nr = 10
    elif key_bit_length == 192:
        nr = 12
    else:
        nr = 14
    key_words = [list(key[i*4:(i+1)*4]) for i in range(nk)]
    w = key_words.copy()
    for i in range(nk, nb * (nr + 1)):
        temp = w[i-1][:]
        if i % nk == 0:
            temp = [x for x in sub_word(rot_word(temp))]
            temp = [temp[j] ^ rcon(i // nk)[j] for j in range(4)]
        elif nk > 6 and i % nk == 4:
            temp = [x for x in sub_word(temp)]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    # Arrange key schedule as 4x4 state per round
    return [[w[round*4 + i] for i in range(4)] for round in range(len(w)//4)]

def add_round_key(state, key_schedule, round):
    for r in range(4):
        for c in range(4):
            state[r][c] ^= key_schedule[round][c][r]

def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = s_box[state[r][c]]

def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else a << 1

def mix_column(col):
    t = col[0] ^ col[1] ^ col[2] ^ col[3]
    u = col[0]
    col[0] ^= t ^ xtime(col[0] ^ col[1])
    col[1] ^= t ^ xtime(col[1] ^ col[2])
    col[2] ^= t ^ xtime(col[2] ^ col[3])
    col[3] ^= t ^ xtime(col[3] ^ u)

def mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mix_column(col)
        for r in range(4):
            state[r][c] = col[r]

def aes_encryption(data, key):
    assert len(data) == 16, "Block size must be 16 bytes"
    key_bit_length = len(key) * 8
    if key_bit_length == 128:
        nr = 10
    elif key_bit_length == 192:
        nr = 12
    else:
        nr = 14
    state = state_from_bytes(data)
    key_schedule = key_expansion(key)
    add_round_key(state, key_schedule, 0)
    for round in range(1, nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, key_schedule, round)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, key_schedule, nr)
    return bytes_from_state(state)

# --- AES-GCM implementation ---

def xor_bytes_gcm(bytes_a: bytes, bytes_b: bytes) -> bytes:
    return bytes([a ^ b for (a, b) in zip(bytes_a, bytes_b)])

def MUL(X_bytes, Y_bytes):
    X = int.from_bytes(X_bytes, 'big')
    Y = int.from_bytes(Y_bytes, 'big')
    R = 0xe1 << 120
    x = [1 if X & (1 << i) else 0 for i in range(127, -1, -1)]
    Z_i = 0
    V_i = Y
    for i in range(128):
        if x[i] == 0:
            Z_i_1 = Z_i
        else:
            Z_i_1 = Z_i ^ V_i
        if V_i % 2 == 0:
            V_i_1 = V_i >> 1
        else:
            V_i_1 = (V_i >> 1) ^ R
        Z_i = Z_i_1
        V_i = V_i_1
    return Z_i.to_bytes(16, 'big')

def GHASH(H, X):
    m = len(X) // 16
    X_blocks = [X[i*16:(i+1)*16] for i in range(m)]
    Y_0 = b'\x00' * 16
    Y_i_1 = Y_0
    for i in range(m):
        X_i = X_blocks[i]
        Y_i = MUL(xor_bytes_gcm(Y_i_1, X_i), H)
        Y_i_1 = Y_i
    return Y_i_1

def INC_32(Y_bytes):
    Y = int.from_bytes(Y_bytes, 'big')
    Y_inc = ((Y >> 32) << 32) ^ (((Y & 0xffffffff) + 1) & 0xffffffff)
    return Y_inc.to_bytes(16, 'big')

def GCTR(K, ICB, X):
    if not X:
        return b''
    n = math.ceil(len(X) / 16)
    X_blocks = [X[i*16:(i+1)*16] for i in range(n)]
    CB = [ICB]
    for i in range(1, n):
        CB_i = INC_32(CB[i-1])
        CB.append(CB_i)
    Y_blocks = []
    for i in range(n):
        X_i = X_blocks[i]
        CB_i = CB[i]
        Y_i = xor_bytes_gcm(X_i, aes_encryption(CB_i, K))
        Y_blocks.append(Y_i)
    Y = b''.join(Y_blocks)
    return Y[:len(X)]

def aes_gcm_encrypt(P, K, IV, A, t):
    H = aes_encryption(b'\x00' * 16, K)
    len_IV = len(IV) * 8
    if len_IV == 96:
        J_0 = IV + b'\x00\x00\x00\x01'
    else:
        s = 128 * math.ceil(len_IV / 128) - len_IV
        O_s_64 = b'\x00' * ((s + 64) // 8)
        len_IV_64 = int.to_bytes(len_IV, 8, 'big')
        J_0 = GHASH(H, IV + O_s_64 + len_IV_64)
    C = GCTR(K, INC_32(J_0), P)
    len_C, len_A = len(C) * 8, len(A) * 8
    u = 128 * math.ceil(len_C / 128) - len_C
    v = 128 * math.ceil(len_A / 128) - len_A
    O_v = b'\x00' * (v // 8)
    O_u = b'\x00' * (u // 8)
    len_A_64 = int.to_bytes(len_A, 8, 'big')
    len_C_64 = int.to_bytes(len_C, 8, 'big')
    S = GHASH(H, A + O_v + C + O_u + len_A_64 + len_C_64)
    T = GCTR(K, J_0, S)[:t // 8]
    return C, T

def aes_gcm_decrypt(C, K, IV, A, T):
    """Return (plaintext, valid) where valid is True if tag matches"""
    H = aes_encryption(b'\x00' * 16, K)
    len_IV = len(IV) * 8
    if len_IV == 96:
        J_0 = IV + b'\x00\x00\x00\x01'
    else:
        s = 128 * math.ceil(len_IV / 128) - len_IV
        O_s_64 = b'\x00' * ((s + 64) // 8)
        len_IV_64 = int.to_bytes(len_IV, 8, 'big')
        J_0 = GHASH(H, IV + O_s_64 + len_IV_64)
    P = GCTR(K, INC_32(J_0), C)
    len_C, len_A = len(C) * 8, len(A) * 8
    u = 128 * math.ceil(len_C / 128) - len_C
    v = 128 * math.ceil(len_A / 128) - len_A
    O_v = b'\x00' * (v // 8)
    O_u = b'\x00' * (u // 8)
    len_A_64 = int.to_bytes(len_A, 8, 'big')
    len_C_64 = int.to_bytes(len_C, 8, 'big')
    S = GHASH(H, A + O_v + C + O_u + len_A_64 + len_C_64)
    T_comp = GCTR(K, J_0, S)[:len(T)]
    return P, (T == T_comp)

# Optionally, add __all__ for exports
__all__ = [
    "aes_encryption",
    "aes_decryption",
    "aes_gcm_encrypt",
    "aes_gcm_decrypt"
]

