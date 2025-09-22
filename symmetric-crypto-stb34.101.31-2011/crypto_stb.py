# crypto_stb.py
BLOCK_SIZE = 16
RED_POLY = 0xC3

SBOX = [
    252,238,221,17,207,110,49,22,251,196,250,218,35,197,4,77,
    233,119,240,219,147,46,153,186,23,54,241,187,20,205,95,193,
    249,24,101,90,226,92,239,33,129,28,60,66,139,1,142,79,
    5,132,2,174,227,106,143,160,6,11,237,152,127,212,211,31,
    235,52,44,81,234,200,72,171,242,42,104,162,253,58,206,204,
    181,112,14,86,8,12,118,18,191,114,19,71,156,183,93,135,
    21,161,150,41,16,123,154,199,243,145,120,111,157,158,178,177,
    50,117,25,61,255,53,138,126,109,84,198,128,195,189,13,87,
    223,245,36,169,62,168,67,201,215,121,214,246,124,34,185,3,
    224,15,236,222,122,148,176,188,220,232,40,80,78,51,10,74,
    167,151,96,115,30,0,98,68,26,184,56,130,100,159,38,65,
    173,69,70,146,39,94,85,47,140,163,165,125,105,213,149,59,
    7,88,179,64,134,172,29,247,48,55,107,228,136,217,231,137,
    225,27,131,73,76,63,248,254,141,83,170,144,202,216,133,97,
    32,113,103,164,45,43,9,91,203,155,37,208,190,229,108,82,
    89,166,116,210,230,244,180,192,209,102,175,194,57,75,99,182
]

INV_SBOX = [0]*256
for i,v in enumerate(SBOX):
    INV_SBOX[v] = i

L_VEC = [148, 32, 133, 16, 194, 192, 1, 251,
         1, 192, 194, 16, 133, 32, 148, 1]

# --- Основные функции ---
def gf_mul(a: int, b: int) -> int:
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        hi = a & 0x80
        a <<= 1
        if hi:
            a ^= RED_POLY
        a &= 0xFF
        b >>= 1
    return res

def sub_bytes(block: bytes) -> bytes:
    return bytes(SBOX[b] for b in block)

def inv_sub_bytes(block: bytes) -> bytes:
    return bytes(INV_SBOX[b] for b in block)

def R_transform(state: bytes) -> bytes:
    x = 0
    for i in range(15):
        x ^= gf_mul(state[i], L_VEC[i])
    x ^= gf_mul(state[15], L_VEC[15])
    return bytes([x]) + state[:15]

def R_inv_transform(state: bytes) -> bytes:
    b0 = state[0]
    rest = state[1:]
    last = 0
    for i in range(15):
        last ^= gf_mul(rest[i], L_VEC[i])
    last ^= gf_mul(b0, L_VEC[15])
    return rest + bytes([last & 0xFF])

def L_transform(block: bytes) -> bytes:
    s = block
    for _ in range(16):
        s = R_transform(s)
    return s

def L_inv_transform(block: bytes) -> bytes:
    s = block
    for _ in range(16):
        s = R_inv_transform(s)
    return s

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def generate_round_consts():
    consts = []
    for i in range(1, 33):
        c = bytes([0]*15 + [i & 0xFF])
        consts.append(L_transform(c))
    return consts

def key_schedule(master_key: bytes):
    assert len(master_key) == 32
    k1 = master_key[:16]
    k2 = master_key[16:]
    round_keys = [k1, k2]
    consts = generate_round_consts()
    for i in range(32):
        a = xor_bytes(k1, consts[i])
        a = sub_bytes(a)
        a = L_transform(a)
        new_k1 = xor_bytes(a, k2)
        k2, k1 = k1, new_k1
        if (i+1) % 8 == 0:
            round_keys.append(k1)
            round_keys.append(k2)
            if len(round_keys) >= 10:
                break
    return round_keys[:10]

# --- Работа с блоками ---
def encrypt_block(block16: bytes, round_keys):
    state = block16
    for i in range(9):
        state = xor_bytes(state, round_keys[i])
        state = sub_bytes(state)
        state = L_transform(state)
    state = xor_bytes(state, round_keys[9])
    return state

def decrypt_block(block16: bytes, round_keys):
    state = block16
    state = xor_bytes(state, round_keys[9])
    for i in range(8, -1, -1):
        state = L_inv_transform(state)
        state = inv_sub_bytes(state)
        state = xor_bytes(state, round_keys[i])
    return state

# --- Padding ---
def pad_pkcs7(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len])*pad_len

def unpad_pkcs7(data: bytes) -> bytes:
    pad = data[-1]
    if pad < 1 or pad > BLOCK_SIZE:
        raise ValueError("Bad padding")
    return data[:-pad]

# --- Режимы ---
def encrypt_ecb(plaintext: bytes, round_keys):
    data = pad_pkcs7(plaintext)
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        out.extend(encrypt_block(data[i:i+BLOCK_SIZE], round_keys))
    return bytes(out)

def decrypt_ecb(ciphertext: bytes, round_keys):
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        out.extend(decrypt_block(ciphertext[i:i+BLOCK_SIZE], round_keys))
    return unpad_pkcs7(bytes(out))

def encrypt_cfb(plaintext: bytes, round_keys, iv: bytes):
    out = bytearray()
    prev = iv
    for i in range(0, len(plaintext), BLOCK_SIZE):
        blk = plaintext[i:i+BLOCK_SIZE]
        gamma = encrypt_block(prev, round_keys)
        cipher_blk = bytes(a ^ b for a,b in zip(blk, gamma[:len(blk)]))
        out.extend(cipher_blk)
        prev = cipher_blk.ljust(16, b'\x00')
    return bytes(out)

def decrypt_cfb(ciphertext: bytes, round_keys, iv: bytes):
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        blk = ciphertext[i:i+BLOCK_SIZE]
        gamma = encrypt_block(prev, round_keys)
        plain_blk = bytes(a ^ b for a,b in zip(blk, gamma[:len(blk)]))
        out.extend(plain_blk)
        prev = blk.ljust(16, b'\x00')
    return bytes(out)
