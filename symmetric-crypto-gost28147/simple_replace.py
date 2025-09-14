# Режим простой замены (ECB - Electronic Codebook)

TABLE = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12]
]

def _substitute(value: int) -> int:
    out = 0
    for i in range(8):
        nibble = (value >> (4 * i)) & 0xF
        out |= TABLE[i][nibble] << (4 * i)
    return out

def _round(L: int, R: int, key: int) -> tuple[int, int]:
    temp = (R + key) % (2**32)
    temp = _substitute(temp)
    temp = ((temp << 11) & 0xFFFFFFFF) | (temp >> (32 - 11))
    return R, L ^ temp

def encrypt_block(block: bytes, keys: list[int]) -> bytes:
    n1 = int.from_bytes(block[:4], "little")
    n2 = int.from_bytes(block[4:], "little")

    for i in range(24):
        n1, n2 = _round(n1, n2, keys[i % 8])
    for i in range(8):
        n1, n2 = _round(n1, n2, keys[7 - i])

    return n2.to_bytes(4, "little") + n1.to_bytes(4, "little")

def decrypt_block(block: bytes, keys: list[int]) -> bytes:
    n1 = int.from_bytes(block[:4], "little")
    n2 = int.from_bytes(block[4:], "little")

    for i in range(8):
        n1, n2 = _round(n1, n2, keys[i])
    for i in range(24):
        n1, n2 = _round(n1, n2, keys[(7 - i) % 8])

    return n2.to_bytes(4, "little") + n1.to_bytes(4, "little")

def simple_replace_ecb_encrypt(blocks: list[bytes], keys: list[int]) -> list[bytes]:
    return [encrypt_block(b, keys) for b in blocks]

def simple_replace_ecb_decrypt(blocks: list[bytes], keys: list[int]) -> list[bytes]:
    return [decrypt_block(b, keys) for b in blocks]


