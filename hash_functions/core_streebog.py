from contants import A, C, TAU, PI
from typing import Tuple


def add_512(a: bytes, b: bytes) -> bytes:
    result = bytearray(64)
    carry = 0
    for i in range(63, -1, -1):
        total = a[i] + b[i] + carry
        result[i] = total & 0xFF
        carry = total >> 8
    return bytes(result)


def transform_x(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def transform_s(data: bytes) -> bytes:
    return bytes(PI[b] for b in data)


def transform_p(data: bytes) -> bytes:
    return bytes(data[TAU[i]] for i in range(64))


def transform_l(data: bytes) -> bytes:
    u64s = []
    for i in range(0, 64, 8):
        chunk = data[i:i+8]
        val = int.from_bytes(chunk, 'big')
        u64s.append(val)

    buffers = [0] * 8
    for i in range(8):
        for j in range(64):
            if (u64s[i] >> j) & 1:
                buffers[i] ^= A[63 - j]

    out = bytearray()
    for val in buffers:
        out.extend(val.to_bytes(8, 'big'))
    return bytes(out)


def key_schedule(key: bytes, iter_index: int) -> bytes:
    key = transform_x(key, C[iter_index])
    key = transform_s(key)
    key = transform_p(key)
    key = transform_l(key)
    return key


def transform_e(key: bytes, block: bytes, state: bytes) -> Tuple[bytes, bytes]:
    state = transform_x(block, key)

    for i in range(12):
        state = transform_s(state)
        state = transform_p(state)
        state = transform_l(state)
        key = key_schedule(key, i)
        state = transform_x(state, key)

    return key, state


def transform_g(n: bytes, hash_val: bytes, message: bytes) -> bytes:
    key = transform_x(n, hash_val)
    key = transform_s(key)
    key = transform_p(key)
    key = transform_l(key)

    _, temp = transform_e(key, message, b'\x00' * 64)

    temp = transform_x(temp, hash_val)
    hash_val = transform_x(temp, message)
    return hash_val


def streebog_core(message: bytes, initial_hash: bytes) -> bytes:
    n = b'\x00' * 64
    sigma = b'\x00' * 64
    hash_val = initial_hash

    blocks = [message[i:i+64] for i in range(0, len(message), 64)]
    if len(blocks) == 0:
        blocks.append(b'')

    for block in blocks:
        block_bitlen = len(block) * 8
        block_size = b'\x00' * 62 + block_bitlen.to_bytes(2, 'big')

        if block == b'':
            padded = b'\x00' * (63 - len(block)) + b'\x01' + block
        elif len(block) == 64:
            padded = block
            padded = padded[::-1]
        else:
            padded = block + b'\x01' + b'\x00' * (63 - len(block))
            padded = padded[::-1]

        hash_val = transform_g(n, hash_val, padded)
        n = add_512(n, block_size)
        sigma = add_512(sigma, padded)

    hash_val = transform_g(b'\x00' * 64, hash_val, n)
    hash_val = transform_g(b'\x00' * 64, hash_val, sigma)

    return hash_val[::-1]


def streebog_512(message: bytes) -> bytes:
    initial_hash = b'\x00' * 64
    return streebog_core(message, initial_hash)


def streebog_256(message: bytes) -> bytes:
    initial_hash = b'\x01' * 64
    full_hash = streebog_core(message, initial_hash)
    return full_hash[32:]
