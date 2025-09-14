import os
from simple_replace import encrypt_block

def xor_blocks(block1: bytes, block2: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(block1, block2))


def simple_replace_ctr(data_blocks: list[bytes], keys: list[int], iv: bytes) -> list[bytes]:
    result = []
    counter = int.from_bytes(iv, "little")

    for block in data_blocks:
        counter_bytes = counter.to_bytes(8, "little")
        gamma = encrypt_block(counter_bytes, keys)
        result.append(xor_blocks(block, gamma))
        counter = (counter + 1) % (1 << 64)

    return result
