from simple_replace import encrypt_block
from typing import List

def xor_blocks(block1: bytes, block2: bytes) -> bytes:
    length = min(len(block1), len(block2))
    return bytes(a ^ b for a, b in zip(block1[:length], block2[:length]))

def simple_replace_cfb_encrypt(data_blocks: List[bytes], keys: List[int], iv: bytes) -> List[bytes]:
    result = []
    shift_register = iv

    for block in data_blocks:
        gamma_full = encrypt_block(shift_register, keys)
        gamma = gamma_full[:len(block)]
        cipher_block = xor_blocks(block, gamma)
        result.append(cipher_block)
        if len(cipher_block) == 8:
            shift_register = cipher_block
        else:
            shift_register = cipher_block.ljust(8, b'\x00')

    return result

def simple_replace_cfb_decrypt(data_blocks: List[bytes], keys: List[int], iv: bytes) -> List[bytes]:
    result = []
    shift_register = iv

    for block in data_blocks:
        gamma_full = encrypt_block(shift_register, keys)
        gamma = gamma_full[:len(block)]

        plain_block = xor_blocks(block, gamma)
        result.append(plain_block)

        if len(block) == 8:
            shift_register = block
        else:
            shift_register = block.ljust(8, b'\x00')

    return result