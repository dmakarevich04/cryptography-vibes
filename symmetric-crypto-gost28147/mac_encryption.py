import os
from simple_replace import encrypt_block
from typing import List, Tuple

def xor_blocks(block1: bytes, block2: bytes) -> bytes:
    length = min(len(block1), len(block2))
    return bytes(a ^ b for a, b in zip(block1[:length], block2[:length]))

def encrypt_with_mac(data_blocks: List[bytes], keys: List[int], iv: bytes = None) -> Tuple[List[bytes], bytes]:
    if iv is None:
        iv = os.urandom(8)
    
    encrypted_blocks = []
    mac_register = iv
    cipher_register = iv
    
    for i, block in enumerate(data_blocks):
        gamma = encrypt_block(cipher_register, keys)
        cipher_block = xor_blocks(block, gamma[:len(block)])
        encrypted_blocks.append(cipher_block)
        
        if len(cipher_block) == 8:
            cipher_register = cipher_block
        else:
            cipher_register = cipher_block.ljust(8, b'\x00')

        mac_input = xor_blocks(cipher_block, mac_register)
        mac_register = encrypt_block(mac_input.ljust(8, b'\x00'), keys)
    
    mac = mac_register[:4]
    
    return encrypted_blocks, mac

def decrypt_with_mac(encrypted_blocks: List[bytes], keys: List[int], iv: bytes, expected_mac: bytes = None) -> Tuple[List[bytes], bool]:
    decrypted_blocks = []
    mac_register = iv
    cipher_register = iv
    mac_valid = True
    
    for cipher_block in encrypted_blocks:
        gamma = encrypt_block(cipher_register, keys)
        plain_block = xor_blocks(cipher_block, gamma[:len(cipher_block)])
        decrypted_blocks.append(plain_block)
        if len(cipher_block) == 8:
            cipher_register = cipher_block
        else:
            cipher_register = cipher_block.ljust(8, b'\x00')

        mac_input = xor_blocks(cipher_block, mac_register)
        mac_register = encrypt_block(mac_input.ljust(8, b'\x00'), keys)

    actual_mac = mac_register[:4]
    if expected_mac is not None:
        mac_valid = (actual_mac == expected_mac)
    
    return decrypted_blocks, mac_valid

def simple_mac_encrypt(data: bytes, keys: List[int]) -> Tuple[bytes, bytes, bytes]:
    iv = os.urandom(8)

    blocks = []
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        blocks.append(block)
    
    encrypted_blocks, mac = encrypt_with_mac(blocks, keys, iv)
    encrypted_data = b"".join(encrypted_blocks)
    
    return encrypted_data, mac, iv

def simple_mac_decrypt(encrypted_data: bytes, keys: List[int], mac: bytes, iv: bytes) -> Tuple[bytes, bool]:
    encrypted_blocks = []
    for i in range(0, len(encrypted_data), 8):
        block = encrypted_data[i:i+8]
        encrypted_blocks.append(block)
    
    decrypted_blocks, mac_valid = decrypt_with_mac(encrypted_blocks, keys, iv, mac)
    decrypted_data = b"".join(decrypted_blocks)
    
    return decrypted_data, mac_valid