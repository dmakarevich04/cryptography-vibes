import os

def read_file_in_binary(filepath: str, block_size: int = 8) -> list[bytes]:
    with open(filepath, "rb") as f:
        data = f.read()
    blocks = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if len(block) < block_size:
            block = block.ljust(block_size, b'\x00')
        blocks.append(block)
    return blocks


def generate_keys() -> list[int]:
    key_bytes = os.urandom(32)
    return [int.from_bytes(key_bytes[i:i+4], "little") for i in range(0, 32, 4)]