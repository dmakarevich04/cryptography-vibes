import os

def read_file_in_binary(filepath: str, block_size: int = 8) -> list[bytes]:
    with open(filepath, "r", errors="replace") as f:
        text = f.read()
    
    data = text.encode("utf-8")
    blocks = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if len(block) < block_size:
            block = block.ljust(block_size, b'\x00')
        blocks.append(block)
    
    return blocks



def generate_keys() -> list[int]: 
    key_bytes = os.urandom(32) #256битный ключ
    return [int.from_bytes(key_bytes[i:i+4], "little") for i in range(8)] #на 8 ключей по 32бит