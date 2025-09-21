import os

def read_file_in_binary(filepath: str, block_size: int = 8) -> list[bytes]:
    # Читаем файл как текст в UTF-8
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    
    # Преобразуем в байты
    data = text.encode("utf-8")
    
    blocks = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if len(block) < block_size:
            block = block.ljust(block_size, b'\x00')
        blocks.append(block)
    
    return blocks



def generate_keys() -> list[int]: # 256-битный ключ K разбивается на восемь 32-битных подключей
    key_bytes = os.urandom(32)
    return [int.from_bytes(key_bytes[i:i+4], "little") for i in range(0, 32, 4)]