from core_streebog import streebog_256, streebog_512
from core_sha1 import sha1_hash

def bytes_to_hex(b: bytes) -> str:
    return ''.join(f'{byte:02x}' for byte in b)


def main():
    test_string = "abc"
    message = test_string.encode('utf-8')

    print(f"Входная строка: {test_string}")

    hash512 = streebog_512(message)
    hash256 = streebog_256(message)

    print(f"Streebog-512: {bytes_to_hex(hash512)}")
    print(f"Streebog-256: {bytes_to_hex(hash256)}")

    hash_sha1 = sha1_hash(message)

    print(f"SHA-1: {hash_sha1}")


if __name__ == "__main__":
    main()
