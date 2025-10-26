from keypair import generate_keys
from signature import sign_file, verify_file


def main():
    key_pair = generate_keys()
    file_path = "el-dig-sign-34-10/main.py"

    signature = sign_file(file_path, key_pair)
    print(f"Signature: {signature}")

    is_valid = verify_file(file_path, signature, key_pair)
    print(f"Signature valid: {is_valid}")


if __name__ == "__main__":
    main()
