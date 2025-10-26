import tkinter as tk
from tkinter import filedialog, scrolledtext
import binascii
import random
from stb_cipher import STB

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Crypto STB GUI")
        self.root.geometry("800x600")

        self.mode_var = tk.StringVar(value="block")
        self.file_content = ""

        tk.Button(root, text="Выбрать файл", command=self.open_file).pack(pady=5)
        tk.Button(root, text="Зашифровать", command=self.encrypt_file).pack(pady=5)

        tk.Radiobutton(root, text="Block", variable=self.mode_var, value="block").pack(anchor="w")
        tk.Radiobutton(root, text="CFB", variable=self.mode_var, value="CFB").pack(anchor="w")

        self.text_output = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=80)
        self.text_output.pack(padx=10, pady=10)

    def open_file(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return

        with open(filepath, "r", encoding="utf-8") as f:
            self.file_content = f.read()

        self.text_output.delete("1.0", tk.END)
        self.text_output.insert(tk.END, f"Файл загружен. Нажмите 'Зашифровать'.\n")

    def encrypt_file(self):
        if not self.file_content:
            self.text_output.insert(tk.END, "Сначала выберите файл!\n")
            return

        text = self.file_content
        data = text.encode("utf-8")
        pad_len = (16 - len(data) % 16) % 16
        data += b"\x00" * pad_len

        random_bytes = bytes([random.randint(0, 255) for _ in range(32)]) #32 байта (256 бит) ключ
        key = list(random_bytes)
        stb = STB(key)

        blocks = [list(data[i:i+16]) for i in range(0, len(data), 16)] #16 байтов (128 бит) блоки
        mode = self.mode_var.get()

        if mode == "block":
            encrypted_blocks = [stb.encryption(block) for block in blocks]
            decrypted_blocks = [stb.decryption(block) for block in encrypted_blocks]
        else:  
            encrypted_blocks = stb.CFB_encrypt(blocks[:])
            decrypted_blocks = stb.CFB_decrypt(encrypted_blocks[:])

        encrypted_result = [b for block in encrypted_blocks for b in block]
        cipher_bytes = bytes([i & 0xFF for i in encrypted_result])
        cipher_hex = binascii.hexlify(cipher_bytes).decode()

        decrypted_bytes = bytes([b for block in decrypted_blocks for b in block])
        decrypted_text = decrypted_bytes.rstrip(b"\x00").decode("utf-8")

        self.text_output.delete("1.0", tk.END)
        self.text_output.insert(tk.END, f"Режим: {mode}\n\n")
        self.text_output.insert(tk.END, f"Исходный текст:\n{text}\n\n")
        self.text_output.insert(tk.END, f"Зашифрованный текст (hex):\n{cipher_hex}\n\n")
        self.text_output.insert(tk.END, f"Расшифрованный текст:\n{decrypted_text}\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
