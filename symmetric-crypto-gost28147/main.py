import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import os

import utils
import simple_replace


class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ГОСТ 28147-89 (ECB)")
        self.root.geometry("900x600")

        self.filepath = None
        self.encrypted_data = None  

        frame_top = tk.Frame(root)
        frame_top.pack(pady=10)

        self.btn_open = tk.Button(frame_top, text="Выбрать файл", command=self.choose_file)
        self.btn_open.pack(side=tk.LEFT, padx=5)

        self.lbl_file = tk.Label(frame_top, text="Файл не выбран", fg="gray")
        self.lbl_file.pack(side=tk.LEFT, padx=5)

        self.keys = utils.generate_keys()

        frame_modes = tk.LabelFrame(root, text="Действие")
        frame_modes.pack(fill="x", padx=10, pady=10)

        tk.Button(frame_modes, text="Зашифровать (ECB)", command=self.run_ecb).pack(fill="x", pady=5)

        self.output = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas", 10), height=30)
        self.output.pack(expand=True, fill="both", padx=10, pady=10)

    def choose_file(self):
        filepath = filedialog.askopenfilename(title="Выберите файл")
        if filepath:
            self.filepath = filepath
            self.lbl_file.config(text=os.path.basename(filepath), fg="black")
            self.log(f"Выбран файл: {filepath}")

    def log(self, text):
        self.output.insert(tk.END, text + "\n\n")
        self.output.see(tk.END)

    def safe_text(self, b: bytes) -> str:
        return b.rstrip(b'\x00').decode("utf-8", errors="ignore")

    def run_ecb(self):
        if not self.filepath:
            messagebox.showwarning("Ошибка", "Сначала выберите файл!")
            return

        try:
            blocks = utils.read_file_in_binary(self.filepath)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось прочитать файл: {e}")
            return

        encrypted = simple_replace.simple_replace_ecb_encrypt(blocks, self.keys)
        decrypted = simple_replace.simple_replace_ecb_decrypt(encrypted, self.keys)

        original_data = b"".join(blocks)
        self.encrypted_data = b"".join(encrypted)
        decrypted_data = b"".join(decrypted)

        self.log("=== [ECB режим] ===")
        self.log(f"Исходный текст:\n{original_data.decode('utf-8', errors='ignore')}")
        self.log(f"\n\nЗашифрованный текст (hex):\n{self.encrypted_data.hex()}")
        self.log(f"Расшифрованный текст:\n{decrypted_data.decode('utf-8', errors='ignore')}")


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
