import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import os

import utils
import simple_replace
import xor_mode
import xor_feedback_mode
import mac_encryption


class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Стандарт шифрования ГОСТ 28147-89")
        self.root.geometry("1200x750")

        self.filepath = None

        frame_top = tk.Frame(root)
        frame_top.pack(pady=10)

        self.btn_open = tk.Button(frame_top, text="Выбрать файл", command=self.choose_file)
        self.btn_open.pack(side=tk.LEFT, padx=5)

        self.lbl_file = tk.Label(frame_top, text="Файл не выбран", fg="gray")
        self.lbl_file.pack(side=tk.LEFT, padx=5)

        self.keys = utils.generate_keys()

        frame_modes = tk.LabelFrame(root, text="Выбор режима")
        frame_modes.pack(fill="x", padx=10, pady=10)

        tk.Button(frame_modes, text="Простая замена (ECB)", command=self.run_ecb).pack(fill="x", pady=2)
        tk.Button(frame_modes, text="Гаммирование (CTR)", command=self.run_ctr).pack(fill="x", pady=2)
        tk.Button(frame_modes, text="Гаммирование с обратной связью (CFB)", command=self.run_cfb).pack(fill="x", pady=2)
        tk.Button(frame_modes, text="С имитовставкой (MAC)", command=self.run_mac).pack(fill="x", pady=2)

        frame_table = tk.LabelFrame(root, text="Визуализация блоков")
        frame_table.pack(fill="both", expand=True, padx=10, pady=5)

        columns = ("#1", "#2", "#3", "#4", "#5")
        self.tree = ttk.Treeview(frame_table, columns=columns, show="headings", height=15)
        self.tree.heading("#1", text="№ блока")
        self.tree.heading("#2", text="Исходный (текст)")
        self.tree.heading("#3", text="Исходный (hex)")
        self.tree.heading("#4", text="Зашифрованный (hex)")
        self.tree.heading("#5", text="Расшифрованный (текст)")

        self.tree.column("#1", width=70, anchor="center")
        self.tree.column("#2", width=200)
        self.tree.column("#3", width=220)
        self.tree.column("#4", width=220)
        self.tree.column("#5", width=200)

        self.tree.pack(fill="both", expand=True)

        self.output = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas", 10), height=10)
        self.output.pack(expand=False, fill="both", padx=10, pady=10)

    def choose_file(self):
        filepath = filedialog.askopenfilename(title="Выберите файл")
        if filepath:
            self.filepath = filepath
            self.lbl_file.config(text=os.path.basename(filepath), fg="black")
            self.log(f"Выбран файл: {filepath}")

    def log(self, text):
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    def check_file(self):
        if not self.filepath:
            messagebox.showwarning("Ошибка", "Сначала выберите файл!")
            return False
        return True

    def clear_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

    def safe_text(self, b):
        return b.decode("utf-8", errors="replace")

    def run_ecb(self):
        if not self.check_file():
            return
        self.clear_table()

        blocks = utils.read_file_in_binary(self.filepath)
        encrypted = simple_replace.simple_replace_ecb_encrypt(blocks, self.keys)
        decrypted = simple_replace.simple_replace_ecb_decrypt(encrypted, self.keys)

        original_data = b"".join(blocks)
        decrypted_data = b"".join(decrypted)

        self.log("\n=== [ECB режим] ===")
        self.log("Исходный текст:\n" + original_data.decode("utf-8", errors="replace"))
        self.log("\nРасшифрованный текст:\n" + decrypted_data.decode("utf-8", errors="replace"))

        for i, (orig, enc, dec) in enumerate(zip(blocks, encrypted, decrypted), start=1):
            self.tree.insert("", "end", values=(
                i,
                self.safe_text(orig),
                orig.hex(),
                enc.hex(),
                self.safe_text(dec)
            ))

    def run_ctr(self):
        if not self.check_file():
            return
        self.clear_table()

        iv = os.urandom(8)
        blocks = utils.read_file_in_binary(self.filepath)
        encrypted = xor_mode.simple_replace_ctr(blocks, self.keys, iv)
        decrypted = xor_mode.simple_replace_ctr(encrypted, self.keys, iv)

        original_data = b"".join(blocks)
        decrypted_data = b"".join(decrypted)

        self.log("\n=== [CTR режим] ===")
        self.log("Исходный текст:\n" + original_data.decode("utf-8", errors="replace"))
        self.log("\nРасшифрованный текст:\n" + decrypted_data.decode("utf-8", errors="replace"))

        for i, (orig, enc, dec) in enumerate(zip(blocks, encrypted, decrypted), start=1):
            self.tree.insert("", "end", values=(
                i,
                self.safe_text(orig),
                orig.hex(),
                enc.hex(),
                self.safe_text(dec)
            ))

    def run_cfb(self):
        if not self.check_file():
            return
        self.clear_table()

        blocks = utils.read_file_in_binary(self.filepath)

        iv = os.urandom(8)
        encrypted = xor_feedback_mode.simple_replace_cfb_encrypt(blocks, self.keys, iv)
        decrypted = xor_feedback_mode.simple_replace_cfb_decrypt(encrypted, self.keys, iv)

        original_data = b"".join(blocks)
        decrypted_data = b"".join(decrypted)

        self.log("\n=== [CFB режим] ===")
        self.log("Исходный текст:\n" + original_data.decode("utf-8", errors="replace"))
        self.log("\nРасшифрованный текст:\n" + decrypted_data.decode("utf-8", errors="replace"))

        for i, (orig, enc, dec) in enumerate(zip(blocks, encrypted, decrypted), start=1):
            self.tree.insert("", "end", values=(
                i,
                self.safe_text(orig),
                orig.hex(),
                enc.hex(),
                self.safe_text(dec)
            ))


    def run_mac(self):
        if not self.check_file():
            return
        self.clear_table()

        with open(self.filepath, "rb") as f:
            original_data = f.read()

        encrypted_data, mac, iv = mac_encryption.simple_mac_encrypt(original_data, self.keys)
        decrypted_data, mac_valid = mac_encryption.simple_mac_decrypt(encrypted_data, self.keys, mac, iv)

        self.log("\n=== [Шифрование с MAC] ===")
        self.log(f"Исходные данные: {len(original_data)} байт")
        self.log(f"Зашифрованные данные: {len(encrypted_data)} байт")
        self.log(f"MAC: {mac.hex()}")
        self.log(f"IV: {iv.hex()}")
        self.log(f"Проверка MAC: {'УСПЕШНО' if mac_valid else 'ОШИБКА'}")

        self.log("\nИсходный текст:\n" + original_data.decode("utf-8", errors="replace"))
        self.log("\nРасшифрованный текст:\n" + decrypted_data.decode("utf-8", errors="replace"))

        self.tree.insert("", "end", values=(
            1, "—", "—", "Данные зашифрованы (MAC)", "MAC проверен"
        ))


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
