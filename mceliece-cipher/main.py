import os
import tkinter as tk
from tkinter import filedialog, scrolledtext
from mceliece_core import (
    generate_keypair,
    encrypt_bytes,
    decrypt_bytes,
    save_key_public,
    save_key_private,
    load_key,
)
import binascii


class McElieceGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("McEliece Encryption")
        self.root.geometry("850x650")
        self.root.configure(bg="#f5f5f5")

        self.pubkey = None
        self.privkey = None

        self.bg_color = "#f5f5f5"
        self.text_color = "#2e2e2e"
        self.btn_color = "#166337"   
        self.btn_hover = "#104928"     
        self.btn_fg = "#ffffff"
        self.success_color = "#007a33"
        self.error_color = "#b00020"
        self.font_main = ("Segoe UI", 10)
        self.font_bold = ("Segoe UI Semibold", 12)
        self.font_title = ("Segoe UI Semibold", 12)

        self.status_label = tk.Label(
            root,
            text="Выберите действие:",
            wraplength=700,
            justify="center",
            fg=self.text_color,
            bg=self.bg_color,
            font=self.font_title,
        )
        self.status_label.pack(pady=10)

        btn_frame = tk.Frame(root, bg=self.bg_color)
        btn_frame.pack(pady=10)

        buttons = [
            ("Сгенерировать ключи", self.generate_keys),
            ("Сохранить ключи", self.save_keys),
            ("Загрузить ключи", self.load_keys),
            ("Зашифровать файл", self.encrypt_file),
            ("Расшифровать файл", self.decrypt_file),
            ("Очистить результат", self.clear_result),
        ]

        for text, command in buttons:
            b = tk.Button(
                btn_frame,
                text=text,
                font=self.font_bold,
                bg=self.btn_color,
                fg=self.btn_fg,
                activebackground=self.btn_hover,
                activeforeground="white",
                relief="flat",
                width=25,
                height=1,
                bd=0,
                command=command,
                cursor="hand2",
                padx=10,
                pady=8,
            )
            b.pack(pady=6, ipadx=4, ipady=4)

        text_frame = tk.Frame(root, bg=self.bg_color)
        text_frame.pack(pady=10, fill="both", expand=True)

        self.result_text = scrolledtext.ScrolledText(
            text_frame,
            width=95,
            height=18,
            font=("Consolas", 10),
            bg="#ffffff",
            fg="#222222",
            relief="flat",
            wrap="word",
            padx=10,
            pady=10,
        )
        self.result_text.pack(padx=15, pady=5, fill="both", expand=True)

    def update_status(self, message, color="#2e2e2e"):
        self.status_label.config(text=message, fg=color)

    def clear_result(self):
        self.result_text.delete("1.0", tk.END)

    def generate_keys(self):
        n, k, t = 31, 21, 1
        self.update_status("Генерация ключей...", "#444")
        self.root.update()
        self.pubkey, self.privkey = generate_keypair(n, k, t)
        self.update_status(f"Ключи сгенерированы (n={n}, k={k}, t={t})", self.success_color)

    def save_keys(self):
        if not self.pubkey or not self.privkey:
            self.update_status("Сначала сгенерируйте ключи", self.error_color)
            return
        pub_file = filedialog.asksaveasfilename(title="Сохранить публичный ключ", defaultextension=".pub")
        priv_file = filedialog.asksaveasfilename(title="Сохранить приватный ключ", defaultextension=".priv")
        if pub_file and priv_file:
            save_key_public(self.pubkey, pub_file)
            save_key_private(self.privkey, priv_file)
            self.update_status(f"Ключи сохранены:\nПубличный: {pub_file}\nПриватный: {priv_file}", self.success_color)

    def load_keys(self):
        pub_file = filedialog.askopenfilename(title="Выбрать публичный ключ")
        priv_file = filedialog.askopenfilename(title="Выбрать приватный ключ")
        if pub_file and priv_file:
            self.pubkey = load_key(pub_file)
            self.privkey = load_key(priv_file)
            self.update_status(f"Ключи загружены:\nПубличный: {pub_file}\nПриватный: {priv_file}", self.success_color)

    def encrypt_file(self):
        if not self.pubkey:
            self.update_status("Сначала загрузите или сгенерируйте ключи", self.error_color)
            return
        infile = filedialog.askopenfilename(
            title="Выбрать файл для шифрования")
        if not infile:
            self.update_status("Файл для шифрования не выбран", self.error_color)
            return

        self.update_status(f"Шифрование файла {infile} ...", "#444")
        self.root.update()
        with open(infile, "rb") as f:
            data = f.read()
        ciphertext = encrypt_bytes(data, self.pubkey)
        hex_cipher = binascii.hexlify(ciphertext).decode("ascii")

        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, hex_cipher)

        outfile = infile + ".enc"
        with open(outfile, "wb") as f:
            f.write(ciphertext)

        self.update_status(f"Файл зашифрован. Результат показан в окне и сохранён как {outfile}",
            self.success_color,
        )

    def decrypt_file(self):
        if not self.privkey:
            self.update_status("Сначала загрузите или сгенерируйте ключи", self.error_color)
            return
        infile = filedialog.askopenfilename(
            title="Выбрать файл для расшифровки")
        if not infile:
            self.update_status("Файл для расшифровки не выбран", self.error_color)
            return

        self.update_status(f"Расшифровка файла {infile} ...", "#444")
        self.root.update()
        with open(infile, "rb") as f:
            ciphertext = f.read()
        try:
            plaintext = decrypt_bytes(ciphertext, self.privkey)
            try:
                text = plaintext.decode("utf-8")
            except UnicodeDecodeError:
                text = repr(plaintext)
        except Exception as e:
            self.update_status(f"Не удалось расшифровать файл: {e}", self.error_color)
            return

        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, text)

        base, ext = os.path.splitext(infile)
        outfile = base + ".dec.txt" if ext == ".enc" else infile + ".dec"
        with open(outfile, "wb") as f:
            f.write(plaintext)

        self.update_status(f"Файл расшифрован. Результат показан в окне и сохранён как {outfile}", self.success_color,)


if __name__ == "__main__":
    root = tk.Tk()
    app = McElieceGUI(root)
    root.mainloop()
