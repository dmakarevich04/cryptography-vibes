import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from main import generate_key, encrypt_text, decrypt_text


class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Crypto Lab2 (tkinter)")
        self.root.geometry("800x600")

        self.open_key, self.close_key = generate_key()
        while self.close_key[0] == self.close_key[1]:
            self.open_key, self.close_key = generate_key()

        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=10)

        self.choose_btn = tk.Button(btn_frame, text="Выбрать файл", command=self.choose_file)
        self.choose_btn.pack(side=tk.LEFT, padx=10)

        self.encrypt_btn = tk.Button(btn_frame, text="Зашифровать", command=self.encrypt_text)
        self.encrypt_btn.pack(side=tk.LEFT, padx=10)

        self.decrypt_btn = tk.Button(btn_frame, text="Расшифровать", command=self.decrypt_text)
        self.decrypt_btn.pack(side=tk.LEFT, padx=10)

        self.original_label = tk.Label(root, text="Исходный текст:")
        self.original_label.pack(anchor="w", padx=10)
        self.original_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=8)
        self.original_text.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        self.encrypted_label = tk.Label(root, text="Зашифрованный текст:")
        self.encrypted_label.pack(anchor="w", padx=10)
        self.encrypted_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=8)
        self.encrypted_text.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        self.decrypted_label = tk.Label(root, text="Расшифрованный текст:")
        self.decrypted_label.pack(anchor="w", padx=10)
        self.decrypted_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=8)
        self.decrypted_text.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

    def choose_file(self):
        path = filedialog.askopenfilename(title="Выберите файл")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
            self.original_text.delete("1.0", tk.END)
            self.original_text.insert(tk.END, text)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось открыть файл:\n{e}")

    def encrypt_text(self):
        text = self.original_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Ошибка", "Нет текста для шифрования!")
            return
        encrypted_result = encrypt_text(text, self.open_key)
        self.encrypted_text.delete("1.0", tk.END)
        self.encrypted_text.insert(tk.END, encrypted_result)

    def decrypt_text(self):
        encrypted_data = self.encrypted_text.get("1.0", tk.END).strip()
        if not encrypted_data:
            messagebox.showwarning("Ошибка", "Нет текста для дешифрования!")
            return
        decrypted_result = decrypt_text(encrypted_data, self.open_key, self.close_key) 
        self.decrypted_text.delete("1.0", tk.END)
        self.decrypted_text.insert(tk.END, decrypted_result)


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
