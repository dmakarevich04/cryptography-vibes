import tkinter as tk
from tkinter import ttk, messagebox
from elgamal import ElGamal
from constants import a, b, x, y, p, q
from elliptic_curve_utils import EllipticCurve


class ElGamalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ElGamal Elliptic Curve Encryption")
        self.root.geometry("800x800")
        self.root.configure(bg="#f7f7f7")

        self.curve = EllipticCurve(a, b, p, q, x, y)
        self.elgamal = ElGamal(self.curve)

        self.private_key = None
        self.public_key = None
        self.encrypted_message = None
        self.decrypted_message = None

        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TFrame", background="#f7f7f7")
        style.configure("TLabel", background="#f7f7f7",
                        foreground="#222", font=("Segoe UI", 11))
        style.configure("TButton", background="#e0e0e0", foreground="#000",
                        font=("Segoe UI", 10, "bold"), padding=6, relief="flat")
        style.map("TButton", background=[
                  ("active", "#613c9b")], foreground=[("active", "#ffffff")])

        ttk.Label(root, text="ElGamal Elliptic Curve Encryption",
                  font=("Segoe UI", 16, "bold"), foreground="#613c9b").pack(pady=10)

        keys_frame = ttk.Frame(root)
        keys_frame.pack(fill="x", padx=20, pady=10)

        ttk.Label(keys_frame, text="Генерация ключей", font=(
            "Segoe UI", 13, "bold")).pack(anchor="w", pady=(0, 5))
        ttk.Button(keys_frame, text="Сгенерировать ключи",
                   command=self.generate_keys).pack(anchor="w", pady=5)

        self.keys_text = tk.Text(keys_frame, width=85, height=6, bg="#ffffff", fg="#222",
                                 font=("Consolas", 10), relief="solid", wrap="word", bd=1)
        self.keys_text.pack(pady=5)
        self.keys_text.config(state=tk.DISABLED)

        msg_frame = ttk.Frame(root)
        msg_frame.pack(fill="x", padx=20, pady=10)

        ttk.Label(msg_frame, text="Ввод сообщения", font=(
            "Segoe UI", 13, "bold")).pack(anchor="w", pady=(0, 5))
        self.message_entry = ttk.Entry(
            msg_frame, width=80, font=("Segoe UI", 11))
        self.message_entry.pack(pady=5, ipady=4)
        ttk.Button(msg_frame, text="Зашифровать",
                   command=self.encrypt_message).pack(anchor="w", pady=5)

        enc_frame = ttk.Frame(root)
        enc_frame.pack(fill="x", padx=20, pady=10)

        ttk.Label(enc_frame, text="Зашифрованное сообщение", font=(
            "Segoe UI", 13, "bold")).pack(anchor="w", pady=(0, 5))
        self.encrypted_text = tk.Text(enc_frame, width=85, height=6, bg="#ffffff", fg="#222",
                                      font=("Consolas", 10), relief="solid", wrap="word", bd=1)
        self.encrypted_text.pack(pady=5)
        self.encrypted_text.config(state=tk.DISABLED)

        ttk.Button(enc_frame, text="Расшифровать",
                   command=self.decrypt_message).pack(anchor="w", pady=5)

        dec_frame = ttk.Frame(root)
        dec_frame.pack(fill="both", padx=20, pady=10, expand=True)

        ttk.Label(dec_frame, text="Расшифрованное сообщение", font=(
            "Segoe UI", 13, "bold")).pack(anchor="w", pady=(0, 5))
        self.decrypted_text = tk.Text(dec_frame, width=85, height=10, bg="#ffffff", fg="#222",
                                      font=("Consolas", 10), relief="solid", wrap="word", bd=1)
        self.decrypted_text.pack(pady=5)
        self.decrypted_text.config(state=tk.DISABLED)

    def generate_keys(self):
        try:
            self.private_key, self.public_key = self.elgamal.generate_keys()

            self.keys_text.config(state=tk.NORMAL)
            self.keys_text.delete("1.0", tk.END)
            self.keys_text.insert(
                tk.END, f"Открытый ключ:\n{self.public_key}\n")
            self.keys_text.insert(
                tk.END, f"Закрытый ключ:\n{self.private_key}")
            self.keys_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def encrypt_message(self):
        message = self.message_entry.get()
        if not message:
            messagebox.showerror("Ошибка", "Введите сообщение для шифрования.")
            return
        if not self.public_key:
            messagebox.showerror("Ошибка", "Сначала сгенерируйте ключи.")
            return
        try:
            self.encrypted_message = self.elgamal.encrypt(
                message, self.public_key, block_size=8)

            self.encrypted_text.config(state=tk.NORMAL)
            self.encrypted_text.delete("1.0", tk.END)

            for idx, (C1, C2) in enumerate(self.encrypted_message, 1):
                self.encrypted_text.insert(
                    tk.END, f"Блок {idx}:\nC1 = {C1}\nC2 = {C2}\n\n"
                )

            self.encrypted_text.config(state=tk.DISABLED)
            
            self.decrypted_text.config(state=tk.NORMAL)
            self.decrypted_text.delete("1.0", tk.END)
            self.decrypted_text.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("Ошибка", str(e))


    def decrypt_message(self):
        if not self.private_key:
            messagebox.showerror("Ошибка", "Сначала сгенерируйте ключи.")
            return
        if not self.encrypted_message:
            messagebox.showerror(
                "Ошибка", "Нет зашифрованного текста для расшифровки.")
            return
        try:
            self.decrypted_message = self.elgamal.decrypt(
                self.encrypted_message, self.private_key)

            self.decrypted_text.config(state=tk.NORMAL)
            self.decrypted_text.delete("1.0", tk.END)
            self.decrypted_text.insert(tk.END, self.decrypted_message)
            self.decrypted_text.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("Ошибка", str(e))



if __name__ == "__main__":
    root = tk.Tk()
    app = ElGamalApp(root)
    root.mainloop()
