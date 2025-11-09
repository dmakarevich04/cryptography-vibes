import tkinter as tk
from tkinter import filedialog, messagebox
import os

from keypair import generate_keys
from signature import sign_file, verify_file

class SignerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("GOST 34.10 Signer")
        self.geometry("800x500")
        self.resizable(False, False)

        self.keypair = None
        self.signature = None
        self.file_path = ""

        self._create_widgets()

    def _create_widgets(self):
        pad = 8

        frm_file = tk.Frame(self)
        frm_file.pack(fill="x", padx=pad, pady=(pad, 0))

        tk.Label(frm_file, text="Файл:").pack(side="left")
        self.ent_file = tk.Entry(frm_file)
        self.ent_file.pack(side="left", fill="x", expand=True, padx=6)
        tk.Button(frm_file, text="Выбрать...", command=self.choose_file).pack(side="right")

        frm_keys = tk.Frame(self)
        frm_keys.pack(fill="x", padx=pad, pady=(6, 0))

        tk.Button(frm_keys, text="Сгенерировать ключи", command=self.generate_keys).pack(side="left")

        self.lbl_pub = tk.Label(
            frm_keys, text="(Открытый ключ: — )", anchor="w", justify="left", wraplength=550)
        self.lbl_pub.pack(side="left", padx=10)

        frm_actions = tk.Frame(self)
        frm_actions.pack(fill="x", padx=pad, pady=(10, 0))

        tk.Button(frm_actions, text="Подписать файл", command=self.sign_current_file).pack(side="left")
        tk.Button(frm_actions, text="Проверить подпись", command=self.verify_current_file).pack(side="left", padx=6)

        frm_sig = tk.Frame(self)
        frm_sig.pack(fill="x", padx=pad, pady=(10, 0))
        tk.Label(frm_sig, text="Подпись (r:s в hex):").pack(anchor="w")
        self.txt_sig = tk.Text(frm_sig, height=3)
        self.txt_sig.pack(fill="x", expand=True)

        frm_status = tk.Frame(self)
        frm_status.pack(fill="x", padx=pad, pady=(10, 0))
        tk.Label(frm_status, text="Статус:").pack(side="left")
        self.lbl_status = tk.Label(frm_status, text="Готово к работе", anchor="w")
        self.lbl_status.pack(side="left", padx=6, pady=10)

    def choose_file(self):
        path = filedialog.askopenfilename(
            title="Выберите файл для подписи/проверки")
        if path:
            self.file_path = path
            self.ent_file.delete(0, tk.END)
            self.ent_file.insert(0, path)
            self.set_status(f"Файл выбран: {os.path.basename(path)}")

    def generate_keys(self):
        if generate_keys is None:
            self.set_status("Ошибка: модуль generate_keys не найден")
            return
        try:
            self.keypair = generate_keys()
            self.set_status("Ключи успешно сгенерированы")
            self.show_public_key()
        except Exception as e:
            self.set_status(f"Ошибка генерации ключей: {e}")

    def show_public_key(self):
        if not self.keypair:
            self.set_status("Ключи не сгенерированы")
            return
        Q = getattr(self.keypair, "Q", None)
        if Q is None:
            self.set_status("У keypair нет атрибута Q (открытый ключ)")
            return
        qx = getattr(Q, "x", None)
        qy = getattr(Q, "y", None)
        if qx is not None and qy is not None:
            txt = f"Открытый ключ:\nQx = {hex(qx)}\nQy = {hex(qy)}"
        else:
            txt = str(Q)
        self.lbl_pub.config(text=txt)

    def sign_current_file(self):
        if sign_file is None:
            self.set_status("Ошибка: модуль sign_file не найден")
            return
        path = self.ent_file.get().strip()
        if not path or not os.path.isfile(path):
            self.set_status("Выберите существующий файл")
            return
        if not self.keypair:
            self.set_status("Сначала сгенерируйте ключи")
            return

        try:
            sig = sign_file(path, self.keypair)
            if isinstance(sig, tuple) and len(sig) == 2:
                self.signature = sig
                self.show_signature(sig)
                self.set_status("Файл успешно подписан")
            else:
                self.txt_sig.delete("1.0", tk.END)
                self.txt_sig.insert(tk.END, str(sig))
                self.set_status("Подпись создана (не (r,s)-кортеж)")
        except Exception as e:
            self.set_status(f"Ошибка подписи: {e}")

    def verify_current_file(self):
        if verify_file is None:
            self.set_status("Ошибка: модуль verify_file не найден")
            return
        path = self.ent_file.get().strip()
        if not path or not os.path.isfile(path):
            self.set_status("Выберите файл для проверки")
            return
        if not self.keypair:
            self.set_status("Нет ключей")
            return

        sig = self.read_signature()
        if sig is None:
            self.set_status("Неверный формат подписи (ожидается r:s)")
            return

        try:
            ok = verify_file(path, sig, self.keypair)
            if ok:
                self.set_status("Подпись корректна")
                messagebox.showinfo("Проверка", "Подпись корректна.")
            else:
                self.set_status("Подпись некорректна")
                messagebox.showwarning(
                    "Проверка", "Подпись не совпадает с файлом/ключом.")
        except Exception as e:
            self.set_status(f"Ошибка проверки: {e}")

    def show_signature(self, sig):
        r, s = sig
        self.txt_sig.delete("1.0", tk.END)
        self.txt_sig.insert(tk.END, f"{format(r, 'x')}:{format(s, 'x')}")

    def read_signature(self):
        txt = self.txt_sig.get("1.0", tk.END).strip()
        if not txt or ":" not in txt:
            return None
        parts = txt.split(":")
        if len(parts) != 2:
            return None
        try:
            r = int(parts[0], 16)
            s = int(parts[1], 16)
            return (r, s)
        except ValueError:
            return None

    def set_status(self, msg):
        self.lbl_status.config(text=msg)


if __name__ == "__main__":
    app = SignerGUI()
    app.mainloop()
