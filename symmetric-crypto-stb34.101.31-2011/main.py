# main.py
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import secrets
from functools import partial
import crypto_stb

# --- Ключ и IV ---
MASTER_KEY = secrets.token_bytes(32)
ROUND_KEYS = crypto_stb.key_schedule(MASTER_KEY)
IV = secrets.token_bytes(16)

# --- Функции для UI ---
def select_file(input_widget):
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read()
        input_widget.config(state='normal')
        input_widget.delete("1.0", tk.END)
        input_widget.insert(tk.END, data)
        input_widget.config(state='disabled')

def encrypt_text(mode, input_widget, output_widget):
    text = input_widget.get("1.0", tk.END).encode('utf-8')
    if mode.get() == "ECB":
        cipher = crypto_stb.encrypt_ecb(text, ROUND_KEYS)
        plain = crypto_stb.decrypt_ecb(cipher, ROUND_KEYS)
    else:
        cipher = crypto_stb.encrypt_cfb(text, ROUND_KEYS, IV)
        plain = crypto_stb.decrypt_cfb(cipher, ROUND_KEYS, IV)
    
    output_widget.config(state='normal')
    output_widget.delete("1.0", tk.END)
    output_widget.insert(tk.END, "--- Исходный текст ---\n")
    output_widget.insert(tk.END, text.decode('utf-8', errors='ignore') + "\n\n")
    output_widget.insert(tk.END, "--- Зашифрованный текст (hex) ---\n")
    output_widget.insert(tk.END, cipher.hex() + "\n\n")
    output_widget.insert(tk.END, "--- Расшифрованный текст ---\n")
    output_widget.insert(tk.END, plain.decode('utf-8', errors='ignore') + "\n")
    output_widget.config(state='disabled')

# --- Tkinter UI ---
root = tk.Tk()
root.title("Симметричная криптография (СТБ 34.101.31-2011)")
root.geometry("900x800")  # фиксированный размер окна

mode = tk.StringVar(value="ECB")

# --- Центральная рамка ---
frame = ttk.Frame(root, padding=10)
frame.pack(expand=True, fill='both')

# --- Выбор файла ---
ttk.Label(frame, text="Исходный файл:").pack(pady=5)
input_text = scrolledtext.ScrolledText(frame, width=80, height=10, state='disabled')
input_text.pack(pady=5)
ttk.Button(frame, text="Выбрать файл", command=partial(select_file, input_text)).pack(pady=5)

# --- Режим шифрования ---
ttk.Label(frame, text="Режим:").pack(pady=5)
mode_frame = ttk.Frame(frame)
mode_frame.pack(pady=5)
ttk.Radiobutton(mode_frame, text="ECB", variable=mode, value="ECB").pack(side="left", padx=10)
ttk.Radiobutton(mode_frame, text="CFB", variable=mode, value="CFB").pack(side="left", padx=10)

# --- Одно окно для вывода всего ---
output_text = scrolledtext.ScrolledText(frame, width=80, height=18, state='disabled')
output_text.pack(pady=10)

# --- Кнопка шифрования ---
ttk.Button(frame, text="Зашифровать",
           command=partial(encrypt_text, mode, input_text, output_text)).pack(pady=(10,20))


root.mainloop()
