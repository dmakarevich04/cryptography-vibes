import tkinter as tk
from tkinter import ttk, scrolledtext
from core_streebog import streebog_256, streebog_512
from core_sha1 import sha1_hash


def bytes_to_hex(b: bytes) -> str:
    return ''.join(f'{byte:02x}' for byte in b)


def compute_hashes():
    text = entry.get()
    if not text:
        text = ''
    message = text.encode('utf-8')

    hash512 = streebog_512(message)
    hash256 = streebog_256(message)
    hash_sha1 = sha1_hash(message)

    streebog512_var.set(bytes_to_hex(hash512))
    streebog256_var.set(bytes_to_hex(hash256))
    sha1_var.set(hash_sha1)


root = tk.Tk()
root.title("Хэш-функции: Streebog и SHA-1")
root.geometry("800x550")
root.configure(bg="white")

style = ttk.Style()
style.configure("Modern.TButton",
                foreground="white",
                background="#008000",
                font=("Helvetica", 12, "bold"),
                padding=5)
style.map("Modern.TButton",
          background=[('active', '#45a049')])

ttk.Label(root, text="Введите фразу:", background="white",
          font=("Helvetica", 14)).pack(pady=10)
entry_frame = tk.Frame(root, highlightbackground="gray",
                       highlightthickness=1, bd=0)
entry_frame.pack(pady=5, padx=10, fill='x')
entry = tk.Entry(entry_frame, width=60, font=("Helvetica", 11), bd=0)
entry.pack(padx=2, pady=2, fill='x')

ttk.Button(root, text="Вычислить хэш", style="Modern.TButton",
           command=compute_hashes).pack(pady=10)


streebog512_var = tk.StringVar()
streebog256_var = tk.StringVar()
sha1_var = tk.StringVar()

def create_scrolled_text(parent, height):
    frame = tk.Frame(parent, highlightbackground="gray",
                     highlightthickness=1, bd=0)
    frame.pack(fill='x', padx=10, pady=2)
    text_widget = scrolledtext.ScrolledText(
        frame, height=height, wrap='word', font=("Courier", 10), bd=0)
    text_widget.pack(fill='both', padx=2, pady=2)
    text_widget.config(state='disabled')
    return text_widget


ttk.Label(root, text="Streebog-512:", background="white",
          font=("Helvetica", 10)).pack(anchor='w', padx=10, pady=10)
streebog512_text = create_scrolled_text(root, 3)

ttk.Label(root, text="Streebog-256:", background="white",
          font=("Helvetica", 10)).pack(anchor='w', padx=10, pady=10)
streebog256_text = create_scrolled_text(root, 3)

ttk.Label(root, text="SHA-1:", background="white",
          font=("Helvetica", 10)).pack(anchor='w', padx=10, pady=10)
sha1_text = create_scrolled_text(root, 3)


def update_textfields():
    streebog512_text.config(state='normal')
    streebog512_text.delete('1.0', tk.END)
    streebog512_text.insert(tk.END, streebog512_var.get())
    streebog512_text.config(state='disabled')

    streebog256_text.config(state='normal')
    streebog256_text.delete('1.0', tk.END)
    streebog256_text.insert(tk.END, streebog256_var.get())
    streebog256_text.config(state='disabled')

    sha1_text.config(state='normal')
    sha1_text.delete('1.0', tk.END)
    sha1_text.insert(tk.END, sha1_var.get())
    sha1_text.config(state='disabled')


streebog512_var.trace_add('write', lambda *args: update_textfields())
streebog256_var.trace_add('write', lambda *args: update_textfields())
sha1_var.trace_add('write', lambda *args: update_textfields())

root.mainloop()
