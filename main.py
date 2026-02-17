import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import hashlib
from PIL import Image

# ===============================
# Generate Encryption Key
# ===============================
key = Fernet.generate_key()
cipher = Fernet(key)

# ===============================
# Encryption Functions
# ===============================
def encrypt_text():
    text = input_text.get("1.0", tk.END).strip()
    if not text:
        messagebox.showerror("Error", "Enter text to encrypt")
        return
    encrypted = cipher.encrypt(text.encode())
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, encrypted.decode())

def decrypt_text():
    try:
        text = input_text.get("1.0", tk.END).strip()
        decrypted = cipher.decrypt(text.encode())
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted.decode())
    except:
        messagebox.showerror("Error", "Invalid encrypted text")

# ===============================
# Hashing Function
# ===============================
def generate_hash():
    text = input_text.get("1.0", tk.END).strip()
    if not text:
        messagebox.showerror("Error", "Enter text to hash")
        return
    hash_value = hashlib.sha256(text.encode()).hexdigest()
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, hash_value)

# ===============================
# Steganography Functions
# ===============================
def hide_message():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    message = input_text.get("1.0", tk.END).strip()
    if not message:
        messagebox.showerror("Error", "Enter message to hide")
        return

    img = Image.open(file_path)
    encoded = img.copy()
    width, height = img.size
    index = 0

    binary_msg = ''.join(format(ord(i), '08b') for i in message) + '1111111111111110'

    for row in range(height):
        for col in range(width):
            if index < len(binary_msg):
                r, g, b = img.getpixel((col, row))
                r = (r & ~1) | int(binary_msg[index])
                encoded.putpixel((col, row), (r, g, b))
                index += 1

    save_path = filedialog.asksaveasfilename(defaultextension=".png")
    encoded.save(save_path)
    messagebox.showinfo("Success", "Message hidden successfully!")

def extract_message():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    img = Image.open(file_path)
    binary_data = ""
    width, height = img.size

    for row in range(height):
        for col in range(width):
            r, g, b = img.getpixel((col, row))
            binary_data += str(r & 1)

    bytes_data = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    message = ""
    for byte in bytes_data:
        if byte == '11111110':
            break
        message += chr(int(byte, 2))

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, message)
def clear_text():
    input_text.delete("1.0", tk.END)
    output_text.delete("1.0", tk.END)


# ===============================
# GUI Setup
# ===============================
app = tk.Tk()
app.title("SecureX - Security Toolkit")
app.geometry("700x600")
app.configure(bg="#1e1e1e")

title = tk.Label(app, text="SecureX Security Toolkit", font=("Arial", 18, "bold"), bg="#1e1e1e", fg="cyan")
title.pack(pady=10)

input_label = tk.Label(app, text="Input:", bg="#1e1e1e", fg="white")
input_label.pack()

input_text = tk.Text(app, height=6, width=70)
input_text.pack(pady=5)

button_frame = tk.Frame(app, bg="#1e1e1e")
button_frame.pack(pady=10)

tk.Button(button_frame, text="Encrypt", command=encrypt_text, width=15).grid(row=0, column=0, padx=5)
tk.Button(button_frame, text="Decrypt", command=decrypt_text, width=15).grid(row=0, column=1, padx=5)
tk.Button(button_frame, text="SHA256 Hash", command=generate_hash, width=15).grid(row=0, column=2, padx=5)
tk.Button(button_frame, text="Hide in Image", command=hide_message, width=15).grid(row=1, column=0, padx=5, pady=5)
tk.Button(button_frame, text="Extract from Image", command=extract_message, width=18).grid(row=1, column=1, padx=5, pady=5)
tk.Button(button_frame, text="Clear", command=clear_text, width=15).grid(row=1, column=2, padx=5, pady=5)

output_label = tk.Label(app, text="Output:", bg="#1e1e1e", fg="white")
output_label.pack()

output_text = tk.Text(app, height=6, width=70)
output_text.pack(pady=5)

app.mainloop()
