import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os


# Function to pad the text
def pad(data):
    padder = padding.PKCS7(128).padder()
    return padder.update(data.encode()) + padder.finalize()


# Function to remove padding
def unpad(data):
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


# Function to encrypt text
def encrypt(plaintext, key, mode):
    iv = os.urandom(16) if mode in ['CBC', 'CFB'] else b''

    try:
        cipher_mode = {
            'ECB': modes.ECB(),
            'CBC': modes.CBC(iv),
            'CFB': modes.CFB(iv)
        }[mode]

        cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(pad(plaintext)) + encryptor.finalize()

        with open("ciphertext.txt", "ab") as f:
            f.write((iv + ciphertext).hex().encode() + b"\n")

        return (iv + ciphertext).hex()
    except Exception as e:
        return f"Encryption error: {str(e)}"


# Function to decrypt text
def decrypt(key, mode):
    try:
        with open("ciphertext.txt", "rb") as f:
            lines = f.readlines()
        if not lines:
            return "No encrypted data available."

        data = bytes.fromhex(lines[-1].strip().decode())
        iv, ciphertext = (data[:16], data[16:]) if mode in ['CBC', 'CFB'] else (b'', data)

        cipher_mode = {
            'ECB': modes.ECB(),
            'CBC': modes.CBC(iv),
            'CFB': modes.CFB(iv)
        }[mode]

        cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = unpad(decryptor.update(ciphertext) + decryptor.finalize()).decode()

        return plaintext
    except Exception as e:
        return f"Decryption error: {str(e)}"


# Function for GUI interaction
def process():
    action = action_var.get()
    mode = mode_var.get()
    key_input = key_entry.get()
    if len(key_input) != 16:
        messagebox.showerror("Error", "The key must be 16 characters long.")
        return
    key = key_input.encode()

    if action == "Encrypt":
        plaintext = text_entry.get("1.0", tk.END).strip()
        ciphertext = encrypt(plaintext, key, mode)
        result_entry.delete("1.0", tk.END)
        result_entry.insert("1.0", ciphertext)
    else:
        plaintext = decrypt(key, mode)
        result_entry.delete("1.0", tk.END)
        result_entry.insert("1.0", plaintext)


# Create the GUI window
root = tk.Tk()
root.title("AES Encryption")
root.geometry("500x400")

#Default values of the window
action_var = tk.StringVar(value="Encrypt")
mode_var = tk.StringVar(value="ECB")

#Place for writing the plaintext
tk.Label(root, text="Text:").pack()
text_entry = tk.Text(root, height=4, width=50)
text_entry.pack()

#Place for writing the key
tk.Label(root, text="Key (16 characters):").pack()
key_entry = tk.Entry(root, width=20)
key_entry.pack()

#Menu for the three encryption/decryption options
tk.Label(root, text="Mode of operation:").pack()
mode_menu = tk.OptionMenu(root, mode_var, "ECB", "CBC", "CFB")
mode_menu.pack()

#Menu for encrey or decrypt
action_menu = tk.OptionMenu(root, action_var, "Encrypt", "Decrypt")
action_menu.pack()

#Execute button
tk.Button(root, text="Execute", command=process).pack()

#Label where the exit text is showed
tk.Label(root, text="Result:").pack()
result_entry = tk.Text(root, height=4, width=50)
result_entry.pack()

#Loop so that the program doesn't finish until the user close the window
root.mainloop()
