import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import sympy
from sympy import *
import ast


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(e, phi):
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("No modular inverse exists")
    return x % phi


class CryptoApp:
    def start(self, root):
        self.root = root
        self.root.title("Cryptography GUI")
        self.mode_var = tk.StringVar(value="library")

        tk.Label(root, text="Select Mode:").grid(row=0, column=0, columnspan=2, pady=5)
        tk.Radiobutton(root, text="Use Cryptographic Library", variable=self.mode_var, value="library",
                       command=self.toggle_fields).grid(row=1, column=0, columnspan=2, pady=5)
        tk.Radiobutton(root, text="RSA without Library", variable=self.mode_var, value="rsa",
                       command=self.toggle_fields).grid(row=2, column=0, columnspan=2, pady=5)

        tk.Label(root, text="Enter text:").grid(row=3, column=0, pady=5)
        self.text_entry = tk.Entry(root, width=50)
        self.text_entry.grid(row=3, column=1, pady=5)

        self.key_label = tk.Label(root, text="Enter key (only for Library mode):")
        self.key_entry = tk.Entry(root, width=50)

        self.prime_label = tk.Label(root, text="Enter two prime numbers (max 1000) for RSA:")
        self.p_entry = tk.Entry(root, width=10)
        self.q_entry = tk.Entry(root, width=10)

        button_frame = tk.Frame(root)
        button_frame.grid(row=7, column=0, columnspan=2, pady=5)
        tk.Button(button_frame, text="Encrypt", command=self.encrypt).grid(row=0, column=0, padx=5)
        tk.Button(button_frame, text="Decrypt", command=self.decrypt).grid(row=0, column=1, padx=5)

        self.result_frame = tk.Frame(root)
        self.result_frame.grid(row=8, column=0, columnspan=2, pady=5)
        tk.Label(self.result_frame, text="Result:").grid(row=0, column=0, pady=5)
        self.result_text = tk.Text(self.result_frame, height=3, width=50)
        self.result_text.grid(row=1, column=0, pady=5)
        self.result_text.config(state=tk.DISABLED)
        self.toggle_fields()

    def toggle_fields(self):
        mode = self.mode_var.get()
        if mode == "library":
            self.key_label.grid(row=4, column=0, pady=5, columnspan=2)
            self.key_entry.grid(row=5, column=0, pady=5, columnspan=2)
            self.prime_label.grid_forget()
            self.p_entry.grid_forget()
            self.q_entry.grid_forget()
        elif mode == "rsa":
            self.key_label.grid_forget()
            self.key_entry.grid_forget()
            self.prime_label.grid(row=4, column=0, pady=5, columnspan=2)
            self.p_entry.grid(row=5, column=0, pady=5)
            self.q_entry.grid(row=5, column=1, pady=5)
            self.key_entry.delete(0, tk.END)

    def encrypt(self):
        mode = self.mode_var.get()
        text = self.text_entry.get()

        if mode == "rsa":
            try:

                p = int(self.p_entry.get())
                q = int(self.q_entry.get())

                if not (sympy.isprime(p) and sympy.isprime(q)) or p > 1000 or q > 1000:
                    raise ValueError("Invalid prime numbers.")

                n = p * q
                phi_n = (p - 1) * (q - 1)
                e = 65537
                d = mod_inverse(e, phi_n)

                text = self.text_entry.get().strip()
                ascii_values = [ord(char) for char in text]    #bucle for en el que se cambia cada valor a ASCII
                encrypted_values = [pow(val, e, n) for val in ascii_values]  #encrypt = x^e mod n


                with open("encrypted_data.txt", "a") as f:
                    f.write(f"Ciphertext: {encrypted_values}\n")
                    f.write(f"Public Key: ({n}, {e})\n")
                    f.write(f"d: {d}\n")

                result = f"Ciphertext: {encrypted_values}, Public Key: ({n}, {e})"

                self.result_text.config(state=tk.NORMAL)
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, result)
                self.result_text.config(state=tk.DISABLED)
            except Exception as ex:
                messagebox.showerror("Error", str(ex))

        elif mode == "library":
            try:
                #generar clave de cifrado Fernet
                key = self.key_entry.get().strip()
                if not key:
                    raise ValueError("Please enter a Fernet key.")

                try:
                    cipher_suite = Fernet(key.encode())
                except Exception:
                    raise ValueError("Invalid Fernet key format. Make sure it's base64 encoded.")

                cipher_suite = Fernet(key)
                #genera clave aleatoria y lo encripta en un solo bloque todo el texto
                encrypted_text = cipher_suite.encrypt(text.encode()).decode()

                #guardar en el archivo sin borrar los datos anteriores
                with open("encrypted_data.txt", "a") as f:
                    f.write(f"Ciphertext: {encrypted_text}\n")
                    f.write(f"Key: {key}\n")

                result = f"Fernet Ciphertext:  {encrypted_text}"

                self.result_text.config(state=tk.NORMAL)
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, result)
                self.result_text.config(state=tk.DISABLED)
            except Exception as ex:
                messagebox.showerror("Error", str(ex))

    def decrypt(self):
        mode = self.mode_var.get()
        input_ciphertext = self.text_entry.get().strip()  #obtener el texto que el usuario ingresó

        try:
            with open("encrypted_data.txt", "r") as f:
                lines = f.readlines()

            if not lines:
                raise ValueError("The file is empty.")

            decrypted_text = ""

            if mode == "rsa":
                #convertir input a lista
                try:
                    input_ciphertext = ast.literal_eval(input_ciphertext)
                    if not isinstance(input_ciphertext, list):
                        raise ValueError
                except (SyntaxError, ValueError):
                    raise ValueError("The RSA format is not valid.")

                #buscar el bloque RSA que coincide con el input
                n, d = None, None
                for i in range(len(lines)):
                    if "Ciphertext:" in lines[i] and "[" in lines[i]:
                        stored_ciphertext = ast.literal_eval(lines[i].split(":")[1].strip())
                        if stored_ciphertext == input_ciphertext:  # Coincidencia exacta
                            n = int(lines[i + 1].split(":")[1].strip().split(",")[0].strip("()"))
                            d = int(lines[i + 2].split(":")[1].strip())
                            break

                if None in (n, d):
                    raise ValueError("Couldn't find the RSA cyphertext in the file.")

                #desencriptar
                decrypted_chars = [chr(pow(c, d, n)) for c in input_ciphertext]
                decrypted_text = "".join(decrypted_chars)

            elif mode == "library":
                #buscar el bloque Fernet que coincide con el input
                key = None
                for i in range(len(lines)):
                    if "Ciphertext:" in lines[i] and "gA" in lines[i]:  # Fernet comienza con "gA"
                        stored_ciphertext = lines[i].split(":")[1].strip()
                        if stored_ciphertext == input_ciphertext:  # Coincidencia exacta
                            key = lines[i + 1].split(":")[1].strip()
                            break

                if key is None:
                    raise ValueError("Couldn't find Fetnet's data in the file.")

                #desencriptar con Fernet
                fernet = Fernet(key.encode())
                decrypted_text = fernet.decrypt(input_ciphertext.encode()).decode()

            self.result_text.config(state=tk.NORMAL)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, decrypted_text)
            self.result_text.config(state=tk.DISABLED)

        except Exception as ex:
            messagebox.showerror("Error", str(ex))
            print(f"Error in the desencryption: {ex}")


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp()
    app.start(root)
    root.mainloop()
