import tkinter as tk
from tkinter import messagebox, simpledialog
from login import login, register
from fileHandler import FileHandler
import random
import string
from codificar import decrypt_data

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.username = None
        self.main_menu()

    def main_menu(self):
        self.clear_window()
        self.username = None

        tk.Label(self.root, text="Welcome to the Password Manager", font=("Arial", 16)).pack(pady=10)
        tk.Button(self.root, text="Log In", command=self.login_screen, width=20).pack(pady=5)
        tk.Button(self.root, text="Register", command=self.register_screen, width=20).pack(pady=5)
        tk.Button(self.root, text="Exit", command=self.root.quit, width=20).pack(pady=5)

    def login_screen(self):
        self.clear_window()

        tk.Label(self.root, text="Log In", font=("Arial", 14)).pack(pady=10)

        tk.Label(self.root, text="Username:").pack()
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack()

        tk.Label(self.root, text="Password:").pack()
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack()

        tk.Button(self.root, text="Log In", command=self.authenticate).pack(pady=5)
        tk.Button(self.root, text="Back", command=self.main_menu).pack(pady=5)

    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showwarning("Warning", "Please fill in all fields.")
            return

        try:
            authenticated_user = login(username, password)
            if authenticated_user:
                self.username = authenticated_user
                self.password_manager_screen()
            else:
                messagebox.showerror("Error", "Incorrect username or password.")
        except Exception as e:
            messagebox.showerror("Error", f"Authentication error: {str(e)}")

    def register_screen(self):
        self.clear_window()

        tk.Label(self.root, text="User Registration", font=("Arial", 14)).pack(pady=10)

        tk.Label(self.root, text="Username:").pack()
        self.reg_username_entry = tk.Entry(self.root)
        self.reg_username_entry.pack()

        tk.Label(self.root, text="Password:").pack()
        self.reg_password_entry = tk.Entry(self.root, show="*")
        self.reg_password_entry.pack()

        tk.Button(self.root, text="Register", command=self.register_user).pack(pady=5)
        tk.Button(self.root, text="Back", command=self.main_menu).pack(pady=5)

    def register_user(self):
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get()

        if not username or not password:
            messagebox.showwarning("Warning", "Please fill in all fields.")
            return

        try:
            registered_user = register(username, password)
            if registered_user:
                messagebox.showinfo("Success", "User registered successfully.")
                self.main_menu()
            else:
                messagebox.showerror("Error", "User already exists.")
        except Exception as e:
            messagebox.showerror("Error", f"Registration error: {str(e)}")

    def password_manager_screen(self):
        self.clear_window()

        tk.Label(self.root, text=f"Password Manager - User: {self.username}", font=("Arial", 14)).pack(pady=10)

        tk.Button(self.root, text="Show Passwords", command=self.show_passwords).pack(pady=5)
        tk.Button(self.root, text="Add Password", command=self.add_password).pack(pady=5)
        tk.Button(self.root, text="Delete Password", command=self.delete_password).pack(pady=5)
        tk.Button(self.root, text="Log Out", command=self.main_menu).pack(pady=5)

    def show_passwords(self):
        fh = FileHandler(self.username)
        passwords = fh.get_all_passwords()

        if not passwords:
            messagebox.showinfo("Info", "No stored passwords.")
            return

        window = tk.Toplevel(self.root)
        window.title("Stored Passwords")
        window.geometry("600x400")

        search_frame = tk.Frame(window)
        search_frame.pack(pady=(10, 0), padx=10, fill=tk.X)

        tk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 10))

        list_frame = tk.Frame(window)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        listbox = tk.Listbox(list_frame, width=50, yscrollcommand=scrollbar.set)
        original_sites = list(passwords.keys())
        for site in passwords.keys():
            listbox.insert(tk.END, site)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar.config(command=listbox.yview)

        details_frame = tk.LabelFrame(window, text="Details", padx=10, pady=10)
        details_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        site_var = tk.StringVar()
        url_var = tk.StringVar()
        notes_var = tk.StringVar()
        password_var = tk.StringVar()
        password_var.set("********")

        tk.Label(details_frame, text="Site:").grid(row=0, column=0, sticky="e")
        tk.Label(details_frame, textvariable=site_var).grid(row=0, column=1, sticky="w")

        tk.Label(details_frame, text="URL:").grid(row=1, column=0, sticky="e")
        tk.Label(details_frame, textvariable=url_var).grid(row=1, column=1, sticky="w")

        tk.Label(details_frame, text="Notes:").grid(row=2, column=0, sticky="e")
        tk.Label(details_frame, textvariable=notes_var).grid(row=2, column=1, sticky="w")

        tk.Label(details_frame, text="Password:").grid(row=3, column=0, sticky="e")
        password_label = tk.Label(details_frame, textvariable=password_var)
        password_label.grid(row=3, column=1, sticky="w")

        show_pwd_btn = tk.Button(details_frame, text="Show Password")
        show_pwd_btn.grid(row=3, column=2, padx=5)

        def update_details(event=None):
            selection = listbox.curselection()
            if not selection:
                return
            site = listbox.get(selection[0])
            data = passwords[site]

            site_var.set(site)
            url_var.set(data['URL'])
            notes_var.set(data['Notes'])
            password_var.set("********")
            show_pwd_btn.config(text="Show Password")

        def filter_sites(*args):
            query = search_var.get().lower()
            listbox.delete(0, tk.END)
            for site in original_sites:
                if query in site.lower():
                    listbox.insert(tk.END, site)

        search_var.trace_add("write", filter_sites)

        def toggle_password():
            selection = listbox.curselection()
            if not selection:
                return
            site = listbox.get(selection[0])
            data = passwords[site]

            if password_var.get() == "********":
                try:
                    decrypted = decrypt_data(data['Password'], fh.key)
                    password_var.set(decrypted)
                    show_pwd_btn.config(text="Hide Password")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not decrypt password:\n{e}")
            else:
                password_var.set("********")
                show_pwd_btn.config(text="Show Password")

        def copy_password():
            selection = listbox.curselection()
            if not selection:
                return
            site = listbox.get(selection[0])
            data = passwords[site]
            try:
                decrypted = decrypt_data(data['Password'], fh.key)
                self.root.clipboard_clear()
                self.root.clipboard_append(decrypted)
                self.root.update()
                messagebox.showinfo("Copied", "Password copied to clipboard.")
            except Exception as e:
                messagebox.showerror("Error", f"Could not copy password:\n{e}")

        listbox.bind('<<ListboxSelect>>', update_details)
        show_pwd_btn.config(command=toggle_password)
        copy_pwd_btn = tk.Button(details_frame, text="Copy Password", command=copy_password)
        copy_pwd_btn.grid(row=3, column=3, padx=5)

        if passwords:
            listbox.selection_set(0)
            update_details()

        tk.Button(window, text="Close", command=window.destroy).pack(pady=5)

    def add_password(self):
        def generate_random_password(length=8):
            characters = string.ascii_letters + string.digits + string.punctuation
            return ''.join(random.choice(characters) for _ in range(length))

        def insert_random_password():
            pwd = generate_random_password()
            password_entry.delete(0, tk.END)
            password_entry.insert(0, pwd)

        def save_password():
            site = site_entry.get().strip()
            password = password_entry.get()
            url = url_entry.get().strip()
            notes = notes_entry.get().strip()

            if not site:
                messagebox.showwarning("Warning", "The 'Site' field is required.")
                return
            if not password:
                messagebox.showwarning("Warning", "The 'Password' field is required.")
                return

            try:
                fh = FileHandler(self.username)
                fh.add_password(site, password, url, notes)
                messagebox.showinfo("Success", "Password added successfully.")
                add_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Could not save the password:\n{e}")

        add_window = tk.Toplevel(self.root)
        add_window.title("Add New Password")
        add_window.resizable(False, False)

        tk.Label(add_window, text="Site:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        site_entry = tk.Entry(add_window, width=40)
        site_entry.grid(row=0, column=1, padx=5, pady=5, columnspan=2)

        tk.Label(add_window, text="Password:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        password_entry = tk.Entry(add_window, width=40, show="*")
        password_entry.grid(row=1, column=1, padx=5, pady=5)

        gen_button = tk.Button(add_window, text="Random Password", command=insert_random_password)
        gen_button.grid(row=1, column=2, padx=5, pady=5)

        tk.Label(add_window, text="URL (optional):").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        url_entry = tk.Entry(add_window, width=40)
        url_entry.grid(row=2, column=1, padx=5, pady=5, columnspan=2)

        tk.Label(add_window, text="Notes (optional):").grid(row=3, column=0, sticky="e", padx=5, pady=5)
        notes_entry = tk.Entry(add_window, width=40)
        notes_entry.grid(row=3, column=1, padx=5, pady=5, columnspan=2)

        save_btn = tk.Button(add_window, text="Save", command=save_password, width=15)
        save_btn.grid(row=4, column=1, pady=10, sticky="e")

        cancel_btn = tk.Button(add_window, text="Cancel", command=add_window.destroy, width=15)
        cancel_btn.grid(row=4, column=2, pady=10, sticky="w")

        site_entry.focus_set()

    def delete_password(self):
        fh = FileHandler(self.username)
        passwords = fh.get_all_passwords()

        if not passwords:
            messagebox.showinfo("Info", "No stored passwords to delete.")
            return

        delete_window = tk.Toplevel(self.root)
        delete_window.title("Delete Password")
        delete_window.resizable(False, False)

        tk.Label(delete_window, text="Select a password to delete:", font=("Arial", 10)).pack(pady=10)

        list_frame = tk.Frame(delete_window)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        listbox = tk.Listbox(list_frame, width=50, height=10, yscrollcommand=scrollbar.set)
        for site in passwords.keys():
            listbox.insert(tk.END, site)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar.config(command=listbox.yview)

        def confirm_delete():
            selection = listbox.curselection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a password to delete.")
                return

            site_to_delete = listbox.get(selection[0])

            if messagebox.askyesno("Confirm", f"Are you sure you want to delete the password for '{site_to_delete}'?"):
                if fh.delete_password(site_to_delete):
                    messagebox.showinfo("Success", "Password deleted successfully.")
                    delete_window.destroy()
                    self.show_passwords() if hasattr(self, 'show_passwords') else None
                else:
                    messagebox.showerror("Error", "Could not delete the password.")

        button_frame = tk.Frame(delete_window)
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Delete", command=confirm_delete).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Cancel", command=delete_window.destroy).pack(side=tk.LEFT, padx=5)

        listbox.selection_set(0)

    def show_scrollable_message(self, title, content):
        window = tk.Toplevel(self.root)
        window.title(title)
        text = tk.Text(window, wrap=tk.WORD)
        text.insert(tk.END, content)
        text.config(state=tk.DISABLED)
        text.pack(expand=True, fill=tk.BOTH)
        tk.Button(window, text="Close", command=window.destroy).pack(pady=5)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def reveal_password(self, encrypted_pwd):
        try:
            fh = FileHandler(self.username)
            decrypted = decrypt_data(encrypted_pwd, fh.key)
            messagebox.showinfo("Password", decrypted)
        except Exception as e:
            messagebox.showerror("Error", f"Incorrect key or corrupted data\n{e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
