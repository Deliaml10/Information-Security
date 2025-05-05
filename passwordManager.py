import os
import csv
from codificar import encrypt_data, decrypt_data

class PasswordManager:
    def __init__(self, username):
        self.username = username
        self.data_file = f"data/{username}_passwords.txt"
        self.key_file = f"data/{username}_key.key"

        # Create files if they don't exist
        if not os.path.exists(self.data_file):
            with open(self.data_file, 'w'): pass  # Create an empty file if it doesn't exist

        if not os.path.exists(self.key_file):
            from codificar import generate_key
            generate_key(self.key_file)  # Generate the key if it doesn't exist

        self.key = self.load_key()

    def load_key(self):
        with open(self.key_file, 'rb') as f:
            return f.read()

    def add_password(self):
        title = input("Title (e.g., Facebook): ")
        password = input("Password: ")
        url = input("URL or application name: ")
        notes = input("Additional notes: ")

        encrypted_password = encrypt_data(password, self.key)

        # Save to file
        with open(self.data_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([title, encrypted_password, url, notes])

        print("✅ Password saved.")

    def search_password(self):
        title = input("Enter the title to search for: ")
        found = False

        with open(self.data_file, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if row and row[0].lower() == title.lower():
                    print(f"Title: {row[0]}")
                    print(f"URL or app: {row[2]}")
                    print(f"Notes: {row[3]}")
                    print("ℹ️ Password hidden. Use the 'Show' option if implemented.")
                    found = True
                    break

        if not found:
            print("❌ Password not found.")

    def update_password(self):
        print("\n📋 Saved passwords:")
        passwords = []  # Temporary list to store decrypted passwords
        with open(self.data_file, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or len(row) < 4:  # Skip empty or malformed rows
                    continue
                try:
                    # Decrypt the stored password
                    decrypted = decrypt_data(row[1], self.key)
                    passwords.append({
                        "title": row[0],
                        "password": decrypted,
                        "url": row[2],
                        "notes": row[3]
                    })
                except ValueError as e:
                    print(f"❌ Cannot decrypt entry {row[0]}: {e}")
                    continue

        if not passwords:
            print("No valid passwords saved.")
            return

        # Display successfully decrypted passwords
        for idx, entry in enumerate(passwords):
            print(f"{idx + 1}. {entry['title']} | {entry['url']} | {entry['notes']} | Password: {entry['password']}")

        try:
            choice = int(input("\nSelect the number of the entry you want to modify: "))
            if choice < 1 or choice > len(passwords):
                print("❌ Invalid selection.")
                return
        except ValueError:
            print("❌ Invalid input.")
            return

        new_password = input("Enter the new password: ")
        passwords[choice - 1]["password"] = new_password  # Update password

        # Rewrite the file with the updated password
        with open(self.data_file, 'w', newline='') as f:
            writer = csv.writer(f)
            for entry in passwords:
                encrypted = encrypt_data(entry["password"], self.key)
                writer.writerow([entry["title"], encrypted, entry["url"], entry["notes"]])

        print("✅ Password updated.")

    def delete_password(self):
        title = input("Enter the title of the password to delete: ")
        found = False
        updated_rows = []

        with open(self.data_file, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if row and row[0].lower() != title.lower():
                    updated_rows.append(row)
                else:
                    found = True

        if found:
            with open(self.data_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerows(updated_rows)
            print("🗑 Password deleted.")
        else:
            print("❌ Password not found.")

    def show_passwords(self):
        print("\n📋 Saved passwords:")
        passwords = []  # Temporary list to store decrypted passwords
        with open(self.data_file, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or len(row) < 4:  # Skip empty or malformed rows
                    continue
                try:
                    # Decrypt the stored password
                    decrypted = decrypt_data(row[1], self.key)
                    passwords.append({
                        "title": row[0],
                        "password": decrypted,
                        "url": row[2],
                        "notes": row[3]
                    })
                except ValueError as e:
                    print(f"❌ Cannot decrypt entry {row[0]}: {e}")
                    continue

        if not passwords:
            print("No valid passwords saved.")
            return

        # Display successfully decrypted passwords
        for idx, entry in enumerate(passwords):
            print(f"{idx + 1}. {entry['title']} | {entry['url']} | {entry['notes']} | Password: {entry['password']}")
