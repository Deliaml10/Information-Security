import os
import io
import csv
from codificar import generate_key, load_key, encrypt_data, decrypt_data

class FileHandler:
    def __init__(self, username):
        self.username = username
        self.folder = 'data'
        self.filename = os.path.join(self.folder, f"{username}_passwords.txt")
        self.keyfile = os.path.join(self.folder, f"{username}_key.key")

        if not os.path.exists(self.folder):
            os.makedirs(self.folder)

        if not os.path.exists(self.keyfile):
            generate_key(self.keyfile)
        self.key = load_key(self.keyfile)

        if not os.path.exists(self.filename):
            with open(self.filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['Title', 'Password', 'URL', 'Notes'])
                writer.writeheader()

    def read_data(self):
        try:
            with open(self.filename, 'r', encoding='utf-8') as f:
                encrypted_content = f.read()
            if not encrypted_content.strip():
                return []

            decrypted_content = decrypt_data(encrypted_content, self.key)

            # Convert the decrypted CSV to a list of dictionaries
            reader = csv.DictReader(decrypted_content.splitlines())
            return list(reader)
        except (FileNotFoundError, ValueError):
            return []

    def get_all_passwords(self):
        data = self.read_data()
        if not data:
            return {}

        return {entry['Title']: {
            'Password': entry['Password'],
            'URL': entry['URL'],
            'Notes': entry['Notes']
        } for entry in data}

    def add_password(self, title, password, url='', notes=''):
        data = self.read_data()

        # Search for and update existing entry
        for entry in data:
            if entry['Title'].lower() == title.lower():
                entry['Password'] = encrypt_data(password, self.key)
                entry['URL'] = url
                entry['Notes'] = notes
                self.write_data(data)
                return

        # Add new entry
        encrypted_password = encrypt_data(password, self.key)
        new_entry = {
            'Title': title,
            'Password': encrypted_password,
            'URL': url,
            'Notes': notes
        }
        data.append(new_entry)
        self.write_data(data)

    def _generate_csv(self, data):
        """Generates CSV content as a string from a list of dictionaries."""
        output = io.StringIO()
        fieldnames = ['Title', 'Password', 'URL', 'Notes']
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for entry in data:
            writer.writerow({
                'Title': entry['Title'],
                'Password': entry['Password'],
                'URL': entry.get('URL', ''),
                'Notes': entry.get('Notes', '')
            })
        return output.getvalue()

    def write_data(self, data):
        # Convert list of dictionaries to CSV format
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=['Title', 'Password', 'URL', 'Notes'])
        writer.writeheader()
        writer.writerows(data)

        # Encrypt and save
        encrypted_content = encrypt_data(output.getvalue(), self.key)
        with open(self.filename, 'w', encoding='utf-8') as f:
            f.write(encrypted_content)

    def delete_password(self, title):
        data = self.read_data()
        new_data = [entry for entry in data if entry['Title'].lower() != title.lower()]

        # Check if anything was actually deleted
        if len(new_data) == len(data):
            return False

        self.write_data(new_data)  # This was the error before - writing `data` instead of `new_data`
        return True
