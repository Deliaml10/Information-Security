import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def generate_key(filepath='data/key.key'):
    key = os.urandom(32)  # AES-256 = 32 bytes
    with open(filepath, 'wb') as f:
        f.write(key)
    return key

def load_key(filepath='data/key.key'):
    with open(filepath, 'rb') as f:
        return f.read()


def encrypt_data(data, key):
    iv = os.urandom(16)  # 16-byte IV (required for AES-CBC)
    padder = padding.PKCS7(128).padder()  # PKCS7 padding (block size: 128 bits)
    padded_data = padder.update(data.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    # Proper combination of IV and ciphertext
    encrypted_blob = iv + encrypted  # Prepend IV for decryption
    return base64.b64encode(encrypted_blob).decode()  # Encode as base64 for storage


def decrypt_data(encrypted_data, key):
    try:
        # Decode the base64 string to bytes
        encrypted_blob = base64.b64decode(encrypted_data)

        # Check it's long enough to contain the IV (16 bytes)
        if len(encrypted_blob) < 16:
            raise ValueError("Encrypted data is invalid or missing the IV.")

        # Extract IV and ciphertext
        iv = encrypted_blob[:16]
        encrypted = encrypted_blob[16:]

        # Initialize AES decryptor
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

        return decrypted.decode()
    except (ValueError, base64.binascii.Error):
        # Provide a clear message about corrupted or invalid data
        raise ValueError("Failed to decrypt: The encrypted data is corrupt or improperly encoded.")
