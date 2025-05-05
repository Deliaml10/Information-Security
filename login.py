import os
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

USERS_FILE = "data/users.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

def hash_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100_000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return urlsafe_b64encode(key).decode()

def register(username, password):
    users = load_users()
    if username in users:
        return None

    salt = os.urandom(16).hex()
    hashed = hash_password(password, salt)

    users[username] = {'hash': hashed, 'salt': salt}
    save_users(users)
    return username

def login(username, password):
    users = load_users()
    if username not in users:
        return None

    salt = users[username]['salt']
    hashed = hash_password(password, salt)

    if hashed == users[username]['hash']:
        return username
    else:
        return None
