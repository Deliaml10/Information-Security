import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def generate_keys():
    # Genera par de claves RSA
    private_key = rsa.generate_private_key(
        public_exponent =65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    # Firma el mensaje con la clave privada
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def serialize_public_key(public_key):
    # Serializa la clave pública a formato PEM
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def send_data_to_app2(public_key, signature, message, host="localhost", port=5001):
    def send_with_size(sock, data: bytes):
        sock.sendall(len(data).to_bytes(4, 'big') + data)

    with socket.create_connection((host, port)) as s:
        for data in (public_key, signature, message.encode()):
            send_with_size(s, data)

def run_app1(message, host="localhost", port=5001):
    # Ejecuta todo el flujo de la App1
    private_key, public_key = generate_keys()
    signature = sign_message(private_key, message)
    public_key_pem = serialize_public_key(public_key)
    send_data_to_app2(public_key_pem, signature, message, host, port)
    return {
        "message": message,
        "signature": signature,
        "public_key_pem": public_key_pem
    }
