import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def receive_data_from_app2(host="localhost", port=5002):
    def recv_with_size(sock):
        size = int.from_bytes(sock.recv(4), 'big')
        data = b""
        while len(data) < size:
            part = sock.recv(size - len(data))
            if not part:
                raise ConnectionError("Connection closed prematurely")
            data += part
        return data

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"[App3] Waiting for data from App2 at {host}:{port}...")
        conn, addr = server_socket.accept()
        with conn:
            print(f"[App3] Connection received from {addr}")
            public_key_bytes = recv_with_size(conn)
            signature = recv_with_size(conn)
            message = recv_with_size(conn)

    return public_key_bytes, signature, message

def verify_signature(public_key_bytes, signature, message):
    try:
        public_key = serialization.load_pem_public_key(public_key_bytes)
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

def run_app3():
    public_key, signature, message = receive_data_from_app2()
    print(f"\n[App3] Message received: {message.decode()}")
    print(f"[App3] Verifying signature...")

    if verify_signature(public_key, signature, message):
        print("[App3] The signature is valid.")
    else:
        print("[App3] The signature is invalid or was tampered with.")
