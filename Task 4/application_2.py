import socket

def receive_data_from_app1(host="localhost", port=5001):
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
        print(f"[App2] Waiting for data from App1 at {host}:{port}...")
        conn, addr = server_socket.accept()
        with conn:
            print(f"[App2] Connection received from {addr}")
            public_key = recv_with_size(conn)
            signature = recv_with_size(conn)
            message = recv_with_size(conn)

    return public_key, signature, message

def tamper_signature(signature: bytes):
    print("\n--- Signature Modification Menu ---")
    print("1. Do not modify (use original signature)")
    print("2. Modify manually (hex)")
    choice = input("Choose an option (1 or 2): ").strip()

    modified_signature = signature  # by default, use the original

    if choice == "2":
        try:
            user_input = input("Enter new signature in hexadecimal format: ")
            modified_signature = bytes.fromhex(user_input)
            if len(modified_signature) != len(signature):
                print("[App2] The signature has an incorrect size. Using original signature.")
                modified_signature = signature
        except ValueError:
            print("[App2] Invalid signature (hex format). Using original signature.")

    return modified_signature  # Now return the correct version


def send_data_to_app3(public_key, signature, message, host="localhost", port=5002):
    print(f"[App2] Signature to be sent (hex): {signature.hex()}")
    def send_with_size(sock, data: bytes):
        sock.sendall(len(data).to_bytes(4, 'big') + data)

    with socket.create_connection((host, port)) as s:
        for data in (public_key, signature, message):
            send_with_size(s, data)
    print(f"[App2] Data forwarded to App3 at {host}:{port}")

def run_app2(*args, **kwargs):
    public_key, signature, message = receive_data_from_app1()
    print(f"\n[App2] Message received: {message.decode()}")
    print(f"[App2] Original signature (hex): {signature.hex()}")
    signature = tamper_signature(signature)
    send_data_to_app3(public_key, signature, message)
