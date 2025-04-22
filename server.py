import socket
import threading
import json
from crypto_utils import decrypt_message, encrypt_message, load_rsa_private_key, load_rsa_public_key

# Load server's private key and client public key
server_private_key = load_rsa_private_key("keys/server_private.pem")
client_public_key = load_rsa_public_key("keys/client_public.pem")  # Assuming one known client

HOST = '127.0.0.1'
PORT = 65432

clients = []

def broadcast(sender_socket, encrypted_payload):
    for client in clients:
        if client != sender_socket:
            try:
                client.sendall(json.dumps(encrypted_payload).encode())
            except:
                client.close()
                clients.remove(client)

def handle_client(conn, addr):
    print(f"[+] Connected by {addr}")
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break

            encrypted_payload = json.loads(data.decode())
            plaintext = decrypt_message(encrypted_payload, server_private_key)
            print(f"[{addr}] {plaintext}")

            # Broadcast encrypted to other clients
            rebroadcast = encrypt_message(plaintext, client_public_key) # Encrypts AES key using Client public key
            broadcast(conn, rebroadcast)

        except Exception as e:
            print(f"[!] Error with {addr}: {e}")
            break

    conn.close()
    clients.remove(conn)
    print(f"[-] Disconnected {addr}")

def start_server():
    print("[*] Starting server...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[*] Listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            clients.append(conn)
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
