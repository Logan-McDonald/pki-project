import socket
import threading
import json
from crypto_utils import decrypt_message, encrypt_message, load_rsa_private_key, load_rsa_public_key

server_private_key = load_rsa_private_key("keys/server_private.pem")
client_public_key = load_rsa_public_key("keys/client_public.pem")

HOST = '127.0.0.1'
PORT = 65432
TIMEOUT = 1 # Used to stop server on keyboard interrupts

clients = []
lock = threading.Lock()

# Broadcasts to every connected client
def broadcast(sender_socket, encrypted_payload):
    with lock:
        for client in clients:
            if client != sender_socket:
                try:
                    client.sendall(json.dumps(encrypted_payload).encode())
                except:
                    client.close()
                    clients.remove(client)

def handle_client(conn, addr):
    print(f"[+] Connected by {addr}")
    with lock:
        clients.append(conn)

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            encrypted_payload = json.loads(data.decode())
            # Displays decrypted payload to the server and then encrypts it to broadcast to each client
            plaintext = decrypt_message(encrypted_payload, server_private_key)
            print(f"[{addr}] {plaintext}")
            rebroadcast = encrypt_message(plaintext, client_public_key)
            broadcast(conn, rebroadcast)
    except Exception as e:
        print(f"[!] Error with {addr}: {e}")
    finally:
        with lock:
            if conn in clients:
                clients.remove(conn)
        conn.close()
        print(f"[-] Disconnected {addr}")

def start_server():
    print("[*] Starting server...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        s.settimeout(TIMEOUT)

        print(f"[*] Listening on {HOST}:{PORT}")

        try:
            while True:
                try:
                    conn, addr = s.accept()
                    threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
                except socket.timeout:
                    continue 
        except KeyboardInterrupt:
            print("\n[*] Server interrupted. Shutting down.")

if __name__ == "__main__":
    start_server()
