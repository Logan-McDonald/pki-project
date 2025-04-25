import socket
import threading
import json
from crypto_utils import encrypt_message, decrypt_message, load_rsa_private_key, load_rsa_public_key

client_private_key = load_rsa_private_key("keys/client_private.pem")
server_public_key = load_rsa_public_key("keys/server_public.pem")

HOST = '127.0.0.1'
PORT = 65432


def receive_messages(sock):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            enc_payload = json.loads(data.decode())
            # Decrypts message using client priv key
            msg = decrypt_message(enc_payload, client_private_key)
            print(f"\nPeer: {msg}\n> ", end="")
        except Exception as e:
            print(f"[Error receiving] {e}")
            break


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print("Connected to server.\nType your messages below:")

    # Start background thread to receive messages
    threading.Thread(target=receive_messages,
                     args=(sock,), daemon=True).start()

    try:
        while True:
            msg = input("> ")
            if not msg.strip():
                continue
            # Encrypts message using server pub key before sending
            enc = encrypt_message(msg, server_public_key) 
            sock.sendall(json.dumps(enc).encode())
    except KeyboardInterrupt:
        print("\nExiting chat.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
