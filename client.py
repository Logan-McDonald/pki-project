import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
import json
from crypto_utils import encrypt_message, decrypt_message, load_rsa_private_key, load_rsa_public_key

# Load client private and server public key
client_private_key = load_rsa_private_key("keys/client_private.pem")
server_public_key = load_rsa_public_key("keys/server_public.pem")

HOST = '127.0.0.1'
PORT = 65432

class ChatClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))

        self.root = tk.Tk()
        self.root.title("Secure Chat")

        self.chat_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=50, height=20, state='disabled')
        self.chat_area.pack(padx=10, pady=10)

        self.entry = tk.Entry(self.root, width=40)
        self.entry.pack(side=tk.LEFT, padx=(10,0), pady=(0,10))

        self.send_button = tk.Button(self.root, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=(5,10), pady=(0,10))

        self.entry.bind('<Return>', lambda event: self.send_message())

        threading.Thread(target=self.receive_messages, daemon=True).start()

        self.root.mainloop()

    def send_message(self):
        msg = self.entry.get()
        if not msg:
            return
        self.entry.delete(0, tk.END)

        encrypted = encrypt_message(msg, server_public_key) # Encrypts AES key using servers public key
        self.sock.sendall(json.dumps(encrypted).encode())

        self.display_message(f"You: {msg}")

    def receive_messages(self):
        while True:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                enc_payload = json.loads(data.decode())
                msg = decrypt_message(enc_payload, client_private_key)
                self.display_message(f"Peer: {msg}")
            except Exception as e:
                self.display_message(f"[Error] {str(e)}")
                break

    def display_message(self, msg):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, msg + "\n")
        self.chat_area.yview(tk.END)
        self.chat_area.config(state='disabled')

if __name__ == "__main__":
    ChatClient()
