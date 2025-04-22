from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64
import os

# Load RSA keys
def load_rsa_public_key(path):
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())

def load_rsa_private_key(path):
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())

# Encrypt message with AES, then wrap AES key with RSA
def encrypt_message(message, receiver_pub_key):
    # Generate random AES key and IV
    aes_key = get_random_bytes(16)
    iv = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv)
    ciphertext = cipher_aes.encrypt(message.encode())

    # Encrypt AES key with RSA
    cipher_rsa = PKCS1_OAEP.new(receiver_pub_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)

    # Encode everything in base64 for sending
    return {
        'key': base64.b64encode(encrypted_key).decode(),
        'iv': base64.b64encode(iv).decode(),
        'message': base64.b64encode(ciphertext).decode()
    }

# Decrypt received message
def decrypt_message(enc_data, receiver_priv_key):
    encrypted_key = base64.b64decode(enc_data['key'])
    iv = base64.b64decode(enc_data['iv'])
    ciphertext = base64.b64decode(enc_data['message'])

    # Decrypt AES key
    cipher_rsa = PKCS1_OAEP.new(receiver_priv_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)

    # Decrypt message
    cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv)
    decrypted = cipher_aes.decrypt(ciphertext)
    return decrypted.decode()
