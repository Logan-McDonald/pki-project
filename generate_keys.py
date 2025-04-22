from Crypto.PublicKey import RSA
import os

def generate_keys(name):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    os.makedirs("keys", exist_ok=True)
    
    with open(f"keys/{name}_private.pem", "wb") as priv_file:
        priv_file.write(private_key)
    
    with open(f"keys/{name}_public.pem", "wb") as pub_file:
        pub_file.write(public_key) 
        
if __name__ == "__main__":
    generate_keys("server")
    generate_keys("client")
    print("Keys generated successfully.")