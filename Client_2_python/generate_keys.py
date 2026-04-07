import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def generate_identity():
    # 1. Generate the key pair
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # 2. Serialize Private Key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() 
    )

    # 3. Serialize Public Key
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 4. Anchor paths and save to disk
    priv_path = os.path.join(BASE_DIR, "my_identity_key.pem")
    pub_path = os.path.join(BASE_DIR, "my_identity_public_key.pem")

    with open(priv_path, "wb") as f:
        f.write(pem_private)
        
    with open(pub_path, "wb") as f:
        f.write(pem_public)
        
    print(f"[+] Keys successfully generated and saved in {BASE_DIR}!")

if __name__ == "__main__":
    generate_identity()