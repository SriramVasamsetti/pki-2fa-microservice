from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import os

def load_private_key(key_path: str):
    """Load private key from PEM file."""
    with open(key_path, 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

def load_public_key(key_path: str):
    """Load public key from PEM file."""
    with open(key_path, 'rb') as f:
        return serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

def decrypt_seed(encrypted_seed: bytes, private_key_path: str) -> str:
    """
    Decrypt the seed using private key.
    Assumes encrypted_seed is base64 encoded string.
    """
    import base64
    private_key = load_private_key(private_key_path)
    
    # Decode from base64
    encrypted_bytes = base64.b64decode(encrypted_seed)
    
    # Decrypt using OAEP padding with SHA-256
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return decrypted.decode('utf-8')

def write_seed_to_file(seed: str, file_path: str):
    """Write decrypted seed (64-char hex) to file."""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w') as f:
        f.write(seed)

def read_seed_from_file(file_path: str) -> str:
    """Read seed from /data/seed.txt."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Seed file not found: {file_path}")
    with open(file_path, 'r') as f:
        return f.read().strip()
