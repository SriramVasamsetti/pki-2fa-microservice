import base64
import sys
import re
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def decrypt_seed_test():
    print("Loading private key...")
    try:
        with open("student_private.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
    except FileNotFoundError:
        print("ERROR: student_private.pem not found.")
        sys.exit(1)
    
    print("Reading encrypted seed...")
    try:
        with open("encrypted_seed.txt", "r") as f:
            encrypted_data_b64 = f.read().strip()
    except FileNotFoundError:
        print("ERROR: encrypted_seed.txt not found (Run Step 4 first).")
        sys.exit(1)
    
    try:
        ciphertext = base64.b64decode(encrypted_data_b64)
        print("Decrypting...")
        decrypted_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_seed = decrypted_bytes.decode('utf-8').strip()
        if len(decrypted_seed) != 64:
            print(f"FAILED: Seed length is {len(decrypted_seed)}, expected 64.")
            sys.exit(1)
        if not re.fullmatch(r'^[0-9a-fA-F]+$', decrypted_seed):
            print("FAILED: Seed contains non-hex characters.")
            sys.exit(1)
        print("\n" + "="*40)
        print("SUCCESS! Decryption verified.")
        print(f"Seed (First 16 chars): {decrypted_seed[:16]}...")
        print("="*40 + "\n")
    except Exception as e:
        print(f"Decryption FAILED: {str(e)}")
        print("Hint: This usually means the Public Key used by the API doesn't match your Private Key.")

if __name__ == "__main__":
    decrypt_seed_test()
