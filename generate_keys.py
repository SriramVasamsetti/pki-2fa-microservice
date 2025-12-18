from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair():
    print("Generating 4096-bit RSA key pair... this may take a moment.")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    
    with open("student_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open("student_public.pem", "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print("Success! Keys saved: student_private.pem, student_public.pem")

if __name__ == "__main__":
    generate_rsa_keypair()
