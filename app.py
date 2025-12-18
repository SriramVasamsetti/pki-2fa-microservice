import os
import base64
import time
import pyotp
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = FastAPI()

# --- CONFIGURATION ---
if os.access("/", os.W_OK): 
    DATA_DIR = "/data"
else:
    DATA_DIR = os.path.join(os.getcwd(), "data")

SEED_FILE = os.path.join(DATA_DIR, "seed.txt")
PRIVATE_KEY_PATH = "student_private.pem"

# --- PYDANTIC MODELS ---
class SeedRequest(BaseModel):
    encrypted_seed: str

class VerifyRequest(BaseModel):
    code: str

# --- HELPER FUNCTIONS ---
def get_private_key():
    try:
        with open(PRIVATE_KEY_PATH, "rb") as key_file:
            return serialization.load_pem_private_key(key_file.read(), password=None)
    except FileNotFoundError:
        raise Exception("Private key not found")

# --- ENDPOINTS ---
@app.post("/decrypt-seed")
def decrypt_seed(payload: SeedRequest):
    try:
        private_key = get_private_key()
        try:
            ciphertext = base64.b64decode(payload.encrypted_seed)
        except:
            return JSONResponse(status_code=500, content={"error": "Invalid Base64"})
        try:
            decrypted_bytes = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            print(f"Crypto Error: {e}")
            return JSONResponse(status_code=500, content={"error": "Decryption failed"})
        seed_hex = decrypted_bytes.decode('utf-8').strip()
        if len(seed_hex) != 64:
            return JSONResponse(status_code=500, content={"error": "Invalid seed length"})
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(SEED_FILE, "w") as f:
            f.write(seed_hex)
        return {"status": "ok"}
    except Exception as e:
        print(f"General Error: {e}")
        return JSONResponse(status_code=500, content={"error": "Decryption failed"})

@app.get("/generate-2fa")
def generate_2fa():
    if not os.path.exists(SEED_FILE):
        return JSONResponse(status_code=500, content={"error": "Seed not decrypted yet"})
    try:
        with open(SEED_FILE, "r") as f:
            hex_seed = f.read().strip()
        seed_bytes = bytes.fromhex(hex_seed)
        base32_seed = base64.b32encode(seed_bytes).decode('utf-8')
        totp = pyotp.TOTP(base32_seed, interval=30)
        code = totp.now()
        remaining_seconds = 30 - (int(time.time()) % 30)
        return {"code": code, "valid_for": remaining_seconds}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Generation failed: {str(e)}"})

@app.post("/verify-2fa")
def verify_2fa(payload: VerifyRequest):
    if not payload.code:
        return JSONResponse(status_code=400, content={"error": "Missing code"})
    if not os.path.exists(SEED_FILE):
        return JSONResponse(status_code=500, content={"error": "Seed not decrypted yet"})
    try:
        with open(SEED_FILE, "r") as f:
            hex_seed = f.read().strip()
        seed_bytes = bytes.fromhex(hex_seed)
        base32_seed = base64.b32encode(seed_bytes).decode('utf-8')
        totp = pyotp.TOTP(base32_seed, interval=30)
        is_valid = totp.verify(payload.code, valid_window=1)
        return {"valid": is_valid}
    except Exception:
        return JSONResponse(status_code=500, content={"error": "Verification failed"})
