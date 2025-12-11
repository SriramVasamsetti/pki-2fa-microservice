import base64
import os
import time
import logging
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pyotp

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pki-2fa")

app = FastAPI(title="PKI TOTP 2FA Microservice")

# Config / paths
PRIVATE_KEY_PATH = os.environ.get("STUDENT_PRIVATE_PEM", "/app/student_private.pem")
SEED_PATH = os.environ.get("SEED_PATH", "/data/seed.txt")
os.makedirs(os.path.dirname(SEED_PATH), exist_ok=True)

# Models
class EncryptedSeedIn(BaseModel):
    encrypted_seed: str

class CodeIn(BaseModel):
    code: str

# Helpers
def load_private_key(path: str):
    try:
        with open(path, "rb") as f:
            data = f.read()
        return serialization.load_pem_private_key(data, password=None)
    except Exception as e:
        logger.error("Failed to load private key from %s: %s", path, e)
        raise

def decrypt_seed_b64(encrypted_seed_b64: str, private_key) -> str:
    try:
        encrypted = base64.b64decode(encrypted_seed_b64)
    except Exception:
        logger.exception("Base64 decode failed")
        raise ValueError("Base64 decode failed")
    try:
        plaintext = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception:
        logger.exception("RSA OAEP decryption failed")
        raise ValueError("RSA OAEP decryption failed")
    try:
        seed = plaintext.decode("utf-8").strip().lower()
    except Exception:
        logger.exception("UTF-8 decode failed")
        raise ValueError("UTF-8 decode failed")
    if len(seed) != 64 or any(c not in "0123456789abcdef" for c in seed):
        logger.error("Decrypted seed validation failed: %r", seed)
        raise ValueError("Bad seed format")
    return seed

def save_seed(hex_seed: str, path: str = SEED_PATH):
    with open(path, "w") as f:
        f.write(hex_seed + "\n")
    try:
        os.chmod(path, 0o600)
    except Exception:
        logger.debug("Could not chmod seed file (ignored)")

def read_seed(path: str = SEED_PATH) -> Optional[str]:
    try:
        with open(path, "r") as f:
            s = f.read().strip().lower()
        if s == "":
            return None
        return s
    except FileNotFoundError:
        return None

def hex_to_base32(hex_seed: str) -> str:
    b = bytes.fromhex(hex_seed)
    return base64.b32encode(b).decode("utf-8")

def generate_totp_code(hex_seed: str) -> str:
    b32 = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(b32, digits=6, interval=30)
    return totp.now()

def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    b32 = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(b32, digits=6, interval=30)
    try:
        return totp.verify(code, valid_window=valid_window)
    except Exception:
        return False

def seconds_remaining_in_period() -> int:
    return 30 - (int(time.time()) % 30)

# Endpoints
@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/decrypt-seed")
async def decrypt_seed(payload: EncryptedSeedIn):
    try:
        private_key = load_private_key(PRIVATE_KEY_PATH)
    except Exception as e:
        logger.error("Private key load error: %s", e)
        raise HTTPException(status_code=500, detail="Private key load failed")
    try:
        seed = decrypt_seed_b64(payload.encrypted_seed, private_key)
    except ValueError as e:
        logger.error("Decryption failed: %s", e)
        raise HTTPException(status_code=500, detail="Decryption failed")
    try:
        save_seed(seed, SEED_PATH)
    except Exception as e:
        logger.exception("Failed to save seed")
        raise HTTPException(status_code=500, detail="Failed to save seed")
    logger.info("Seed decrypted and saved to %s", SEED_PATH)
    return {"status": "ok"}

@app.get("/generate-2fa")
async def generate_2fa():
    seed = read_seed()
    if not seed:
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")
    try:
        code = generate_totp_code(seed)
        valid_for = seconds_remaining_in_period()
        return {"code": code, "valid_for": valid_for}
    except Exception:
        logger.exception("TOTP generation failed")
        raise HTTPException(status_code=500, detail="TOTP generation failed")

@app.post("/verify-2fa")
async def verify_2fa(payload: CodeIn):
    if not payload.code:
        raise HTTPException(status_code=400, detail="Missing code")
    seed = read_seed()
    if not seed:
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")
    is_valid = verify_totp_code(seed, payload.code, valid_window=1)
    return {"valid": bool(is_valid)}