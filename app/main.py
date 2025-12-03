from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
from datetime import datetime, timezone
from app.crypto_utils import decrypt_seed, write_seed_to_file, read_seed_from_file
from app.totp_utils import generate_totp_code, verify_totp_code

app = FastAPI(title="PKI 2FA Microservice")

DATA_DIR = "/data"
SEED_FILE = os.path.join(DATA_DIR, "seed.txt")
PRIVATE_KEY_PATH = "/app/keys/student_private.pem"

# Ensure /data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

class DecryptSeedRequest(BaseModel):
    encrypted_seed: str

class VerifyCodeRequest(BaseModel):
    code: str

@app.post("/decrypt-seed")
async def decrypt_seed_endpoint(request: DecryptSeedRequest):
    """
    Decrypt the seed using student private key.
    Write 64-char hex seed to /data/seed.txt.
    """
    try:
        decrypted_seed = decrypt_seed(request.encrypted_seed, PRIVATE_KEY_PATH)
        
        # Validate it's 64-char hex
        if len(decrypted_seed) != 64 or not all(c in '0123456789abcdefABCDEF' for c in decrypted_seed):
            raise ValueError("Decrypted seed is not valid 64-char hex")
        
        write_seed_to_file(decrypted_seed, SEED_FILE)
        return {"status": "success", "message": "Seed decrypted and saved"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

@app.get("/generate-2fa")
async def generate_2fa():
    """
    Generate current 6-digit TOTP code.
    Reads seed from /data/seed.txt.
    """
    try:
        hex_seed = read_seed_from_file(SEED_FILE)
        code = generate_totp_code(hex_seed)
        return {"code": code, "timestamp": datetime.now(timezone.utc).isoformat()}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Seed file not found. Call /decrypt-seed first.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to generate code: {str(e)}")

@app.post("/verify-2fa")
async def verify_2fa(request: VerifyCodeRequest):
    """
    Verify a TOTP code with ±1 time-step tolerance.
    """
    try:
        hex_seed = read_seed_from_file(SEED_FILE)
        is_valid = verify_totp_code(hex_seed, request.code, valid_window=1)
        return {"valid": is_valid, "timestamp": datetime.now(timezone.utc).isoformat()}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Seed file not found. Call /decrypt-seed first.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Verification failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
