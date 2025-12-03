import pyotp
import base64
import binascii

def hex_to_base32(hex_seed: str) -> str:
    """Convert 64-char hex seed to base32 string for TOTP."""
    try:
        # Convert hex string to bytes
        seed_bytes = binascii.unhexlify(hex_seed)
        # Base32 encode (pyotp expects base32)
        return base64.b32encode(seed_bytes).decode('utf-8')
    except Exception as e:
        raise ValueError(f"Invalid hex seed: {e}")

def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current 6-digit TOTP code.
    Uses SHA-1, 30-second time step (default), 6 digits.
    """
    base32_seed = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    return totp.now()

def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify a TOTP code with ±valid_window time steps tolerance.
    Default window=1 allows ±1 time step (±30 seconds).
    """
    base32_seed = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    return totp.verify(code, valid_window=valid_window)
