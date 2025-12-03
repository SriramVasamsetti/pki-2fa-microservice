#!/usr/bin/env python3
import os
import sys
from datetime import datetime, timezone
from app.crypto_utils import read_seed_from_file
from app.totp_utils import generate_totp_code

SEED_FILE = "/data/seed.txt"
CRON_LOG_FILE = "/cron/last_code.txt"

def main():
    try:
        # Read seed from /data/seed.txt
        hex_seed = read_seed_from_file(SEED_FILE)
        
        # Generate TOTP code
        code = generate_totp_code(hex_seed)
        
        # Get current UTC time
        now = datetime.now(timezone.utc)
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
        
        # Append to /cron/last_code.txt
        os.makedirs(os.path.dirname(CRON_LOG_FILE), exist_ok=True)
        with open(CRON_LOG_FILE, 'a') as f:
            f.write(f"{timestamp} - 2FA Code: {code}\n")
        
        print(f"{timestamp} - 2FA Code: {code}")
    except Exception as e:
        print(f"Error in cron script: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
