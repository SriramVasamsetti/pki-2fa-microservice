import urllib.request
import json
import sys

STUDENT_ID = "23P31A1232"
REPO_URL = "https://github.com/SriramVasamsetti/pki-2fa-microservice"
API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"

def get_seed():
    print(f"Reading public key for ID {STUDENT_ID}...")
    try:
        with open("student_public.pem", "r") as f:
            pub_key = f.read().replace('\r\n', '\n').strip()
            if not pub_key.endswith('\n'):
                pub_key += '\n'
    except FileNotFoundError:
        print("Error: student_public.pem not found!")
        sys.exit(1)
    
    payload = {
        "student_id": STUDENT_ID,
        "github_repo_url": REPO_URL,
        "public_key": pub_key
    }
    print(f"Sending request to Instructor API...")
    
    req = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    try:
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode('utf-8'))
            if result.get("status") == "success":
                enc_seed = result['encrypted_seed']
                with open("encrypted_seed.txt", "w") as f:
                    f.write(enc_seed)
                print("\n" + "="*50)
                print("SUCCESS! Encrypted seed saved to 'encrypted_seed.txt'")
                print("="*50 + "\n")
            else:
                print("API Error Response:", result)
    except urllib.error.HTTPError as e:
        error_message = e.read().decode()
        print(f"\nHTTP Request Failed ({e.code}):")
        print(error_message)
    except Exception as e:
        print(f"\nUnexpected Error: {e}")

if __name__ == "__main__":
    get_seed()
