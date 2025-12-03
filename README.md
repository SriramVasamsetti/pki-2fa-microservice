# PKI 2FA Microservice

A FastAPI-based microservice for PKI-based 2FA using TOTP (Time-based One-Time Password).

## Features
- RSA encryption/decryption of seeds using 4096-bit keys
- TOTP code generation and verification (SHA-1, 30s interval, 6 digits)
- Cron-based periodic TOTP code logging
- Docker and Docker Compose support
- UTC timezone normalization

## API Endpoints

### POST /decrypt-seed
Decrypt the encrypted seed and save to /data/seed.txt.

### GET /generate-2fa
Generate current 6-digit TOTP code.

### POST /verify-2fa
Verify a TOTP code with ±1 time-step tolerance.

## Setup
Generate RSA keys:

openssl genrsa -out keys/student_private.pem 4096
openssl rsa -in keys/student_private.pem -pubout -out keys/student_public.pem

Run with Docker:

docker-compose up
