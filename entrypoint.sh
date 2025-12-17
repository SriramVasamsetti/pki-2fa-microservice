#!/bin/bash
set -e

# Start cron daemon in background
echo "Starting cron daemon..."
service cron start

# Start FastAPI server
echo "Starting FastAPI server..."
exec python -m uvicorn app.main:app --host 0.0.0.0 --port 8080
