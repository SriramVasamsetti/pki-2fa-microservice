# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

WORKDIR /app

# Install cron and other runtime tools
RUN apt-get update && apt-get install -y \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Set timezone
ENV TZ=UTC

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Copy application code
COPY app /app/app
COPY scripts/ ./scripts/
COPY cron/2fa-cron /etc/cron.d/2fa-cron

# Set correct permissions for cron file
RUN chmod 0644 /etc/cron.d/2fa-cron

# Create /data and /cron directories
RUN mkdir -p /data /cron

# Expose port for API
EXPOSE 8080

# Copy entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Start cron daemon and FastAPI app
ENTRYPOINT ["/app/entrypoint.sh"]
