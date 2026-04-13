# ArgusML — Autonomous ML-powered IDPS
# Built by Juan Manuel De La Garza

FROM python:3.12-slim

LABEL maintainer="Juan Manuel De La Garza"
LABEL description="ArgusML — Autonomous ML-powered Intrusion Detection & Prevention System"
LABEL version="1.0.0"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/models /app/datasets /app/output \
    /var/lib/suricata/rules /var/log/suricata

# Expose ports
EXPOSE 5000 5001

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV ARGUSML_ENV=docker

# Default command
CMD ["python3", "argus_ml.py"]
