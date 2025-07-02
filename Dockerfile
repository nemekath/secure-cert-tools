FROM python:3.12-slim

LABEL maintainer="Benjamin"
LABEL description="Secure Cert-Tools - Professional certificate toolkit with CSR generation, validation, analysis, and verification capabilities"
LABEL version="2.4.0"
LABEL security.fixes="CVE-2024-6345,GHSA-5rjg-fvgr-3xxf"

# Set working directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install system dependencies and Python dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create a non-root user for security and setup directories
RUN adduser --disabled-password --gecos '' appuser && \
    mkdir -p /app/certs && \
    chmod +x start_server.py && \
    chown -R appuser:appuser /app
USER appuser

# Expose port 5555 (the port the Flask app uses)
EXPOSE 5555

# Health check (try HTTPS first, fall back to HTTP)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -k -f https://localhost:5555/ || curl -f http://localhost:5555/ || exit 1

# Default environment for production
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Run the application with startup script for HTTPS support
CMD ["python", "start_server.py"]
