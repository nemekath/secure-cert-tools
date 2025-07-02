# Secure Cert-Tools - Offline Deployment Guide

## Package Contents

This deployment package contains everything needed to run Secure Cert-Tools in an offline environment:

- `secure-cert-tools-v2.4.0-complete.tar` - Complete Docker image with all recent changes
- `docker-compose.yml` - Production Docker Compose configuration (Gunicorn)
- `docker-compose.dev.yml` - Development Docker Compose configuration (Flask dev server)
- `docker-compose.swarm.yml` - Docker Swarm configuration (for production)
- `.env.example` - Environment variables template
- `offline-deployment-guide.md` - This deployment guide
- `load-and-run.sh` - Quick deployment script (Linux/macOS)
- `load-and-run.ps1` - Quick deployment script (Windows PowerShell)

## Prerequisites

The target machine must have:
- Docker Engine installed and running
- Docker Compose (for easier management)
- Minimum 300 MB free disk space
- Available port 5555 (or modify configuration)

## Quick Deployment

### Option 1: Automated Script (Recommended)

**Linux/macOS:**
```bash
chmod +x load-and-run.sh
./load-and-run.sh
```

**Windows PowerShell:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\load-and-run.ps1
```

### Option 2: Manual Steps

1. **Load the Docker image:**
   ```bash
docker load -i secure-cert-tools-v2.4.0-complete.tar
   ```

2. **Verify image loaded:**
   ```bash
   docker images | grep secure-cert-tools
   # On Windows PowerShell:
   # docker images | Select-String secure-cert-tools
   ```

3. **Run with Docker Compose:**
   ```bash
   docker-compose up -d
   ```

4. **Access the application:**
   - HTTPS: https://localhost:5555
   - HTTP: http://localhost:5555

## Configuration Options

### Environment Variables

Create a `.env` file from the template:
```bash
cp .env.example .env
```

Key variables:
- `FLASK_ENV=production` - Environment mode (production uses Gunicorn, development uses Flask dev server)
- `CERT_DOMAIN=localhost` - Domain for certificates
- `SECRET_KEY=your-secure-key` - Required for production
- `DEBUG=false` - Debug mode (development only)

### Custom Certificates

To use your own certificates, place them in a `certs/` directory:
```
certs/
├── cacert-chain.pem    # CA certificate chain
├── servercert.pem      # Server certificate  
├── privatekey.pem      # Private key
└── private-ca.crt      # Legacy CA certificate (optional)
```

Then uncomment the certificate volume mounts in `docker-compose.yml`.

### Port Configuration

To use a different port, edit `docker-compose.yml`:
```yaml
ports:
  - "8080:5555"  # Use port 8080 instead of 5555
```

## Production Deployment (Docker Swarm)

For production environments with high availability:

1. **Initialize Docker Swarm:**
   ```bash
   docker swarm init
   ```

2. **Create Docker secrets:**
   ```bash
   echo "your-secure-secret-key" | docker secret create flask_secret_key_v1 -
   docker secret create cacert_chain_v1 certs/cacert-chain.pem
   docker secret create server_cert_v1 certs/servercert.pem
   docker secret create private_key_v1 certs/privatekey.pem
   ```

3. **Deploy the stack:**
   ```bash
   docker stack deploy -c docker-compose.swarm.yml secure-cert-tools
   ```

## Management Commands

**View logs:**
```bash
docker-compose logs -f secure-cert-tools
```

**Stop the service:**
```bash
docker-compose down
```

**Update and restart:**
```bash
docker-compose up -d --force-recreate
```

**Check health:**
```bash
docker-compose ps
```

## Security Features

- **Production Mode**: Uses Gunicorn WSGI server with multiple workers (no Flask dev server warnings)
- **Development Mode**: Uses Flask development server with debug features (development only)
- Application runs as non-root user (`appuser`)
- Automatic self-signed certificate generation
- Support for custom CA certificates
- HTTPS by default with HTTP fallback
- Secure file permissions and directory structure
- Comprehensive security testing (22+ security tests)

## Troubleshooting

### Port Already in Use
Change the port mapping in `docker-compose.yml`:
```yaml
ports:
  - "8080:5555"
```

### Certificate Issues
Check logs for CA certificate installation messages:
```bash
docker-compose logs secure-cert-tools | grep -i certificate
```

### Permission Denied
Ensure Docker has proper permissions and the user is in the docker group:
```bash
sudo usermod -aG docker $USER
# Logout and login again
```

### Container Won't Start
Check if the image loaded correctly:
```bash
docker images | grep secure-cert-tools
```

## Application Features

Once running, the application provides:

- **CSR Generation**: Create certificate signing requests
- **Certificate Validation**: Verify certificate chains and validity
- **Certificate Analysis**: Detailed certificate inspection
- **Security Scanning**: Check for common certificate issues
- **Modern Web Interface**: Responsive design with dark/light themes
- **API Access**: REST API for automated operations

## Support

For issues or questions:
1. Check the container logs first
2. Verify network connectivity and port availability
3. Ensure Docker daemon is running
4. Review the main project documentation

## Version Information

- **Application Version**: 2.4.0
- **Docker Image Size**: 246 MB
- **Base Image**: python:3.12-slim
- **Server Technology**: Gunicorn (production) / Flask dev server (development)
- **Security Patches**: CVE-2024-6345, GHSA-5rjg-fvgr-3xxf, CVE-2023-45853 included
- **Test Coverage**: 185+ tests with 89% coverage including 22+ security tests

This offline deployment package is completely self-contained and does not require internet connectivity during deployment or operation.
