# Deployment Modes Guide

This guide explains the proper separation between development and production deployments for Secure Cert-Tools v2.4.0, following Flask best practices.

## Overview

Secure Cert-Tools supports two distinct deployment modes:

- **Development Mode**: Uses Flask's built-in development server with debug features
- **Production Mode**: Uses Gunicorn WSGI server for production-ready deployment

## Important Security Notice

**NEVER use Flask's development server in production!** 

Flask's development server:
- Is not designed for production workloads
- Has security vulnerabilities when exposed to the internet
- Lacks performance optimizations
- Will display a warning when used inappropriately

## Development Mode

### When to Use
- Local development and testing
- Debugging application issues
- Feature development

### Features
- Flask development server with debug mode
- Hot reload on code changes (if source is mounted)
- Detailed error pages
- Debug toolbar (optional)

### Configuration

**Option 1: Environment Variable**
```bash
export FLASK_ENV=development
docker-compose -f docker-compose.dev.yml up
```

**Option 2: Command Line Flag**
```bash
python start_server.py --dev
```

**Option 3: .env File**
```env
FLASK_ENV=development
DEBUG=true
```

### Docker Commands

```bash
# Development with Docker Compose
docker-compose -f docker-compose.dev.yml up -d

# Development with direct Docker run
docker run -e FLASK_ENV=development -p 5555:5555 secure-cert-tools:2.4.0
```

## Production Mode

### When to Use
- Production deployments
- Staging environments
- Performance testing
- Any internet-facing deployment

### Features
- Gunicorn WSGI server
- Multiple worker processes
- Production-optimized logging
- Better security and performance
- Automatic worker recycling

### Configuration

**Default Configuration**
```env
FLASK_ENV=production
DEBUG=false
```

### Docker Commands

```bash
# Production with Docker Compose (default)
docker-compose up -d

# Production with direct Docker run
docker run -e FLASK_ENV=production -p 5555:5555 secure-cert-tools:2.4.0
```

## Configuration Files

### docker-compose.yml (Production)
- Uses Gunicorn WSGI server
- Production environment variables
- Resource limits for stability
- Proper health checks

### docker-compose.dev.yml (Development)
- Uses Flask development server
- Debug mode enabled
- Optional source code mounting
- Relaxed resource limits

## Environment Variables

### Required for All Modes
- `CERT_DOMAIN`: Domain for SSL certificates (default: localhost)
- `PORT`: Server port (default: 5555)

### Production-Specific
- `FLASK_ENV=production` (enforced)
- `SECRET_KEY`: Secure secret key (required for sessions)
- `PYTHONUNBUFFERED=1`: Better logging output

### Development-Specific
- `FLASK_ENV=development`
- `DEBUG=true`: Enable Flask debug mode

## SSL/TLS Configuration

Both modes support HTTPS with:
- Self-signed certificates (auto-generated)
- Custom certificates (mounted via volumes)
- CA certificate installation (for custom CAs)

### Custom Certificates

```yaml
volumes:
  - ./certs/server.crt:/app/certs/server.crt:ro
  - ./certs/server.key:/app/certs/server.key:ro
```

## Performance Comparison

| Feature | Development | Production |
|---------|-------------|------------|
| Server | Flask dev server | Gunicorn WSGI |
| Workers | Single-threaded | Multi-process |
| Debug | Enabled | Disabled |
| Hot Reload | Yes | No |
| Performance | Low | High |
| Security | Basic | Enhanced |

## Deployment Examples

### Development Setup

**Option 1: With Docker Compose (Recommended)**
```bash
# 1. Load Docker image
docker load -i secure-cert-tools-v2.4.0-complete.tar

# 2. Create development environment
cp .env.example .env
echo "FLASK_ENV=development" >> .env
echo "DEBUG=true" >> .env

# 3. Start in development mode
docker-compose -f docker-compose.dev.yml up -d

# 4. Access application
open https://localhost:5555
```

**Option 2: Direct Python Execution**
```bash
# 1. Clone repository (if not using offline package)
git clone <repository-url>
cd secure-cert-tools

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set development mode
export FLASK_ENV=development

# 4. Run application
python start_server.py --dev

# 5. Access application
open https://localhost:5555
```

### Production Setup

```bash
# 1. Load Docker image
docker load -i secure-cert-tools-v2.4.0-complete.tar

# 2. Create production environment
cp .env.example .env
# Edit .env with production settings
# Set secure SECRET_KEY!

# 3. Start in production mode
docker-compose up -d

# 4. Verify deployment
docker-compose ps
docker-compose logs secure-cert-tools
```

### Quick Production Deployment

```bash
# Using the provided scripts
chmod +x load-and-run.sh
./load-and-run.sh
```

## Monitoring and Logs

### Development Logs
```bash
docker-compose -f docker-compose.dev.yml logs -f secure-cert-tools-dev
```

### Production Logs
```bash
docker-compose logs -f secure-cert-tools
```

## Security Best Practices

### Production Checklist
- Use `FLASK_ENV=production`
- Set secure `SECRET_KEY`
- Disable debug mode
- Use HTTPS with valid certificates
- Configure proper firewall rules
- Monitor logs for security events
- Regular security updates

### Development Checklist
- Only use on trusted networks
- Never expose development server to internet
- Use `FLASK_ENV=development`
- Enable debug mode for troubleshooting

## Troubleshooting

### Flask Development Server Warning

If you see:
```
WARNING: This is a development server. Do not use it in a production deployment.
```

**Solution**: Set `FLASK_ENV=production` to use Gunicorn instead.

### Performance Issues

**Development**: Expected - Flask dev server is single-threaded and not optimized
**Production**: Check Gunicorn worker configuration and resource limits

### Flask Development Server Warning

In development mode, you'll see:
```
WARNING: This is a development server. Do not use it in a production deployment.
```

This is normal and expected for development mode. The application automatically switches to Gunicorn when `FLASK_ENV=production`.

### SSL Certificate Issues

Both modes auto-generate self-signed certificates. For production:
1. Replace with CA-signed certificates
2. Mount certificates via Docker volumes
3. Update CERT_DOMAIN environment variable

## Migration Guide

### Development to Production

1. Change environment variables:
   ```bash
   FLASK_ENV=production
   DEBUG=false
   ```

2. Switch Docker Compose files:
   ```bash
   docker-compose -f docker-compose.dev.yml down
   docker-compose up -d
   ```

3. Verify Gunicorn is running:
   ```bash
   docker-compose logs | grep gunicorn
   ```

This deployment mode separation ensures optimal performance, security, and debugging capabilities for each environment.
