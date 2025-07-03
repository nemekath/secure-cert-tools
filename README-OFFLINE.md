# Secure Cert-Tools - Offline Deployment Package

This package contains everything needed to deploy Secure Cert-Tools on machines without internet access.

## 🚀 Quick Start

### Windows
```powershell
.\deploy-offline.ps1
```

### macOS/Linux
```bash
chmod +x deploy-offline-unix.sh
./deploy-offline-unix.sh
```

Then open: **https://localhost:5555**

## 📋 Requirements

- Docker Desktop (Windows/macOS) or Docker CE/EE (Linux)
- PowerShell (Windows) or Bash (macOS/Linux)

## 📄 Files Included

- `secure-cert-tools-offline.tar` (64MB) - Docker image
- `secure-cert-tools-offline.tar.gz` (63MB) - Compressed image
- `deploy-offline.ps1` - Windows deployment script
- `deploy-offline-unix.sh` - macOS/Linux deployment script
- `OFFLINE_DEPLOYMENT_GUIDE.md` - Complete instructions
- `README-OFFLINE.md` - This file

## 📖 Full Documentation

See `OFFLINE_DEPLOYMENT_GUIDE.md` for detailed instructions, troubleshooting, and advanced configuration options.

## 🔧 Common Commands

After deployment:

```bash
# Check status
docker ps | grep secure-cert-tools

# View logs
docker logs secure-cert-tools

# Stop/restart
docker stop secure-cert-tools
docker start secure-cert-tools
```

## ⚠️ Security Notice

The application uses self-signed certificates. Your browser will show a security warning - this is normal and expected.
