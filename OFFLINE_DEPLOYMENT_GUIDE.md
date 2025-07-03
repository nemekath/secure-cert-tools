# Secure Cert-Tools - Offline Deployment Guide

This guide provides step-by-step instructions for deploying Secure Cert-Tools on machines without internet access using pre-built Docker images.

## 📦 Package Contents

Your offline deployment package should contain:

- `secure-cert-tools-offline.tar` (64MB) - Docker image file
- `secure-cert-tools-offline.tar.gz` (63MB) - Compressed Docker image file
- `deploy-offline-unix.sh` - Deployment script for macOS/Linux
- `deploy-offline.ps1` - PowerShell deployment script for Windows
- `OFFLINE_DEPLOYMENT_GUIDE.md` - This guide

## 🖥️ Platform-Specific Instructions

### Windows Deployment

#### Prerequisites
1. **Docker Desktop for Windows** installed and running
   - Download from: https://docs.docker.com/desktop/install/windows-install/
   - Ensure Docker Desktop is started and running

2. **PowerShell** (pre-installed on Windows 10/11)

#### Deployment Steps

1. **Copy Files**
   ```
   Copy the following files to your Windows machine:
   - secure-cert-tools-offline.tar (or .tar.gz)
   - deploy-offline.ps1
   ```

2. **Open PowerShell as Administrator**
   - Right-click on PowerShell and select "Run as Administrator"
   - Navigate to the directory containing the files

3. **Set Execution Policy** (if needed)
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

4. **Run Deployment Script**
   ```powershell
   # Basic deployment (uses port 5555)
   .\deploy-offline.ps1
   
   # Custom port
   .\deploy-offline.ps1 -Port 8443
   
   # Use compressed file
   .\deploy-offline.ps1 -DockerFile "secure-cert-tools-offline.tar.gz"
   ```

5. **Access Application**
   - Open browser and navigate to: https://localhost:5555
   - Accept the self-signed certificate warning

#### Windows Management Commands
```powershell
# Check status
docker ps | findstr secure-cert-tools

# View logs
docker logs secure-cert-tools

# Stop container
docker stop secure-cert-tools

# Start container
docker start secure-cert-tools

# Remove container
docker stop secure-cert-tools; docker rm secure-cert-tools
```

---

### macOS/Linux Deployment

#### Prerequisites
1. **Docker** installed and running
   - macOS: Docker Desktop for Mac
   - Linux: Docker CE/EE
   - Verify with: `docker --version`

2. **Bash shell** (standard on macOS/Linux)

#### Deployment Steps

1. **Copy Files**
   ```bash
   # Copy files to your target machine
   scp secure-cert-tools-offline.tar* deploy-offline-unix.sh user@target-machine:/path/to/deployment/
   ```

2. **Make Script Executable**
   ```bash
   chmod +x deploy-offline-unix.sh
   ```

3. **Run Deployment Script**
   ```bash
   # Basic deployment (uses port 5555)
   ./deploy-offline-unix.sh
   
   # Custom port
   PORT=8443 ./deploy-offline-unix.sh
   
   # Use compressed file (rename it first)
   mv secure-cert-tools-offline.tar.gz secure-cert-tools-offline.tar
   ./deploy-offline-unix.sh
   ```

4. **Access Application**
   - Open browser and navigate to: https://localhost:5555
   - Accept the self-signed certificate warning

#### macOS/Linux Management Commands
```bash
# Check status
docker ps | grep secure-cert-tools

# View logs
docker logs secure-cert-tools

# Stop container
docker stop secure-cert-tools

# Start container
docker start secure-cert-tools

# Remove container
docker stop secure-cert-tools && docker rm secure-cert-tools
```

---

## 🔧 Advanced Configuration

### Custom Port Configuration

**Windows:**
```powershell
.\deploy-offline.ps1 -Port 8443
```

**macOS/Linux:**
```bash
PORT=8443 ./deploy-offline-unix.sh
```

### Using Compressed Files

If you want to save bandwidth and use the compressed `.tar.gz` file:

**Windows:**
- Ensure 7-Zip is installed OR use Windows 10 1903+ built-in tar
- Run: `.\deploy-offline.ps1 -DockerFile "secure-cert-tools-offline.tar.gz"`

**macOS/Linux:**
- Rename the file: `mv secure-cert-tools-offline.tar.gz secure-cert-tools-offline.tar`
- The script will auto-detect and decompress

### Container Persistence

The container is configured with `--restart unless-stopped`, meaning:
- It will automatically restart if it crashes
- It will restart when the machine reboots
- It will only stop when explicitly stopped with `docker stop`

---

## 🛠️ Troubleshooting

### Common Issues

#### Docker Not Running
**Symptoms:** "Docker daemon is not running"
**Solutions:**
- **Windows:** Start Docker Desktop from Start Menu
- **macOS:** Start Docker Desktop from Applications
- **Linux:** `sudo systemctl start docker`

#### Port Already in Use
**Symptoms:** "Port 5555 is already allocated"
**Solutions:**
- Use a different port: `-Port 8443` (Windows) or `PORT=8443` (Unix)
- Stop conflicting service: `docker stop $(docker ps -q --filter "publish=5555")`

#### File Not Found
**Symptoms:** "Docker image file not found"
**Solutions:**
- Verify file exists in current directory: `ls *.tar*` (Unix) or `dir *.tar*` (Windows)
- Check file permissions: `chmod 644 *.tar*` (Unix)

#### Certificate Warnings
**Symptoms:** Browser shows "Your connection is not private"
**Solutions:**
- Click "Advanced" → "Proceed to localhost (unsafe)"
- This is expected behavior with self-signed certificates

### Manual Docker Commands

If the scripts fail, you can deploy manually:

1. **Load Image:**
   ```bash
   docker load -i secure-cert-tools-offline.tar
   ```

2. **Run Container:**
   ```bash
   docker run -d \
     --name secure-cert-tools \
     -p 5555:5555 \
     -e FLASK_ENV=production \
     --restart unless-stopped \
     secure-cert-tools-offline:latest
   ```

---

## 📊 Resource Requirements

- **CPU:** 1 core minimum, 2+ cores recommended
- **RAM:** 512MB minimum, 1GB recommended  
- **Disk:** 500MB for image + 100MB for container
- **Network:** Port 5555 (default) or custom port

---

## 🔒 Security Notes

1. **Self-Signed Certificates:** The application generates self-signed certificates automatically. For production use, replace with valid CA-signed certificates.

2. **Network Security:** The application runs on localhost by default. To expose on network, modify the Docker run command to include `-p 0.0.0.0:5555:5555`.

3. **Container Security:** The container runs as a non-root user (`appuser`) for enhanced security.

4. **Data Persistence:** No persistent data is stored. All CSRs and keys are generated in memory and downloaded by the user.

---

## 📞 Support

If you encounter issues:

1. Check the container logs: `docker logs secure-cert-tools`
2. Verify Docker is running: `docker info`
3. Ensure the image file is not corrupted: check file size matches expected values
4. Try the manual deployment steps if scripts fail

---

## 🎯 Quick Reference

### File Sizes
- `secure-cert-tools-offline.tar`: ~64MB
- `secure-cert-tools-offline.tar.gz`: ~63MB
- Docker image when loaded: ~308MB

### Default Access
- **URL:** https://localhost:5555
- **Container Name:** secure-cert-tools
- **Image Name:** secure-cert-tools-offline:latest

### Key Commands
```bash
# Status
docker ps | grep secure-cert-tools

# Logs  
docker logs secure-cert-tools

# Stop/Start
docker stop secure-cert-tools
docker start secure-cert-tools
```
