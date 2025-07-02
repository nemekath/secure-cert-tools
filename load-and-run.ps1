# Secure Cert-Tools - Offline Deployment Script
# For Windows PowerShell

# Prompt user for script execution permission
$ExecutionPolicy = Get-ExecutionPolicy
if ($ExecutionPolicy -ne 'RemoteSigned' -and $ExecutionPolicy -ne 'Unrestricted') {
    Write-Host "Setting execution policy to RemoteSigned for current session..."
    Set-ExecutionPolicy RemoteSigned -Scope Process -Force
}

Write-Host "=================================================="
Write-Host "Secure Cert-Tools - Offline Deployment"
Write-Host "Version: 2.4.0"
Write-Host "=================================================="

# Check Docker service
if (-not (Get-Service -Name "docker" -ErrorAction SilentlyContinue)) {
    Write-Host "Docker service not found. Please install Docker and try again." -ForegroundColor Red
    exit 1
}

# Check if Docker is running
if ((Get-Service -Name 'docker').Status -ne 'Running') {
    Write-Host "Docker service is not running. Please start Docker and try again." -ForegroundColor Red
    exit 1
}

# Check if image file exists
$imageFile = "secure-cert-tools-v2.4.0-complete.tar"
if (-not (Test-Path $imageFile)) {
    Write-Host "Docker image file '$imageFile' not found." -ForegroundColor Red
    Write-Host "Please ensure the image file is in the current directory."
    exit 1
}

Write-Host "Loading Docker image from $imageFile..."
& docker load -i $imageFile

Write-Host "Docker image loaded successfully" -ForegroundColor Green

# Check if docker-compose.yml exists
if (-not (Test-Path "docker-compose.yml")) {
    Write-Host "Warning: docker-compose.yml not found. Creating basic configuration..." -ForegroundColor Yellow
    @'
version: '3.8'

services:
  secure-cert-tools:
    image: secure-cert-tools:2.4.0
    ports:
      - "5555:5555"
    environment:
      - FLASK_ENV=production
      - CERT_DOMAIN=localhost
    volumes:
      - cert_data:/app/certs
    healthcheck:
      test: ["CMD", "curl", "-k", "-f", "https://localhost:5555/", "||", "curl", "-f", "http://localhost:5555/", "||", "exit", "1"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
    restart: unless-stopped

volumes:
  cert_data:
    driver: local
'@ | Out-File -Encoding utf8 -FilePath docker-compose.yml
    Write-Host "Created basic docker-compose.yml" -ForegroundColor Green
}

Write-Host "Creating .env file from template..."
if (-not (Test-Path ".env") -and (Test-Path ".env.example")) {
    Copy-Item -Force .env.example .env
    Write-Host "Created .env file" -ForegroundColor Green
}

Write-Host "Starting application with Docker Compose..."
& docker-compose up -d

Write-Host "==================================================" -ForegroundColor Green
Write-Host "🚀 Deployment Complete!"
Write-Host "=================================================="

Write-Host "Access your application at:"
Write-Host "  HTTPS: https://localhost:5555"
Write-Host "  HTTP:  http://localhost:5555"

Write-Host "Management commands:"
Write-Host "  View logs:    docker-compose logs -f secure-cert-tools"
Write-Host "  Stop:         docker-compose down"
Write-Host "  Restart:      docker-compose restart"
Write-Host "  Status:       docker-compose ps"

Write-Host "The application may take 30-60 seconds to fully start." 
Write-Host "Check status with: docker-compose ps" -ForegroundColor Yellow
Write-Host "==================================================" -ForegroundColor Green

# Wait a moment and check if container is running
Start-Sleep -Seconds 5
if ((& docker-compose ps) -match "Up") {
    Write-Host "✓ Container is running successfully!" -ForegroundColor Green
} else {
    Write-Host "⚠ Container may still be starting. Check logs if needed:" -ForegroundColor Yellow
    Write-Host "   docker-compose logs secure-cert-tools"
}
