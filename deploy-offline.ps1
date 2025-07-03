# PowerShell script for offline Docker deployment on Windows
# Secure Cert-Tools Offline Deployment Script for Windows
# This script loads and runs the Docker image on a Windows machine without internet access

param(
    [int]$Port = 5555,
    [string]$DockerFile = "secure-cert-tools-offline.tar"
)

# Configuration
$ImageName = "secure-cert-tools-offline"
$ImageTag = "latest"
$ContainerName = "secure-cert-tools"

# Function to write colored output
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    } else {
        $input | Write-Output
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

function Write-Success($message) { Write-ColorOutput Green "✅ $message" }
function Write-Error($message) { Write-ColorOutput Red "❌ $message" }
function Write-Warning($message) { Write-ColorOutput Yellow "⚠️  $message" }
function Write-Info($message) { Write-ColorOutput Cyan "ℹ️  $message" }

Write-ColorOutput Blue "🚀 Secure Cert-Tools Offline Deployment for Windows"
Write-Output "==========================================="

# Check if Docker is installed
try {
    $dockerVersion = docker --version 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker command failed"
    }
    Write-Success "Docker is installed: $dockerVersion"
} catch {
    Write-Error "Docker is not installed or not in PATH"
    Write-Output "Please install Docker Desktop for Windows:"
    Write-Output "https://docs.docker.com/desktop/install/windows-install/"
    exit 1
}

# Check if Docker daemon is running
try {
    docker info 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker daemon not running"
    }
    Write-Success "Docker daemon is running"
} catch {
    Write-Error "Docker daemon is not running"
    Write-Output "Please start Docker Desktop and try again"
    exit 1
}

# Check if Docker image file exists
if (!(Test-Path $DockerFile)) {
    Write-Error "Docker image file '$DockerFile' not found"
    Write-Output "Expected files:"
    Write-Output "  - secure-cert-tools-offline.tar (64MB)"
    Write-Output "  - secure-cert-tools-offline.tar.gz (63MB, compressed)"
    Write-Output ""
    Write-Output "Current directory contents:"
    Get-ChildItem -Name "*.tar*" | ForEach-Object { Write-Output "  - $_" }
    exit 1
}

Write-Success "Docker image file found: $DockerFile"

# Stop and remove existing container if it exists
$existingContainer = docker ps -a --filter "name=$ContainerName" --format "{{.Names}}" 2>$null
if ($existingContainer -eq $ContainerName) {
    Write-Warning "Stopping existing container..."
    docker stop $ContainerName 2>$null | Out-Null
    docker rm $ContainerName 2>$null | Out-Null
    Write-Success "Existing container removed"
}

# Load the Docker image
Write-Info "Loading Docker image..."
try {
    if ($DockerFile.EndsWith(".gz")) {
        # For compressed files, we need to decompress first
        Write-Info "Decompressing and loading image..."
        if (Get-Command 7z -ErrorAction SilentlyContinue) {
            # Use 7-Zip if available
            7z x $DockerFile -so | docker load
        } elseif (Get-Command tar -ErrorAction SilentlyContinue) {
            # Use tar if available (Windows 10 1903+ has built-in tar)
            tar -xzOf $DockerFile | docker load
        } else {
            Write-Error "Cannot decompress .gz file. Please install 7-Zip or use the .tar file instead"
            Write-Output "Download 7-Zip from: https://www.7-zip.org/"
            exit 1
        }
    } else {
        docker load -i $DockerFile
    }
    
    if ($LASTEXITCODE -ne 0) {
        throw "Docker load failed"
    }
    Write-Success "Docker image loaded successfully"
} catch {
    Write-Error "Failed to load Docker image: $_"
    exit 1
}

# Verify the image was loaded
$loadedImage = docker images --filter "reference=$ImageName" --format "{{.Repository}}" 2>$null
if ($loadedImage -ne $ImageName) {
    Write-Error "Failed to verify loaded Docker image"
    exit 1
}

# Create and start the container
Write-Info "Starting Secure Cert-Tools container..."
try {
    $containerId = docker run -d `
        --name $ContainerName `
        -p "${Port}:5555" `
        -e FLASK_ENV=production `
        --restart unless-stopped `
        --health-cmd "curl -k -f https://localhost:5555/ || curl -f http://localhost:5555/ || exit 1" `
        --health-interval 30s `
        --health-timeout 10s `
        --health-retries 3 `
        "${ImageName}:${ImageTag}"
    
    if ($LASTEXITCODE -ne 0) {
        throw "Docker run failed"
    }
} catch {
    Write-Error "Failed to start container: $_"
    exit 1
}

# Wait for container to start
Write-Info "Waiting for container to start..."
Start-Sleep -Seconds 5

# Check if container is running
$runningContainer = docker ps --filter "name=$ContainerName" --format "{{.Names}}" 2>$null
if ($runningContainer -eq $ContainerName) {
    Write-Success "Container started successfully!"
    Write-Output ""
    Write-ColorOutput Blue "📍 Access Information:"
    Write-Output "  🌐 URL: https://localhost:$Port"
    Write-Output "  🔒 HTTPS: Enabled (self-signed certificate)"
    Write-Output "  📊 Status: docker ps | findstr $ContainerName"
    Write-Output "  📋 Logs: docker logs $ContainerName"
    Write-Output ""
    Write-Warning "Note: Your browser will show a security warning for the self-signed certificate."
    Write-Warning "This is normal and expected for local development/testing."
    Write-Output ""
    Write-ColorOutput Blue "🔧 Management Commands:"
    Write-Output "  Stop:    docker stop $ContainerName"
    Write-Output "  Start:   docker start $ContainerName"
    Write-Output "  Restart: docker restart $ContainerName"
    Write-Output "  Remove:  docker stop $ContainerName; docker rm $ContainerName"
    Write-Output ""
    Write-Success "🎉 Deployment completed successfully!"
} else {
    Write-Error "Container failed to start"
    Write-Output "Checking logs:"
    docker logs $ContainerName 2>&1
    exit 1
}
