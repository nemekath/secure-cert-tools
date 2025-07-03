#!/bin/bash
# Offline Docker Deployment Script for Secure Cert-Tools
# This script loads and runs the Docker image on a machine without internet access

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="secure-cert-tools-offline"
IMAGE_TAG="latest"
CONTAINER_NAME="secure-cert-tools"
PORT="${PORT:-5555}"
DOCKER_FILE="secure-cert-tools-offline.tar"

echo -e "${BLUE}🚀 Secure Cert-Tools Offline Deployment${NC}"
echo "========================================"

# Check if Docker is installed and running
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed or not in PATH${NC}"
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo -e "${RED}❌ Docker daemon is not running${NC}"
    echo "Please start Docker and try again"
    exit 1
fi

echo -e "${GREEN}✅ Docker is available${NC}"

# Check if Docker image file exists
if [ ! -f "$DOCKER_FILE" ]; then
    echo -e "${RED}❌ Docker image file '$DOCKER_FILE' not found${NC}"
    echo "Expected files:"
    echo "  - secure-cert-tools-offline.tar (64MB)"
    echo "  - secure-cert-tools-offline.tar.gz (63MB, compressed)"
    exit 1
fi

echo -e "${GREEN}✅ Docker image file found${NC}"

# Stop and remove existing container if it exists
if docker ps -a | grep -q "$CONTAINER_NAME"; then
    echo -e "${YELLOW}🔄 Stopping existing container...${NC}"
    docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    docker rm "$CONTAINER_NAME" >/dev/null 2>&1 || true
fi

# Load the Docker image
echo -e "${BLUE}📦 Loading Docker image...${NC}"
if [[ "$DOCKER_FILE" == *.gz ]]; then
    gunzip -c "$DOCKER_FILE" | docker load
else
    docker load -i "$DOCKER_FILE"
fi

echo -e "${GREEN}✅ Docker image loaded successfully${NC}"

# Verify the image was loaded
if ! docker images | grep -q "$IMAGE_NAME"; then
    echo -e "${RED}❌ Failed to load Docker image${NC}"
    exit 1
fi

# Create and start the container
echo -e "${BLUE}🚀 Starting Secure Cert-Tools container...${NC}"
docker run -d \
    --name "$CONTAINER_NAME" \
    -p "$PORT:5555" \
    -e FLASK_ENV=production \
    --restart unless-stopped \
    --health-cmd="curl -k -f https://localhost:5555/ || curl -f http://localhost:5555/ || exit 1" \
    --health-interval=30s \
    --health-timeout=10s \
    --health-retries=3 \
    "$IMAGE_NAME:$IMAGE_TAG"

# Wait a moment for the container to start
echo -e "${YELLOW}⏳ Waiting for container to start...${NC}"
sleep 5

# Check if container is running
if docker ps | grep -q "$CONTAINER_NAME"; then
    echo -e "${GREEN}✅ Container started successfully!${NC}"
    echo ""
    echo -e "${BLUE}📍 Access Information:${NC}"
    echo "  🌐 URL: https://localhost:$PORT"
    echo "  🔒 HTTPS: Enabled (self-signed certificate)"
    echo "  📊 Status: docker ps | grep $CONTAINER_NAME"
    echo "  📋 Logs: docker logs $CONTAINER_NAME"
    echo ""
    echo -e "${YELLOW}⚠️  Note: Your browser will show a security warning for the self-signed certificate.${NC}"
    echo -e "${YELLOW}   This is normal and expected for local development/testing.${NC}"
    echo ""
    echo -e "${GREEN}🎉 Deployment completed successfully!${NC}"
else
    echo -e "${RED}❌ Container failed to start${NC}"
    echo "Checking logs:"
    docker logs "$CONTAINER_NAME" 2>&1 || true
    exit 1
fi
