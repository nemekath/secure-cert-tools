#!/bin/bash

# Secure Cert-Tools - Offline Deployment Script
# For Linux/macOS systems

set -e

echo "=================================================="
echo "Secure Cert-Tools - Offline Deployment"
echo "Version: 2.4.0"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running. Please start Docker and try again.${NC}"
    exit 1
fi

# Check if image file exists
IMAGE_FILE="secure-cert-tools-v2.4.0-complete.tar"
if [ ! -f "$IMAGE_FILE" ]; then
    echo -e "${RED}Error: Docker image file '$IMAGE_FILE' not found.${NC}"
    echo "Please ensure the image file is in the current directory."
    exit 1
fi

echo -e "${BLUE}Loading Docker image from $IMAGE_FILE...${NC}"
docker load -i "$IMAGE_FILE"

echo -e "${GREEN}✓ Docker image loaded successfully${NC}"

# Check if docker-compose.yml exists
if [ ! -f "docker-compose.yml" ]; then
    echo -e "${YELLOW}Warning: docker-compose.yml not found. Creating basic configuration...${NC}"
    cat > docker-compose.yml << 'EOF'
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
EOF
    echo -e "${GREEN}✓ Created basic docker-compose.yml${NC}"
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    echo -e "${BLUE}Creating .env file from template...${NC}"
    cp .env.example .env
    echo -e "${GREEN}✓ Created .env file${NC}"
fi

echo -e "${BLUE}Starting application with Docker Compose...${NC}"
docker-compose up -d

echo ""
echo -e "${GREEN}=================================================="
echo "🚀 Deployment Complete!"
echo "=================================================="
echo ""
echo "Access your application at:"
echo "  HTTPS: https://localhost:5555"
echo "  HTTP:  http://localhost:5555"
echo ""
echo "Management commands:"
echo "  View logs:    docker-compose logs -f secure-cert-tools"
echo "  Stop:         docker-compose down"
echo "  Restart:      docker-compose restart"
echo "  Status:       docker-compose ps"
echo ""
echo "The application may take 30-60 seconds to fully start."
echo -e "Check status with: ${YELLOW}docker-compose ps${NC}"
echo -e "${GREEN}=================================================="
echo -e "${NC}"

# Wait a moment and check if container is running
sleep 5
if docker-compose ps | grep -q "Up"; then
    echo -e "${GREEN}✓ Container is running successfully!${NC}"
else
    echo -e "${YELLOW}⚠ Container may still be starting. Check logs if needed:${NC}"
    echo "   docker-compose logs secure-cert-tools"
fi
