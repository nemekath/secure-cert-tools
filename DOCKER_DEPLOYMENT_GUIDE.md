# Docker Deployment Guide - Secure Cert-Tools

## Table of Contents

1. [Docker Overview](#docker-overview)
2. [Building the Container](#building-the-container)
3. [Running Containers](#running-containers)
4. [Docker Compose Deployment](#docker-compose-deployment)
5. [Production Deployment](#production-deployment)
6. [Security Configuration](#security-configuration)
7. [Monitoring and Maintenance](#monitoring-and-maintenance)
8. [Troubleshooting](#troubleshooting)

---

## Docker Overview

### Container Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                SECURE CERT-TOOLS CONTAINER                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │   Application   │    │   SSL/TLS       │                │
│  │                 │    │   Certificates  │                │
│  │ ├─ Flask App    │    │                 │                │
│  │ ├─ Dependencies │    │ ├─ server.crt   │                │
│  │ ├─ Static Files │    │ └─ server.key   │                │
│  │ └─ Templates    │    │                 │                │
│  └─────────────────┘    └─────────────────┘                │
│           │                       │                        │
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │   Python        │    │   Security      │                │
│  │   Runtime       │    │   Features      │                │
│  │                 │    │                 │                │
│  │ ├─ Python 3.12  │    │ ├─ Non-root usr │                │
│  │ ├─ pip packages │    │ ├─ Health checks│                │
│  │ └─ System libs  │    │ └─ Resource lmt │                │
│  └─────────────────┘    └─────────────────┘                │
├─────────────────────────────────────────────────────────────┤
│              Debian 12 (Bookworm) Slim Base                │
└─────────────────────────────────────────────────────────────┘
```

### Key Container Features

- **Base Image**: `python:3.12-slim` (Debian-based, security-focused)
- **Security**: Non-root user execution, minimal attack surface
- **Size**: Optimized for production (~200MB)
- **Health Checks**: Built-in container health monitoring
- **SSL/TLS**: Automatic certificate generation or custom mounting
- **Multi-Stage**: Optimized build process

---

## Building the Container

### Basic Build

```bash
# Build with default settings
docker build -t secure-cert-tools:2.6.0 .

# Build with custom tag
docker build -t myorg/secure-cert-tools:latest .

# Build with specific Docker file
docker build -f Dockerfile -t secure-cert-tools:2.6.0 .
```

### Advanced Build Options

```bash
# Build with build arguments
docker build \
  --build-arg PYTHON_VERSION=3.12 \
  --build-arg APP_VERSION=2.6.0 \
  -t secure-cert-tools:2.6.0 .

# Build for multiple architectures
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t secure-cert-tools:2.6.0 \
  --push .

# Build with no cache (clean build)
docker build --no-cache -t secure-cert-tools:2.6.0 .
```

### Multi-Stage Build Analysis

```dockerfile
# Stage 1: Dependencies and build
FROM python:3.12-slim as builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Production image
FROM python:3.12-slim
# Copy only what's needed from builder stage
COPY --from=builder /root/.local /root/.local
# Application code
COPY . .
# Security and runtime configuration
RUN adduser --disabled-password appuser
USER appuser
CMD ["python", "start_server.py"]
```

---

## Running Containers

### Development Mode

```bash
# Basic development container
docker run -d \
  --name secure-cert-tools-dev \
  -p 5555:5555 \
  -e FLASK_ENV=development \
  -e DEBUG=true \
  secure-cert-tools:2.6.0

# Development with volume mounting
docker run -d \
  --name secure-cert-tools-dev \
  -p 5555:5555 \
  -e FLASK_ENV=development \
  -e DEBUG=true \
  -v $(pwd)/certs:/app/certs \
  -v $(pwd)/logs:/app/logs \
  secure-cert-tools:2.6.0

# Interactive development (bash access)
docker run -it \
  --name secure-cert-tools-debug \
  -p 5555:5555 \
  -e FLASK_ENV=development \
  secure-cert-tools:2.6.0 /bin/bash
```

### Production Mode

```bash
# Basic production container
docker run -d \
  --name secure-cert-tools-prod \
  -p 443:5555 \
  -e FLASK_ENV=production \
  --restart unless-stopped \
  secure-cert-tools:2.6.0

# Production with custom certificates
docker run -d \
  --name secure-cert-tools-prod \
  -p 443:5555 \
  -e FLASK_ENV=production \
  -e CERT_DOMAIN=api.example.com \
  -v /etc/ssl/certs/api.example.com.crt:/app/certs/server.crt:ro \
  -v /etc/ssl/private/api.example.com.key:/app/certs/server.key:ro \
  --restart unless-stopped \
  --memory=512m \
  --cpus=1.0 \
  secure-cert-tools:2.6.0

# Production with logging
docker run -d \
  --name secure-cert-tools-prod \
  -p 443:5555 \
  -e FLASK_ENV=production \
  -v /var/log/secure-cert-tools:/app/logs \
  --log-driver json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  --restart unless-stopped \
  secure-cert-tools:2.6.0
```

### Testing Mode

```bash
# Testing container (CSRF disabled)
docker run -d \
  --name secure-cert-tools-test \
  -p 5556:5555 \
  -e TESTING=true \
  -e FLASK_ENV=testing \
  secure-cert-tools:2.6.0

# CI/CD testing with timeout
timeout 60s docker run \
  --name secure-cert-tools-ci \
  -p 5557:5555 \
  -e TESTING=true \
  -e FLASK_ENV=testing \
  secure-cert-tools:2.6.0
```

---

## Docker Compose Deployment

### Production Deployment (`docker-compose.yml`)

```yaml
version: '3.8'

services:
  secure-cert-tools:
    image: secure-cert-tools:2.6.0
    container_name: secure-cert-tools-prod
    ports:
      - "5555:5555"
    environment:
      - FLASK_ENV=production
      - CERT_DOMAIN=${CERT_DOMAIN:-localhost}
      - PYTHONUNBUFFERED=1
      - SECRET_KEY=${SECRET_KEY}
    volumes:
      - cert_data:/app/certs
      - ./logs:/app/logs
      # Custom certificates (optional)
      # - /etc/ssl/certs/server.crt:/app/certs/server.crt:ro
      # - /etc/ssl/private/server.key:/app/certs/server.key:ro
    healthcheck:
      test: ["CMD", "curl", "-k", "-f", "https://localhost:5555/version"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1.0'
        reservations:
          memory: 256M
          cpus: '0.5'
    networks:
      - secure-cert-network

  # Optional: Reverse proxy with nginx
  nginx:
    image: nginx:alpine
    container_name: nginx-proxy
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - secure-cert-tools
    restart: unless-stopped
    networks:
      - secure-cert-network

volumes:
  cert_data:
    driver: local

networks:
  secure-cert-network:
    driver: bridge
```

### Development Deployment (`docker-compose.dev.yml`)

```yaml
version: '3.8'

services:
  secure-cert-tools-dev:
    image: secure-cert-tools:2.6.0
    container_name: secure-cert-tools-dev
    build:
      context: .
      target: development  # Multi-stage build target
    ports:
      - "5555:5555"
    environment:
      - FLASK_ENV=development
      - DEBUG=true
      - PYTHONUNBUFFERED=1
    volumes:
      - cert_data:/app/certs
      - ./logs:/app/logs
      # Source code mounting for development
      - .:/app:ro
    restart: unless-stopped
    networks:
      - dev-network

  # Optional: Development database (if needed)
  redis:
    image: redis:alpine
    container_name: redis-dev
    ports:
      - "6379:6379"
    networks:
      - dev-network

volumes:
  cert_data:
    driver: local

networks:
  dev-network:
    driver: bridge
```

### High Availability Deployment (`docker-compose.ha.yml`)

```yaml
version: '3.8'

services:
  app:
    image: secure-cert-tools:2.6.0
    environment:
      - FLASK_ENV=production
      - CERT_DOMAIN=${CERT_DOMAIN}
    volumes:
      - cert_data:/app/certs
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
        order: start-first
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      resources:
        limits:
          memory: 512M
          cpus: '1.0'
        reservations:
          memory: 256M
          cpus: '0.5'
    healthcheck:
      test: ["CMD", "curl", "-k", "-f", "https://localhost:5555/version"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - app-network

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx-ha.conf:/etc/nginx/nginx.conf:ro
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 128M
          cpus: '0.5'
    depends_on:
      - app
    networks:
      - app-network

volumes:
  cert_data:
    driver: local

networks:
  app-network:
    driver: overlay
    attachable: true
```

### Running with Docker Compose

```bash
# Production deployment
docker-compose up -d

# Development deployment
docker-compose -f docker-compose.dev.yml up -d

# High availability deployment (Docker Swarm)
docker stack deploy -c docker-compose.ha.yml secure-cert-tools

# Scale services
docker-compose up -d --scale secure-cert-tools=3

# Update services
docker-compose pull
docker-compose up -d --force-recreate

# View logs
docker-compose logs -f secure-cert-tools

# Stop services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

---

## Production Deployment

### Docker Swarm Deployment

```bash
# Initialize Docker Swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.ha.yml secure-cert-tools

# Scale services
docker service scale secure-cert-tools_app=5

# Update service
docker service update \
  --image secure-cert-tools:2.6.1 \
  secure-cert-tools_app

# Monitor services
docker stack ps secure-cert-tools
docker service logs secure-cert-tools_app
```

### Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-cert-tools
  labels:
    app: secure-cert-tools
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-cert-tools
  template:
    metadata:
      labels:
        app: secure-cert-tools
    spec:
      containers:
      - name: secure-cert-tools
        image: secure-cert-tools:2.6.0
        ports:
        - containerPort: 5555
        env:
        - name: FLASK_ENV
          value: "production"
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: secret-key
        resources:
          limits:
            memory: "512Mi"
            cpu: "1000m"
          requests:
            memory: "256Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /version
            port: 5555
            scheme: HTTPS
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /version
            port: 5555
            scheme: HTTPS
          initialDelaySeconds: 5
          periodSeconds: 10
        volumeMounts:
        - name: cert-storage
          mountPath: /app/certs
      volumes:
      - name: cert-storage
        persistentVolumeClaim:
          claimName: cert-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: secure-cert-tools-service
spec:
  selector:
    app: secure-cert-tools
  ports:
  - port: 443
    targetPort: 5555
    protocol: TCP
  type: LoadBalancer
```

```bash
# Deploy to Kubernetes
kubectl apply -f k8s-deployment.yaml

# Scale deployment
kubectl scale deployment secure-cert-tools --replicas=5

# Update deployment
kubectl set image deployment/secure-cert-tools \
  secure-cert-tools=secure-cert-tools:2.6.1

# Monitor deployment
kubectl get pods -l app=secure-cert-tools
kubectl logs -f deployment/secure-cert-tools
```

### Cloud Deployment Examples

#### AWS ECS

```json
{
  "family": "secure-cert-tools",
  "taskRoleArn": "arn:aws:iam::account:role/ecsTaskRole",
  "executionRoleArn": "arn:aws:iam::account:role/ecsExecutionRole",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "containerDefinitions": [
    {
      "name": "secure-cert-tools",
      "image": "your-account.dkr.ecr.region.amazonaws.com/secure-cert-tools:2.6.0",
      "portMappings": [
        {
          "containerPort": 5555,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "FLASK_ENV",
          "value": "production"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/secure-cert-tools",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": [
          "CMD-SHELL",
          "curl -k -f https://localhost:5555/version || exit 1"
        ],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      }
    }
  ]
}
```

#### Google Cloud Run

```yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: secure-cert-tools
  annotations:
    run.googleapis.com/ingress: all
spec:
  template:
    metadata:
      annotations:
        run.googleapis.com/cpu-limit: "1000m"
        run.googleapis.com/memory-limit: "512Mi"
        run.googleapis.com/execution-environment: gen2
    spec:
      containerConcurrency: 10
      timeoutSeconds: 300
      containers:
      - name: secure-cert-tools
        image: gcr.io/project-id/secure-cert-tools:2.6.0
        ports:
        - containerPort: 5555
        env:
        - name: FLASK_ENV
          value: production
        - name: PORT
          value: "5555"
        resources:
          limits:
            cpu: 1000m
            memory: 512Mi
          requests:
            cpu: 500m
            memory: 256Mi
```

---

## Security Configuration

### Container Security Best Practices

#### 1. **Non-Root User Execution**

```dockerfile
# Create and use non-root user
RUN adduser --disabled-password --gecos '' appuser && \
    chown -R appuser:appuser /app
USER appuser

# Verify in running container
docker exec container-name whoami  # Should return 'appuser'
```

#### 2. **Resource Limits**

```bash
# CPU and memory limits
docker run -d \
  --name secure-cert-tools \
  --memory=512m \
  --cpus=1.0 \
  --pids-limit=100 \
  secure-cert-tools:2.6.0

# Using Docker Compose
services:
  app:
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1.0'
        reservations:
          memory: 256M
```

#### 3. **Read-Only Filesystem**

```bash
# Run with read-only root filesystem
docker run -d \
  --name secure-cert-tools \
  --read-only \
  --tmpfs /tmp \
  --tmpfs /var/run \
  -v cert_data:/app/certs \
  secure-cert-tools:2.6.0
```

#### 4. **Network Security**

```bash
# Custom network with isolation
docker network create --driver bridge secure-network

docker run -d \
  --name secure-cert-tools \
  --network secure-network \
  --no-new-privileges \
  secure-cert-tools:2.6.0

# Expose only necessary ports
docker run -d \
  --name secure-cert-tools \
  -p 127.0.0.1:5555:5555 \  # Bind to localhost only
  secure-cert-tools:2.6.0
```

#### 5. **Secrets Management**

```bash
# Using Docker secrets
echo "your-secret-key" | docker secret create app-secret-key -

docker service create \
  --name secure-cert-tools \
  --secret app-secret-key \
  --env SECRET_KEY_FILE=/run/secrets/app-secret-key \
  secure-cert-tools:2.6.0

# Using environment files
echo "SECRET_KEY=your-secret-key" > .env
docker run -d \
  --name secure-cert-tools \
  --env-file .env \
  secure-cert-tools:2.6.0
```

### SSL/TLS Certificate Management

#### 1. **Self-Signed Certificates (Development)**

```bash
# Automatic generation (default)
docker run -d \
  --name secure-cert-tools-dev \
  -p 5555:5555 \
  -e FLASK_ENV=development \
  secure-cert-tools:2.6.0

# Certificate persists in volume
docker run -d \
  --name secure-cert-tools-dev \
  -p 5555:5555 \
  -v cert_data:/app/certs \
  secure-cert-tools:2.6.0
```

#### 2. **Custom Certificates (Production)**

```bash
# Mount custom certificates
docker run -d \
  --name secure-cert-tools-prod \
  -p 443:5555 \
  -v /path/to/your.crt:/app/certs/server.crt:ro \
  -v /path/to/your.key:/app/certs/server.key:ro \
  -e CERT_DOMAIN=yourdomain.com \
  secure-cert-tools:2.6.0

# Using Docker secrets for certificates
docker secret create server-crt server.crt
docker secret create server-key server.key

docker service create \
  --name secure-cert-tools \
  --secret server-crt \
  --secret server-key \
  --mount type=bind,source=/run/secrets/server-crt,target=/app/certs/server.crt \
  --mount type=bind,source=/run/secrets/server-key,target=/app/certs/server.key \
  secure-cert-tools:2.6.0
```

#### 3. **Let's Encrypt Integration**

```yaml
# docker-compose with Let's Encrypt
version: '3.8'
services:
  app:
    image: secure-cert-tools:2.6.0
    volumes:
      - letsencrypt:/etc/letsencrypt:ro
    environment:
      - CERT_DOMAIN=yourdomain.com
      - CERTFILE=/etc/letsencrypt/live/yourdomain.com/fullchain.pem
      - KEYFILE=/etc/letsencrypt/live/yourdomain.com/privkey.pem

  certbot:
    image: certbot/certbot
    volumes:
      - letsencrypt:/etc/letsencrypt
      - certbot_webroot:/var/www/certbot
    command: certonly --webroot -w /var/www/certbot -d yourdomain.com --email admin@yourdomain.com --agree-tos --no-eff-email

volumes:
  letsencrypt:
  certbot_webroot:
```

---

## Monitoring and Maintenance

### Health Checks

```bash
# Built-in health check
docker ps  # Shows health status

# Manual health check
docker exec secure-cert-tools curl -k -f https://localhost:5555/version

# Custom health check
docker run -d \
  --name secure-cert-tools \
  --health-cmd="curl -k -f https://localhost:5555/version || exit 1" \
  --health-interval=30s \
  --health-timeout=10s \
  --health-retries=3 \
  secure-cert-tools:2.6.0
```

### Logging

```bash
# View container logs
docker logs secure-cert-tools

# Follow logs in real-time
docker logs -f secure-cert-tools

# View last 100 lines
docker logs --tail 100 secure-cert-tools

# Logs with timestamps
docker logs -t secure-cert-tools

# Configure log rotation
docker run -d \
  --name secure-cert-tools \
  --log-driver json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  secure-cert-tools:2.6.0
```

### Monitoring with Prometheus

```yaml
# docker-compose.monitoring.yml
version: '3.8'
services:
  app:
    image: secure-cert-tools:2.6.0
    labels:
      - "prometheus.io/scrape=true"
      - "prometheus.io/port=5555"
      - "prometheus.io/path=/metrics"

  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana

volumes:
  grafana_data:
```

### Container Updates

```bash
# Update to new version
docker pull secure-cert-tools:2.6.1

# Rolling update with zero downtime
docker run -d --name secure-cert-tools-new secure-cert-tools:2.6.1
# Test new container
docker stop secure-cert-tools
docker rm secure-cert-tools
docker rename secure-cert-tools-new secure-cert-tools

# Using Docker Compose
docker-compose pull
docker-compose up -d --force-recreate
```

### Backup and Recovery

```bash
# Backup certificates volume
docker run --rm \
  -v cert_data:/source:ro \
  -v $(pwd):/backup \
  alpine tar czf /backup/certs-backup.tar.gz -C /source .

# Restore certificates
docker run --rm \
  -v cert_data:/target \
  -v $(pwd):/backup \
  alpine tar xzf /backup/certs-backup.tar.gz -C /target

# Full container backup
docker commit secure-cert-tools secure-cert-tools:backup-$(date +%Y%m%d)
```

---

## Offline/Airgapped Deployment

For environments without internet access, secure facilities, or airgapped networks:

### Overview

Offline deployment enables running Secure Cert-Tools in environments completely isolated from the internet. This is essential for:
- Government and military installations
- Financial institutions with strict security policies
- Manufacturing facilities with isolated networks
- Research environments requiring complete network isolation
- High-security data centers

### Offline Package Components

```
offline-deployment-package/
├── secure-cert-tools-offline.tar.gz    # Compressed Docker image (~63MB)
├── deploy-offline-unix.sh              # Automated deployment for macOS/Linux
├── deploy-offline.ps1                  # PowerShell script for Windows
├── OFFLINE_DEPLOYMENT_GUIDE.md         # Complete instructions
└── README-OFFLINE.md                   # Quick start guide
```

### Quick Offline Deployment

#### macOS/Linux Deployment

```bash
# 1. Make script executable
chmod +x deploy-offline-unix.sh

# 2. Run automated deployment
./deploy-offline-unix.sh

# 3. Verify deployment
curl -k https://localhost:5555/version
```

#### Windows PowerShell Deployment

```powershell
# 1. Run PowerShell as Administrator (recommended)

# 2. Execute deployment script
.\deploy-offline.ps1

# 3. Verify deployment
Invoke-WebRequest -Uri "https://localhost:5555/version" -SkipCertificateCheck
```

### Manual Offline Deployment

For environments requiring manual installation:

```bash
# 1. Verify Docker installation
docker --version
docker info

# 2. Load the offline Docker image
docker load -i secure-cert-tools-offline.tar.gz

# 3. Verify image loaded successfully
docker images | grep secure-cert-tools-offline

# 4. Run the container in production mode
docker run -d \
  --name secure-cert-tools-offline \
  -p 5555:5555 \
  -e FLASK_ENV=production \
  --restart unless-stopped \
  --memory=512m \
  --cpus=1.0 \
  secure-cert-tools-offline:latest

# 5. Check container status
docker ps | grep secure-cert-tools-offline

# 6. Verify application is running
curl -k https://localhost:5555/version

# 7. Test functionality
curl -k https://localhost:5555/
```

### Advanced Offline Configuration

#### Custom Network Configuration

```bash
# Create isolated network
docker network create --driver bridge secure-offline-network

# Run container on custom network
docker run -d \
  --name secure-cert-tools-offline \
  --network secure-offline-network \
  -p 5555:5555 \
  -e FLASK_ENV=production \
  secure-cert-tools-offline:latest
```

#### Custom SSL Certificates

```bash
# Mount custom certificates for production
docker run -d \
  --name secure-cert-tools-offline \
  -p 5555:5555 \
  -e FLASK_ENV=production \
  -e CERT_DOMAIN=your-internal-domain.local \
  -v /path/to/your.crt:/app/certs/server.crt:ro \
  -v /path/to/your.key:/app/certs/server.key:ro \
  secure-cert-tools-offline:latest
```

#### Resource Constraints

```bash
# Deployment with specific resource limits
docker run -d \
  --name secure-cert-tools-offline \
  -p 5555:5555 \
  -e FLASK_ENV=production \
  --memory=256m \
  --cpus=0.5 \
  --pids-limit=100 \
  --read-only \
  --tmpfs /tmp \
  -v cert_data:/app/certs \
  secure-cert-tools-offline:latest
```

### Creating Your Own Offline Package

If you need to create a custom offline package:

```bash
# 1. Build the Docker image with custom tag
docker build -t secure-cert-tools-offline:custom .

# 2. Export as compressed archive
docker save secure-cert-tools-offline:custom | gzip  secure-cert-tools-custom.tar.gz

# 3. Verify archive integrity
file secure-cert-tools-custom.tar.gz
ls -lh secure-cert-tools-custom.tar.gz

# 4. Test the exported image
docker rmi secure-cert-tools-offline:custom  # Remove original
docker load -i secure-cert-tools-custom.tar.gz  # Load from archive
docker run --rm -p 5555:5555 secure-cert-tools-offline:custom
```

### Offline Security Considerations

#### Network Isolation Verification

```bash
# Verify container has no internet access
docker exec secure-cert-tools-offline ping -c 3 8.8.8.8
# Should fail with "ping: bad address" or network unreachable

# Check DNS resolution
docker exec secure-cert-tools-offline nslookup google.com
# Should fail in truly airgapped environment

# Verify no outbound network connections
docker exec secure-cert-tools-offline netstat -an
```

#### Container Security Hardening

```bash
# Run with enhanced security
docker run -d \
  --name secure-cert-tools-offline \
  -p 127.0.0.1:5555:5555 \  # Bind to localhost only
  -e FLASK_ENV=production \
  --read-only \
  --tmpfs /tmp:noexec,nosuid,size=100m \
  --cap-drop=ALL \
  --cap-add=CHOWN \
  --cap-add=SETGID \
  --cap-add=SETUID \
  --security-opt=no-new-privileges \
  --user appuser \
  -v cert_data:/app/certs \
  secure-cert-tools-offline:latest
```

### Offline Monitoring and Maintenance

#### Health Monitoring

```bash
# Monitor container health
watch -n 30 'docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"'

# Check application health endpoint
watch -n 60 'curl -k -s https://localhost:5555/version | jq .'

# Monitor resource usage
docker stats secure-cert-tools-offline
```

#### Log Management

```bash
# Configure log rotation for offline environment
docker run -d \
  --name secure-cert-tools-offline \
  -p 5555:5555 \
  -e FLASK_ENV=production \
  --log-driver json-file \
  --log-opt max-size=10m \
  --log-opt max-file=5 \
  -v /var/log/secure-cert-tools:/app/logs \
  secure-cert-tools-offline:latest

# View logs
docker logs -f secure-cert-tools-offline
tail -f /var/log/secure-cert-tools/app.log
```

### Troubleshooting Offline Deployment

#### Common Issues

**1. Docker Image Loading Fails**
```bash
# Check file integrity
file secure-cert-tools-offline.tar.gz
md5sum secure-cert-tools-offline.tar.gz

# Check available disk space
df -h

# Try loading with verbose output
docker load --input secure-cert-tools-offline.tar.gz
```

**2. Container Won't Start**
```bash
# Check Docker daemon status
sudo systemctl status docker

# Inspect container configuration
docker inspect secure-cert-tools-offline

# Check for port conflicts
netstat -tulpn | grep 5555
lsof -i :5555
```

**3. Application Not Accessible**
```bash
# Check container logs
docker logs secure-cert-tools-offline

# Verify port mapping
docker port secure-cert-tools-offline

# Test internal connectivity
docker exec secure-cert-tools-offline curl -k https://localhost:5555/version
```

**4. SSL Certificate Issues**
```bash
# Check certificate files
docker exec secure-cert-tools-offline ls -la /app/certs/

# Regenerate self-signed certificates
docker exec secure-cert-tools-offline rm -f /app/certs/server.*
docker restart secure-cert-tools-offline

# Test with certificate validation disabled
curl -k https://localhost:5555/version
```

### Offline Performance Optimization

```bash
# Optimize for minimal resource usage
docker run -d \
  --name secure-cert-tools-offline \
  -p 5555:5555 \
  -e FLASK_ENV=production \
  --memory=128m \
  --cpus=0.25 \
  --oom-kill-disable=false \
  secure-cert-tools-offline:latest

# Monitor performance
docker stats --no-stream secure-cert-tools-offline
```

For complete offline deployment documentation, see `OFFLINE_DEPLOYMENT_GUIDE.md`.

---

## Troubleshooting

### Common Issues

#### 1. **Container Won't Start**

```bash
# Check container logs
docker logs secure-cert-tools

# Run interactively to debug
docker run -it --rm secure-cert-tools:2.6.0 /bin/bash

# Check image layers
docker history secure-cert-tools:2.6.0

# Inspect container configuration
docker inspect secure-cert-tools
```

#### 2. **SSL/TLS Certificate Issues**

```bash
# Check certificate files
docker exec secure-cert-tools ls -la /app/certs/

# Test certificate validity
docker exec secure-cert-tools openssl x509 -in /app/certs/server.crt -text -noout

# Regenerate self-signed certificate
docker exec secure-cert-tools rm -f /app/certs/server.*
docker restart secure-cert-tools
```

#### 3. **Port Binding Issues**

```bash
# Check if port is already in use
netstat -tulpn | grep 5555
lsof -i :5555

# Use different port
docker run -d -p 5556:5555 secure-cert-tools:2.6.0

# Check Docker port mapping
docker port secure-cert-tools
```

#### 4. **Memory/Resource Issues**

```bash
# Check container resource usage
docker stats secure-cert-tools

# Increase memory limit
docker update --memory=1g secure-cert-tools

# Check system resources
df -h  # Disk space
free -h  # Memory
```

#### 5. **Network Connectivity**

```bash
# Test network connectivity
docker exec secure-cert-tools ping google.com

# Check DNS resolution
docker exec secure-cert-tools nslookup example.com

# Test application endpoint
docker exec secure-cert-tools curl -k https://localhost:5555/version

# Check container networking
docker network ls
docker network inspect bridge
```

### Debugging Tools

```bash
# Enter running container
docker exec -it secure-cert-tools /bin/bash

# Run one-off debugging container
docker run -it --rm \
  --network container:secure-cert-tools \
  --pid container:secure-cert-tools \
  alpine sh

# Copy files from container
docker cp secure-cert-tools:/app/logs/app.log ./debug.log

# Check container processes
docker exec secure-cert-tools ps aux
```

### Performance Tuning

```bash
# Optimize for production
docker run -d \
  --name secure-cert-tools-optimized \
  --memory=512m \
  --cpus=1.0 \
  --restart=unless-stopped \
  --log-driver=json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  -e FLASK_ENV=production \
  -e PYTHONUNBUFFERED=1 \
  secure-cert-tools:2.6.0

# Monitor performance
docker stats --no-stream secure-cert-tools

# Profile application in container
docker exec secure-cert-tools python -m cProfile -o profile.stats app.py
```

This comprehensive Docker deployment guide provides everything needed to successfully deploy, manage, and troubleshoot the Secure Cert-Tools application in containerized environments.
