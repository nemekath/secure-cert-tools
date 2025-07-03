# Production Deployment Guide
## Secure CSR Generator with Session-Based Encryption

**Version:** 2.1.0  
**Last Updated:** 2025-01-03  
**Security Level:** Enterprise-Grade

---

## Pre-Deployment Security Checklist

### ✅ Required Security Validations

Before deploying to production, ensure all security requirements are met:

#### 1. **Security Audit Verification**
- [ ] Review `SECURITY_AUDIT_REPORT.md` and confirm all findings are addressed
- [ ] Verify all cryptographic implementations are production-ready
- [ ] Confirm session-based encryption is enabled and tested
- [ ] Validate all security claims through test execution

#### 2. **Environment Security**
- [ ] HTTPS enforced (TLS 1.2+ required)
- [ ] Valid TLS certificates deployed (not self-signed)
- [ ] Secure secret management implemented
- [ ] Firewall rules configured (allow only necessary ports)
- [ ] System hardening completed per organizational standards

#### 3. **Application Security**
- [ ] `FLASK_ENV=production` configured
- [ ] CSRF protection enabled (`TESTING=false`)
- [ ] Rate limiting configured appropriately
- [ ] Security headers verified
- [ ] Session timeout configured (default: 1 hour)
- [ ] Log sanitization enabled

---

## Deployment Options

### Option 1: Docker Deployment (Recommended)

#### Standard Docker Deployment
```bash
# Build production image
docker build -t secure-cert-tools:latest .

# Run with security configurations
docker run -d \
  --name secure-cert-tools \
  -p 443:5555 \
  -e FLASK_ENV=production \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e CERT_DOMAIN=your-domain.com \
  -v /etc/ssl/certs:/app/certs:ro \
  --restart unless-stopped \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp \
  secure-cert-tools:latest
```

#### Docker Compose Deployment
```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  secure-cert-tools:
    build: .
    ports:
      - "443:5555"
    environment:
      - FLASK_ENV=production
      - SECRET_KEY_FILE=/run/secrets/flask_secret
      - CERT_DOMAIN=your-domain.com
    secrets:
      - flask_secret
    volumes:
      - /etc/ssl/certs:/app/certs:ro
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp

secrets:
  flask_secret:
    file: ./secrets/flask_secret.txt
```

Deploy with:
```bash
docker-compose -f docker-compose.prod.yml up -d
```

### Option 2: Kubernetes Deployment

#### Kubernetes Manifests
```yaml
# k8s-deployment.yml
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
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: secure-cert-tools
        image: secure-cert-tools:latest
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
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        livenessProbe:
          httpGet:
            path: /version
            port: 5555
            scheme: HTTPS
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /version
            port: 5555
            scheme: HTTPS
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: tmp
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: secure-cert-tools-service
spec:
  selector:
    app: secure-cert-tools
  ports:
  - protocol: TCP
    port: 443
    targetPort: 5555
  type: LoadBalancer
```

### Option 3: Traditional Server Deployment

#### System Preparation
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3.9+
sudo apt install python3.9 python3.9-venv python3.9-dev

# Create application user
sudo useradd -r -s /bin/false certtools
sudo mkdir -p /opt/secure-cert-tools
sudo chown certtools:certtools /opt/secure-cert-tools
```

#### Application Setup
```bash
# Switch to application user
sudo -u certtools bash

# Setup application
cd /opt/secure-cert-tools
python3.9 -m venv venv
source venv/bin/activate
pip install --upgrade pip

# Clone and install
git clone https://github.com/nemekath/secure-cert-tools.git .
pip install -r requirements.txt

# Set permissions
chmod -R 750 .
```

#### Systemd Service
```ini
# /etc/systemd/system/secure-cert-tools.service
[Unit]
Description=Secure Cert Tools - CSR Generator
After=network.target

[Service]
Type=exec
User=certtools
Group=certtools
WorkingDirectory=/opt/secure-cert-tools
Environment=FLASK_ENV=production
Environment=SECRET_KEY_FILE=/etc/secure-cert-tools/secret-key
ExecStart=/opt/secure-cert-tools/venv/bin/python start_server.py
Restart=always
RestartSec=5

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/secure-cert-tools/logs
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable secure-cert-tools
sudo systemctl start secure-cert-tools
```

---

## Security Configuration

### Environment Variables (Production)

#### Required Variables
```bash
# Core Configuration
export FLASK_ENV=production
export SECRET_KEY="$(openssl rand -hex 32)"

# Security Settings
export TESTING=false  # Enables CSRF protection
export WTF_CSRF_ENABLED=true

# SSL/TLS Configuration
export CERT_DOMAIN=your-domain.com
export CERTFILE=/path/to/certificate.pem
export KEYFILE=/path/to/private-key.pem

# Session Configuration
export SESSION_TIMEOUT=3600  # 1 hour
export MAX_CONTENT_LENGTH=1048576  # 1MB
```

#### Optional Security Variables
```bash
# Rate Limiting
export RATE_LIMIT_STORAGE_URL=redis://localhost:6379
export RATE_LIMIT_PER_MINUTE=10
export RATE_LIMIT_PER_HOUR=100

# Monitoring
export SENTRY_DSN=your-sentry-dsn
export LOG_LEVEL=INFO
```

### TLS/SSL Configuration

#### Certificate Requirements
- **Minimum**: TLS 1.2
- **Recommended**: TLS 1.3
- **Certificate Type**: Valid domain certificate (not self-signed)
- **Key Size**: Minimum 2048-bit RSA or P-256 ECDSA

#### Obtaining Certificates

**Let's Encrypt (Recommended):**
```bash
# Install certbot
sudo apt install certbot

# Obtain certificate
sudo certbot certonly --standalone -d your-domain.com

# Configure auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

**Corporate CA:**
```bash
# Place certificates in secure location
sudo mkdir -p /etc/ssl/secure-cert-tools
sudo chmod 700 /etc/ssl/secure-cert-tools

# Set environment variables
export CERTFILE=/etc/ssl/secure-cert-tools/cert.pem
export KEYFILE=/etc/ssl/secure-cert-tools/key.pem
```

### Firewall Configuration

#### Basic iptables Rules
```bash
# Allow SSH (change port as needed)
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTPS
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Drop all other input
sudo iptables -P INPUT DROP

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

#### UFW (Ubuntu Firewall)
```bash
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 443/tcp
sudo ufw status
```

---

## Load Balancer and Reverse Proxy

### Nginx Configuration

#### SSL Termination at Nginx
```nginx
# /etc/nginx/sites-available/secure-cert-tools
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    # SSL Configuration
    ssl_certificate /etc/ssl/certs/your-domain.com.crt;
    ssl_certificate_key /etc/ssl/private/your-domain.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    
    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/m;
    limit_req zone=api burst=5 nodelay;
    
    location / {
        proxy_pass http://127.0.0.1:5555;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Security
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}
```

### HAProxy Configuration

#### High Availability Setup
```
# /etc/haproxy/haproxy.cfg
global
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option httplog

frontend secure_cert_tools_frontend
    bind *:443 ssl crt /etc/ssl/certs/your-domain.com.pem
    redirect scheme https if !{ ssl_fc }
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header X-Content-Type-Options "nosniff"
    http-response set-header X-Frame-Options "DENY"
    
    # Rate limiting
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src
    http-request reject if { sc_http_req_rate(0) gt 20 }
    
    default_backend secure_cert_tools_backend

backend secure_cert_tools_backend
    balance roundrobin
    option httpchk GET /version
    server app1 127.0.0.1:5555 check
    server app2 127.0.0.1:5556 check
    server app3 127.0.0.1:5557 check
```

---

## Monitoring and Observability

### Health Check Endpoints

The application provides several monitoring endpoints:

#### Version and Health
```bash
# Basic health check
curl -k https://your-domain.com/version

# Session crypto statistics
curl -k https://your-domain.com/session-stats
```

#### Expected Responses
```json
{
  "version": "2.1.0",
  "release_date": "2025-01-03",
  "project_name": "Secure Cert-Tools",
  "description": "Professional Certificate Toolkit with Session-Based Encryption",
  "security_fixes": ["Session-based encryption", "RFC-compliant validation"]
}
```

### Logging Configuration

#### Structured Logging Setup
```python
# logging_config.py
import logging
import json
from datetime import datetime

class StructuredLogger:
    def __init__(self, name):
        self.logger = logging.getLogger(name)
        handler = logging.StreamHandler()
        handler.setFormatter(self.JSONFormatter())
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    class JSONFormatter(logging.Formatter):
        def format(self, record):
            log_obj = {
                'timestamp': datetime.utcnow().isoformat(),
                'level': record.levelname,
                'message': record.getMessage(),
                'module': record.module,
                'function': record.funcName,
                'line': record.lineno
            }
            if hasattr(record, 'client_ip'):
                log_obj['client_ip'] = record.client_ip
            if hasattr(record, 'session_id'):
                log_obj['session_id'] = record.session_id[:8] + '...'
            
            return json.dumps(log_obj)
```

#### Log Aggregation (ELK Stack)
```yaml
# docker-compose.monitoring.yml
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.8.0
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
  
  logstash:
    image: docker.elastic.co/logstash/logstash:8.8.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    ports:
      - "5044:5044"
  
  kibana:
    image: docker.elastic.co/kibana/kibana:8.8.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
```

### Metrics and Alerting

#### Prometheus Metrics
```python
# metrics.py
from prometheus_client import Counter, Histogram, Gauge, start_http_server

# Define metrics
csr_generation_requests = Counter('csr_generation_total', 'Total CSR generation requests', ['status', 'encryption_type'])
session_encryption_operations = Counter('session_encryption_total', 'Total session encryption operations')
active_sessions = Gauge('active_sessions', 'Number of active encryption sessions')
request_duration = Histogram('request_duration_seconds', 'Request duration', ['endpoint'])

# Start metrics server
start_http_server(8000)
```

#### Grafana Dashboard Configuration
```json
{
  "dashboard": {
    "title": "Secure Cert-Tools Monitoring",
    "panels": [
      {
        "title": "CSR Generation Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(csr_generation_total[5m])",
            "legendFormat": "CSR/sec"
          }
        ]
      },
      {
        "title": "Session Encryption Usage",
        "type": "stat",
        "targets": [
          {
            "expr": "session_encryption_total",
            "legendFormat": "Encrypted Sessions"
          }
        ]
      },
      {
        "title": "Active Sessions",
        "type": "gauge",
        "targets": [
          {
            "expr": "active_sessions",
            "legendFormat": "Active"
          }
        ]
      }
    ]
  }
}
```

### Security Monitoring

#### Security Event Alerts
```yaml
# alerts.yml
groups:
- name: security
  rules:
  - alert: HighRateOfFailedRequests
    expr: rate(csr_generation_total{status="error"}[5m]) > 0.1
    for: 2m
    annotations:
      summary: "High rate of failed CSR generation requests"
      description: "More than 10% of CSR requests are failing"
  
  - alert: SessionEncryptionFailure
    expr: rate(session_encryption_failures[5m]) > 0
    for: 1m
    annotations:
      summary: "Session encryption failures detected"
      description: "Session-based encryption is failing"
  
  - alert: AbnormalTrafficPattern
    expr: rate(http_requests_total[1m]) > 100
    for: 5m
    annotations:
      summary: "Abnormal traffic pattern detected"
      description: "Request rate is unusually high"
```

---

## Backup and Recovery

### Application Backup

#### Session Manager State
```bash
#!/bin/bash
# backup-session-state.sh

# Create backup directory
mkdir -p /backup/secure-cert-tools/$(date +%Y%m%d)

# Backup application logs
cp /var/log/secure-cert-tools/* /backup/secure-cert-tools/$(date +%Y%m%d)/

# Backup configuration
cp /etc/secure-cert-tools/* /backup/secure-cert-tools/$(date +%Y%m%d)/

# Note: Session data is ephemeral and not backed up by design
echo "Session encryption data is ephemeral - no backup needed" > /backup/secure-cert-tools/$(date +%Y%m%d)/SESSION_NOTE.txt
```

#### Database Backup (if applicable)
```bash
# If using external session storage
redis-cli BGSAVE
cp /var/lib/redis/dump.rdb /backup/secure-cert-tools/$(date +%Y%m%d)/
```

### Disaster Recovery

#### Recovery Procedures
1. **Application Recovery**:
   ```bash
   # Restore application
   docker pull secure-cert-tools:latest
   docker-compose -f docker-compose.prod.yml up -d
   ```

2. **Configuration Recovery**:
   ```bash
   # Restore certificates and keys
   cp /backup/secure-cert-tools/latest/certs/* /etc/ssl/secure-cert-tools/
   
   # Restore environment configuration
   cp /backup/secure-cert-tools/latest/env /opt/secure-cert-tools/.env
   ```

3. **Validation**:
   ```bash
   # Test application health
   curl -k https://your-domain.com/version
   
   # Test session encryption
   curl -k -X POST https://your-domain.com/generate \
     -d "CN=test.example.com&sessionEncryption=true"
   ```

---

## Security Maintenance

### Regular Security Tasks

#### Weekly Tasks
- [ ] Review security logs for anomalies
- [ ] Check session encryption statistics
- [ ] Validate certificate expiration dates
- [ ] Review rate limiting effectiveness

#### Monthly Tasks  
- [ ] Update dependencies (`pip list --outdated`)
- [ ] Review and rotate secrets
- [ ] Security scan with vulnerability tools
- [ ] Performance benchmarking

#### Quarterly Tasks
- [ ] Full security audit
- [ ] Penetration testing
- [ ] Disaster recovery testing
- [ ] Security training updates

### Security Updates

#### Automated Updates
```bash
#!/bin/bash
# security-update.sh

# Update system packages
sudo apt update && sudo apt upgrade -y

# Update Python dependencies
pip install --upgrade pip
pip list --outdated | awk 'NR>2 {print $1}' | xargs pip install --upgrade

# Restart application
sudo systemctl restart secure-cert-tools

# Validate deployment
curl -k https://your-domain.com/version
```

#### Security Scanning
```bash
# Vulnerability scanning
docker run --rm -v $(pwd):/target \
  aquasec/trivy filesystem /target

# SAST scanning
bandit -r . -x tests/

# Dependency checking
safety check
```

---

## Troubleshooting

### Common Issues

#### Session Encryption Not Working
**Symptoms**: Fallback to standard generation
**Causes**: 
- Browser doesn't support WebCrypto API
- Not using HTTPS
- Invalid session parameters

**Solutions**:
```bash
# Check HTTPS configuration
curl -I https://your-domain.com

# Verify browser compatibility
# Check console for WebCrypto errors

# Test session endpoint
curl -k https://your-domain.com/session-stats
```

#### High Memory Usage
**Symptoms**: Application consuming excessive memory
**Causes**: 
- Too many active sessions
- Session cleanup not working

**Solutions**:
```bash
# Check active sessions
curl -k https://your-domain.com/session-stats

# Restart application to clear sessions
sudo systemctl restart secure-cert-tools

# Reduce session timeout
export SESSION_TIMEOUT=1800  # 30 minutes
```

#### Rate Limiting Issues
**Symptoms**: Legitimate requests being blocked
**Causes**: 
- Rate limits too restrictive
- Shared IP addresses

**Solutions**:
```bash
# Adjust rate limits
export RATE_LIMIT_PER_MINUTE=20
export RATE_LIMIT_PER_HOUR=200

# Check rate limit headers
curl -I https://your-domain.com/generate
```

### Debug Mode

#### Enable Debug Logging
```bash
# Development only - never in production
export FLASK_ENV=development
export DEBUG=true

# Restart application
sudo systemctl restart secure-cert-tools
```

#### Session Crypto Debug
```bash
# Test session encryption
python3 demo_session_security.py

# Check session statistics
curl -k https://your-domain.com/session-stats?debug=true
```

---

## Performance Optimization

### Scaling Considerations

#### Horizontal Scaling
- **Stateless Design**: Session data is per-worker, enabling easy horizontal scaling
- **Load Balancing**: Distribute requests across multiple instances
- **Session Affinity**: Not required due to client-side key storage

#### Vertical Scaling
- **Memory**: ~50KB per active session
- **CPU**: Minimal overhead (~1% for crypto operations)
- **Network**: Standard HTTPS overhead

### Performance Monitoring

#### Key Metrics
- Session creation rate
- Encryption operation latency
- Active session count
- Memory usage per worker
- Request/response times

#### Optimization Tips
```bash
# Gunicorn worker optimization
export WEB_CONCURRENCY=4  # 2x CPU cores
export WORKER_CLASS=sync  # Use sync workers for CPU-bound crypto

# Session timeout optimization
export SESSION_TIMEOUT=3600  # Balance security vs performance

# Rate limiting optimization
export RATE_LIMIT_STORAGE_URL=redis://localhost:6379  # Use Redis for better performance
```

---

## Compliance and Audit Trail

### Audit Logging

#### Security Events
All security-relevant events are logged:
- Session creation and destruction
- Encryption operations
- Authentication failures
- Rate limit violations
- CSRF violations

#### Log Format
```json
{
  "timestamp": "2025-01-03T17:57:59Z",
  "level": "INFO",
  "event": "session_encryption_created",
  "session_id": "12345678...",
  "client_ip": "192.168.1.100",
  "encryption_algorithm": "AES-GCM-256",
  "key_exchange": "ECDH-P256"
}
```

### Compliance Requirements

#### SOC 2 Type II
- ✅ Security controls implemented
- ✅ Availability monitoring
- ✅ Processing integrity verified
- ✅ Confidentiality protected
- ✅ Privacy controls in place

#### ISO 27001
- ✅ Information security management system
- ✅ Risk assessment procedures
- ✅ Security controls implementation
- ✅ Incident response procedures
- ✅ Business continuity planning

#### NIST Cybersecurity Framework
- ✅ **Identify**: Asset inventory and risk assessment
- ✅ **Protect**: Access controls and data protection
- ✅ **Detect**: Monitoring and anomaly detection
- ✅ **Respond**: Incident response procedures
- ✅ **Recover**: Recovery planning and improvements

---

## Support and Maintenance

### Support Contacts
- **Security Issues**: security@your-domain.com
- **Technical Support**: support@your-domain.com
- **Emergency**: +1-xxx-xxx-xxxx

### Documentation Updates
Keep deployment documentation current:
- Update after security patches
- Revise after configuration changes
- Review quarterly for accuracy

### Training Requirements
- Security team: Session encryption architecture
- Operations team: Deployment and monitoring procedures
- Development team: Secure coding practices

---

**Document Version**: 1.0  
**Next Review**: 2025-04-03  
**Owner**: Security Team  
**Approved By**: CISO
