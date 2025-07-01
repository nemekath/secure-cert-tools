# Gunicorn configuration for production deployment
# This replaces Flask's development server with a production-ready WSGI server

import multiprocessing
import os

# Server socket
bind = f"0.0.0.0:{os.environ.get('PORT', '5555')}"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

# Restart workers after this many requests, to prevent memory leaks
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "csr-generator"

# Server mechanics
preload_app = True
daemon = False
pidfile = "/tmp/gunicorn.pid"
user = None
group = None
tmp_upload_dir = None

# SSL (if certificates are provided)
# Check if certificate files exist and configure SSL
certfile_path = os.environ.get('CERTFILE', './certs/server.crt')
keyfile_path = os.environ.get('KEYFILE', './certs/server.key')

if os.path.exists(certfile_path) and os.path.exists(keyfile_path):
    certfile = certfile_path
    keyfile = keyfile_path
else:
    certfile = None
    keyfile = None

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190
