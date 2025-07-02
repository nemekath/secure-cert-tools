#!/usr/bin/env python3
"""
Startup script for Secure Cert-Tools with HTTPS support.
This script ensures SSL certificates are generated before starting the server.
"""

import os
import sys
import logging
import subprocess
from datetime import datetime, timedelta
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def create_self_signed_cert(cert_dir, cert_file, key_file):
    """
    Create a self-signed certificate for HTTPS.
    """
    logger.info("Generating self-signed certificate...")
    
    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Subject and issuer (same for self-signed)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Secure Cert-Tools"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    issuer = subject

    # Create certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"localhost"),
            x509.DNSName(u"127.0.0.1"),
            x509.IPAddress(ipaddress.IPv4Address(u"127.0.0.1")),
        ]),
        critical=False,
    ).sign(key, hashes.SHA256(), default_backend())

    # Write certificate to disk
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Write private key to disk
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
    logger.info(f"Certificate created: {cert_file}")
    logger.info(f"Private key created: {key_file}")


def setup_certificates():
    """
    Ensure SSL certificates exist.
    """
    cert_dir = "./certs"
    cert_file = os.path.join(cert_dir, "server.crt")
    key_file = os.path.join(cert_dir, "server.key")
    
    # Create certs directory if it doesn't exist
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)
        logger.info(f"Created certificate directory: {cert_dir}")
    
    # Generate self-signed certificate if it doesn't exist
    if not os.path.isfile(cert_file) or not os.path.isfile(key_file):
        logger.info("SSL certificates not found. Generating self-signed certificate...")
        create_self_signed_cert(cert_dir, cert_file, key_file)
        logger.info("✅ Self-signed certificate generated successfully!")
        logger.info("⚠️  This is a self-signed certificate - browsers will show a security warning.")
        logger.info("⚠️  For production, replace with a certificate from a trusted CA.")
    else:
        logger.info(f"Using existing SSL certificate: {cert_file}")
    
    return cert_file, key_file


def start_server():
    """
    Start the server with appropriate configuration.
    """
    # Setup certificates
    cert_file, key_file = setup_certificates()
    
    # Set environment variables for Gunicorn
    os.environ['CERTFILE'] = cert_file
    os.environ['KEYFILE'] = key_file
    
    # Determine if we're running in development or production
    flask_env = os.environ.get('FLASK_ENV', 'production').lower()
    is_development = flask_env == 'development' or '--dev' in sys.argv
    
    if is_development:
        logger.info("🚨 Starting in DEVELOPMENT mode with Flask dev server")
        logger.info("⚠️  WARNING: This is for development only, not for production!")
        logger.info("🔒 HTTPS enabled with self-signed certificate")
        logger.info("📍 Access at: https://localhost:5555")
        
        # Import and run Flask app directly (not via os.system)
        from app import app, setup_https
        ssl_context = setup_https()
        port = int(os.environ.get('PORT', 5555))
        
        # Set Flask to development mode
        app.config['ENV'] = 'development'
        app.config['DEBUG'] = True
        
        try:
            app.run(host='0.0.0.0', port=port, ssl_context=ssl_context, debug=True)
        except Exception as e:
            logger.error(f"Failed to start Flask dev server with HTTPS: {e}")
            logger.info("Falling back to HTTP for development...")
            app.run(host='0.0.0.0', port=port, debug=True)
    else:
        logger.info("🚀 Starting in PRODUCTION mode with Gunicorn")
        logger.info("🔒 HTTPS enabled with SSL certificates")
        logger.info("📍 Access at: https://localhost:5555")
        
        # Ensure production environment is set
        os.environ['FLASK_ENV'] = 'production'
        
        # Start Gunicorn production server
        cmd = ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
        result = subprocess.run(cmd)
        return result.returncode


if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        sys.exit(1)
