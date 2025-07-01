#!/usr/bin/env python
"""
Secure Cert-Tools - Professional Certificate Toolkit

Original work by David Wittman: https://github.com/DavidWittman/csrgenerator.com
This fork adds features, security enhancements and dependency updates.

License: GNU General Public License v3.0
"""

from _version import __version__

import os
import logging
import ipaddress
import re
from datetime import datetime, timedelta
from flask import Flask, request, Response, render_template, jsonify
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from csr import CsrGenerator

app = Flask(__name__)

# Security configurations
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32))
app.config['SESSION_COOKIE_SECURE'] = True  # Using HTTPS by default
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max request size

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def sanitize_for_logging(text):
    """
    Sanitize text for safe logging by removing/masking dangerous characters.
    Prevents log injection and information disclosure.
    """
    if not text:
        return text
    
    # Remove or replace dangerous characters that could be used for log injection
    dangerous_patterns = [
        (r'[\r\n]', ' '),  # Replace newlines with spaces
        (r'[\x00-\x1F\x7F]', '?'),  # Replace control characters
        (r'<script[^>]*>.*?</script>', '[SCRIPT_REMOVED]'),  # Remove script tags
        (r'<[^>]+>', '[HTML_REMOVED]'),  # Remove HTML tags
        (r'[\\/:*?"<>|]', '_'),  # Replace path/file dangerous chars
        (r'\$\{[^}]*\}', '[VARIABLE_REMOVED]'),  # Remove variable expressions
        (r'\$\([^)]*\)', '[COMMAND_REMOVED]'),  # Remove command substitutions
    ]
    
    sanitized = str(text)
    for pattern, replacement in dangerous_patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
    
    # Truncate if too long to prevent log flooding
    if len(sanitized) > 200:
        sanitized = sanitized[:200] + '...[TRUNCATED]'
    
    return sanitized

# Add security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Add HSTS for HTTPS
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


# Error handler for request size limits
@app.errorhandler(413)
def request_entity_too_large(error):
    client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    logger.warning(f"Request entity too large from {client_ip}")
    return jsonify({
        'error': 'Request too large. Maximum request size is 1MB.',
        'error_type': 'RequestTooLarge'
    }), 413


@app.route('/')
def index():
    return render_template('modern_index.html')


@app.route('/version')
def version():
    """Return version information as JSON"""
    from _version import __version__, RELEASE_DATE, PROJECT_NAME, PROJECT_DESCRIPTION, SECURITY_FIXES
    return jsonify({
        'version': __version__,
        'release_date': RELEASE_DATE,
        'project_name': PROJECT_NAME,
        'description': PROJECT_DESCRIPTION,
        'security_fixes': SECURITY_FIXES
    })


@app.route('/generate', methods=['POST'])
def generate_csr():
    try:
        # Log the request (without sensitive data)
        client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        logger.info(f"CSR generation request from {client_ip}")
        
        # Validate required fields
        if not request.form.get('CN'):
            logger.warning(f"CSR generation failed - missing CN from {client_ip}")
            return jsonify({'error': 'Common Name (CN) is required'}), 400
        
        # Generate CSR
        csr = CsrGenerator(request.form)
        
        # Return JSON with separate fields
        response_data = {
            'csr': csr.csr.decode('utf-8'),
            'private_key': csr.private_key.decode('utf-8')
        }
        
        logger.info(f"CSR generated successfully for {client_ip}")
        return jsonify(response_data), 200
        
    except KeyError as e:
        logger.warning(f"CSR generation failed - invalid key/curve from {client_ip}: {str(e)}")
        error_msg = str(e)
        if "Only 2048 and 4096-bit RSA keys are supported" in error_msg:
            return jsonify({
                'error': 'Invalid RSA key size. Only 2048-bit and 4096-bit RSA keys are supported for security reasons.'
            }), 400
        elif "Unsupported ECDSA curve" in error_msg:
            return jsonify({
                'error': 'Invalid ECDSA curve. Supported curves are P-256, P-384, and P-521.'
            }), 400
        else:
            return jsonify({'error': f'Missing required field: {error_msg}'}), 400
            
    except ValueError as e:
        sanitized_error = sanitize_for_logging(str(e))
        logger.warning(f"CSR generation failed - invalid input from {client_ip}: {sanitized_error}")
        return jsonify({'error': f'Invalid input: {str(e)}'}), 400
        
    except Exception as e:
        logger.error(f"CSR generation failed - unexpected error from {client_ip}: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred during CSR generation'}), 500


@app.route('/verify', methods=['POST'])
def verify_csr_private_key():
    """
    Endpoint to verify that a CSR and private key match.
    """
    try:
        # Extract CSR and private key from request
        csr_pem = request.form.get('csr')
        private_key_pem = request.form.get('privateKey')
        client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        
        if not csr_pem or not private_key_pem:
            logger.warning(f"Verification failed - missing input from {client_ip}")
            return jsonify({'match': False, 'message': 'Both CSR and private key are required for verification.'}), 400
        
        # Verify CSR and private key match
        result = CsrGenerator.verify_csr_private_key_match(csr_pem, private_key_pem)
        if result['match']:
            logger.info(f"CSR and private key verification successful for {client_ip}")
            return jsonify({'match': True, 'message': result['message'], 'details': result.get('details')}), 200
        else:
            logger.info(f"CSR and private key mismatch for {client_ip}: {result['message']}")
            return jsonify({'match': False, 'message': result['message'], 'details': result.get('details')}), 400
    
    except Exception as e:
        logger.error(f"Error during CSR and private key verification from {client_ip}: {str(e)}")
        return jsonify({'match': False, 'message': 'An unexpected error occurred during verification.', 'details': str(e)}), 500


@app.route('/analyze', methods=['POST'])
def analyze_csr():
    """
    Endpoint to analyze a CSR and extract all information with RFC compliance checking.
    """
    try:
        # Extract CSR from request
        csr_pem = request.form.get('csr', '').strip()
        client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        
        if not csr_pem:
            logger.warning(f"CSR analysis failed - missing CSR from {client_ip}")
            return jsonify({
                'valid': False, 
                'error': 'CSR content is required for analysis',
                'error_type': 'ValidationError'
            }), 400
        
        # Perform CSR analysis
        result = CsrGenerator.analyze_csr(csr_pem)
        
        # Log the result
        if result.get('valid'):
            subject_cn = result.get('subject', {}).get('raw', {}).get('CN', 'Unknown')
            warning_count = len(result.get('rfc_warnings', []))
            logger.info(f"CSR analysis from {client_ip}: Valid CSR for '{subject_cn}' with {warning_count} warnings")
        else:
            logger.warning(f"CSR analysis from {client_ip}: Invalid CSR - {result.get('error', 'Unknown error')}")
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error during CSR analysis from {client_ip}: {str(e)}")
        return jsonify({
            'valid': False,
            'error': f'Analysis failed: {str(e)}',
            'error_type': 'InternalError'
        }), 500


@app.route('/verify-certificate', methods=['POST'])
def verify_certificate_private_key():
    """
    Endpoint to verify that a CA-signed certificate and private key match.
    Supports both encrypted and unencrypted private keys.
    """
    try:
        # Extract certificate, private key, and optional passphrase from request
        certificate_pem = request.form.get('certificate')
        private_key_pem = request.form.get('privateKey')
        passphrase = request.form.get('passphrase')  # Optional passphrase for encrypted keys
        client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        
        if not certificate_pem or not private_key_pem:
            logger.warning(f"Certificate verification failed - missing input from {client_ip}")
            return jsonify({'match': False, 'message': 'Both certificate and private key are required for verification.'}), 400
        
        # Verify certificate and private key match (with optional passphrase)
        result = CsrGenerator.verify_certificate_private_key_match(certificate_pem, private_key_pem, passphrase)
        
        if result['match']:
            logger.info(f"Certificate and private key verification successful for {client_ip}")
            return jsonify({
                'match': True, 
                'message': result['message'], 
                'details': result.get('details'),
                'cert_info': result.get('cert_info')
            }), 200
        else:
            # Check if we need to prompt for passphrase
            if result.get('requires_passphrase'):
                logger.info(f"Certificate verification requires passphrase for {client_ip}")
                return jsonify({
                    'match': False, 
                    'message': result['message'], 
                    'details': result.get('details'),
                    'requires_passphrase': True
                }), 400
            else:
                logger.info(f"Certificate and private key mismatch for {client_ip}: {result['message']}")
                return jsonify({
                    'match': False, 
                    'message': result['message'], 
                    'details': result.get('details'),
                    'cert_info': result.get('cert_info')
                }), 400
    
    except Exception as e:
        logger.error(f"Error during certificate and private key verification from {client_ip}: {str(e)}")
        return jsonify({'match': False, 'message': 'An unexpected error occurred during verification.', 'details': str(e)}), 500


def create_self_signed_cert(cert_dir, cert_file, key_file):
    """
    Create a self-signed certificate for HTTPS development/testing.
    """
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
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Secure Cert-Tools Development"),
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
    
    logger.info(f"Self-signed certificate created: {cert_file}")
    logger.info(f"Private key created: {key_file}")


def setup_https():
    """
    Setup HTTPS with self-signed certificate for development.
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
        logger.info("Self-signed certificate not found. Generating new certificate...")
        create_self_signed_cert(cert_dir, cert_file, key_file)
        logger.info("Self-signed certificate generated successfully!")
        logger.info("⚠️  This is a self-signed certificate for development only.")
        logger.info("⚠️  Your browser will show a security warning - this is normal.")
    else:
        logger.info(f"Using existing certificate: {cert_file}")
    
    return (cert_file, key_file)


if __name__ == '__main__':
    import ipaddress
    
    # Setup HTTPS
    ssl_context = setup_https()
    
    port = int(os.environ.get('FLASK_PORT', 5555))
    
    logger.info(f"Starting Secure Cert-Tools with HTTPS on port {port}")
    logger.info(f"Access the application at: https://localhost:{port}")
    logger.info("🔒 HTTPS is enabled with self-signed certificate")
    
    try:
        app.run(host='0.0.0.0', port=port, ssl_context=ssl_context)
    except Exception as e:
        logger.error(f"Failed to start server with HTTPS: {e}")
        logger.info("Falling back to HTTP...")
        app.run(host='0.0.0.0', port=port)
