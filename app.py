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

# Security enhancements
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, validate_csrf
from werkzeug.exceptions import TooManyRequests, RequestEntityTooLarge

from csr import CsrGenerator
from session_crypto import get_session_crypto_manager

app = Flask(__name__)

# Security configurations
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32))
app.config['SESSION_COOKIE_SECURE'] = True  # Using HTTPS by default
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max request size

# CSRF Protection configuration
# Disable CSRF for testing environments (CI/CD)
testing_mode = os.environ.get('TESTING', '').lower() == 'true'
flask_env = os.environ.get('FLASK_ENV', 'production').lower()
is_testing = testing_mode or flask_env == 'testing'

app.config['WTF_CSRF_ENABLED'] = not is_testing  # Disable CSRF in testing mode
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour
app.config['WTF_CSRF_SSL_STRICT'] = True  # HTTPS enforcement

# Configure logging first
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Log CSRF status for transparency
if is_testing:
    logger.warning("⚠️  CSRF protection DISABLED for testing mode")
    logger.warning("⚠️  This should only be used in CI/CD or testing environments!")
else:
    logger.info("🛡️  CSRF protection ENABLED for production security")

# Initialize security extensions
csrf = CSRFProtect(app)

# Rate limiting configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour", "20 per minute"],
    storage_uri="memory://",
    headers_enabled=True
)


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
        (r'[\x00-\x1F\x7F]', '_'),  # Replace control characters with underscore
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


# Error handler for rate limiting
@app.errorhandler(429)
def rate_limit_exceeded(error):
    client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    logger.warning(f"Rate limit exceeded from {client_ip}: {error.description}")
    return jsonify({
        'error': 'Rate limit exceeded. Please wait before making another request.',
        'error_type': 'RateLimitExceeded',
        'retry_after': error.retry_after
    }), 429


# Error handler for CSRF validation
@app.errorhandler(400)
def handle_csrf_error(error):
    if 'CSRF' in str(error):
        client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        logger.warning(f"CSRF validation failed from {client_ip}")
        return jsonify({
            'error': 'CSRF token validation failed. Please refresh the page and try again.',
            'error_type': 'CSRFError'
        }), 400
    return error


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


@app.route('/session-stats')
def session_stats():
    """Return session cryptography statistics for monitoring"""
    try:
        session_manager = get_session_crypto_manager()
        stats = session_manager.get_statistics()
        
        # Add security status
        stats['session_encryption_enabled'] = True
        stats['security_level'] = 'enhanced'
        
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({
            'session_encryption_enabled': False,
            'security_level': 'standard',
            'error': str(e)
        }), 200


@app.route('/generate', methods=['POST'])
@limiter.limit("10 per minute", error_message="Too many CSR generation requests. Please wait before trying again.")
def generate_csr():
    try:
        # Log the request (without sensitive data)
        client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        
        # Check if session encryption is requested
        session_encryption = request.form.get('sessionEncryption', 'false').lower() == 'true'
        
        if session_encryption:
            return _generate_csr_with_session_encryption(client_ip)
        else:
            return _generate_csr_standard(client_ip)
        
    except KeyError as e:
        client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
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
        client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        sanitized_error = sanitize_for_logging(str(e))
        logger.warning(f"CSR generation failed - invalid input from {client_ip}: {sanitized_error}")
        return jsonify({'error': f'Invalid input: {str(e)}'}), 400
        
    except RequestEntityTooLarge:
        client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        logger.warning(f"Request entity too large from {client_ip}")
        return jsonify({
            'error': 'Request too large. Maximum request size is 1MB.',
            'error_type': 'RequestTooLarge'
        }), 413
        
    except Exception as e:
        client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        # Check if this is a request entity too large error (fallback)
        if '413 Request Entity Too Large' in str(e) or 'RequestEntityTooLarge' in str(type(e).__name__):
            logger.warning(f"Request entity too large from {client_ip}")
            return jsonify({
                'error': 'Request too large. Maximum request size is 1MB.',
                'error_type': 'RequestTooLarge'
            }), 413
        
        logger.error(f"CSR generation failed - unexpected error from {client_ip}: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred during CSR generation'}), 500


def _generate_csr_with_session_encryption(client_ip):
    """
    Generate CSR with session-based encryption for enhanced security
    """
    import json
    
    try:
        logger.info(f"🔐 Session-encrypted CSR generation request from {client_ip}")
        
        # Extract session encryption parameters
        session_id = request.form.get('sessionId')
        client_public_key = request.form.get('clientPublicKey')
        client_entropy = request.form.get('sessionEntropy')
        
        if not all([session_id, client_public_key, client_entropy]):
            logger.warning(f"Session encryption failed - missing parameters from {client_ip}")
            return jsonify({'error': 'Missing session encryption parameters'}), 400
        
        # Validate required CSR fields
        if not request.form.get('CN'):
            logger.warning(f"Session-encrypted CSR generation failed - missing CN from {client_ip}")
            return jsonify({'error': 'Common Name (CN) is required'}), 400
        
        # Parse client data
        try:
            client_public_key_data = bytes(json.loads(client_public_key))
            client_entropy_data = bytes(json.loads(client_entropy))
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Session encryption failed - invalid client data from {client_ip}: {str(e)}")
            return jsonify({'error': 'Invalid session encryption data format'}), 400
        
        # Get session crypto manager
        session_manager = get_session_crypto_manager()
        
        # Create session encryption
        session_crypto = session_manager.create_session_encryption(
            session_id, 
            client_public_key_data, 
            client_entropy_data,
            client_ip
        )
        
        # Generate CSR normally
        csr = CsrGenerator(request.form)
        
        # Encrypt private key using session encryption
        encryption_result = session_manager.encrypt_private_key(
            session_id,
            csr.private_key.decode('utf-8')
        )
        
        # Prepare response with encrypted private key
        response_data = {
            'csr': csr.csr.decode('utf-8'),
            'encryptedPrivateKey': encryption_result['encrypted_data'],
            'encryptionIV': encryption_result['iv'],
            'serverPublicKey': session_crypto['worker_public_key_data'],
            'sessionId': session_id,
            'encryption': 'session-based',
            'encryptionAlgorithm': encryption_result['encryption_algorithm']
        }
        
        logger.info(f"🛡️ Session-encrypted CSR generated successfully for {client_ip} (session: {session_id[:8]}...)")
        return jsonify(response_data), 200
        
    except Exception as e:
        sanitized_error = sanitize_for_logging(str(e))
        logger.error(f"Session-encrypted CSR generation failed from {client_ip}: {sanitized_error}")
        # Fallback to standard generation
        logger.info(f"⚠️ Falling back to standard CSR generation for {client_ip}")
        return _generate_csr_standard(client_ip)


def _generate_csr_standard(client_ip):
    """
    Generate CSR with standard (legacy) method
    """
    try:
        logger.info(f"🔧 Standard CSR generation request from {client_ip}")
        
        # Validate required fields
        if not request.form.get('CN'):
            logger.warning(f"CSR generation failed - missing CN from {client_ip}")
            return jsonify({'error': 'Common Name (CN) is required'}), 400
        
        # Generate CSR
        csr = CsrGenerator(request.form)
        
        # Return JSON with separate fields
        response_data = {
            'csr': csr.csr.decode('utf-8'),
            'private_key': csr.private_key.decode('utf-8'),
            'encryption': 'none'
        }
        
        logger.info(f"✅ Standard CSR generated successfully for {client_ip}")
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
        
    except RequestEntityTooLarge:
        logger.warning(f"Request entity too large from {client_ip}")
        return jsonify({
            'error': 'Request too large. Maximum request size is 1MB.',
            'error_type': 'RequestTooLarge'
        }), 413
        
    except Exception as e:
        # Check if this is a request entity too large error (fallback)
        if '413 Request Entity Too Large' in str(e) or 'RequestEntityTooLarge' in str(type(e).__name__):
            logger.warning(f"Request entity too large from {client_ip}")
            return jsonify({
                'error': 'Request too large. Maximum request size is 1MB.',
                'error_type': 'RequestTooLarge'
            }), 413
        
        sanitized_error = sanitize_for_logging(str(e))
        logger.error(f"Standard CSR generation failed from {client_ip}: {sanitized_error}")
        return jsonify({'error': 'An unexpected error occurred during CSR generation'}), 500


@app.route('/verify', methods=['POST'])
@limiter.limit("15 per minute", error_message="Too many verification requests. Please wait before trying again.")
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
@limiter.limit("15 per minute", error_message="Too many analysis requests. Please wait before trying again.")
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
@limiter.limit("15 per minute", error_message="Too many certificate verification requests. Please wait before trying again.")
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
    
    # SECURITY WARNING: Check if running in production environment
    flask_env = os.environ.get('FLASK_ENV', 'production').lower()
    production_mode = os.environ.get('PRODUCTION_MODE', '').lower() == 'true'
    
    if flask_env == 'production' or production_mode:
        logger.error("🚨 SECURITY ERROR: Cannot run Flask development server in production mode!")
        logger.error("❌ Use 'python start_server.py' instead for production deployment")
        logger.error("❌ Flask's built-in server is not suitable for production use")
        logger.error("✅ For development: Set FLASK_ENV=development first")
        exit(1)
    
    logger.warning("⚠️  DEVELOPMENT MODE: Running Flask development server")
    logger.warning("⚠️  This should only be used for local development!")
    
    # Setup HTTPS
    ssl_context = setup_https()
    
    port = int(os.environ.get('FLASK_PORT', 5555))
    
    logger.info(f"Starting Secure Cert-Tools with HTTPS on port {port}")
    logger.info(f"Access the application at: https://localhost:{port}")
    logger.info("🔒 HTTPS is enabled with self-signed certificate")
    
    try:
        app.run(host='0.0.0.0', port=port, ssl_context=ssl_context, debug=True)
    except Exception as e:
        logger.error(f"Failed to start server with HTTPS: {e}")
        logger.info("Falling back to HTTP...")
        app.run(host='0.0.0.0', port=port, debug=True)
