# Secure Cert-Tools

A professional certificate toolkit for generating, validating, and analyzing Certificate Signing Requests (CSRs) with enhanced security features.

## Overview

Secure Cert-Tools is a web-based application that provides secure CSR generation, certificate verification, and comprehensive analysis capabilities. Built with Flask and featuring security hardening, it supports both RSA and ECDSA key types with RFC-compliant validation.

## Features

### Core Functionality
- **CSR Generation**: Create certificate signing requests with RSA (2048/4096-bit) or ECDSA (P-256/P-384/P-521) keys
- **Certificate Verification**: Verify CSR/private key and certificate/private key matching
- **CSR Analysis**: Comprehensive analysis with RFC compliance checking
- **Subject Alternative Names**: Support for multiple domain names and wildcards

### Security Features
- **HTTPS by default** with automatic self-signed certificate generation
- **CSRF Protection** via Flask-WTF for all state-changing operations
- **Rate Limiting** to prevent DoS attacks (configurable per endpoint)
- **Security headers** (HSTS, XSS protection, content type options, CSP)
- **Input validation and sanitization** with RFC compliance checking
- **Request size limits** (1MB max) and file upload security
- **No external dependencies** (removed jQuery CDN for security)
- **Log injection prevention** and secure error handling
- **Comprehensive security testing** (47+ dedicated security tests)
- **Modern cryptography** (minimum 2048-bit RSA, secure ECDSA curves)

### Technical Features
- Modern responsive web interface with dark/light theme support
- JSON API endpoints for programmatic access
- Docker containerization support
- Production-ready with Gunicorn WSGI server
- Comprehensive test suite (185+ tests with 89% coverage)

## Installation

### Prerequisites
- Python 3.9 or higher
- pip package manager

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/csrgenerator-secure.git
   cd csrgenerator-secure
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   
   **Development Mode:**
   ```bash
   python start_server.py --dev
   # or
   export FLASK_ENV=development
   python start_server.py
   ```
   
   **Production Mode:**
   ```bash
   export FLASK_ENV=production
   python start_server.py
   ```

   Access the application at `https://localhost:5555`

### Docker Deployment

**Production (Default):**
```bash
# Build the container
docker build -t secure-cert-tools .

# Run in production mode (uses Gunicorn)
docker run -p 5555:5555 -e FLASK_ENV=production secure-cert-tools

# Or use Docker Compose
docker-compose up -d
```

**Development:**
```bash
# Run in development mode (uses Flask dev server)
docker run -p 5555:5555 -e FLASK_ENV=development secure-cert-tools

# Or use development Docker Compose
docker-compose -f docker-compose.dev.yml up -d
```

### Production Deployment

The application automatically uses Gunicorn in production mode:

```bash
# Set production environment
export FLASK_ENV=production

# Install dependencies
pip install -r requirements.txt

# Run with automatic server selection (Gunicorn in production)
python start_server.py

# Or run Gunicorn directly
gunicorn -c gunicorn.conf.py app:app
```

**Key Differences:**
- **Development**: Flask dev server with debug mode, hot reload
- **Production**: Gunicorn WSGI server with multiple workers, optimized for performance

See `DEPLOYMENT_MODES.md` for detailed deployment mode documentation.

## API Endpoints

### Generate CSR
```
POST /generate
Content-Type: application/x-www-form-urlencoded

Parameters:
- CN: Common Name (required)
- C: Country (2-letter code)
- ST: State/Province
- L: Locality/City
- O: Organization
- OU: Organizational Unit
- keyType: RSA or ECDSA (default: RSA)
- keySize: 2048 or 4096 (default: 2048)
- curve: P-256, P-384, or P-521 (for ECDSA)
- subjectAltNames: Comma-separated domain list
- allowPrivateDomains: true/false (for internal domains)
```

### Verify CSR/Private Key Match
```
POST /verify
Content-Type: application/x-www-form-urlencoded

Parameters:
- csr: PEM-encoded CSR
- privateKey: PEM-encoded private key
```

### Analyze CSR
```
POST /analyze
Content-Type: application/x-www-form-urlencoded

Parameters:
- csr: PEM-encoded CSR
```

### Certificate/Private Key Verification
```
POST /verify-certificate
Content-Type: application/x-www-form-urlencoded

Parameters:
- certificate: PEM-encoded certificate
- privateKey: PEM-encoded private key
- passphrase: Optional passphrase for encrypted keys
```

## Security Considerations

### Input Validation
- RFC-compliant domain name validation
- Field length limits according to X.509 standards
- Sanitization of user inputs for logging
- Prevention of log injection attacks

### Cryptographic Security
- Minimum 2048-bit RSA keys (1024-bit deprecated)
- Support for modern ECDSA curves
- SHA-256 signatures (SHA-1 deprecated)
- Secure random number generation

### Web Application Security
- HTTPS enforced with security headers
- CSRF protection via Flask's built-in mechanisms
- Content Security Policy headers
- Request size limitations

## Testing

Run the comprehensive test suite:

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run all tests with coverage
pytest tests.py test_security_hardening.py test_csrf_security.py test_enhanced_security.py --cov=app --cov=csr --cov=_version --cov-report=term-missing -v

# Run core tests only
pytest tests.py -v

# Run security tests only
pytest test_security_hardening.py test_csrf_security.py test_enhanced_security.py -v

# Run CSRF protection tests
pytest test_csrf_security.py -v

# Check test coverage
python scripts/validate_tests.py
```

### Test Suite Overview

The comprehensive test suite includes **185+ tests** with **89% code coverage**:

#### Core Test Files
- **tests.py** (136 tests): Core functionality, API endpoints, validation logic
- **test_security_hardening.py** (22 tests): Security-focused testing and attack prevention
- **test_additional_coverage.py** (23 tests): Edge cases, error handling, and coverage improvements
- **test_final_push.py** (4 tests): Specific uncovered line coverage

#### Test Categories
- **Functional Tests**: CSR generation, validation, certificate verification
- **Security Tests**: XSS prevention, injection attacks, file parsing security
- **Error Handling**: Exception scenarios, malformed input, edge cases
- **RFC Compliance**: Domain validation, field limits, cryptographic standards
- **API Testing**: Endpoint responses, error codes, JSON validation
- **Integration Testing**: End-to-end workflows and component interaction

#### Coverage Breakdown
- **app.py**: 80% coverage (Flask endpoints, error handling, security features)
- **csr.py**: 91% coverage (Core CSR logic, validation, cryptographic operations)
- **_version.py**: 100% coverage (Version information and metadata)
- **Overall**: 89% total coverage across core codebase

## Configuration

### Environment Variables
- `FLASK_ENV`: Environment mode (`development` or `production`)
- `PORT`: Server port (default: 5555)
- `SECRET_KEY`: Flask secret key for sessions (required for production)
- `CERT_DOMAIN`: Domain for SSL certificates (default: localhost)
- `CERTFILE`: Path to SSL certificate (auto-generated if not provided)
- `KEYFILE`: Path to SSL private key (auto-generated if not provided)
- `DEBUG`: Enable debug mode (`true` for development only)

### Security Configuration
The application includes built-in security configurations:
- Session cookie security (HTTPOnly, Secure, SameSite)
- Request size limits
- Security headers
- HTTPS enforcement

## Development

### Prerequisites for Development
```bash
pip install -r requirements-dev.txt
```

### Code Quality
The project maintains code quality through:
- Flake8 linting with complexity limits
- Comprehensive testing (185+ tests with 89% coverage)
- Security-focused testing and hardening
- Edge case and error handling coverage
- CI/CD pipeline with automated checks

### Contributing
When contributing:
1. Ensure all tests pass
2. Follow existing code style
3. Add tests for new functionality
4. Update documentation as needed

## Dependencies

### Core Dependencies
- Flask 3.1.1 - Web framework
- cryptography 45.0.4 - Cryptographic operations
- pyOpenSSL 25.1.0 - OpenSSL bindings
- Gunicorn 23.0.0 - WSGI server

### Security Dependencies
- Flask-Limiter 3.8.0 - Rate limiting and DoS protection
- Flask-WTF 1.2.1 - CSRF protection for forms

### Removed Legacy Dependencies
- ❌ jQuery 1.12.4 (security risk, external CDN)
- ❌ Google Analytics tracking
- ❌ Spectre CSS framework
- ❌ Legacy template system

### Security Updates
The project actively addresses security vulnerabilities:
- CVE-2024-6345: Fixed in current cryptography version
- CVE-2023-45853: Path traversal fix in zipp ≥3.19.1
- GHSA-5rjg-fvgr-3xxf: Security hardening implemented

## License

MIT License - see LICENSE file for details.

## Credits

Originally based on [csrgenerator.com](https://github.com/DavidWittman/csrgenerator.com) by David Wittman.
Security enhancements and additional features by Benjamin (nemekath).

## Version Information

Current version: 2.4.0
- Comprehensive security hardening
- 185+ tests with 89% code coverage including 22+ security-focused tests
- Attack prevention (XSS, injection, file parsing)
- Enhanced validation and error handling with extensive edge case coverage
- Advanced certificate verification with encrypted key support
- Production-ready deployment options
