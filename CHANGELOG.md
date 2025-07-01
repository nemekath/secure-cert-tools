# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.0] - 2024-07-01

### Added
- Comprehensive security hardening implementation
- 22 dedicated security tests for attack prevention
- Enhanced input validation and sanitization
- Log injection prevention mechanisms
- Request size limitations (1MB maximum)
- Security headers enforcement (HSTS, XSS protection)
- CSR and certificate verification endpoints
- Modern responsive UI with dark/light theme support
- Production-ready Gunicorn configuration
- Docker containerization support

### Changed
- Upgraded Flask to 3.1.1 for security improvements
- Updated cryptography library to 45.0.4
- Enhanced error handling and logging
- Improved RFC compliance validation
- Modernized web interface design

### Fixed
- CVE-2024-6345: Updated cryptography dependency
- CVE-2023-45853: Path traversal vulnerability in zipp
- GHSA-5rjg-fvgr-3xxf: Security hardening implementation
- Log injection vulnerabilities
- Input sanitization gaps

### Security
- Implemented CSRF protection
- Added XSS prevention measures
- Enhanced cryptographic key validation
- Secure session cookie configuration
- Prevention of malicious file parsing

## [2.3.x] - Previous Versions

### Features
- Basic CSR generation functionality
- RSA and ECDSA key support
- Subject Alternative Names support
- Basic web interface

### Security Updates
- Regular dependency updates
- Basic input validation
- HTTPS support

## [Earlier Versions]

Based on the original csrgenerator.com project by David Wittman with security enhancements and additional features.

---

## Types of Changes

- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes
