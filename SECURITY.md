# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.4.x   | :white_check_mark: |
| <= 2.3  | :x:                |

## Security Features

This project implements comprehensive security measures:

### Application Security
- HTTPS enforcement with security headers
- Input validation and sanitization
- Request size limitations (1MB)
- CSRF protection
- XSS prevention
- Log injection prevention

### Cryptographic Security
- Minimum 2048-bit RSA keys
- Modern ECDSA curves (P-256, P-384, P-521)
- SHA-256 signatures (SHA-1 deprecated)
- Secure random number generation

### Dependencies
- Regular security updates for all dependencies
- Automated vulnerability scanning via Dependabot
- CVE tracking and remediation

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

To report a security vulnerability:

1. **Email**: Send details to the project maintainers
2. **Include**: 
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested remediation (if any)


### Severity Classification

- **Critical**: Remote code execution, privilege escalation
- **High**: Data exposure, authentication bypass
- **Medium**: Information disclosure, CSRF
- **Low**: Minor information leaks, configuration issues

## Security Testing

The project includes:
- 22 dedicated security tests
- Attack prevention verification
- Input validation testing
- Cryptographic validation
- RFC compliance checking

## Known Security Fixes

### Version 2.4.0
- Fixed log injection vulnerabilities
- Enhanced input sanitization
- Improved error handling
- Added comprehensive security testing

### Dependencies
- CVE-2024-6345: Fixed in cryptography 45.0.4
- CVE-2023-45853: Fixed in zipp ≥3.19.1
- GHSA-5rjg-fvgr-3xxf: Security hardening implemented

## Security Best Practices

When using this application:

1. **Deployment**
   - Use HTTPS in production
   - Set proper environment variables
   - Keep dependencies updated
   - Monitor security logs

2. **Key Management**
   - Generate keys in secure environments
   - Never store private keys in version control
   - Use proper key rotation practices
   - Secure key storage and transmission

3. **Monitoring**
   - Monitor for unusual request patterns
   - Review security logs regularly
   - Set up alerting for security events
   - Keep backups of certificates

## Contact

For security-related questions or concerns, contact the project maintainers.
