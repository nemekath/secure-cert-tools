# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.6.x   | :white_check_mark: |
| 2.5.x   | :white_check_mark: |
| <= 2.4  | :x:                |

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

The project includes comprehensive security testing with **71% test coverage**:

### Test Coverage
- **254+ total tests** with comprehensive security focus
- **64+ dedicated security tests** for attack prevention
- **Complete edge case coverage** for error handling
- **Advanced certificate verification** with encrypted key testing
- **Domain validation security** with RFC compliance edge cases
- **Input sanitization testing** with security edge cases

### Security Test Categories
- **Attack Prevention**: XSS, injection, file parsing security
- **Input Validation**: Malformed data, boundary conditions
- **Cryptographic Security**: Key validation, signature verification
- **Certificate Verification**: Authentication, encrypted key handling
- **RFC Compliance**: Domain validation, field limits
- **Error Handling**: Security-aware exception management

## Known Security Fixes

### Version 2.4.0
- **Comprehensive security testing** with 89% coverage achievement
- **Fixed log injection vulnerabilities** with extensive testing
- **Enhanced input sanitization** with security edge case coverage
- **Improved error handling** with complete test coverage
- **Certificate verification security** with encrypted key edge cases
- **Domain validation security** gaps closed with comprehensive testing
- **Attack prevention scenarios** thoroughly tested

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
