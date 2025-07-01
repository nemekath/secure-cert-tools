# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.0] - 2024-07-01

### Added
- Comprehensive test coverage achieving 89% line coverage (185+ tests)
- Enhanced security testing suite with 22+ dedicated security tests
- Comprehensive edge case and error handling test coverage
- Advanced certificate verification with encrypted key support
- Multiple test files for comprehensive validation:
  - `test_additional_coverage.py` (23 edge case tests)
  - `test_final_push.py` (4 specific coverage tests)
- Enhanced input validation and sanitization testing
- Log injection prevention with comprehensive testing
- Request size limitations with proper error handling tests
- Security headers enforcement testing (HSTS, XSS protection)
- CSR and certificate verification endpoints with full error path coverage
- Modern responsive UI with dark/light theme support
- Production-ready Gunicorn configuration
- Docker containerization support

### Changed
- Comprehensive test suite expansion from 125 to 185+ tests
- Test coverage improvement from 84% to 89% (core codebase)
- Enhanced error handling and logging with complete test coverage
- Improved RFC compliance validation with edge case testing
- Modernized web interface design
- Upgraded Flask to 3.1.1 for security improvements
- Updated cryptography library to 45.0.4

### Fixed
- Fixed failing certificate verification test with proper error path mocking
- Enhanced comprehensive error handling test coverage
- All test failures resolved achieving 100% pass rate
- CVE-2024-6345: Updated cryptography dependency
- CVE-2023-45853: Path traversal vulnerability in zipp
- GHSA-5rjg-fvgr-3xxf: Security hardening implementation
- Log injection vulnerabilities with comprehensive testing
- Input sanitization gaps with security edge case coverage

### Security
- Comprehensive security test coverage (22+ dedicated tests)
- Complete encrypted private key detection testing
- Certificate verification security edge cases covered
- Domain validation security gaps closed with comprehensive testing
- Input sanitization security validated with edge case testing
- Attack prevention scenarios thoroughly tested
- Implemented CSRF protection with testing
- Added XSS prevention measures with validation
- Enhanced cryptographic key validation with comprehensive coverage
- Secure session cookie configuration
- Prevention of malicious file parsing with security testing

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
