# Contributing to Secure Cert-Tools

## Development Process

### Prerequisites
- Python 3.9 or higher
- pip package manager
- Git

### Setup Development Environment

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/yourusername/csrgenerator-secure.git
   cd csrgenerator-secure
   ```

3. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```

4. Run tests to ensure everything works:
   ```bash
   pytest tests.py test_security_hardening.py -v
   ```

### Code Standards

#### Security Requirements
- All user inputs must be validated and sanitized
- New cryptographic features require security review
- Security tests must be added for new attack vectors
- Follow OWASP secure coding practices

#### Code Quality
- Follow PEP 8 style guidelines
- Maximum line length: 100 characters
- Use type hints for new functions
- Maintain test coverage above 90%

#### Testing Requirements
- Add unit tests for all new functionality
- Include security tests for input validation
- Verify RFC compliance for certificate-related features
- Test error handling and edge cases

### Submission Process

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the code standards

3. Run the full test suite:
   ```bash
   pytest tests.py test_security_hardening.py -v
   python scripts/validate_tests.py
   ```

4. Commit with descriptive messages:
   ```bash
   git commit -m "Add feature: description of change"
   ```

5. Push to your fork and create a pull request

### Security Considerations

#### Sensitive Data
- Never commit certificates, private keys, or secrets
- Use environment variables for configuration
- Sanitize all logging output

#### Vulnerability Reporting
For security vulnerabilities, please contact the maintainers privately before creating public issues.

### Review Process

Pull requests will be reviewed for:
- Code quality and style compliance
- Security implications
- Test coverage
- Documentation updates
- Breaking changes

### Questions

For questions about contributing, please open an issue with the "question" label.
