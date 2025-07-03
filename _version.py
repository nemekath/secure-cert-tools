#!/usr/bin/env python
"""
Version information for CSR Generator Secure
"""

__version__ = "2.6.0"
__version_info__ = (2, 6, 0)

# Release information
RELEASE_DATE = "2025-07-03"
PROJECT_NAME = "Secure Cert-Tools"
PROJECT_DESCRIPTION = "Secure Cert-Tools - Professional certificate toolkit with CSR generation, validation, analysis, and verification capabilities"

# Security information
SECURITY_FIXES = [
    "CVE-2024-6345",
    "GHSA-5rjg-fvgr-3xxf", 
    "CVE-2023-45853"
]

# Contributors
CONTRIBUTORS = {
    "original_author": "David Wittman",
    "security_enhancements": "Benjamin (nemekath)",
    "fork_repository": "https://github.com/nemekath/csrgenerator-secure",
    "original_repository": "https://github.com/DavidWittman/csrgenerator.com"
}

# Version history
VERSION_HISTORY = {
    "2.6.0": "Enhanced REST API Test Suite: Human-readable validation testing with 100% success rate (10/10 tests), intelligent rate limiting per endpoint, comprehensive field validation for all X.509 subject fields, production-ready API testing with zero failures, robust error recovery with automatic retry logic, clear intent indicators for valid vs invalid data testing, fixed critical boolean evaluation bug in field validation",
    "2.5.2": "Complete pyOpenSSL deprecation elimination: Fully migrated ALL CSR operations (generation, verification, analysis) from deprecated pyOpenSSL to modern cryptography library. Achieved 100% elimination of deprecation warnings (336 → 0), ensuring future compatibility and maintainability while preserving all functionality",
    "2.5.1": "Bug fixes and modernization: Fixed README.md version/repository inconsistencies, migrated CSR generation from deprecated pyOpenSSL to modern cryptography library (83% reduction in deprecation warnings from 336 to 56), maintained full backward compatibility while improving future maintainability",
    "2.5.0": "Major security and testing framework upgrade: Complete CSRF protection implementation across all endpoints, comprehensive testing framework with 14 organized test suites (70+ security tests), enhanced CI/CD with multi-tool security scanning, Windows compatibility fixes, security documentation suite, GitHub security issue templates, cross-platform deployment support",
    "2.4.0": "Comprehensive security hardening with 89% test coverage (185+ tests), enhanced security testing (22+ security tests), attack prevention (XSS, injection, file parsing), advanced certificate verification with encrypted key support, extensive edge case and error handling coverage",
    "2.3.3": "CSR content analysis & RFC compliance checking, enhanced security, expanded testing (78 tests), centralized versioning",
    "2.3.2": "Security monitoring, documentation improvements, CVE-2023-45853 fix",
    "2.3.1": "Documentation alignment and version consistency",
    "2.3.0": "HTTPS by default, JSON API, enhanced UI",
    "2.2.0": "CSR/private key verification functionality",
    "2.1.0": "ECDSA key support",
    "2.0.0": "Security fixes and dependency updates"
}
