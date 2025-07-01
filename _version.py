#!/usr/bin/env python
"""
Version information for CSR Generator Secure
"""

__version__ = "2.4.0"
__version_info__ = (2, 4, 0)

# Release information
RELEASE_DATE = "2025-07-01"
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
    "2.4.0": "Comprehensive security hardening with 22 security tests, attack prevention (XSS, injection, file parsing), log sanitization, request limiting, expanded testing to 125 total tests",
    "2.3.3": "CSR content analysis & RFC compliance checking, enhanced security, expanded testing (78 tests), centralized versioning",
    "2.3.2": "Security monitoring, documentation improvements, CVE-2023-45853 fix",
    "2.3.1": "Documentation alignment and version consistency",
    "2.3.0": "HTTPS by default, JSON API, enhanced UI",
    "2.2.0": "CSR/private key verification functionality",
    "2.1.0": "ECDSA key support",
    "2.0.0": "Security fixes and dependency updates"
}
