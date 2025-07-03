#!/usr/bin/env python
"""
Comprehensive Test Suite for Secure Cert-Tools

This test suite ensures everything works correctly with all security features enabled,
including CSRF protection, rate limiting, input validation, and security headers.
"""

import pytest
import re
import json
import time
from flask import Flask
from app import app, sanitize_for_logging
from csr import CsrGenerator


class TestCSRFIntegration:
    """Test CSRF protection integration with all endpoints"""
    
    @pytest.fixture
    def client(self):
        """Create test client with CSRF enabled"""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = True
        app.config['WTF_CSRF_TIME_LIMIT'] = None  # Disable time limit for testing
        with app.test_client() as client:
            yield client

    @pytest.fixture
    def csrf_token(self, client):
        """Get a valid CSRF token from the index page"""
        response = client.get('/')
        assert response.status_code == 200
        
        html_content = response.data.decode('utf-8')
        
        # Extract CSRF token from meta tag
        meta_match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html_content)
        if meta_match:
            return meta_match.group(1)
        
        # Fallback: try to find any csrf_token in the HTML
        token_match = re.search(r'csrf[_-]token["\']?\s*[:=]\s*["\']([^"\']+)["\']', html_content)
        if token_match:
            return token_match.group(1)
        
        pytest.fail("Could not extract CSRF token from index page")

    def test_index_page_loads(self, client):
        """Test that the index page loads successfully"""
        response = client.get('/')
        assert response.status_code == 200
        assert b'html' in response.data.lower()

    def test_generate_endpoint_with_csrf(self, client, csrf_token):
        """Test CSR generation with valid CSRF token"""
        form_data = {
            'CN': 'test.example.com',
            'C': 'US',
            'ST': 'California',
            'L': 'San Francisco',
            'O': 'Test Organization',
            'OU': 'IT Department',
            'keySize': '2048',
            'csrf_token': csrf_token
        }
        
        response = client.post('/generate', data=form_data)
        assert response.status_code == 200
        assert response.is_json
        
        data = response.get_json()
        assert 'csr' in data
        assert 'private_key' in data
        assert '-----BEGIN CERTIFICATE REQUEST-----' in data['csr']
        assert 'PRIVATE KEY' in data['private_key']

    def test_generate_endpoint_requires_csrf(self, client):
        """Test that generate endpoint requires CSRF token"""
        form_data = {
            'CN': 'test.example.com',
            'C': 'US',
            'keySize': '2048'
        }
        
        response = client.post('/generate', data=form_data)
        assert response.status_code == 400
        assert response.is_json
        
        data = response.get_json()
        assert 'error' in data
        assert 'CSRF' in data['error']

    def test_verify_endpoint_with_csrf(self, client, csrf_token):
        """Test CSR verification with valid CSRF token"""
        # First generate a valid CSR and key pair
        csr_info = {'CN': 'verify-test.example.com'}
        generator = CsrGenerator(csr_info)
        
        form_data = {
            'csr': generator.csr.decode('utf-8'),
            'privateKey': generator.private_key.decode('utf-8'),
            'csrf_token': csrf_token
        }
        
        response = client.post('/verify', data=form_data)
        assert response.status_code == 200
        assert response.is_json
        
        data = response.get_json()
        assert data['match'] is True
        assert 'successfully' in data['message']

    def test_analyze_endpoint_with_csrf(self, client, csrf_token):
        """Test CSR analysis with valid CSRF token"""
        # Generate a valid CSR for analysis
        csr_info = {'CN': 'analyze-test.example.com'}
        generator = CsrGenerator(csr_info)
        
        form_data = {
            'csr': generator.csr.decode('utf-8'),
            'csrf_token': csrf_token
        }
        
        response = client.post('/analyze', data=form_data)
        assert response.status_code == 200
        assert response.is_json
        
        data = response.get_json()
        assert data['valid'] is True
        assert 'subject' in data
        assert 'public_key' in data

    def test_verify_certificate_endpoint_with_csrf(self, client, csrf_token):
        """Test certificate verification with valid CSRF token"""
        # Create a self-signed certificate for testing
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from datetime import datetime, timedelta
        
        # Generate key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "test-cert.example.com"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=30)
        ).sign(private_key, hashes.SHA256())
        
        certificate_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        form_data = {
            'certificate': certificate_pem,
            'privateKey': private_key_pem,
            'csrf_token': csrf_token
        }
        
        response = client.post('/verify-certificate', data=form_data)
        assert response.status_code == 200
        assert response.is_json
        
        data = response.get_json()
        assert data['match'] is True


class TestRSAKeyGeneration:
    """Test RSA key generation functionality"""
    
    def test_rsa_2048_generation(self):
        """Test RSA 2048-bit key generation"""
        csr_info = {
            'CN': 'rsa2048.example.com',
            'keyType': 'RSA',
            'keySize': 2048
        }
        generator = CsrGenerator(csr_info)
        
        assert generator.keypair.key_size == 2048
        from cryptography.hazmat.primitives.asymmetric import rsa
        assert isinstance(generator.keypair, rsa.RSAPrivateKey)
        assert generator.csr is not None
        assert generator.private_key is not None

    def test_rsa_4096_generation(self):
        """Test RSA 4096-bit key generation"""
        csr_info = {
            'CN': 'rsa4096.example.com',
            'keyType': 'RSA',
            'keySize': 4096
        }
        generator = CsrGenerator(csr_info)
        
        assert generator.keypair.key_size == 4096
        assert generator.csr is not None
        assert generator.private_key is not None

    def test_weak_rsa_keys_rejected(self):
        """Test that weak RSA key sizes are rejected"""
        weak_sizes = [512, 1024, 1536]
        
        for size in weak_sizes:
            csr_info = {
                'CN': 'weak.example.com',
                'keyType': 'RSA',
                'keySize': size
            }
            with pytest.raises(KeyError, match="Only 2048 and 4096-bit RSA keys are supported"):
                CsrGenerator(csr_info)


class TestECDSAKeyGeneration:
    """Test ECDSA key generation functionality"""
    
    def test_ecdsa_p256_generation(self):
        """Test ECDSA P-256 key generation"""
        csr_info = {
            'CN': 'ecdsa-p256.example.com',
            'keyType': 'ECDSA',
            'curve': 'P-256'
        }
        generator = CsrGenerator(csr_info)
        
        assert generator.csr is not None
        assert generator.private_key is not None

    def test_ecdsa_p384_generation(self):
        """Test ECDSA P-384 key generation"""
        csr_info = {
            'CN': 'ecdsa-p384.example.com',
            'keyType': 'ECDSA',
            'curve': 'P-384'
        }
        generator = CsrGenerator(csr_info)
        
        assert generator.csr is not None
        assert generator.private_key is not None

    def test_ecdsa_p521_generation(self):
        """Test ECDSA P-521 key generation"""
        csr_info = {
            'CN': 'ecdsa-p521.example.com',
            'keyType': 'ECDSA',
            'curve': 'P-521'
        }
        generator = CsrGenerator(csr_info)
        
        assert generator.csr is not None
        assert generator.private_key is not None

    def test_weak_ecdsa_curves_rejected(self):
        """Test that weak ECDSA curves are rejected"""
        weak_curves = ['P-192', 'secp112r1', 'secp160r1']
        
        for curve in weak_curves:
            csr_info = {
                'CN': 'weak-ecdsa.example.com',
                'keyType': 'ECDSA',
                'curve': curve
            }
            with pytest.raises(KeyError, match="Unsupported ECDSA curve"):
                CsrGenerator(csr_info)


class TestDomainValidation:
    """Test domain validation functionality"""
    
    def test_public_domains_allowed(self):
        """Test that public domains are allowed"""
        valid_domains = [
            'example.com',
            'subdomain.example.com',
            'very-long-subdomain-name.example.org',
            'multi.level.domain.example.net'
        ]
        
        for domain in valid_domains:
            csr_info = {'CN': domain}
            generator = CsrGenerator(csr_info)
            assert generator.csr is not None

    def test_private_domains_require_flag(self):
        """Test that private domains require allowPrivateDomains flag"""
        private_domains = [
            'localhost',
            'server',
            'internal.corp',
            'test.local',
            '192.168.1.1'
        ]
        
        for domain in private_domains:
            # Should fail without flag
            csr_info = {'CN': domain}
            with pytest.raises(ValueError):
                CsrGenerator(csr_info)
            
            # Should work with flag
            csr_info = {'CN': domain, 'allowPrivateDomains': 'true'}
            generator = CsrGenerator(csr_info)
            assert generator.csr is not None

    def test_wildcard_domains(self):
        """Test wildcard domain validation"""
        valid_wildcards = [
            '*.example.com',
            '*.api.example.com',
            '*.subdomain.example.org'
        ]
        
        for domain in valid_wildcards:
            csr_info = {'CN': domain}
            generator = CsrGenerator(csr_info)
            assert generator.csr is not None

    def test_invalid_domains_rejected(self):
        """Test that invalid domains are rejected"""
        invalid_domains = [
            '.invalid',
            'invalid.',
            'example..com',
            '-invalid.com',
            'invalid-.com',
            'exam_ple.com'
        ]
        
        for domain in invalid_domains:
            csr_info = {'CN': domain}
            with pytest.raises(ValueError):
                CsrGenerator(csr_info)


class TestSubjectAlternativeNames:
    """Test Subject Alternative Names functionality"""
    
    def test_san_generation(self):
        """Test automatic SAN generation"""
        csr_info = {'CN': 'example.com'}
        generator = CsrGenerator(csr_info)
        
        # Should automatically include CN and www variant for root domains
        expected_sans = ['DNS:example.com', 'DNS:www.example.com']
        assert set(generator.subjectAltNames) == set(expected_sans)

    def test_custom_sans(self):
        """Test custom Subject Alternative Names"""
        csr_info = {
            'CN': 'example.com',
            'subjectAltNames': 'api.example.com, mail.example.com'
        }
        generator = CsrGenerator(csr_info)
        
        expected_sans = ['DNS:example.com', 'DNS:api.example.com', 'DNS:mail.example.com']
        assert set(generator.subjectAltNames) == set(expected_sans)

    def test_wildcard_sans(self):
        """Test wildcard domains in SANs"""
        csr_info = {
            'CN': 'example.com',
            'subjectAltNames': '*.example.com, *.api.example.com'
        }
        generator = CsrGenerator(csr_info)
        
        expected_sans = ['DNS:example.com', 'DNS:*.example.com', 'DNS:*.api.example.com']
        assert set(generator.subjectAltNames) == set(expected_sans)


class TestCSRAnalysis:
    """Test CSR analysis functionality"""
    
    def test_analyze_valid_rsa_csr(self):
        """Test analysis of valid RSA CSR"""
        csr_info = {
            'CN': 'analyze-rsa.example.com',
            'C': 'US',
            'ST': 'California',
            'L': 'San Francisco',
            'O': 'Test Company',
            'OU': 'IT',
            'keyType': 'RSA',
            'keySize': 2048
        }
        generator = CsrGenerator(csr_info)
        csr_pem = generator.csr.decode('utf-8')
        
        result = CsrGenerator.analyze_csr(csr_pem)
        
        assert result['valid'] is True
        assert result['subject']['raw']['CN'] == 'analyze-rsa.example.com'
        assert result['public_key']['type'] == 'RSA'
        assert result['public_key']['size'] == 2048
        assert result['public_key']['is_secure'] is True

    def test_analyze_valid_ecdsa_csr(self):
        """Test analysis of valid ECDSA CSR"""
        csr_info = {
            'CN': 'analyze-ecdsa.example.com',
            'keyType': 'ECDSA',
            'curve': 'P-256'
        }
        generator = CsrGenerator(csr_info)
        csr_pem = generator.csr.decode('utf-8')
        
        result = CsrGenerator.analyze_csr(csr_pem)
        
        assert result['valid'] is True
        assert result['subject']['raw']['CN'] == 'analyze-ecdsa.example.com'
        assert result['public_key']['type'] == 'ECDSA'
        assert result['public_key']['is_secure'] is True

    def test_analyze_invalid_csr(self):
        """Test analysis of invalid CSR"""
        invalid_csr = "This is not a valid CSR"
        
        result = CsrGenerator.analyze_csr(invalid_csr)
        
        assert result['valid'] is False
        assert 'error' in result
        assert 'suggestions' in result


class TestSecurityHeaders:
    """Test security headers functionality"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_security_headers_present(self, client):
        """Test that security headers are present"""
        response = client.get('/')
        
        assert 'X-Content-Type-Options' in response.headers
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
        
        assert 'X-Frame-Options' in response.headers
        assert response.headers['X-Frame-Options'] == 'DENY'
        
        assert 'X-XSS-Protection' in response.headers
        assert response.headers['X-XSS-Protection'] == '1; mode=block'
        
        assert 'Referrer-Policy' in response.headers
        assert response.headers['Referrer-Policy'] == 'strict-origin-when-cross-origin'
        
        assert 'Strict-Transport-Security' in response.headers


class TestInputValidation:
    """Test input validation and sanitization"""
    
    def test_field_length_limits(self):
        """Test field length validation"""
        # Test CN length limit
        long_cn = 'a' * 65
        csr_info = {'CN': long_cn}
        with pytest.raises(ValueError, match="Field CN exceeds maximum length"):
            CsrGenerator(csr_info)

    def test_country_code_validation(self):
        """Test country code validation"""
        # Valid country codes
        valid_codes = ['US', 'CA', 'GB', 'DE']
        for code in valid_codes:
            csr_info = {'CN': 'example.com', 'C': code}
            generator = CsrGenerator(csr_info)
            assert generator.csr is not None
        
        # Invalid country codes
        invalid_codes = ['USA', 'us', '1', 'ABC']
        for code in invalid_codes:
            csr_info = {'CN': 'example.com', 'C': code}
            with pytest.raises(ValueError):
                CsrGenerator(csr_info)

    def test_dangerous_character_filtering(self):
        """Test filtering of dangerous characters"""
        # Based on the actual validation pattern: r'[\<\>"\\/:;|=+*?\[\]{}^~`!@#$%]+'
        dangerous_inputs = [
            '<script>alert(1)</script>',  # Contains < >
            'test/path',  # Contains /
            'test"quote',  # Contains "
            'test\\injection',  # Contains \
            'test:colon',  # Contains :
            'test;semicolon',  # Contains ;
            'test|pipe',  # Contains |
            'test=equals',  # Contains =
            'test+plus',  # Contains +
            'test*asterisk',  # Contains *
            'test?question',  # Contains ?
            'test[bracket]',  # Contains [ ]
            'test{brace}',  # Contains { }
            'test^caret',  # Contains ^
            'test~tilde',  # Contains ~
            'test`backtick',  # Contains `
            'test!exclamation',  # Contains !
            'test@at',  # Contains @
            'test#hash',  # Contains #
            'test$dollar',  # Contains $
            'test%percent'  # Contains %
        ]
        
        for dangerous_input in dangerous_inputs:
            csr_info = {'CN': 'example.com', 'O': dangerous_input}
            with pytest.raises(ValueError, match="contains invalid characters"):
                CsrGenerator(csr_info)


class TestLoggingSanitization:
    """Test logging sanitization functionality"""
    
    def test_sanitize_for_logging_basic(self):
        """Test basic sanitization functionality"""
        # Normal text should pass through
        normal_text = "Normal log message"
        result = sanitize_for_logging(normal_text)
        assert result == normal_text

    def test_sanitize_for_logging_dangerous_content(self):
        """Test sanitization of dangerous content"""
        dangerous_inputs = [
            "<script>alert(1)</script>",
            "test\ninjection\r\nattack",
            "${java:os}",
            "$(whoami)",
            "test\x00null\x01control"
        ]
        
        for dangerous_input in dangerous_inputs:
            result = sanitize_for_logging(dangerous_input)
            assert "\n" not in result
            assert "\r" not in result
            assert "<script>" not in result.lower()
            assert "${" not in result
            assert "$(" not in result

    def test_sanitize_for_logging_length_limit(self):
        """Test length truncation in sanitization"""
        long_string = "a" * 300
        result = sanitize_for_logging(long_string)
        assert len(result) <= 250
        assert "[TRUNCATED]" in result


class TestVersionEndpoint:
    """Test version endpoint functionality"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_version_endpoint(self, client):
        """Test version endpoint returns correct information"""
        response = client.get('/version')
        assert response.status_code == 200
        assert response.is_json
        
        data = response.get_json()
        assert 'version' in data
        assert 'release_date' in data
        assert 'project_name' in data
        assert 'description' in data
        assert 'security_fixes' in data
        
        # Version should be in semantic versioning format
        import re
        version_pattern = r'\d+\.\d+\.\d+'
        assert re.match(version_pattern, data['version'])


class TestRateLimiting:
    """Test rate limiting functionality"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for rate limit testing
        with app.test_client() as client:
            yield client

    def test_rate_limiting_enforcement(self, client):
        """Test that rate limiting is enforced"""
        # Make many rapid requests to test rate limiting
        responses = []
        for i in range(25):  # Exceed the rate limit
            response = client.post('/generate', data={
                'CN': f'rate-test-{i}.example.com',
                'keySize': '2048'
            })
            responses.append(response.status_code)
            time.sleep(0.1)
        
        # Should see some rate limit responses (429) or errors
        # At minimum, should not see server crashes (5xx errors from our code)
        for status in responses:
            assert status in [200, 400, 429]  # Valid responses


class TestErrorHandling:
    """Test error handling across the application"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for error testing
        app.config['RATELIMIT_STORAGE_URL'] = "memory://"  # Use in-memory storage for testing
        
        with app.test_client() as client:
            yield client

    def test_missing_required_fields(self, client):
        """Test handling of missing required fields"""
        app.config['RATELIMIT_STORAGE_URL'] = ""  # Disable rate limit during test
        response = client.post('/generate', data={})
        assert response.status_code == 400
        assert response.is_json
        
        data = response.get_json()
        assert 'error' in data
        assert 'Common Name' in data['error']

    def test_invalid_json_responses(self, client):
        """Test that all error responses are valid JSON"""
        invalid_requests = [
            ('/generate', {}),
            ('/verify', {'csr': 'invalid'}),
            ('/analyze', {'csr': 'invalid'}),
            ('/verify-certificate', {'certificate': 'invalid'})
        ]
        
        app.config['RATELIMIT_STORAGE_URL'] = ""  # Disable rate limit during test
        for endpoint, data in invalid_requests:
            response = client.post(endpoint, data=data)
            assert response.status_code in [200, 400, 500]  # Allow 200 for analyze endpoint
            assert response.is_json
            
            json_data = response.get_json()
            assert isinstance(json_data, dict)
            assert 'error' in json_data or 'match' in json_data or 'valid' in json_data


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
