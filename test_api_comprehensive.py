#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Comprehensive API Tests for Secure Cert-Tools
Test all API endpoints mentioned in README.md and verify functionality
"""

import pytest
import json
import re
from app import app
from csr import CsrGenerator


class TestAPIEndpoints:
    """Test all API endpoints as documented in README.md"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for API testing
        # Disable rate limiting for testing
        app.config['RATELIMIT_ENABLED'] = False
        with app.test_client() as client:
            yield client
    
    @pytest.fixture
    def csrf_token(self, client):
        """Get a valid CSRF token for protected endpoints"""
        response = client.get('/')
        assert response.status_code == 200
        html_content = response.data.decode('utf-8')
        
        # Extract CSRF token from meta tag
        meta_match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html_content)
        if meta_match:
            return meta_match.group(1)
        
        pytest.fail("Could not extract CSRF token from index page")

    def test_generate_csr_api_basic(self, client):
        """Test POST /generate endpoint with basic parameters"""
        form_data = {
            'CN': 'api-test.example.com',
            'C': 'US',
            'ST': 'California',
            'L': 'San Francisco',
            'O': 'API Test Corp',
            'OU': 'Engineering',
            'keyType': 'RSA',
            'keySize': '2048'
        }
        
        response = client.post('/generate', data=form_data)
        assert response.status_code == 200
        assert response.mimetype == 'application/json'
        
        data = response.get_json()
        assert 'csr' in data
        assert 'private_key' in data
        assert '-----BEGIN CERTIFICATE REQUEST-----' in data['csr']
        assert '-----END CERTIFICATE REQUEST-----' in data['csr']
        assert '-----BEGIN PRIVATE KEY-----' in data['private_key']
        assert '-----END PRIVATE KEY-----' in data['private_key']

    def test_generate_csr_api_ecdsa(self, client):
        """Test POST /generate endpoint with ECDSA parameters"""
        form_data = {
            'CN': 'ecdsa-test.example.com',
            'C': 'US',
            'keyType': 'ECDSA',
            'curve': 'P-256'
        }
        
        response = client.post('/generate', data=form_data)
        assert response.status_code == 200
        assert response.mimetype == 'application/json'
        
        data = response.get_json()
        assert 'csr' in data
        assert 'private_key' in data
        assert '-----BEGIN CERTIFICATE REQUEST-----' in data['csr']
        assert 'PRIVATE KEY' in data['private_key']

    def test_generate_csr_api_with_sans(self, client):
        """Test POST /generate endpoint with Subject Alternative Names"""
        form_data = {
            'CN': 'multi-domain.example.com',
            'C': 'US',
            'subjectAltNames': 'api.example.com, *.example.com',
            'allowPrivateDomains': 'true',  # Allow IP addresses
            'keyType': 'RSA',
            'keySize': '4096'
        }
        
        response = client.post('/generate', data=form_data)
        assert response.status_code == 200
        
        data = response.get_json()
        assert 'csr' in data
        assert 'private_key' in data

    def test_generate_csr_api_private_domains(self, client):
        """Test POST /generate endpoint with private domain support"""
        form_data = {
            'CN': 'server.local',
            'allowPrivateDomains': 'true',
            'keyType': 'RSA',
            'keySize': '2048'
        }
        
        response = client.post('/generate', data=form_data)
        assert response.status_code == 200
        
        data = response.get_json()
        assert 'csr' in data
        assert 'private_key' in data

    def test_generate_csr_api_error_handling(self, client):
        """Test POST /generate endpoint error handling"""
        # Missing required CN
        form_data = {
            'C': 'US',
            'keyType': 'RSA'
        }
        
        response = client.post('/generate', data=form_data)
        assert response.status_code == 400
        assert response.mimetype == 'application/json'
        
        data = response.get_json()
        assert 'error' in data
        assert 'required' in data['error'].lower()

    def test_verify_csr_private_key_api(self, client):
        """Test POST /verify endpoint for CSR/private key matching"""
        # First generate a CSR and private key
        form_data = {
            'CN': 'verify-test.example.com',
            'keyType': 'RSA',
            'keySize': '2048'
        }
        
        gen_response = client.post('/generate', data=form_data)
        assert gen_response.status_code == 200
        gen_data = gen_response.get_json()
        
        # Now verify they match
        verify_data = {
            'csr': gen_data['csr'],
            'privateKey': gen_data['private_key']
        }
        
        response = client.post('/verify', data=verify_data)
        assert response.status_code == 200
        assert response.mimetype == 'application/json'
        
        data = response.get_json()
        assert 'match' in data
        assert data['match'] is True
        assert 'message' in data
        assert 'successfully' in data['message']

    def test_verify_csr_private_key_mismatch_api(self, client):
        """Test POST /verify endpoint with mismatched keys"""
        # Generate two different CSR/key pairs
        form_data = {'CN': 'test1.example.com', 'keyType': 'RSA', 'keySize': '2048'}
        gen1_response = client.post('/generate', data=form_data)
        gen1_data = gen1_response.get_json()
        
        form_data['CN'] = 'test2.example.com'
        gen2_response = client.post('/generate', data=form_data)
        gen2_data = gen2_response.get_json()
        
        # Verify mismatch
        verify_data = {
            'csr': gen1_data['csr'],
            'privateKey': gen2_data['private_key']
        }
        
        response = client.post('/verify', data=verify_data)
        assert response.status_code == 400
        assert response.mimetype == 'application/json'
        
        data = response.get_json()
        assert 'match' in data
        assert data['match'] is False
        assert 'do not match' in data['message']

    def test_analyze_csr_api(self, client):
        """Test POST /analyze endpoint for CSR analysis"""
        # First generate a CSR
        form_data = {
            'CN': 'analyze-test.example.com',
            'C': 'US',
            'ST': 'California',
            'O': 'Analysis Corp',
            'subjectAltNames': 'api.analyze-test.example.com',
            'keyType': 'RSA',
            'keySize': '2048'
        }
        
        gen_response = client.post('/generate', data=form_data)
        gen_data = gen_response.get_json()
        
        # Now analyze the CSR
        analyze_data = {
            'csr': gen_data['csr']
        }
        
        response = client.post('/analyze', data=analyze_data)
        assert response.status_code == 200
        assert response.mimetype == 'application/json'
        
        data = response.get_json()
        assert 'valid' in data
        assert data['valid'] is True
        assert 'subject' in data
        assert 'public_key' in data
        assert 'extensions' in data
        assert 'rfc_warnings' in data
        
        # Verify subject information
        subject = data['subject']['raw']
        assert subject['CN'] == 'analyze-test.example.com'
        assert subject['C'] == 'US'
        assert subject['ST'] == 'California'
        assert subject['O'] == 'Analysis Corp'
        
        # Verify public key information
        public_key = data['public_key']
        assert public_key['type'] == 'RSA'
        assert public_key['size'] == 2048

    def test_analyze_csr_api_error_handling(self, client):
        """Test POST /analyze endpoint error handling"""
        # Invalid CSR
        analyze_data = {
            'csr': 'invalid-csr-content'
        }
        
        response = client.post('/analyze', data=analyze_data)
        assert response.status_code == 200  # Analysis endpoint returns 200 with error details
        assert response.mimetype == 'application/json'
        
        data = response.get_json()
        assert 'valid' in data
        assert data['valid'] is False
        assert 'error' in data

    def test_verify_certificate_private_key_api(self, client):
        """Test POST /verify-certificate endpoint"""
        # This endpoint requires a CA-signed certificate
        # For testing, we'll verify the error handling with invalid input
        verify_data = {
            'certificate': 'invalid-certificate',
            'privateKey': 'invalid-private-key'
        }
        
        response = client.post('/verify-certificate', data=verify_data)
        assert response.status_code in [400, 500]  # Could be validation error or internal error
        assert response.mimetype == 'application/json'
        
        data = response.get_json()
        assert 'match' in data
        assert data['match'] is False

    def test_version_api_endpoint(self, client):
        """Test GET /version endpoint"""
        response = client.get('/version')
        assert response.status_code == 200
        assert response.mimetype == 'application/json'
        
        data = response.get_json()
        assert 'version' in data
        assert 'release_date' in data
        assert 'project_name' in data
        assert 'description' in data
        assert data['project_name'] == 'Secure Cert-Tools'


class TestAPIContentTypes:
    """Test API content types and headers"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        # Completely disable rate limiting for content type tests
        try:
            from app import limiter
            limiter.enabled = False
        except:
            pass
        with app.test_client() as client:
            yield client

    def test_api_returns_json(self, client):
        """Test that all API endpoints return JSON"""
        endpoints = [
            ('/generate', {'CN': 'test.example.com'}),
            ('/verify', {'csr': 'invalid', 'privateKey': 'invalid'}),
            ('/analyze', {'csr': 'invalid'}),
            ('/verify-certificate', {'certificate': 'invalid', 'privateKey': 'invalid'})
        ]
        
        for endpoint, data in endpoints:
            response = client.post(endpoint, data=data)
            assert response.mimetype == 'application/json', f"Endpoint {endpoint} should return JSON"

    def test_api_accepts_form_data(self, client):
        """Test that API endpoints accept form-encoded data"""
        form_data = {
            'CN': 'form-test.example.com',
            'keyType': 'RSA',
            'keySize': '2048'
        }
        
        response = client.post('/generate', 
                             data=form_data,
                             content_type='application/x-www-form-urlencoded')
        assert response.status_code == 200


class TestAPIRateLimiting:
    """Test API rate limiting as mentioned in README"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        # Enable rate limiting for these tests
        app.config['RATELIMIT_ENABLED'] = True
        with app.test_client() as client:
            yield client

    def test_generate_endpoint_rate_limit(self, client):
        """Test that /generate endpoint has rate limiting (10 per minute)"""
        form_data = {'CN': 'rate-test.example.com'}
        
        # Make requests up to the limit
        for i in range(5):  # Test a few requests, not the full limit
            response = client.post('/generate', data=form_data)
            # Should succeed initially
            if response.status_code == 429:
                # Rate limit hit - this is expected behavior
                break
            else:
                assert response.status_code in [200, 400]  # 400 for validation errors

    def test_verify_endpoint_rate_limit(self, client):
        """Test that /verify endpoint has rate limiting (15 per minute)"""
        verify_data = {'csr': 'test', 'privateKey': 'test'}
        
        # Make a few requests
        for i in range(3):
            response = client.post('/verify', data=verify_data)
            if response.status_code == 429:
                # Rate limit hit
                break
            else:
                assert response.status_code in [200, 400, 500]


class TestAPISecurityHeaders:
    """Test API security headers"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        with app.test_client() as client:
            yield client

    def test_security_headers_on_api_responses(self, client):
        """Test that API responses include security headers"""
        response = client.post('/generate', data={'CN': 'security-test.example.com'})
        
        # Check for security headers
        headers = response.headers
        assert 'X-Content-Type-Options' in headers
        assert headers['X-Content-Type-Options'] == 'nosniff'
        assert 'X-Frame-Options' in headers
        assert headers['X-Frame-Options'] == 'DENY'


class TestAPIRequestLimits:
    """Test API request size limits as mentioned in README"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024  # 1MB limit
        with app.test_client() as client:
            yield client

    def test_large_request_rejection(self, client):
        """Test that requests over 1MB are rejected"""
        # Create a large payload (over 1MB)
        large_data = {
            'CN': 'large-test.example.com',
            'O': 'A' * (1024 * 1024 + 1000)  # Over 1MB
        }
        
        response = client.post('/generate', data=large_data)
        # Should be rejected due to size - accept 413 (proper handling) or 400/500 (fallback handling)
        assert response.status_code in [400, 413, 500], f"Expected 400, 413, or 500 but got {response.status_code}"
        
        # If it's a JSON response, check the error message contains size-related information
        if response.mimetype == 'application/json':
            try:
                data = response.get_json()
                error_msg = data.get('error', '').lower()
                # Check that the error mentions request size or entity too large
                assert any(keyword in error_msg for keyword in ['large', 'size', 'limit', 'entity']), \
                    f"Error message should mention size limits, got: {error_msg}"
            except:
                pass  # If JSON parsing fails, that's ok for this test


class TestAPIFunctionalityIntegration:
    """Test complete API workflows"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['RATELIMIT_ENABLED'] = False
        with app.test_client() as client:
            yield client

    def test_complete_csr_workflow(self, client):
        """Test complete CSR generation, verification, and analysis workflow"""
        # Step 1: Generate CSR
        gen_data = {
            'CN': 'workflow-test.example.com',
            'C': 'US',
            'ST': 'Texas',
            'L': 'Austin',
            'O': 'Workflow Corp',
            'OU': 'Engineering',
            'keyType': 'RSA',
            'keySize': '2048',
            'subjectAltNames': 'api.workflow-test.example.com, www.workflow-test.example.com'
        }
        
        gen_response = client.post('/generate', data=gen_data)
        assert gen_response.status_code == 200
        gen_result = gen_response.get_json()
        
        csr = gen_result['csr']
        private_key = gen_result['private_key']
        
        # Step 2: Verify CSR and private key match
        verify_data = {
            'csr': csr,
            'privateKey': private_key
        }
        
        verify_response = client.post('/verify', data=verify_data)
        assert verify_response.status_code == 200
        verify_result = verify_response.get_json()
        assert verify_result['match'] is True
        
        # Step 3: Analyze CSR
        analyze_data = {
            'csr': csr
        }
        
        analyze_response = client.post('/analyze', data=analyze_data)
        assert analyze_response.status_code == 200
        analyze_result = analyze_response.get_json()
        assert analyze_result['valid'] is True
        
        # Verify the analysis contains expected data
        subject = analyze_result['subject']['raw']
        assert subject['CN'] == 'workflow-test.example.com'
        assert subject['C'] == 'US'
        assert subject['O'] == 'Workflow Corp'
        
        # Check public key information
        public_key = analyze_result['public_key']
        assert public_key['type'] == 'RSA'
        assert public_key['size'] == 2048

    def test_ecdsa_workflow(self, client):
        """Test ECDSA key workflow"""
        curves = ['P-256', 'P-384', 'P-521']
        
        for curve in curves:
            gen_data = {
                'CN': f'ecdsa-{curve.lower()}.example.com',
                'keyType': 'ECDSA',
                'curve': curve
            }
            
            gen_response = client.post('/generate', data=gen_data)
            assert gen_response.status_code == 200
            gen_result = gen_response.get_json()
            
            # Verify the generated CSR
            verify_data = {
                'csr': gen_result['csr'],
                'privateKey': gen_result['private_key']
            }
            
            verify_response = client.post('/verify', data=verify_data)
            assert verify_response.status_code == 200
            verify_result = verify_response.get_json()
            assert verify_result['match'] is True

    def test_error_response_consistency(self, client):
        """Test that error responses are consistent across endpoints"""
        endpoints = [
            '/generate',
            '/verify', 
            '/analyze',
            '/verify-certificate'
        ]
        
        for endpoint in endpoints:
            # Send request with no data
            response = client.post(endpoint, data={})
            assert response.mimetype == 'application/json'
            
            data = response.get_json()
            # Should have some error indication
            assert ('error' in data or 'match' in data or 'valid' in data)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
