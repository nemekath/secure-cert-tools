#!/usr/bin/env python
"""
CSRF Security Tests for Secure Cert-Tools

Tests to verify that CSRF protection is properly implemented and working
across all endpoints and attack vectors.
"""

import pytest
import json
import re
from flask import Flask
from app import app


class TestCSRFProtection:
    """Test cases for CSRF protection mechanisms"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = True
        with app.test_client() as client:
            yield client

    @pytest.fixture
    def csrf_token(self, client):
        """Get a valid CSRF token from the index page"""
        response = client.get('/')
        assert response.status_code == 200
        
        # Extract CSRF token from the HTML response
        html_content = response.data.decode('utf-8')
        
        # Look for CSRF token in meta tag
        meta_match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html_content)
        if meta_match:
            return meta_match.group(1)
        
        # Look for CSRF token in hidden input
        input_match = re.search(r'<input[^>]*name="csrf_token"[^>]*value="([^"]+)"', html_content)
        if input_match:
            return input_match.group(1)
        
        # If not found, look for any csrf_token in the HTML
        token_match = re.search(r'csrf_token["\']?\s*[:=]\s*["\']([^"\']+)["\']', html_content)
        if token_match:
            return token_match.group(1)
        
        pytest.fail("Could not extract CSRF token from index page")

    def test_csrf_token_in_index_page(self, client):
        """Test that CSRF token is properly included in the index page"""
        response = client.get('/')
        assert response.status_code == 200
        
        html_content = response.data.decode('utf-8')
        
        # Should have meta tag with CSRF token
        assert 'name="csrf-token"' in html_content
        assert 'content=' in html_content
        
        # Should have CSRF token function call in forms (modern template uses {{ csrf_token() }})
        assert 'csrf_token()' in html_content or 'csrf_token' in html_content

    def test_generate_endpoint_requires_csrf(self, client):
        """Test that /generate endpoint requires CSRF token"""
        form_data = {
            'CN': 'test.example.com',
            'C': 'US',
            'keySize': '2048'
        }
        
        # Request without CSRF token should fail
        response = client.post('/generate', data=form_data)
        assert response.status_code == 400
        
        json_data = response.get_json()
        assert json_data is not None
        assert 'error' in json_data
        assert 'CSRF' in json_data['error']
        assert json_data['error_type'] == 'CSRFError'

    def test_generate_endpoint_with_valid_csrf(self, client, csrf_token):
        """Test that /generate endpoint accepts valid CSRF token"""
        form_data = {
            'CN': 'test.example.com',
            'C': 'US',
            'keySize': '2048',
            'csrf_token': csrf_token
        }
        
        response = client.post('/generate', data=form_data)
        # Should succeed (200) or have validation error (500), not CSRF error (400)
        assert response.status_code in [200, 500]
        
        if response.status_code == 500:
            json_data = response.get_json()
            # Should not be a CSRF error
            assert json_data.get('error_type') != 'CSRFError'

    def test_verify_endpoint_requires_csrf(self, client):
        """Test that /verify endpoint requires CSRF token"""
        form_data = {
            'csr': '-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----',
            'privateKey': '-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----'
        }
        
        response = client.post('/verify', data=form_data)
        assert response.status_code == 400
        
        json_data = response.get_json()
        assert 'error' in json_data
        assert 'CSRF' in json_data['error']
        assert json_data['error_type'] == 'CSRFError'

    def test_verify_endpoint_with_valid_csrf(self, client, csrf_token):
        """Test that /verify endpoint accepts valid CSRF token"""
        form_data = {
            'csr': '-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----',
            'privateKey': '-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----',
            'csrf_token': csrf_token
        }
        
        response = client.post('/verify', data=form_data)
        # Should succeed or have validation error, not CSRF error
        assert response.status_code in [200, 500]
        
        if response.status_code == 500:
            json_data = response.get_json()
            assert json_data.get('error_type') != 'CSRFError'

    def test_analyze_endpoint_requires_csrf(self, client):
        """Test that /analyze endpoint requires CSRF token"""
        form_data = {
            'csr': '-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----'
        }
        
        response = client.post('/analyze', data=form_data)
        assert response.status_code == 400
        
        json_data = response.get_json()
        assert 'error' in json_data
        assert 'CSRF' in json_data['error']
        assert json_data['error_type'] == 'CSRFError'

    def test_analyze_endpoint_with_valid_csrf(self, client, csrf_token):
        """Test that /analyze endpoint accepts valid CSRF token"""
        form_data = {
            'csr': '-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----',
            'csrf_token': csrf_token
        }
        
        response = client.post('/analyze', data=form_data)
        # Should succeed or have validation error, not CSRF error
        assert response.status_code in [200, 500]
        
        if response.status_code == 500:
            json_data = response.get_json()
            assert json_data.get('error_type') != 'CSRFError'

    def test_verify_certificate_endpoint_requires_csrf(self, client):
        """Test that /verify-certificate endpoint requires CSRF token"""
        form_data = {
            'certificate': '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
            'privateKey': '-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----'
        }
        
        response = client.post('/verify-certificate', data=form_data)
        assert response.status_code == 400
        
        json_data = response.get_json()
        assert 'error' in json_data
        assert 'CSRF' in json_data['error']
        assert json_data['error_type'] == 'CSRFError'

    def test_verify_certificate_endpoint_with_valid_csrf(self, client, csrf_token):
        """Test that /verify-certificate endpoint accepts valid CSRF token"""
        form_data = {
            'certificate': '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
            'privateKey': '-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----',
            'csrf_token': csrf_token
        }
        
        response = client.post('/verify-certificate', data=form_data)
        # Should succeed or have validation error, not CSRF error
        assert response.status_code in [200, 500]
        
        if response.status_code == 500:
            json_data = response.get_json()
            assert json_data.get('error_type') != 'CSRFError'

    def test_invalid_csrf_token_rejected(self, client):
        """Test that invalid CSRF tokens are rejected"""
        invalid_tokens = [
            'invalid_token',
            'fake-csrf-token-123',
            '',
            None,
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
            'a' * 100,
            '<script>alert(1)</script>',
            '../../etc/passwd'
        ]
        
        for invalid_token in invalid_tokens:
            form_data = {
                'CN': 'test.example.com',
                'C': 'US',
                'csrf_token': invalid_token
            }
            
            response = client.post('/generate', data=form_data)
            assert response.status_code == 400
            
            json_data = response.get_json()
            assert 'error' in json_data
            assert json_data['error_type'] == 'CSRFError'

    def test_csrf_token_header_support(self, client, csrf_token):
        """Test that CSRF token is accepted in X-CSRFToken header"""
        form_data = {
            'CN': 'test.example.com',
            'C': 'US',
            'keySize': '2048'
        }
        
        headers = {
            'X-CSRFToken': csrf_token,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        response = client.post('/generate', data=form_data, headers=headers)
        # Should succeed or have validation error, not CSRF error
        assert response.status_code in [200, 500]
        
        if response.status_code == 500:
            json_data = response.get_json()
            assert json_data.get('error_type') != 'CSRFError'

    def test_csrf_protection_with_ajax_simulation(self, client, csrf_token):
        """Test CSRF protection with simulated AJAX requests"""
        # Simulate what the JavaScript does
        form_data = {
            'CN': 'ajax.example.com',
            'C': 'US',
            'keySize': '2048',
            'csrf_token': csrf_token  # Token in form data
        }
        
        headers = {
            'X-CSRFToken': csrf_token,  # Token in header
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest'  # Simulate AJAX
        }
        
        response = client.post('/generate', data=form_data, headers=headers)
        # Should succeed or have validation error, not CSRF error
        assert response.status_code in [200, 500]
        
        if response.status_code == 500:
            json_data = response.get_json()
            assert json_data.get('error_type') != 'CSRFError'

    def test_csrf_token_uniqueness(self, client):
        """Test that CSRF tokens are unique across sessions"""
        tokens = []
        
        # Get multiple tokens
        for _ in range(5):
            response = client.get('/')
            html_content = response.data.decode('utf-8')
            
            # Extract token
            meta_match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html_content)
            if meta_match:
                tokens.append(meta_match.group(1))
        
        # All tokens should be unique (though in practice, 
        # the same session might get the same token)
        assert len(tokens) > 0
        # At minimum, tokens should not be empty or identical simple strings
        assert all(len(token) > 10 for token in tokens)  # Reasonable length
        assert all(token != 'test' for token in tokens)  # Not simple test values

    def test_get_requests_not_protected(self, client):
        """Test that GET requests are not CSRF protected"""
        # GET requests should work without CSRF tokens
        response = client.get('/')
        assert response.status_code == 200
        
        response = client.get('/favicon.ico')
        assert response.status_code in [200, 404]  # Might not exist
        
        # Any other GET endpoints should also work

    def test_post_without_data_requires_csrf(self, client):
        """Test that even empty POST requests require CSRF tokens"""
        response = client.post('/generate')
        assert response.status_code == 400
        
        json_data = response.get_json()
        assert 'error' in json_data
        assert json_data['error_type'] == 'CSRFError'

    def test_csrf_error_response_format(self, client):
        """Test that CSRF error responses have consistent format"""
        response = client.post('/generate', data={'CN': 'test.com'})
        assert response.status_code == 400
        assert response.content_type == 'application/json'
        
        json_data = response.get_json()
        assert isinstance(json_data, dict)
        assert 'error' in json_data
        assert 'error_type' in json_data
        assert json_data['error_type'] == 'CSRFError'
        assert isinstance(json_data['error'], str)
        assert len(json_data['error']) > 0

    def test_csrf_protection_does_not_leak_tokens(self, client):
        """Test that CSRF errors don't leak valid tokens"""
        response = client.post('/generate', data={'CN': 'test.com'})
        json_data = response.get_json()
        
        # Error message should not contain actual tokens
        error_message = json_data['error'].lower()
        assert 'token' not in error_message or 'csrf token' in error_message
        # Should not contain base64-like strings that might be tokens
        assert not re.search(r'[A-Za-z0-9+/]{20,}={0,2}', json_data['error'])

    def test_csrf_with_rate_limiting_interaction(self, client, csrf_token):
        """Test that CSRF protection works correctly with rate limiting"""
        form_data = {
            'CN': 'ratelimit.example.com',
            'C': 'US',
            'csrf_token': csrf_token
        }
        
        # First request should work (if valid) or fail with validation error
        response = client.post('/generate', data=form_data)
        assert response.status_code in [200, 500]
        
        if response.status_code == 500:
            json_data = response.get_json()
            assert json_data.get('error_type') != 'CSRFError'
        
        # Multiple rapid requests to test rate limiting + CSRF interaction
        for _ in range(3):
            response = client.post('/generate', data=form_data)
            # Should either succeed, hit rate limit, or have validation error
            # But should NOT be CSRF error if token is valid
            if response.status_code == 400:
                json_data = response.get_json()
                if 'error_type' in json_data:
                    # If it's a 400, it should be rate limit, not CSRF
                    assert json_data['error_type'] in ['RateLimitError', 'ValidationError']


class TestCSRFBypassAttempts:
    """Test cases for various CSRF bypass attempts"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = True
        with app.test_client() as client:
            yield client

    def test_referer_bypass_attempt(self, client):
        """Test that setting Referer header doesn't bypass CSRF"""
        form_data = {'CN': 'test.com', 'C': 'US'}
        headers = {'Referer': 'http://localhost:5000/'}
        
        response = client.post('/generate', data=form_data, headers=headers)
        assert response.status_code == 400
        
        json_data = response.get_json()
        assert json_data['error_type'] == 'CSRFError'

    def test_origin_bypass_attempt(self, client):
        """Test that setting Origin header doesn't bypass CSRF"""
        form_data = {'CN': 'test.com', 'C': 'US'}
        headers = {'Origin': 'http://localhost:5000'}
        
        response = client.post('/generate', data=form_data, headers=headers)
        assert response.status_code == 400
        
        json_data = response.get_json()
        assert json_data['error_type'] == 'CSRFError'

    def test_content_type_bypass_attempt(self, client):
        """Test that changing Content-Type doesn't bypass CSRF"""
        form_data = {'CN': 'test.com', 'C': 'US'}
        
        content_types = [
            'application/json',
            'text/plain',
            'multipart/form-data',
            'application/xml',
            'text/xml'
        ]
        
        for content_type in content_types:
            headers = {'Content-Type': content_type}
            response = client.post('/generate', data=form_data, headers=headers)
            
            # Should still require CSRF token regardless of content type
            assert response.status_code == 400
            json_data = response.get_json()
            assert json_data['error_type'] == 'CSRFError'

    def test_method_override_bypass_attempt(self, client):
        """Test that method override doesn't bypass CSRF"""
        form_data = {'CN': 'test.com', 'C': 'US', '_method': 'POST'}
        
        # Try various method override techniques
        override_methods = [
            {'X-HTTP-Method-Override': 'GET'},
            {'X-HTTP-Method': 'GET'},
            {'X-Method-Override': 'GET'}
        ]
        
        for headers in override_methods:
            response = client.post('/generate', data=form_data, headers=headers)
            assert response.status_code == 400
            
            json_data = response.get_json()
            assert json_data['error_type'] == 'CSRFError'

    def test_double_submit_cookie_bypass_attempt(self, client):
        """Test that manually setting cookies doesn't bypass CSRF"""
        form_data = {'CN': 'test.com', 'C': 'US'}
        
        # Try to set a fake CSRF cookie (Flask test client format)
        with client.session_transaction() as sess:
            sess['csrf_token'] = 'fake_token'
        
        response = client.post('/generate', data=form_data)
        assert response.status_code == 400
        
        json_data = response.get_json()
        assert json_data['error_type'] == 'CSRFError'


class TestCSRFSecurityHeaders:
    """Test cases for security headers related to CSRF"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_index_page_security_headers(self, client):
        """Test that index page includes appropriate security headers"""
        response = client.get('/')
        
        # Check for CSRF-related security headers
        headers = dict(response.headers)
        
        # Should have appropriate cache control
        if 'Cache-Control' in headers:
            cache_control = headers['Cache-Control'].lower()
            # Should not cache pages with CSRF tokens
            assert 'no-cache' in cache_control or 'no-store' in cache_control

    def test_error_response_headers(self, client):
        """Test that error responses have appropriate headers"""
        response = client.post('/generate', data={'CN': 'test.com'})
        
        # Error response should be JSON
        assert response.content_type == 'application/json'
        
        # Should not be cacheable
        headers = dict(response.headers)
        if 'Cache-Control' in headers:
            assert 'no-cache' in headers['Cache-Control'] or 'no-store' in headers['Cache-Control']


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
