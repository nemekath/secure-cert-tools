#!/usr/bin/env python3
"""
Test script to verify that large request handling is working correctly
"""

import pytest
import re
from app import app


@pytest.fixture
def client():
    """Create test client with CSRF disabled for easier testing"""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for these tests
    app.config['RATELIMIT_STORAGE_URL'] = "memory://"  # Use in-memory storage for testing
    with app.test_client() as client:
        yield client


def test_large_request_handling(client):
    """Test that large requests are properly handled with 413 status code"""
    # Create a large payload (over 1MB)
    large_data = {
        'CN': 'large-request-test.example.com',
        'O': 'X' * (1024 * 1024 + 1000),  # Over 1MB
        'keyType': 'RSA',
        'keySize': '2048'
    }
    
    response = client.post('/generate', data=large_data)
    
    # Should get 413 Request Entity Too Large or 400 Bad Request
    assert response.status_code in [400, 413], f"Expected 400 or 413, got {response.status_code}"
    
    if response.is_json:
        data = response.get_json()
        assert 'error' in data
        # Error message should mention size, large, or limit
        error_msg = data['error'].lower()
        assert any(keyword in error_msg for keyword in ['large', 'size', 'limit', 'entity', 'too big']), \
            f"Error message should mention size limits: {data['error']}"


def test_normal_request_still_works(client):
    """Test that normal-sized requests still work correctly"""
    normal_data = {
        'CN': 'normal-request-test.example.com',
        'C': 'US',
        'O': 'Normal Request Corp',
        'keyType': 'RSA',
        'keySize': '2048'
    }
    
    response = client.post('/generate', data=normal_data)
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    assert response.is_json
    
    data = response.get_json()
    assert 'csr' in data
    assert 'private_key' in data
    assert '-----BEGIN CERTIFICATE REQUEST-----' in data['csr']
    assert 'PRIVATE KEY' in data['private_key']


if __name__ == "__main__":
    pytest.main([__file__, '-v'])
