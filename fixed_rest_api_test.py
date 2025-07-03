#!/usr/bin/env python3
"""
Fixed REST API Test for Secure Cert-Tools
Addresses all failed tests and no response errors with proper rate limiting
"""

import requests
import json
import re
import urllib3
import time
from datetime import datetime

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class FixedAPITester:
    def __init__(self, base_url="https://localhost:5555"):
        self.base_url = base_url
        self.session = requests.Session()
        self.csrf_token = None
        self.test_results = []
        self.request_count = 0
        
    def get_csrf_token(self):
        """Get CSRF token from the main page"""
        try:
            response = self.session.get(self.base_url, verify=False)
            response.raise_for_status()
            meta_match = re.search(r'<meta name="csrf-token" content="([^"]+)"', response.text)
            if meta_match:
                self.csrf_token = meta_match.group(1)
                return True
            return False
        except Exception as e:
            print(f"❌ Error getting CSRF token: {e}")
            return False
    
    def make_api_request(self, endpoint, data, expected_status=200, description="", max_retries=3):
        """Make API request with improved rate limiting and retry logic"""
        self.request_count += 1
        
        # Add progressive delay to avoid rate limiting
        if self.request_count > 1:
            time.sleep(1.0)  # 1 second delay between requests
        
        if not self.csrf_token:
            self.get_csrf_token()
        
        data_copy = data.copy()
        data_copy['csrf_token'] = self.csrf_token
        
        headers = {
            'Referer': self.base_url,
            'X-CSRFToken': self.csrf_token,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
            'User-Agent': 'Secure-Cert-Tools-Test/1.0'
        }
        
        for attempt in range(max_retries):
            try:
                response = self.session.post(f"{self.base_url}{endpoint}", 
                                           data=data_copy, headers=headers, verify=False, timeout=30)
                
                # Handle rate limiting with exponential backoff
                if response.status_code == 429:
                    wait_time = (2 ** attempt) * 10  # 10s, 20s, 40s
                    print(f"⚠️ Rate limited (attempt {attempt + 1}/{max_retries}), waiting {wait_time}s...")
                    time.sleep(wait_time)
                    
                    # Refresh CSRF token on rate limit
                    if not self.get_csrf_token():
                        print("❌ Failed to refresh CSRF token")
                        break
                    data_copy['csrf_token'] = self.csrf_token
                    headers['X-CSRFToken'] = self.csrf_token
                    continue
                
                # Success - record result and return
                result = {
                    'endpoint': endpoint,
                    'description': description,
                    'status_code': response.status_code,
                    'expected_status': expected_status,
                    'success': response.status_code == expected_status,
                    'attempt': attempt + 1
                }
                
                try:
                    result['response_json'] = response.json()
                except:
                    result['response_text'] = response.text[:200]
                
                self.test_results.append(result)
                return response
                
            except requests.exceptions.Timeout:
                print(f"⚠️ Request timeout (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(5)
                    continue
            except requests.exceptions.ConnectionError:
                print(f"⚠️ Connection error (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(5)
                    continue
            except Exception as e:
                print(f"⚠️ Request error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(5)
                    continue
        
        # All retries failed
        result = {
            'endpoint': endpoint,
            'description': description,
            'error': 'All retry attempts failed',
            'success': False
        }
        self.test_results.append(result)
        return None
    
    def print_result(self, description, success, details=""):
        """Print test result"""
        status = "✅" if success else "❌"
        print(f"{status} {description}")
        if details:
            print(f"   {details}")
    
    def test_version_endpoint(self):
        """Test version endpoint (no rate limiting)"""
        print("\n🔍 Testing Version Endpoint")
        
        try:
            response = self.session.get(f"{self.base_url}/version", verify=False, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                required_fields = ['version', 'project_name', 'release_date']
                success = all(field in result for field in required_fields)
                
                self.print_result(
                    "Version endpoint",
                    success,
                    f"Version: {result.get('version')}, Project: {result.get('project_name')}"
                )
                return True
            else:
                self.print_result("Version endpoint", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.print_result("Version endpoint", False, f"Exception: {str(e)}")
            return False
    
    def test_basic_csr_generation(self):
        """Test basic CSR generation with all fields"""
        print("\n🔍 Testing Basic CSR Generation")
        
        data = {
            'CN': 'test-basic.example.com',
            'C': 'US',
            'ST': 'California',
            'L': 'San Francisco',
            'O': 'Test Corporation',
            'OU': 'Engineering',
            'keyType': 'RSA',
            'keySize': '2048'
        }
        
        response = self.make_api_request('/generate', data, 200, "Basic CSR generation")
        
        if response and response.status_code == 200:
            result = response.json()
            success = 'csr' in result and 'private_key' in result
            
            self.print_result(
                "Basic CSR generation",
                success,
                f"CSR: {len(result.get('csr', ''))} chars, Key: {len(result.get('private_key', ''))} chars"
            )
            return result if success else None
        else:
            self.print_result("Basic CSR generation", False, f"Status: {response.status_code if response else 'No response'}")
            return None
    
    def test_key_types_sequential(self):
        """Test different key types sequentially with proper spacing"""
        print("\n🔍 Testing Key Types (Sequential)")
        
        test_cases = [
            {
                'name': 'RSA 4096-bit',
                'data': {'CN': 'rsa4096-fixed.example.com', 'keyType': 'RSA', 'keySize': '4096'},
                'delay': 3  # Extra delay for RSA 4096
            },
            {
                'name': 'ECDSA P-256',
                'data': {'CN': 'ecdsa256-fixed.example.com', 'keyType': 'ECDSA', 'curve': 'P-256'},
                'delay': 2
            },
            {
                'name': 'ECDSA P-384',
                'data': {'CN': 'ecdsa384-fixed.example.com', 'keyType': 'ECDSA', 'curve': 'P-384'},
                'delay': 2
            },
            {
                'name': 'ECDSA P-521',
                'data': {'CN': 'ecdsa521-fixed.example.com', 'keyType': 'ECDSA', 'curve': 'P-521'},
                'delay': 2
            }
        ]
        
        results = {}
        
        for i, test_case in enumerate(test_cases):
            if i > 0:  # Add extra delay between different key types
                print(f"   Waiting {test_case['delay']}s before next key generation...")
                time.sleep(test_case['delay'])
            
            response = self.make_api_request('/generate', test_case['data'], 200, 
                                           f"Key test: {test_case['name']}")
            
            if response and response.status_code == 200:
                result = response.json()
                success = 'csr' in result and 'private_key' in result
                results[test_case['name']] = result if success else None
                
                key_size = len(result.get('private_key', ''))
                self.print_result(
                    f"Key type: {test_case['name']}",
                    success,
                    f"Private key: {key_size} chars"
                )
            else:
                results[test_case['name']] = None
                status_code = response.status_code if response else 'No response'
                self.print_result(f"Key type: {test_case['name']}", False, f"Status: {status_code}")
        
        return results
    
    def test_subject_alternative_names(self):
        """Test SAN functionality with proper spacing"""
        print("\n🔍 Testing Subject Alternative Names")
        
        test_cases = [
            {
                'name': 'Multiple domains',
                'subjectAltNames': 'api-fixed.example.com, www-fixed.example.com'
            },
            {
                'name': 'Wildcard domain',
                'subjectAltNames': '*.fixed.example.com'
            }
        ]
        
        for i, test_case in enumerate(test_cases):
            if i > 0:
                time.sleep(2)  # Delay between SAN tests
            
            data = {
                'CN': 'san-fixed.example.com',
                'C': 'US',
                'O': 'SAN Fixed Test',
                'subjectAltNames': test_case['subjectAltNames'],
                'keyType': 'RSA',
                'keySize': '2048'
            }
            
            response = self.make_api_request('/generate', data, 200, f"SAN test: {test_case['name']}")
            
            if response and response.status_code == 200:
                result = response.json()
                success = 'csr' in result
                
                self.print_result(
                    f"SAN: {test_case['name']}",
                    success,
                    f"Domains: {test_case['subjectAltNames']}"
                )
            else:
                status_code = response.status_code if response else 'No response'
                self.print_result(f"SAN: {test_case['name']}", False, f"Status: {status_code}")
    
    def test_private_domains_fixed(self):
        """Test private domain support with proper error handling"""
        print("\n🔍 Testing Private Domain Support (Fixed)")
        
        test_cases = [
            {
                'name': 'Single-label domain',
                'CN': 'servertest',
                'allowPrivateDomains': 'true'
            },
            {
                'name': 'Corporate domain',
                'CN': 'app-test.corp',
                'allowPrivateDomains': 'true'
            }
        ]
        
        for i, test_case in enumerate(test_cases):
            if i > 0:
                time.sleep(3)  # Extra delay for private domain tests
            
            data = {
                'CN': test_case['CN'],
                'C': 'US',
                'O': 'Private Domain Fixed Test',
                'keyType': 'RSA',
                'keySize': '2048',
                'allowPrivateDomains': test_case['allowPrivateDomains']
            }
            
            response = self.make_api_request('/generate', data, 200, f"Private domain: {test_case['name']}")
            
            if response and response.status_code == 200:
                result = response.json()
                success = 'csr' in result
                
                self.print_result(
                    f"Private domain: {test_case['name']}",
                    success,
                    f"Domain: {test_case['CN']}"
                )
            else:
                status_code = response.status_code if response else 'No response'
                self.print_result(f"Private domain: {test_case['name']}", False, f"Status: {status_code}")
    
    def test_field_validation_fixed(self):
        """Test field validation with proper error handling"""
        print("\n🔍 Testing Field Validation (Fixed)")
        
        test_cases = [
            {
                'name': 'Invalid country code',
                'data': {'CN': 'validation1.example.com', 'C': 'USA'},  # Should be 2 chars
                'expected_status': 400
            },
            {
                'name': 'Invalid RSA key size',
                'data': {'CN': 'validation2.example.com', 'keyType': 'RSA', 'keySize': '1024'},
                'expected_status': 400
            },
            {
                'name': 'Missing required CN',
                'data': {'C': 'US', 'keyType': 'RSA', 'keySize': '2048'},
                'expected_status': 400
            }
        ]
        
        for i, test_case in enumerate(test_cases):
            if i > 0:
                time.sleep(2)  # Delay between validation tests
            
            response = self.make_api_request('/generate', test_case['data'], 
                                           test_case['expected_status'], 
                                           f"Validation: {test_case['name']}")
            
            if response:
                success = response.status_code == test_case['expected_status']
                
                if response.status_code >= 400:
                    try:
                        result = response.json()
                        error_msg = result.get('error', 'No error message')[:60]
                    except:
                        error_msg = "Could not parse JSON response"
                else:
                    error_msg = "Request succeeded unexpectedly"
                
                self.print_result(
                    f"Validation: {test_case['name']}",
                    success,
                    f"Status: {response.status_code}, Error: {error_msg}"
                )
            else:
                self.print_result(f"Validation: {test_case['name']}", False, "No response received")
    
    def test_verify_functionality_fixed(self, csr_data):
        """Test CSR verification with improved error handling"""
        print("\n🔍 Testing CSR Verification (Fixed)")
        
        if not csr_data or 'csr' not in csr_data:
            print("❌ No CSR data available for verification tests")
            return
        
        time.sleep(2)  # Delay before verification test
        
        verify_data = {
            'csr': csr_data['csr'],
            'privateKey': csr_data['private_key']
        }
        
        response = self.make_api_request('/verify', verify_data, 200, "Verify matching CSR and key")
        
        if response and response.status_code == 200:
            result = response.json()
            success = result.get('match') is True
            
            self.print_result(
                "Verify matching CSR and private key",
                success,
                f"Match: {result.get('match')}, Message: {result.get('message', '')[:50]}"
            )
        else:
            status_code = response.status_code if response else 'No response'
            self.print_result("Verify matching CSR and private key", False, f"Status: {status_code}")
    
    def test_analyze_functionality_fixed(self, csr_data):
        """Test CSR analysis with improved error handling"""
        print("\n🔍 Testing CSR Analysis (Fixed)")
        
        if not csr_data or 'csr' not in csr_data:
            print("❌ No CSR data available for analysis tests")
            return
        
        time.sleep(2)  # Delay before analysis test
        
        analyze_data = {
            'csr': csr_data['csr']
        }
        
        response = self.make_api_request('/analyze', analyze_data, 200, "Analyze CSR")
        
        if response and response.status_code == 200:
            result = response.json()
            success = result.get('valid') is True
            
            if success:
                subject_cn = result.get('subject', {}).get('raw', {}).get('CN', 'Unknown')
                key_info = result.get('public_key', {})
                key_type = key_info.get('type', 'Unknown')
                key_size = key_info.get('size', 'Unknown')
                warnings = len(result.get('rfc_warnings', []))
                
                details = f"CN: {subject_cn}, Key: {key_type} {key_size}bit, Warnings: {warnings}"
            else:
                details = f"Analysis failed: {result.get('error', 'Unknown error')}"
            
            self.print_result("CSR analysis", success, details)
        else:
            status_code = response.status_code if response else 'No response'
            self.print_result("CSR analysis", False, f"Status: {status_code}")
    
    def test_error_handling(self):
        """Test error handling with invalid inputs"""
        print("\n🔍 Testing Error Handling")
        
        time.sleep(2)
        
        # Test invalid CSR analysis
        invalid_data = {
            'csr': 'invalid-csr-content'
        }
        
        response = self.make_api_request('/analyze', invalid_data, 200, "Invalid CSR analysis")
        
        if response and response.status_code == 200:
            result = response.json()
            success = result.get('valid') is False  # Should be invalid
            
            self.print_result(
                "Invalid CSR handling",
                success,
                f"Valid: {result.get('valid')}, Error detected properly"
            )
        else:
            status_code = response.status_code if response else 'No response'
            self.print_result("Invalid CSR handling", False, f"Status: {status_code}")
    
    def run_fixed_tests(self):
        """Run all fixed tests with proper error handling and rate limiting"""
        print("🚀 FIXED REST API TEST SUITE")
        print("🔧 Addresses all failed tests and no response errors")
        print("⏱️ With improved rate limiting and retry logic")
        print("=" * 65)
        
        start_time = datetime.now()
        
        # Check server connectivity first
        print("🔍 Checking server connectivity...")
        try:
            response = self.session.get(self.base_url, verify=False, timeout=10)
            if response.status_code != 200:
                print(f"❌ Server not responding properly: {response.status_code}")
                return
            else:
                print("✅ Server is responding")
        except Exception as e:
            print(f"❌ Cannot connect to server: {e}")
            return
        
        # Get CSRF token
        if not self.get_csrf_token():
            print("❌ Failed to get CSRF token. Exiting.")
            return
        
        print(f"🎫 CSRF Token obtained: {self.csrf_token[:20]}...")
        
        # Run tests with proper spacing
        print("\n" + "="*50)
        print("Starting test sequence...")
        print("="*50)
        
        # Test 1: Version endpoint (no rate limiting)
        self.test_version_endpoint()
        
        # Test 2: Basic CSR generation
        basic_result = self.test_basic_csr_generation()
        
        # Test 3: Different key types (with spacing)
        self.test_key_types_sequential()
        
        # Test 4: Subject Alternative Names
        self.test_subject_alternative_names()
        
        # Test 5: Private domains
        self.test_private_domains_fixed()
        
        # Test 6: Field validation
        self.test_field_validation_fixed()
        
        # Test 7: Verification functionality
        if basic_result:
            self.test_verify_functionality_fixed(basic_result)
            self.test_analyze_functionality_fixed(basic_result)
        
        # Test 8: Error handling
        self.test_error_handling()
        
        end_time = datetime.now()
        duration = end_time - start_time
        
        # Generate final summary
        self.generate_fixed_summary(duration)
    
    def generate_fixed_summary(self, duration):
        """Generate summary of fixed test results"""
        print("\n" + "=" * 65)
        print("📊 FIXED TEST RESULTS SUMMARY")
        print("=" * 65)
        
        total_tests = len(self.test_results)
        successful_tests = sum(1 for result in self.test_results if result.get('success', False))
        failed_tests = total_tests - successful_tests
        
        print(f"⏱️ Duration: {duration.total_seconds():.1f} seconds")
        print(f"🧪 Total Tests: {total_tests}")
        print(f"✅ Successful: {successful_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"📈 Success Rate: {(successful_tests/total_tests*100):.1f}%" if total_tests > 0 else "0.0%")
        
        # Show any remaining failures
        failures = [r for r in self.test_results if not r.get('success', False)]
        if failures:
            print("\n❌ REMAINING FAILURES:")
            for failure in failures:
                endpoint = failure.get('endpoint', 'Unknown')
                desc = failure.get('description', 'No description')
                error = failure.get('error', f"Status {failure.get('status_code', 'unknown')}")
                print(f"  • {endpoint} - {desc}: {error}")
        else:
            print("\n🎉 ALL TESTS PASSED! No failures remaining.")
        
        print("\n✅ FIXES IMPLEMENTED:")
        print("  • Improved rate limiting with exponential backoff")
        print("  • Added request timeouts and retry logic")
        print("  • Enhanced error handling for network issues")
        print("  • Sequential test execution with proper delays")
        print("  • CSRF token refresh on rate limit errors")
        print("  • Connection verification before testing")
        print("  • Robust response parsing and validation")
        
        print("\n🏁 FIXED REST API TESTING COMPLETED!")

if __name__ == "__main__":
    tester = FixedAPITester()
    tester.run_fixed_tests()
