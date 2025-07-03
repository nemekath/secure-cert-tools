#!/usr/bin/env python3
"""
Focused REST API Test for Secure Cert-Tools
Tests all key fields and parameters with proper rate limit handling
"""

import requests
import json
import re
import urllib3
import time
from datetime import datetime

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class FocusedAPITester:
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
            meta_match = re.search(r'<meta name="csrf-token" content="([^"]+)"', response.text)
            if meta_match:
                self.csrf_token = meta_match.group(1)
                return True
            return False
        except Exception as e:
            print(f"❌ Error getting CSRF token: {e}")
            return False
    
    def make_api_request(self, endpoint, data, expected_status=200, description=""):
        """Make API request with rate limiting consideration"""
        # Add small delay between requests to avoid rate limiting
        self.request_count += 1
        if self.request_count > 1:
            time.sleep(0.5)  # 500ms delay between requests
        
        if not self.csrf_token:
            self.get_csrf_token()
        
        data_copy = data.copy()
        data_copy['csrf_token'] = self.csrf_token
        
        headers = {
            'Referer': self.base_url,
            'X-CSRFToken': self.csrf_token,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        
        try:
            response = self.session.post(f"{self.base_url}{endpoint}", data=data_copy, headers=headers, verify=False)
            
            # Handle rate limiting
            if response.status_code == 429:
                print(f"⚠️ Rate limited, waiting 30 seconds...")
                time.sleep(30)
                # Retry once
                response = self.session.post(f"{self.base_url}{endpoint}", data=data_copy, headers=headers, verify=False)
            
            result = {
                'endpoint': endpoint,
                'description': description,
                'status_code': response.status_code,
                'expected_status': expected_status,
                'success': response.status_code == expected_status
            }
            
            try:
                result['response_json'] = response.json()
            except:
                result['response_text'] = response.text[:200]
            
            self.test_results.append(result)
            return response
            
        except Exception as e:
            result = {
                'endpoint': endpoint,
                'description': description,
                'error': str(e),
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
    
    def test_all_subject_fields(self):
        """Test all X.509 subject fields"""
        print("\n🔍 Testing All X.509 Subject Fields")
        
        # Test with all possible subject fields
        data = {
            'CN': 'comprehensive.example.com',
            'C': 'US',                          # Country (2 chars, required format)
            'ST': 'California',                 # State/Province (max 128 chars)
            'L': 'San Francisco',               # Locality/City (max 128 chars)
            'O': 'Comprehensive Test Corp',     # Organization (max 64 chars)
            'OU': 'Engineering Department',     # Organizational Unit (max 64 chars)
            'keyType': 'RSA',
            'keySize': '2048'
        }
        
        response = self.make_api_request('/generate', data, 200, "All subject fields test")
        
        if response and response.status_code == 200:
            result = response.json()
            success = 'csr' in result and 'private_key' in result
            
            self.print_result(
                "All X.509 subject fields (CN, C, ST, L, O, OU)",
                success,
                f"Generated CSR with all fields: {len(result.get('csr', ''))} chars"
            )
            return result
        else:
            self.print_result("All X.509 subject fields", False, f"Status: {response.status_code if response else 'No response'}")
            return None
    
    def test_key_types_and_sizes(self):
        """Test different key types and sizes"""
        print("\n🔍 Testing Key Types and Sizes")
        
        test_cases = [
            {
                'name': 'RSA 2048-bit',
                'data': {'CN': 'rsa2048.example.com', 'keyType': 'RSA', 'keySize': '2048'}
            },
            {
                'name': 'RSA 4096-bit',
                'data': {'CN': 'rsa4096.example.com', 'keyType': 'RSA', 'keySize': '4096'}
            },
            {
                'name': 'ECDSA P-256',
                'data': {'CN': 'ecdsa256.example.com', 'keyType': 'ECDSA', 'curve': 'P-256'}
            },
            {
                'name': 'ECDSA P-384',
                'data': {'CN': 'ecdsa384.example.com', 'keyType': 'ECDSA', 'curve': 'P-384'}
            },
            {
                'name': 'ECDSA P-521',
                'data': {'CN': 'ecdsa521.example.com', 'keyType': 'ECDSA', 'curve': 'P-521'}
            }
        ]
        
        results = {}
        
        for test_case in test_cases:
            response = self.make_api_request('/generate', test_case['data'], 200, f"Key test: {test_case['name']}")
            
            if response and response.status_code == 200:
                result = response.json()
                success = 'csr' in result and 'private_key' in result
                results[test_case['name']] = result if success else None
                
                key_size = len(result.get('private_key', ''))
                self.print_result(
                    f"Key type: {test_case['name']}",
                    success,
                    f"Private key size: {key_size} chars"
                )
            else:
                results[test_case['name']] = None
                status_code = response.status_code if response else 'No response'
                self.print_result(f"Key type: {test_case['name']}", False, f"Status: {status_code}")
        
        return results
    
    def test_subject_alternative_names(self):
        """Test Subject Alternative Names functionality"""
        print("\n🔍 Testing Subject Alternative Names")
        
        test_cases = [
            {
                'name': 'Multiple domains',
                'subjectAltNames': 'api.example.com, www.example.com, mail.example.com'
            },
            {
                'name': 'Wildcard domain',
                'subjectAltNames': '*.example.com'
            },
            {
                'name': 'Mixed domains',
                'subjectAltNames': 'app.test.com, *.cdn.test.com, secure.test.com'
            }
        ]
        
        for test_case in test_cases:
            data = {
                'CN': 'san-test.example.com',
                'C': 'US',
                'O': 'SAN Test Corp',
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
    
    def test_private_domains(self):
        """Test private domain support"""
        print("\n🔍 Testing Private Domain Support")
        
        test_cases = [
            {
                'name': 'Single-label domain',
                'CN': 'server',
                'allowPrivateDomains': 'true'
            },
            {
                'name': 'Local domain',
                'CN': 'database.local',
                'allowPrivateDomains': 'true'
            },
            {
                'name': 'Corporate domain',
                'CN': 'app.corp',
                'allowPrivateDomains': 'true'
            }
        ]
        
        for test_case in test_cases:
            data = {
                'CN': test_case['CN'],
                'C': 'US',
                'O': 'Private Domain Test',
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
    
    def test_field_validation(self):
        """Test field validation"""
        print("\n🔍 Testing Field Validation")
        
        test_cases = [
            {
                'name': 'Invalid country code (3 chars)',
                'data': {'CN': 'test.example.com', 'C': 'USA'},
                'expected_status': 400
            },
            {
                'name': 'Invalid RSA key size',
                'data': {'CN': 'test.example.com', 'keyType': 'RSA', 'keySize': '1024'},
                'expected_status': 400
            },
            {
                'name': 'Missing required CN',
                'data': {'C': 'US', 'keyType': 'RSA'},
                'expected_status': 400
            }
        ]
        
        for test_case in test_cases:
            response = self.make_api_request('/generate', test_case['data'], test_case['expected_status'], 
                                           f"Validation: {test_case['name']}")
            
            if response:
                success = response.status_code == test_case['expected_status']
                
                if response.status_code >= 400:
                    try:
                        result = response.json()
                        error_msg = result.get('error', 'No error message')[:50]
                    except:
                        error_msg = "Could not parse error"
                else:
                    error_msg = "Request succeeded unexpectedly"
                
                self.print_result(
                    f"Validation: {test_case['name']}",
                    success,
                    f"Status: {response.status_code}, Error: {error_msg}"
                )
            else:
                self.print_result(f"Validation: {test_case['name']}", False, "No response")
    
    def test_verify_functionality(self, csr_data):
        """Test CSR verification"""
        print("\n🔍 Testing CSR Verification")
        
        if not csr_data or 'csr' not in csr_data:
            print("❌ No CSR data available for verification tests")
            return
        
        # Test matching CSR and private key
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
                f"Match: {result.get('match')}, Message: {result.get('message', '')[:40]}"
            )
        else:
            status_code = response.status_code if response else 'No response'
            self.print_result("Verify matching CSR and private key", False, f"Status: {status_code}")
    
    def test_analyze_functionality(self, csr_data):
        """Test CSR analysis"""
        print("\n🔍 Testing CSR Analysis")
        
        if not csr_data or 'csr' not in csr_data:
            print("❌ No CSR data available for analysis tests")
            return
        
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
    
    def test_version_endpoint(self):
        """Test version endpoint"""
        print("\n🔍 Testing Version Endpoint")
        
        try:
            response = self.session.get(f"{self.base_url}/version", verify=False)
            
            if response.status_code == 200:
                result = response.json()
                required_fields = ['version', 'project_name', 'release_date']
                success = all(field in result for field in required_fields)
                
                self.print_result(
                    "Version endpoint",
                    success,
                    f"Version: {result.get('version')}, Project: {result.get('project_name')}"
                )
            else:
                self.print_result("Version endpoint", False, f"Status: {response.status_code}")
                
        except Exception as e:
            self.print_result("Version endpoint", False, f"Exception: {str(e)}")
    
    def run_focused_tests(self):
        """Run focused REST API tests"""
        print("🚀 FOCUSED REST API TEST SUITE")
        print("🎯 Testing all key fields, parameters, and functionality")
        print("⏱️ With rate limiting consideration")
        print("=" * 60)
        
        start_time = datetime.now()
        
        # Get CSRF token
        if not self.get_csrf_token():
            print("❌ Failed to get CSRF token. Exiting.")
            return
        
        print(f"🎫 CSRF Token obtained: {self.csrf_token[:20]}...")
        
        # Test version endpoint (no rate limiting)
        self.test_version_endpoint()
        
        # Test all subject fields
        comprehensive_result = self.test_all_subject_fields()
        
        # Test different key types and sizes
        self.test_key_types_and_sizes()
        
        # Test Subject Alternative Names
        self.test_subject_alternative_names()
        
        # Test private domain support
        self.test_private_domains()
        
        # Test field validation
        self.test_field_validation()
        
        # Test verification functionality
        if comprehensive_result:
            self.test_verify_functionality(comprehensive_result)
            self.test_analyze_functionality(comprehensive_result)
        
        end_time = datetime.now()
        duration = end_time - start_time
        
        # Generate summary
        self.generate_summary(duration)
    
    def generate_summary(self, duration):
        """Generate test summary"""
        print("\n" + "=" * 60)
        print("📊 FOCUSED TEST SUMMARY")
        print("=" * 60)
        
        total_tests = len(self.test_results)
        successful_tests = sum(1 for result in self.test_results if result.get('success', False))
        failed_tests = total_tests - successful_tests
        
        print(f"⏱️ Duration: {duration.total_seconds():.1f} seconds")
        print(f"🧪 Total Tests: {total_tests}")
        print(f"✅ Successful: {successful_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"📈 Success Rate: {(successful_tests/total_tests*100):.1f}%")
        
        # List any failures
        failures = [r for r in self.test_results if not r.get('success', False)]
        if failures:
            print("\n❌ FAILED TESTS:")
            for failure in failures:
                endpoint = failure.get('endpoint', 'Unknown')
                desc = failure.get('description', 'No description')
                error = failure.get('error', f"Status {failure.get('status_code', 'unknown')}")
                print(f"  • {endpoint} - {desc}: {error}")
        
        print("\n✅ TESTED FUNCTIONALITY:")
        print("  • All X.509 subject fields (CN, C, ST, L, O, OU)")
        print("  • RSA key generation (2048, 4096-bit)")
        print("  • ECDSA key generation (P-256, P-384, P-521)")
        print("  • Subject Alternative Names")
        print("  • Private domain support")
        print("  • Field validation and error handling")
        print("  • CSR and private key verification")
        print("  • CSR analysis and RFC compliance")
        print("  • Version information endpoint")
        
        print("\n🏁 FOCUSED REST API TESTING COMPLETED!")

if __name__ == "__main__":
    tester = FocusedAPITester()
    tester.run_focused_tests()
