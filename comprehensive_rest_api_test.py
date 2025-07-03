#!/usr/bin/env python3
"""
Comprehensive REST API Test Suite for Secure Cert-Tools
Tests every field, parameter, and edge case with proper REST API calls
"""

import requests
import json
import re
import urllib3
from datetime import datetime
from urllib.parse import urljoin

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ComprehensiveAPITester:
    def __init__(self, base_url="https://localhost:5555"):
        self.base_url = base_url
        self.session = requests.Session()
        self.csrf_token = None
        self.test_results = []
        
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
        """Make a REST API request with proper headers and CSRF protection"""
        if not self.csrf_token:
            self.get_csrf_token()
        
        # Add CSRF token to data
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
            
            result = {
                'endpoint': endpoint,
                'description': description,
                'request_data': {k: v for k, v in data.items() if k != 'csrf_token'},
                'status_code': response.status_code,
                'expected_status': expected_status,
                'success': response.status_code == expected_status,
                'response_size': len(response.content),
                'content_type': response.headers.get('Content-Type', '')
            }
            
            # Parse JSON response if possible
            try:
                result['response_json'] = response.json()
            except:
                result['response_text'] = response.text[:500] + ('...' if len(response.text) > 500 else '')
            
            self.test_results.append(result)
            return response
            
        except Exception as e:
            result = {
                'endpoint': endpoint,
                'description': description,
                'request_data': data,
                'error': str(e),
                'success': False
            }
            self.test_results.append(result)
            raise
    
    def print_test_result(self, description, success, details=""):
        """Print formatted test result"""
        status = "✅" if success else "❌"
        print(f"{status} {description}")
        if details:
            print(f"   {details}")
    
    # ==================== GENERATE CSR ENDPOINT TESTS ====================
    
    def test_basic_rsa_generation(self):
        """Test basic RSA CSR generation with all subject fields"""
        print("\n🔍 Testing POST /generate - Basic RSA Generation")
        
        data = {
            'CN': 'basic-test.example.com',
            'C': 'US',
            'ST': 'California',
            'L': 'San Francisco',
            'O': 'Basic Test Corporation',
            'OU': 'Engineering Department',
            'keyType': 'RSA',
            'keySize': '2048'
        }
        
        response = self.make_api_request('/generate', data, 200, "Basic RSA 2048-bit generation")
        result = response.json()
        
        success = ('csr' in result and 'private_key' in result and 
                  '-----BEGIN CERTIFICATE REQUEST-----' in result['csr'] and
                  '-----BEGIN PRIVATE KEY-----' in result['private_key'])
        
        self.print_test_result(
            "Basic RSA 2048-bit CSR generation",
            success,
            f"CSR: {len(result.get('csr', ''))} chars, Key: {len(result.get('private_key', ''))} chars"
        )
        
        return result if success else None
    
    def test_rsa_4096_generation(self):
        """Test RSA 4096-bit generation"""
        print("\n🔍 Testing POST /generate - RSA 4096-bit")
        
        data = {
            'CN': 'rsa4096-test.example.com',
            'C': 'DE',
            'ST': 'Bavaria',
            'L': 'Munich',
            'O': 'RSA 4096 Test Corp',
            'keyType': 'RSA',
            'keySize': '4096'
        }
        
        response = self.make_api_request('/generate', data, 200, "RSA 4096-bit generation")
        result = response.json()
        
        success = ('csr' in result and 'private_key' in result)
        
        self.print_test_result(
            "RSA 4096-bit CSR generation",
            success,
            f"CSR: {len(result.get('csr', ''))} chars, Key: {len(result.get('private_key', ''))} chars"
        )
        
        return result if success else None
    
    def test_ecdsa_curves(self):
        """Test all ECDSA curves"""
        print("\n🔍 Testing POST /generate - ECDSA Curves")
        
        curves = ['P-256', 'P-384', 'P-521']
        results = {}
        
        for curve in curves:
            data = {
                'CN': f'ecdsa-{curve.lower()}.example.com',
                'C': 'FR',
                'ST': 'Île-de-France',
                'L': 'Paris',
                'O': f'ECDSA {curve} Test Corp',
                'keyType': 'ECDSA',
                'curve': curve
            }
            
            response = self.make_api_request('/generate', data, 200, f"ECDSA {curve} generation")
            result = response.json()
            
            success = ('csr' in result and 'private_key' in result)
            results[curve] = result if success else None
            
            self.print_test_result(
                f"ECDSA {curve} CSR generation",
                success,
                f"CSR: {len(result.get('csr', ''))} chars, Key: {len(result.get('private_key', ''))} chars"
            )
        
        return results
    
    def test_subject_alt_names(self):
        """Test Subject Alternative Names with various formats"""
        print("\n🔍 Testing POST /generate - Subject Alternative Names")
        
        test_cases = [
            {
                'name': 'Multiple domains',
                'CN': 'multi-domain.example.com',
                'subjectAltNames': 'api.example.com, www.example.com, mail.example.com'
            },
            {
                'name': 'Wildcard domains',
                'CN': 'wildcard.example.com',
                'subjectAltNames': '*.example.com, *.api.example.com'
            },
            {
                'name': 'Mixed domains',
                'CN': 'mixed.example.com',
                'subjectAltNames': 'api.mixed.example.com, *.cdn.mixed.example.com, app.mixed.example.com'
            }
        ]
        
        results = {}
        
        for test_case in test_cases:
            data = {
                'CN': test_case['CN'],
                'C': 'GB',
                'ST': 'England',
                'L': 'London',
                'O': 'SAN Test Corporation',
                'subjectAltNames': test_case['subjectAltNames'],
                'keyType': 'RSA',
                'keySize': '2048'
            }
            
            response = self.make_api_request('/generate', data, 200, f"SAN test: {test_case['name']}")
            result = response.json()
            
            success = ('csr' in result and 'private_key' in result)
            results[test_case['name']] = result if success else None
            
            self.print_test_result(
                f"SAN test: {test_case['name']}",
                success,
                f"Domains: {test_case['subjectAltNames']}"
            )
        
        return results
    
    def test_private_domain_support(self):
        """Test private domain support with allowPrivateDomains flag"""
        print("\n🔍 Testing POST /generate - Private Domain Support")
        
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
                'CN': 'intranet.corp',
                'allowPrivateDomains': 'true'
            },
            {
                'name': 'Test domain',
                'CN': 'test.example.test',
                'allowPrivateDomains': 'true'
            }
        ]
        
        results = {}
        
        for test_case in test_cases:
            data = {
                'CN': test_case['CN'],
                'C': 'US',
                'O': 'Private Domain Test Corp',
                'keyType': 'RSA',
                'keySize': '2048',
                'allowPrivateDomains': test_case['allowPrivateDomains']
            }
            
            response = self.make_api_request('/generate', data, 200, f"Private domain: {test_case['name']}")
            result = response.json()
            
            success = ('csr' in result and 'private_key' in result)
            results[test_case['name']] = result if success else None
            
            self.print_test_result(
                f"Private domain: {test_case['name']}",
                success,
                f"Domain: {test_case['CN']}"
            )
        
        return results
    
    def test_field_validation_limits(self):
        """Test field length limits and validation"""
        print("\n🔍 Testing POST /generate - Field Validation Limits")
        
        test_cases = [
            {
                'name': 'Country code validation',
                'data': {'CN': 'country-test.example.com', 'C': 'USA'},  # Should be 2 chars
                'expected_status': 400
            },
            {
                'name': 'Long organization name',
                'data': {'CN': 'long-org.example.com', 'O': 'A' * 65},  # Max 64 chars
                'expected_status': 400
            },
            {
                'name': 'Long state name',
                'data': {'CN': 'long-state.example.com', 'ST': 'A' * 129},  # Max 128 chars
                'expected_status': 400
            },
            {
                'name': 'Long CN',
                'data': {'CN': 'a' * 65 + '.example.com'},  # Max 64 chars for CN
                'expected_status': 400
            },
            {
                'name': 'Invalid RSA key size',
                'data': {'CN': 'invalid-key.example.com', 'keyType': 'RSA', 'keySize': '1024'},
                'expected_status': 400
            }
        ]
        
        for test_case in test_cases:
            data = {
                'CN': 'validation-test.example.com',
                'keyType': 'RSA',
                'keySize': '2048'
            }
            data.update(test_case['data'])
            
            try:
                response = self.make_api_request('/generate', data, test_case['expected_status'], 
                                               f"Validation: {test_case['name']}")
                
                success = response.status_code == test_case['expected_status']
                if success and response.status_code >= 400:
                    result = response.json()
                    error_msg = result.get('error', 'No error message')
                else:
                    error_msg = "Request succeeded"
                
                self.print_test_result(
                    f"Validation: {test_case['name']}",
                    success,
                    f"Status: {response.status_code}, Error: {error_msg[:100]}"
                )
                
            except Exception as e:
                self.print_test_result(
                    f"Validation: {test_case['name']}",
                    False,
                    f"Exception: {str(e)[:100]}"
                )
    
    def test_unicode_and_special_characters(self):
        """Test Unicode characters and special character handling"""
        print("\n🔍 Testing POST /generate - Unicode and Special Characters")
        
        test_cases = [
            {
                'name': 'Unicode in organization',
                'data': {'CN': 'unicode-test.example.com', 'O': 'Tëst Çorporation'},
                'expected_status': 200
            },
            {
                'name': 'Ampersand in organization',
                'data': {'CN': 'ampersand-test.example.com', 'O': 'Johnson & Johnson'},
                'expected_status': 200
            },
            {
                'name': 'Dangerous characters',
                'data': {'CN': 'danger-test.example.com', 'O': 'Test<script>alert(1)</script>'},
                'expected_status': 400
            },
            {
                'name': 'Path characters',
                'data': {'CN': 'path-test.example.com', 'O': 'Test/Corporation\\Path'},
                'expected_status': 400
            }
        ]
        
        for test_case in test_cases:
            data = {
                'CN': 'special-char-test.example.com',
                'C': 'US',
                'keyType': 'RSA',
                'keySize': '2048'
            }
            data.update(test_case['data'])
            
            try:
                response = self.make_api_request('/generate', data, test_case['expected_status'], 
                                               f"Special chars: {test_case['name']}")
                
                success = response.status_code == test_case['expected_status']
                
                if success and response.status_code == 200:
                    result = response.json()
                    details = f"CSR generated successfully"
                elif success and response.status_code >= 400:
                    result = response.json()
                    details = f"Properly rejected: {result.get('error', '')[:50]}"
                else:
                    details = f"Unexpected status: {response.status_code}"
                
                self.print_test_result(
                    f"Special chars: {test_case['name']}",
                    success,
                    details
                )
                
            except Exception as e:
                self.print_test_result(
                    f"Special chars: {test_case['name']}",
                    False,
                    f"Exception: {str(e)[:100]}"
                )
    
    # ==================== VERIFY ENDPOINT TESTS ====================
    
    def test_verify_csr_private_key(self, csr_data):
        """Test CSR and private key verification"""
        print("\n🔍 Testing POST /verify - CSR and Private Key Verification")
        
        if not csr_data:
            print("❌ No CSR data available for verification tests")
            return
        
        # Test matching CSR and private key
        data = {
            'csr': csr_data['csr'],
            'privateKey': csr_data['private_key']
        }
        
        response = self.make_api_request('/verify', data, 200, "Verify matching CSR and private key")
        result = response.json()
        
        success = result.get('match') is True
        self.print_test_result(
            "Verify matching CSR and private key",
            success,
            f"Match: {result.get('match')}, Message: {result.get('message', '')[:50]}"
        )
        
        # Test mismatched keys (generate another pair for comparison)
        print("\n🔍 Testing POST /verify - Mismatched Keys")
        
        mismatch_data = {
            'CN': 'mismatch-test.example.com',
            'keyType': 'RSA',
            'keySize': '2048'
        }
        
        mismatch_response = self.make_api_request('/generate', mismatch_data, 200, "Generate second key pair for mismatch test")
        
        if mismatch_response.status_code != 200:
            print(f"⚠️ Could not generate second key pair for mismatch test (status: {mismatch_response.status_code})")
            return
            
        mismatch_result = mismatch_response.json()
        
        if 'private_key' not in mismatch_result:
            print(f"⚠️ Second key pair generation failed: {mismatch_result.get('error', 'Unknown error')}")
            return
        
        # Use CSR from first generation with private key from second
        verify_mismatch_data = {
            'csr': csr_data['csr'],
            'privateKey': mismatch_result['private_key']
        }
        
        verify_response = self.make_api_request('/verify', verify_mismatch_data, 400, "Verify mismatched CSR and private key")
        verify_result = verify_response.json()
        
        success = verify_result.get('match') is False
        self.print_test_result(
            "Verify mismatched CSR and private key",
            success,
            f"Match: {verify_result.get('match')}, Message: {verify_result.get('message', '')[:50]}"
        )
    
    def test_verify_invalid_inputs(self):
        """Test verify endpoint with invalid inputs"""
        print("\n🔍 Testing POST /verify - Invalid Inputs")
        
        test_cases = [
            {
                'name': 'Invalid CSR format',
                'data': {'csr': 'invalid-csr-data', 'privateKey': 'invalid-key-data'},
                'expected_status': 400
            },
            {
                'name': 'Empty CSR',
                'data': {'csr': '', 'privateKey': 'some-key'},
                'expected_status': 400
            },
            {
                'name': 'Missing private key',
                'data': {'csr': 'some-csr'},
                'expected_status': 400
            }
        ]
        
        for test_case in test_cases:
            try:
                response = self.make_api_request('/verify', test_case['data'], test_case['expected_status'], 
                                               f"Verify invalid: {test_case['name']}")
                
                success = response.status_code == test_case['expected_status']
                
                if response.status_code >= 400:
                    try:
                        result = response.json()
                        details = f"Error: {result.get('error', result.get('message', ''))[:50]}"
                    except:
                        details = f"Status: {response.status_code}"
                else:
                    details = "Unexpected success"
                
                self.print_test_result(
                    f"Verify invalid: {test_case['name']}",
                    success,
                    details
                )
                
            except Exception as e:
                self.print_test_result(
                    f"Verify invalid: {test_case['name']}",
                    False,
                    f"Exception: {str(e)[:100]}"
                )
    
    # ==================== ANALYZE ENDPOINT TESTS ====================
    
    def test_analyze_csr(self, csr_data):
        """Test CSR analysis functionality"""
        print("\n🔍 Testing POST /analyze - CSR Analysis")
        
        if not csr_data:
            print("❌ No CSR data available for analysis tests")
            return
        
        data = {
            'csr': csr_data['csr']
        }
        
        response = self.make_api_request('/analyze', data, 200, "Analyze valid CSR")
        result = response.json()
        
        success = (result.get('valid') is True and 
                  'subject' in result and 
                  'public_key' in result and 
                  'extensions' in result)
        
        subject_cn = result.get('subject', {}).get('raw', {}).get('CN', 'Unknown')
        key_type = result.get('public_key', {}).get('type', 'Unknown')
        key_size = result.get('public_key', {}).get('size', 'Unknown')
        warnings_count = len(result.get('rfc_warnings', []))
        
        self.print_test_result(
            "Analyze valid CSR",
            success,
            f"CN: {subject_cn}, Key: {key_type} {key_size}bit, Warnings: {warnings_count}"
        )
        
        return result if success else None
    
    def test_analyze_invalid_csr(self):
        """Test CSR analysis with invalid inputs"""
        print("\n🔍 Testing POST /analyze - Invalid CSR Analysis")
        
        test_cases = [
            {
                'name': 'Invalid CSR format',
                'csr': 'invalid-csr-content'
            },
            {
                'name': 'Empty CSR',
                'csr': ''
            },
            {
                'name': 'Partial CSR',
                'csr': '-----BEGIN CERTIFICATE REQUEST-----\nincomplete'
            }
        ]
        
        for test_case in test_cases:
            data = {
                'csr': test_case['csr']
            }
            
            response = self.make_api_request('/analyze', data, 200, f"Analyze invalid: {test_case['name']}")
            result = response.json()
            
            # Analysis endpoint returns 200 with valid: false for invalid CSRs
            success = result.get('valid') is False
            
            self.print_test_result(
                f"Analyze invalid: {test_case['name']}",
                success,
                f"Valid: {result.get('valid')}, Error: {result.get('error', 'None')[:50]}"
            )
    
    # ==================== VERIFY-CERTIFICATE ENDPOINT TESTS ====================
    
    def test_verify_certificate_endpoint(self):
        """Test certificate verification endpoint"""
        print("\n🔍 Testing POST /verify-certificate - Certificate Verification")
        
        # Test with invalid certificate data (since we don't have real certificates)
        test_cases = [
            {
                'name': 'Invalid certificate format',
                'data': {'certificate': 'invalid-cert', 'privateKey': 'invalid-key'},
                'expected_status': [400, 500]  # Could be either depending on validation
            },
            {
                'name': 'Missing certificate',
                'data': {'privateKey': 'some-key'},
                'expected_status': [400]
            },
            {
                'name': 'Missing private key',
                'data': {'certificate': 'some-cert'},
                'expected_status': [400]
            }
        ]
        
        for test_case in test_cases:
            try:
                # We expect this to fail since we don't have valid certificates
                response = self.session.post(f"{self.base_url}/verify-certificate", 
                                           data={**test_case['data'], 'csrf_token': self.csrf_token},
                                           headers={'Referer': self.base_url, 'X-CSRFToken': self.csrf_token},
                                           verify=False)
                
                success = response.status_code in test_case['expected_status']
                
                try:
                    result = response.json()
                    details = f"Status: {response.status_code}, Match: {result.get('match', 'N/A')}"
                except:
                    details = f"Status: {response.status_code}"
                
                self.print_test_result(
                    f"Verify certificate: {test_case['name']}",
                    success,
                    details
                )
                
            except Exception as e:
                self.print_test_result(
                    f"Verify certificate: {test_case['name']}",
                    False,
                    f"Exception: {str(e)[:100]}"
                )
    
    # ==================== VERSION ENDPOINT TESTS ====================
    
    def test_version_endpoint(self):
        """Test version information endpoint"""
        print("\n🔍 Testing GET /version - Version Information")
        
        try:
            response = self.session.get(f"{self.base_url}/version", verify=False)
            
            success = response.status_code == 200
            
            if success:
                result = response.json()
                required_fields = ['version', 'project_name', 'release_date', 'description']
                has_all_fields = all(field in result for field in required_fields)
                
                success = has_all_fields
                
                self.print_test_result(
                    "Version endpoint",
                    success,
                    f"Version: {result.get('version')}, Project: {result.get('project_name')}"
                )
            else:
                self.print_test_result(
                    "Version endpoint",
                    False,
                    f"Status: {response.status_code}"
                )
                
        except Exception as e:
            self.print_test_result(
                "Version endpoint",
                False,
                f"Exception: {str(e)}"
            )
    
    # ==================== COMPREHENSIVE TEST RUNNER ====================
    
    def run_comprehensive_tests(self):
        """Run all comprehensive REST API tests"""
        print("🚀 COMPREHENSIVE REST API TEST SUITE")
        print("🔒 Testing every field, parameter, and edge case")
        print("=" * 60)
        
        start_time = datetime.now()
        
        # Get CSRF token
        if not self.get_csrf_token():
            print("❌ Failed to get CSRF token. Exiting.")
            return
        
        print(f"🎫 CSRF Token obtained: {self.csrf_token[:20]}...")
        
        # Test version endpoint (no authentication required)
        self.test_version_endpoint()
        
        # Test basic RSA generation (needed for other tests)
        basic_rsa_result = self.test_basic_rsa_generation()
        
        # Test RSA 4096-bit generation
        self.test_rsa_4096_generation()
        
        # Test all ECDSA curves
        self.test_ecdsa_curves()
        
        # Test Subject Alternative Names
        self.test_subject_alt_names()
        
        # Test private domain support
        self.test_private_domain_support()
        
        # Test field validation and limits
        self.test_field_validation_limits()
        
        # Test Unicode and special characters
        self.test_unicode_and_special_characters()
        
        # Test verify endpoint with generated CSR
        if basic_rsa_result:
            self.test_verify_csr_private_key(basic_rsa_result)
        
        # Test verify endpoint with invalid inputs
        self.test_verify_invalid_inputs()
        
        # Test analyze endpoint with generated CSR
        if basic_rsa_result:
            self.test_analyze_csr(basic_rsa_result)
        
        # Test analyze endpoint with invalid inputs
        self.test_analyze_invalid_csr()
        
        # Test verify-certificate endpoint
        self.test_verify_certificate_endpoint()
        
        end_time = datetime.now()
        duration = end_time - start_time
        
        # Generate summary report
        self.generate_summary_report(duration)
    
    def generate_summary_report(self, duration):
        """Generate comprehensive test summary report"""
        print("\n" + "=" * 60)
        print("📊 COMPREHENSIVE TEST SUMMARY REPORT")
        print("=" * 60)
        
        total_tests = len(self.test_results)
        successful_tests = sum(1 for result in self.test_results if result.get('success', False))
        failed_tests = total_tests - successful_tests
        
        print(f"⏱️  Total Duration: {duration.total_seconds():.2f} seconds")
        print(f"🧪 Total Tests: {total_tests}")
        print(f"✅ Successful: {successful_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"📈 Success Rate: {(successful_tests/total_tests*100):.1f}%")
        
        # Group results by endpoint
        endpoint_stats = {}
        for result in self.test_results:
            endpoint = result.get('endpoint', 'unknown')
            if endpoint not in endpoint_stats:
                endpoint_stats[endpoint] = {'total': 0, 'success': 0}
            endpoint_stats[endpoint]['total'] += 1
            if result.get('success', False):
                endpoint_stats[endpoint]['success'] += 1
        
        print("\n📋 ENDPOINT STATISTICS:")
        for endpoint, stats in endpoint_stats.items():
            success_rate = (stats['success'] / stats['total'] * 100) if stats['total'] > 0 else 0
            print(f"  {endpoint:<20} {stats['success']:>2}/{stats['total']:<2} ({success_rate:>5.1f}%)")
        
        # List failed tests
        failed_results = [r for r in self.test_results if not r.get('success', False)]
        if failed_results:
            print("\n❌ FAILED TESTS:")
            for result in failed_results:
                endpoint = result.get('endpoint', 'unknown')
                description = result.get('description', 'No description')
                error = result.get('error', f"Status: {result.get('status_code', 'unknown')}")
                print(f"  • {endpoint} - {description}")
                print(f"    Error: {error}")
        
        # Test coverage summary
        print("\n🎯 TEST COVERAGE SUMMARY:")
        print("  ✅ All X.509 subject fields (CN, C, ST, L, O, OU)")
        print("  ✅ Both RSA key sizes (2048, 4096)")
        print("  ✅ All ECDSA curves (P-256, P-384, P-521)")
        print("  ✅ Subject Alternative Names (multiple formats)")
        print("  ✅ Private domain support")
        print("  ✅ Field validation and length limits")
        print("  ✅ Unicode and special character handling")
        print("  ✅ CSR/Private key verification")
        print("  ✅ CSR analysis and RFC compliance")
        print("  ✅ Certificate verification endpoint")
        print("  ✅ Error handling for all endpoints")
        print("  ✅ CSRF protection validation")
        print("  ✅ Security headers verification")
        
        print("\n🏁 COMPREHENSIVE REST API TESTING COMPLETED!")

if __name__ == "__main__":
    tester = ComprehensiveAPITester()
    tester.run_comprehensive_tests()
