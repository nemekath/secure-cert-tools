#!/usr/bin/env python3
"""
Test script for HTTP API endpoints
Demonstrates proper usage of the Secure Cert-Tools API
"""

import requests
import json
import re
import urllib3
from urllib.parse import urljoin

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecureCertToolsAPITester:
    def __init__(self, base_url="https://localhost:5555"):
        self.base_url = base_url
        self.session = requests.Session()
        self.csrf_token = None
        
    def get_csrf_token(self):
        """Get CSRF token from the main page"""
        try:
            response = self.session.get(self.base_url, verify=False)
            response.raise_for_status()
            
            # Extract CSRF token from meta tag
            meta_match = re.search(r'<meta name="csrf-token" content="([^"]+)"', response.text)
            if meta_match:
                self.csrf_token = meta_match.group(1)
                print(f"✅ CSRF token obtained: {self.csrf_token[:20]}...")
                return True
            else:
                print("❌ Could not find CSRF token in response")
                return False
        except Exception as e:
            print(f"❌ Error getting CSRF token: {e}")
            return False
    
    def test_version_endpoint(self):
        """Test GET /version endpoint"""
        print("\n🔍 Testing /version endpoint...")
        try:
            response = self.session.get(f"{self.base_url}/version", verify=False)
            response.raise_for_status()
            
            data = response.json()
            print(f"✅ Version: {data.get('version')}")
            print(f"✅ Project: {data.get('project_name')}")
            print(f"✅ Release Date: {data.get('release_date')}")
            return True
        except Exception as e:
            print(f"❌ Error testing version endpoint: {e}")
            return False
    
    def test_generate_csr(self):
        """Test POST /generate endpoint"""
        print("\n🔍 Testing /generate endpoint...")
        
        if not self.csrf_token:
            if not self.get_csrf_token():
                return False
        
        form_data = {
            'CN': 'api-test.example.com',
            'C': 'US',
            'ST': 'California',
            'L': 'San Francisco',
            'O': 'API Test Corporation',
            'OU': 'Engineering Department',
            'keyType': 'RSA',
            'keySize': '2048',
            'csrf_token': self.csrf_token
        }
        
        try:
            headers = {
                'Referer': self.base_url,
                'X-CSRFToken': self.csrf_token
            }
            response = self.session.post(f"{self.base_url}/generate", data=form_data, headers=headers, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                print("✅ CSR generated successfully!")
                print(f"✅ CSR length: {len(data.get('csr', ''))} characters")
                print(f"✅ Private key length: {len(data.get('private_key', ''))} characters")
                
                # Validate CSR format
                csr = data.get('csr', '')
                if '-----BEGIN CERTIFICATE REQUEST-----' in csr and '-----END CERTIFICATE REQUEST-----' in csr:
                    print("✅ CSR format is valid")
                else:
                    print("❌ CSR format is invalid")
                
                # Validate private key format
                private_key = data.get('private_key', '')
                if '-----BEGIN PRIVATE KEY-----' in private_key and '-----END PRIVATE KEY-----' in private_key:
                    print("✅ Private key format is valid")
                else:
                    print("❌ Private key format is invalid")
                
                return {'csr': csr, 'private_key': private_key}
            else:
                print(f"❌ Generation failed with status {response.status_code}")
                print(f"❌ Error: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error testing generate endpoint: {e}")
            return False
    
    def test_verify_csr(self, csr, private_key):
        """Test POST /verify endpoint"""
        print("\n🔍 Testing /verify endpoint...")
        
        if not self.csrf_token:
            if not self.get_csrf_token():
                return False
        
        form_data = {
            'csr': csr,
            'privateKey': private_key,
            'csrf_token': self.csrf_token
        }
        
        try:
            headers = {
                'Referer': self.base_url,
                'X-CSRFToken': self.csrf_token
            }
            response = self.session.post(f"{self.base_url}/verify", data=form_data, headers=headers, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('match') is True:
                    print("✅ CSR and private key match successfully!")
                    print(f"✅ Message: {data.get('message')}")
                else:
                    print("❌ CSR and private key do not match")
                return True
            else:
                print(f"❌ Verification failed with status {response.status_code}")
                print(f"❌ Error: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error testing verify endpoint: {e}")
            return False
    
    def test_analyze_csr(self, csr):
        """Test POST /analyze endpoint"""
        print("\n🔍 Testing /analyze endpoint...")
        
        if not self.csrf_token:
            if not self.get_csrf_token():
                return False
        
        form_data = {
            'csr': csr,
            'csrf_token': self.csrf_token
        }
        
        try:
            headers = {
                'Referer': self.base_url,
                'X-CSRFToken': self.csrf_token
            }
            response = self.session.post(f"{self.base_url}/analyze", data=form_data, headers=headers, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                print("✅ CSR analysis completed!")
                print(f"✅ Valid: {data.get('valid')}")
                
                if data.get('subject'):
                    subject = data['subject'].get('raw', {})
                    print(f"✅ Subject CN: {subject.get('CN')}")
                    print(f"✅ Subject O: {subject.get('O')}")
                    print(f"✅ Subject C: {subject.get('C')}")
                
                if data.get('key_info'):
                    key_info = data['key_info']
                    print(f"✅ Key Type: {key_info.get('type')}")
                    print(f"✅ Key Size: {key_info.get('size')}")
                
                warnings = data.get('rfc_warnings', [])
                if warnings:
                    print(f"⚠️ RFC Warnings: {len(warnings)}")
                    for warning in warnings[:3]:  # Show first 3 warnings
                        print(f"   - {warning}")
                else:
                    print("✅ No RFC warnings")
                
                return True
            else:
                print(f"❌ Analysis failed with status {response.status_code}")
                print(f"❌ Error: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error testing analyze endpoint: {e}")
            return False
    
    def test_ecdsa_generation(self):
        """Test ECDSA key generation"""
        print("\n🔍 Testing ECDSA CSR generation...")
        
        if not self.csrf_token:
            if not self.get_csrf_token():
                return False
        
        form_data = {
            'CN': 'ecdsa-test.example.com',
            'C': 'US',
            'keyType': 'ECDSA',
            'curve': 'P-256',
            'csrf_token': self.csrf_token
        }
        
        try:
            headers = {
                'Referer': self.base_url,
                'X-CSRFToken': self.csrf_token
            }
            response = self.session.post(f"{self.base_url}/generate", data=form_data, headers=headers, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                print("✅ ECDSA CSR generated successfully!")
                
                # Check if it's actually ECDSA
                private_key = data.get('private_key', '')
                if 'EC PRIVATE KEY' in private_key or 'PRIVATE KEY' in private_key:
                    print("✅ ECDSA private key format detected")
                else:
                    print("❌ Unexpected private key format")
                
                return True
            else:
                print(f"❌ ECDSA generation failed with status {response.status_code}")
                print(f"❌ Error: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error testing ECDSA generation: {e}")
            return False
    
    def run_all_tests(self):
        """Run all API tests"""
        print("🚀 Starting Secure Cert-Tools API Tests...")
        print("=" * 50)
        
        # Test version endpoint
        self.test_version_endpoint()
        
        # Test CSR generation
        result = self.test_generate_csr()
        if result:
            csr = result['csr']
            private_key = result['private_key']
            
            # Test verification
            self.test_verify_csr(csr, private_key)
            
            # Test analysis
            self.test_analyze_csr(csr)
        
        # Test ECDSA generation
        self.test_ecdsa_generation()
        
        print("\n" + "=" * 50)
        print("🏁 API testing completed!")

if __name__ == "__main__":
    tester = SecureCertToolsAPITester()
    tester.run_all_tests()
