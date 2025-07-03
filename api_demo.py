#!/usr/bin/env python3
"""
API Demo Script for Secure Cert-Tools
Demonstrates all available HTTP API endpoints and their capabilities
"""

import requests
import json
import re
import urllib3
from urllib.parse import urljoin

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class APIDemonstration:
    def __init__(self, base_url="https://localhost:5555"):
        self.base_url = base_url
        self.session = requests.Session()
        self.csrf_token = None
        
    def get_csrf_token(self):
        """Get CSRF token from the main page"""
        response = self.session.get(self.base_url, verify=False)
        meta_match = re.search(r'<meta name="csrf-token" content="([^"]+)"', response.text)
        if meta_match:
            self.csrf_token = meta_match.group(1)
            return True
        return False
    
    def demo_version_endpoint(self):
        """Demonstrate GET /version endpoint"""
        print("\n" + "="*60)
        print("🔍 API ENDPOINT: GET /version")
        print("="*60)
        print("Purpose: Get version and project information")
        print("Authentication: None required")
        print("Rate limit: Not rate limited")
        
        response = self.session.get(f"{self.base_url}/version", verify=False)
        data = response.json()
        
        print(f"\n📊 Response:")
        print(json.dumps(data, indent=2))
        
        return data
    
    def demo_generate_endpoint(self):
        """Demonstrate POST /generate endpoint"""
        print("\n" + "="*60)
        print("🔍 API ENDPOINT: POST /generate")
        print("="*60)
        print("Purpose: Generate CSR and private key")
        print("Authentication: CSRF token required")
        print("Rate limit: 10 per minute")
        
        if not self.csrf_token:
            self.get_csrf_token()
        
        print(f"\n📝 Request Parameters:")
        form_data = {
            'CN': 'demo.example.com',
            'C': 'US',
            'ST': 'California',
            'L': 'San Francisco',
            'O': 'Demo Corporation',
            'OU': 'IT Department',
            'keyType': 'RSA',
            'keySize': '2048',
            'subjectAltNames': 'api.demo.example.com, www.demo.example.com',
            'csrf_token': self.csrf_token
        }
        
        for key, value in form_data.items():
            if key != 'csrf_token':
                print(f"  {key}: {value}")
        
        headers = {
            'Referer': self.base_url,
            'X-CSRFToken': self.csrf_token
        }
        
        response = self.session.post(f"{self.base_url}/generate", data=form_data, headers=headers, verify=False)
        data = response.json()
        
        print(f"\n📊 Response Summary:")
        print(f"  Status: {response.status_code}")
        print(f"  CSR Length: {len(data.get('csr', ''))} characters")
        print(f"  Private Key Length: {len(data.get('private_key', ''))} characters")
        
        # Show first few lines of CSR
        if 'csr' in data:
            csr_lines = data['csr'].split('\\n')
            print(f"\\n📜 CSR Preview:")
            for i, line in enumerate(csr_lines[:5]):
                print(f"  {line}")
            if len(csr_lines) > 5:
                print(f"  ... ({len(csr_lines)-5} more lines)")
        
        return data
    
    def demo_verify_endpoint(self, csr, private_key):
        """Demonstrate POST /verify endpoint"""
        print("\n" + "="*60)
        print("🔍 API ENDPOINT: POST /verify")
        print("="*60)
        print("Purpose: Verify CSR and private key match")
        print("Authentication: CSRF token required")
        print("Rate limit: 15 per minute")
        
        form_data = {
            'csr': csr,
            'privateKey': private_key,
            'csrf_token': self.csrf_token
        }
        
        print(f"\n📝 Request Parameters:")
        print(f"  csr: <{len(csr)} character CSR>")
        print(f"  privateKey: <{len(private_key)} character private key>")
        
        headers = {
            'Referer': self.base_url,
            'X-CSRFToken': self.csrf_token
        }
        
        response = self.session.post(f"{self.base_url}/verify", data=form_data, headers=headers, verify=False)
        data = response.json()
        
        print(f"\n📊 Response:")
        print(json.dumps(data, indent=2))
        
        return data
    
    def demo_analyze_endpoint(self, csr):
        """Demonstrate POST /analyze endpoint"""
        print("\n" + "="*60)
        print("🔍 API ENDPOINT: POST /analyze")
        print("="*60)
        print("Purpose: Analyze CSR and extract detailed information")
        print("Authentication: CSRF token required")
        print("Rate limit: 15 per minute")
        
        form_data = {
            'csr': csr,
            'csrf_token': self.csrf_token
        }
        
        print(f"\n📝 Request Parameters:")
        print(f"  csr: <{len(csr)} character CSR>")
        
        headers = {
            'Referer': self.base_url,
            'X-CSRFToken': self.csrf_token
        }
        
        response = self.session.post(f"{self.base_url}/analyze", data=form_data, headers=headers, verify=False)
        data = response.json()
        
        print(f"\n📊 Response Summary:")
        print(f"  Status: {response.status_code}")
        print(f"  Valid CSR: {data.get('valid')}")
        
        if data.get('subject'):
            print(f"  Subject CN: {data['subject'].get('raw', {}).get('CN')}")
        
        if data.get('key_info'):
            key_info = data['key_info']
            print(f"  Key Type: {key_info.get('type')}")
            print(f"  Key Size: {key_info.get('size')} bits")
        
        if data.get('san'):
            print(f"  Subject Alt Names: {len(data['san'])} entries")
        
        warnings = data.get('rfc_warnings', [])
        print(f"  RFC Warnings: {len(warnings)}")
        
        print(f"\n📊 Detailed Response:")
        print(json.dumps(data, indent=2))
        
        return data
    
    def demo_ecdsa_generation(self):
        """Demonstrate ECDSA key generation"""
        print("\n" + "="*60)
        print("🔍 API ENDPOINT: POST /generate (ECDSA)")
        print("="*60)
        print("Purpose: Generate ECDSA CSR and private key")
        print("Authentication: CSRF token required")
        print("Rate limit: 10 per minute")
        
        form_data = {
            'CN': 'ecdsa-demo.example.com',
            'C': 'DE',
            'ST': 'Bavaria',
            'L': 'Munich',
            'O': 'ECDSA Demo Corp',
            'keyType': 'ECDSA',
            'curve': 'P-384',  # Using P-384 for demonstration
            'csrf_token': self.csrf_token
        }
        
        print(f"\n📝 Request Parameters:")
        for key, value in form_data.items():
            if key != 'csrf_token':
                print(f"  {key}: {value}")
        
        headers = {
            'Referer': self.base_url,
            'X-CSRFToken': self.csrf_token
        }
        
        response = self.session.post(f"{self.base_url}/generate", data=form_data, headers=headers, verify=False)
        data = response.json()
        
        print(f"\n📊 Response Summary:")
        print(f"  Status: {response.status_code}")
        print(f"  CSR Length: {len(data.get('csr', ''))} characters")
        print(f"  Private Key Length: {len(data.get('private_key', ''))} characters")
        
        return data
    
    def demo_error_handling(self):
        """Demonstrate error handling"""
        print("\n" + "="*60)
        print("🔍 API ERROR HANDLING DEMONSTRATION")
        print("="*60)
        print("Purpose: Show how the API handles various error conditions")
        
        # Test missing CN
        print("\n🚫 Test 1: Missing required CN field")
        form_data = {
            'C': 'US',
            'keyType': 'RSA',
            'csrf_token': self.csrf_token
        }
        
        headers = {
            'Referer': self.base_url,
            'X-CSRFToken': self.csrf_token
        }
        
        response = self.session.post(f"{self.base_url}/generate", data=form_data, headers=headers, verify=False)
        data = response.json()
        
        print(f"  Status: {response.status_code}")
        print(f"  Error: {data.get('error')}")
        
        # Test invalid key size
        print("\n🚫 Test 2: Invalid RSA key size")
        form_data = {
            'CN': 'invalid.example.com',
            'keyType': 'RSA',
            'keySize': '1024',  # Not supported for security reasons
            'csrf_token': self.csrf_token
        }
        
        response = self.session.post(f"{self.base_url}/generate", data=form_data, headers=headers, verify=False)
        if response.status_code != 200:
            try:
                data = response.json()
                print(f"  Status: {response.status_code}")
                print(f"  Error: {data.get('error')}")
            except:
                print(f"  Status: {response.status_code}")
                print(f"  Raw response: {response.text[:200]}...")
    
    def run_complete_demo(self):
        """Run complete API demonstration"""
        print("🚀 SECURE CERT-TOOLS HTTP API DEMONSTRATION")
        print("🔒 Server running on HTTPS with self-signed certificate")
        print("🛡️ CSRF protection enabled for security")
        print("⚡ Rate limiting active to prevent abuse")
        
        # Get CSRF token
        self.get_csrf_token()
        print(f"🎫 CSRF Token obtained: {self.csrf_token[:20]}...")
        
        # Demo all endpoints
        version_data = self.demo_version_endpoint()
        
        generate_data = self.demo_generate_endpoint()
        if generate_data and 'csr' in generate_data:
            csr = generate_data['csr']
            private_key = generate_data['private_key']
            
            self.demo_verify_endpoint(csr, private_key)
            self.demo_analyze_endpoint(csr)
        
        self.demo_ecdsa_generation()
        self.demo_error_handling()
        
        print("\n" + "="*60)
        print("🏁 API DEMONSTRATION COMPLETED!")
        print("="*60)
        print("\n📋 AVAILABLE ENDPOINTS SUMMARY:")
        print("  GET  /version           - Get version information")
        print("  POST /generate          - Generate CSR and private key")
        print("  POST /verify            - Verify CSR/private key match")
        print("  POST /analyze           - Analyze CSR details")
        print("  POST /verify-certificate - Verify certificate/private key match")
        print("\n🔗 API Documentation: See README.md for full details")
        print("🌐 Web Interface: https://localhost:5555/")

if __name__ == "__main__":
    demo = APIDemonstration()
    demo.run_complete_demo()
