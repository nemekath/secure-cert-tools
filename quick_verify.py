#!/usr/bin/env python
"""
Quick Verification Script for Secure Cert-Tools

This script performs a quick sanity check to verify that the core functionality
works correctly. Run this after installation or deployment to ensure everything
is functioning as intended.
"""

import sys
import os

def print_status(message, status):
    """Print a status message with colored output"""
    try:
        if status:
            print(f"✅ {message}")
        else:
            print(f"❌ {message}")
    except UnicodeEncodeError:
        if status:
            print(f"[PASS] {message}")
        else:
            print(f"[FAIL] {message}")

def check_dependencies():
    """Check if all required dependencies are installed"""
    try:
        print("🔍 Checking dependencies...")
    except UnicodeEncodeError:
        print("Checking dependencies...")
    
    required_modules = [
        'flask', 'flask_wtf', 'flask_limiter', 'cryptography', 
        'OpenSSL', 'pytest'
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            __import__(module)
            print_status(f"{module} installed", True)
        except ImportError:
            print_status(f"{module} missing", False)
            missing_modules.append(module)
    
    return len(missing_modules) == 0

def test_csr_generation():
    """Test basic CSR generation functionality"""
    try:
        print("\n🔧 Testing CSR generation...")
    except UnicodeEncodeError:
        print("\nTesting CSR generation...")
    
    try:
        from csr import CsrGenerator
        
        # Test RSA key generation
        csr_info = {
            'CN': 'test.example.com',
            'C': 'US',
            'O': 'Test Organization',
            'keyType': 'RSA',
            'keySize': 2048
        }
        
        generator = CsrGenerator(csr_info)
        
        # Check if CSR and private key were generated
        csr_generated = generator.csr is not None and len(generator.csr) > 0
        key_generated = generator.private_key is not None and len(generator.private_key) > 0
        
        print_status("RSA 2048-bit CSR generation", csr_generated)
        print_status("RSA private key generation", key_generated)
        
        # Test ECDSA key generation
        csr_info_ecdsa = {
            'CN': 'ecdsa-test.example.com',
            'keyType': 'ECDSA',
            'curve': 'P-256'
        }
        
        generator_ecdsa = CsrGenerator(csr_info_ecdsa)
        ecdsa_csr_generated = generator_ecdsa.csr is not None and len(generator_ecdsa.csr) > 0
        ecdsa_key_generated = generator_ecdsa.private_key is not None and len(generator_ecdsa.private_key) > 0
        
        print_status("ECDSA P-256 CSR generation", ecdsa_csr_generated)
        print_status("ECDSA private key generation", ecdsa_key_generated)
        
        return csr_generated and key_generated and ecdsa_csr_generated and ecdsa_key_generated
        
    except Exception as e:
        print_status(f"CSR generation failed: {str(e)}", False)
        return False

def test_domain_validation():
    """Test domain validation functionality"""
    try:
        print("\n🌐 Testing domain validation...")
    except UnicodeEncodeError:
        print("\nTesting domain validation...")
    
    try:
        from csr import CsrGenerator
        
        # Test valid public domain
        valid_domain_info = {'CN': 'example.com'}
        try:
            generator = CsrGenerator(valid_domain_info)
            print_status("Valid public domain accepted", True)
        except Exception as e:
            print_status(f"Valid domain rejected: {str(e)}", False)
            return False
        
        # Test private domain without flag (should fail)
        private_domain_info = {'CN': 'localhost'}
        try:
            generator = CsrGenerator(private_domain_info)
            print_status("Private domain incorrectly accepted without flag", False)
            return False
        except ValueError:
            print_status("Private domain correctly rejected without flag", True)
        
        # Test private domain with flag (should work)
        private_domain_with_flag = {'CN': 'localhost', 'allowPrivateDomains': 'true'}
        try:
            generator = CsrGenerator(private_domain_with_flag)
            print_status("Private domain accepted with flag", True)
        except Exception as e:
            print_status(f"Private domain with flag failed: {str(e)}", False)
            return False
        
        return True
        
    except Exception as e:
        print_status(f"Domain validation test failed: {str(e)}", False)
        return False

def test_input_validation():
    """Test input validation functionality"""
    try:
        print("\n🛡️ Testing input validation...")
    except UnicodeEncodeError:
        print("\nTesting input validation...")
    
    try:
        from csr import CsrGenerator
        
        # Test field length validation
        long_cn = 'a' * 70  # Exceeds 64 character limit
        try:
            generator = CsrGenerator({'CN': long_cn})
            print_status("Long CN incorrectly accepted", False)
            return False
        except ValueError:
            print_status("Long CN correctly rejected", True)
        
        # Test dangerous character filtering
        dangerous_org = 'Test<script>alert(1)</script>Org'
        try:
            generator = CsrGenerator({'CN': 'example.com', 'O': dangerous_org})
            print_status("Dangerous characters incorrectly accepted", False)
            return False
        except ValueError:
            print_status("Dangerous characters correctly rejected", True)
        
        # Test country code validation
        invalid_country = 'USA'  # Should be 2 characters
        try:
            generator = CsrGenerator({'CN': 'example.com', 'C': invalid_country})
            print_status("Invalid country code incorrectly accepted", False)
            return False
        except ValueError:
            print_status("Invalid country code correctly rejected", True)
        
        return True
        
    except Exception as e:
        print_status(f"Input validation test failed: {str(e)}", False)
        return False

def test_security_features():
    """Test key security features"""
    try:
        print("\n🔒 Testing security features...")
    except UnicodeEncodeError:
        print("\nTesting security features...")
    
    try:
        from csr import CsrGenerator
        
        # Test weak key rejection
        weak_key_info = {'CN': 'example.com', 'keySize': 1024}
        try:
            generator = CsrGenerator(weak_key_info)
            print_status("Weak 1024-bit key incorrectly accepted", False)
            return False
        except KeyError:
            print_status("Weak 1024-bit key correctly rejected", True)
        
        # Test weak curve rejection
        weak_curve_info = {'CN': 'example.com', 'keyType': 'ECDSA', 'curve': 'P-192'}
        try:
            generator = CsrGenerator(weak_curve_info)
            print_status("Weak P-192 curve incorrectly accepted", False)
            return False
        except KeyError:
            print_status("Weak P-192 curve correctly rejected", True)
        
        return True
        
    except Exception as e:
        print_status(f"Security feature test failed: {str(e)}", False)
        return False

def test_flask_app():
    """Test Flask application basic functionality"""
    try:
        print("\n🌐 Testing Flask application...")
    except UnicodeEncodeError:
        print("\nTesting Flask application...")
    
    try:
        from app import app
        
        # Test basic app configuration
        app.config['TESTING'] = True
        
        with app.test_client() as client:
            # Test index page
            response = client.get('/')
            index_works = response.status_code == 200
            print_status("Index page loads", index_works)
            
            # Test version endpoint
            response = client.get('/version')
            version_works = response.status_code == 200 and response.is_json
            print_status("Version endpoint works", version_works)
            
            return index_works and version_works
        
    except Exception as e:
        print_status(f"Flask app test failed: {str(e)}", False)
        return False

def main():
    """Main verification function"""
    try:
        print("🚀 Quick Verification for Secure Cert-Tools")
    except UnicodeEncodeError:
        print("Quick Verification for Secure Cert-Tools")
    print("=" * 50)
    
    # Check current directory
    if not os.path.exists("app.py"):
        try:
            print("❌ Error: app.py not found. Please run from the project root directory.")
        except UnicodeEncodeError:
            print("Error: app.py not found. Please run from the project root directory.")
        return 1
    
    # Run verification tests
    tests = [
        ("Dependencies", check_dependencies),
        ("CSR Generation", test_csr_generation),
        ("Domain Validation", test_domain_validation),
        ("Input Validation", test_input_validation),
        ("Security Features", test_security_features),
        ("Flask Application", test_flask_app),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print_status(f"{test_name} test error: {str(e)}", False)
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    try:
        print("📊 VERIFICATION SUMMARY")
    except UnicodeEncodeError:
        print("VERIFICATION SUMMARY")
    print("=" * 50)
    
    passed_tests = sum(1 for _, result in results if result)
    total_tests = len(results)
    
    for test_name, result in results:
        print_status(test_name, result)
    
    try:
        print(f"\n📈 Results: {passed_tests}/{total_tests} tests passed")
    except UnicodeEncodeError:
        print(f"\nResults: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        try:
            print("🎉 ALL VERIFICATIONS PASSED!")
            print("✅ The application is working correctly and ready to use.")
        except UnicodeEncodeError:
            print("ALL VERIFICATIONS PASSED!")
            print("The application is working correctly and ready to use.")
        return 0
    else:
        try:
            print(f"⚠️ {total_tests - passed_tests} verification(s) failed.")
            print("❌ Please check the output above and fix any issues.")
        except UnicodeEncodeError:
            print(f"WARNING: {total_tests - passed_tests} verification(s) failed.")
            print("Please check the output above and fix any issues.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
