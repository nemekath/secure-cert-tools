#!/usr/bin/env python3
"""
Test script to verify that large request handling is working correctly
"""

import requests
import re
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_large_request_handling():
    """Test that large requests are properly handled with 413 status code"""
    base_url = "https://localhost:5555"
    
    # Get CSRF token
    session = requests.Session()
    response = session.get(base_url, verify=False)
    meta_match = re.search(r'<meta name="csrf-token" content="([^"]+)"', response.text)
    if not meta_match:
        print("❌ Could not get CSRF token")
        return False
    
    csrf_token = meta_match.group(1)
    print(f"✅ CSRF token obtained: {csrf_token[:20]}...")
    
    # Create a large payload (over 1MB)
    large_data = {
        'CN': 'large-request-test.example.com',
        'O': 'X' * (1024 * 1024 + 1000),  # Over 1MB
        'csrf_token': csrf_token
    }
    
    headers = {
        'Referer': base_url,
        'X-CSRFToken': csrf_token
    }
    
    print("\n🔍 Testing large request handling...")
    print(f"📦 Request size: ~{len(large_data['O']) / 1024 / 1024:.1f} MB")
    
    try:
        response = session.post(f"{base_url}/generate", data=large_data, headers=headers, verify=False)
        
        print(f"📊 Response status: {response.status_code}")
        
        if response.status_code == 413:
            print("✅ Perfect! Got 413 Request Entity Too Large (proper handling)")
            data = response.json()
            print(f"✅ Error message: {data.get('error')}")
            print(f"✅ Error type: {data.get('error_type')}")
            return True
        elif response.status_code in [400, 500]:
            print(f"⚠️  Got {response.status_code} instead of 413, but request was still rejected")
            try:
                data = response.json()
                error_msg = data.get('error', '').lower()
                if any(keyword in error_msg for keyword in ['large', 'size', 'limit', 'entity']):
                    print(f"✅ Error message correctly mentions size: {data.get('error')}")
                    return True
                else:
                    print(f"❌ Error message doesn't mention size: {data.get('error')}")
                    return False
            except:
                print("❌ Could not parse JSON response")
                return False
        else:
            print(f"❌ Unexpected status code: {response.status_code}")
            print(f"❌ Response: {response.text[:200]}...")
            return False
            
    except Exception as e:
        print(f"❌ Request failed with exception: {e}")
        return False

def test_normal_request_still_works():
    """Test that normal-sized requests still work correctly"""
    base_url = "https://localhost:5555"
    
    # Get CSRF token
    session = requests.Session()
    response = session.get(base_url, verify=False)
    meta_match = re.search(r'<meta name="csrf-token" content="([^"]+)"', response.text)
    csrf_token = meta_match.group(1)
    
    # Normal request
    normal_data = {
        'CN': 'normal-request-test.example.com',
        'C': 'US',
        'O': 'Normal Request Corp',
        'keyType': 'RSA',
        'keySize': '2048',
        'csrf_token': csrf_token
    }
    
    headers = {
        'Referer': base_url,
        'X-CSRFToken': csrf_token
    }
    
    print("\n🔍 Testing normal request still works...")
    
    try:
        response = session.post(f"{base_url}/generate", data=normal_data, headers=headers, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            if 'csr' in data and 'private_key' in data:
                print("✅ Normal request works perfectly!")
                print(f"✅ CSR generated ({len(data['csr'])} characters)")
                return True
            else:
                print("❌ Normal request returned 200 but missing CSR/key")
                return False
        else:
            print(f"❌ Normal request failed with status {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Normal request failed with exception: {e}")
        return False

if __name__ == "__main__":
    print("🧪 TESTING LARGE REQUEST HANDLING FIX")
    print("=" * 50)
    
    # Test 1: Large request should be rejected
    large_test = test_large_request_handling()
    
    # Test 2: Normal request should still work
    normal_test = test_normal_request_still_works()
    
    print("\n" + "=" * 50)
    print("📋 TEST RESULTS:")
    print(f"  Large request handling: {'✅ PASS' if large_test else '❌ FAIL'}")
    print(f"  Normal request handling: {'✅ PASS' if normal_test else '❌ FAIL'}")
    
    if large_test and normal_test:
        print("\n🎉 ALL TESTS PASSED! Large request fix is working correctly.")
    else:
        print("\n❌ Some tests failed. Please check the implementation.")
