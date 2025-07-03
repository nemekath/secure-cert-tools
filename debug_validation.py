#!/usr/bin/env python3
"""
Debug script to test the field validation issue
"""

import sys
import os
sys.path.append(os.getcwd())

from final_optimized_api_test import OptimizedAPITester
import time

def debug_validation():
    print("🔍 DEBUG: Testing field validation...")
    
    tester = OptimizedAPITester()
    
    # Get CSRF token
    if not tester.get_csrf_token():
        print("❌ Failed to get CSRF token")
        return
    
    print(f"✅ CSRF token obtained: {tester.csrf_token[:20]}...")
    
    # Wait for rate limiting
    print("⏱️ Waiting 10s for rate limiting...")
    time.sleep(10)
    
    # Test validation data (invalid country code)
    validation_data = {
        'CN': 'debug-validation.example.com',
        'C': 'USA',  # Invalid - should be 2 chars
        'keyType': 'RSA',
        'keySize': '2048'
    }
    
    print("🔍 Making validation request...")
    response = tester.make_api_request_enhanced('/generate', validation_data, 400, "Debug validation")
    
    print(f"📊 Response type: {type(response)}")
    print(f"📊 Response is None: {response is None}")
    print(f"📊 Response evaluates to: {bool(response)}")
    
    if response:
        print(f"✅ Response received!")
        print(f"📡 Status code: {response.status_code}")
        print(f"📡 Expected 400: {response.status_code == 400}")
        try:
            result = response.json()
            print(f"📊 Response JSON: {result}")
        except:
            print(f"📊 Response text: {response.text[:200]}")
    else:
        print("❌ No response received")
    
    # Check test results
    print(f"\n📊 Test results recorded: {len(tester.test_results)}")
    if tester.test_results:
        last_result = tester.test_results[-1]
        print(f"📊 Last result: {last_result}")

if __name__ == "__main__":
    debug_validation()
