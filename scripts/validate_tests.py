#!/usr/bin/env python3
"""
Test validation script for CI/CD pipelines
Ensures all test files are being executed and validates test coverage
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd, description):
    """Run a command and return the result"""
    print(f"🔍 {description}...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        return result
    except Exception as e:
        print(f"❌ Error running command: {e}")
        return None

def validate_test_files():
    """Validate that all test files exist and are executable"""
    test_files = ["tests.py", "test_security_hardening.py"]
    missing_files = []
    
    for test_file in test_files:
        if not Path(test_file).exists():
            missing_files.append(test_file)
    
    if missing_files:
        print(f"❌ Missing test files: {missing_files}")
        return False
    
    print(f"✅ All test files found: {test_files}")
    return True

def run_test_suite():
    """Run the complete test suite and validate results"""
    cmd = "python -m pytest tests.py test_security_hardening.py -v --tb=short"
    result = run_command(cmd, "Running complete test suite")
    
    if not result:
        return False, 0, 0
    
    if result.returncode != 0:
        print(f"❌ Test suite failed with return code {result.returncode}")
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        return False, 0, 0
    
    # Count tests
    output_lines = result.stdout.split('\n')
    passed_count = sum(1 for line in output_lines if ' PASSED' in line)
    failed_count = sum(1 for line in output_lines if ' FAILED' in line)
    
    # Look for test summary line
    summary_lines = [line for line in output_lines if 'passed' in line and ('warning' in line or 'error' in line or 'failed' in line)]
    
    print(f"✅ Test execution completed")
    print(f"📊 Tests passed: {passed_count}")
    print(f"📊 Tests failed: {failed_count}")
    
    if summary_lines:
        print(f"📋 Summary: {summary_lines[-1]}")
    
    return True, passed_count, failed_count

def validate_security_tests():
    """Specifically validate security hardening tests"""
    cmd = "python -m pytest test_security_hardening.py -v --tb=short"
    result = run_command(cmd, "Running security hardening tests")
    
    if not result:
        return False, 0
    
    if result.returncode != 0:
        print(f"❌ Security tests failed with return code {result.returncode}")
        return False, 0
    
    # Count security tests
    output_lines = result.stdout.split('\n')
    security_passed = sum(1 for line in output_lines if ' PASSED' in line)
    
    print(f"🔒 Security tests passed: {security_passed}")
    return True, security_passed

def validate_expected_test_count():
    """Validate that we have the expected number of tests"""
    expected_total = 125
    expected_security = 22
    expected_functional = 103
    
    # Run functional tests
    cmd_functional = "python -m pytest tests.py -v --tb=short"
    result_functional = run_command(cmd_functional, "Counting functional tests")
    
    if not result_functional or result_functional.returncode != 0:
        print("❌ Could not count functional tests")
        return False
    
    functional_count = sum(1 for line in result_functional.stdout.split('\n') if ' PASSED' in line)
    
    # Run security tests  
    cmd_security = "python -m pytest test_security_hardening.py -v --tb=short"
    result_security = run_command(cmd_security, "Counting security tests")
    
    if not result_security or result_security.returncode != 0:
        print("❌ Could not count security tests")
        return False
    
    security_count = sum(1 for line in result_security.stdout.split('\n') if ' PASSED' in line)
    
    total_count = functional_count + security_count
    
    print(f"📊 Test count validation:")
    print(f"   Functional tests: {functional_count} (expected: {expected_functional})")
    print(f"   Security tests: {security_count} (expected: {expected_security})")
    print(f"   Total tests: {total_count} (expected: {expected_total})")
    
    if total_count != expected_total:
        print(f"⚠️  Test count mismatch! Expected {expected_total}, got {total_count}")
        print("   This might indicate missing tests or changes in test structure")
        return False
    
    if security_count != expected_security:
        print(f"⚠️  Security test count mismatch! Expected {expected_security}, got {security_count}")
        return False
    
    if functional_count != expected_functional:
        print(f"⚠️  Functional test count mismatch! Expected {expected_functional}, got {functional_count}")
        return False
    
    print("✅ Test count validation passed")
    return True

def main():
    """Main validation function"""
    print("🧪 Starting test validation...")
    print("=" * 50)
    
    # Change to script directory
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    os.chdir(project_root)
    
    success = True
    
    # 1. Validate test files exist
    if not validate_test_files():
        success = False
    
    # 2. Run complete test suite
    test_success, passed, failed = run_test_suite()
    if not test_success or failed > 0:
        success = False
    
    # 3. Validate security tests specifically
    security_success, security_passed = validate_security_tests()
    if not security_success:
        success = False
    
    # 4. Validate expected test counts
    if not validate_expected_test_count():
        success = False
    
    print("=" * 50)
    if success:
        print("✅ All test validations passed!")
        print(f"🎉 Ready for deployment - {passed + failed} tests executed successfully")
        sys.exit(0)
    else:
        print("❌ Test validation failed!")
        print("🚨 Issues found - please review and fix before deployment")
        sys.exit(1)

if __name__ == "__main__":
    main()
