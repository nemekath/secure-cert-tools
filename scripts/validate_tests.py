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
        cmd_list = cmd.split() if isinstance(cmd, str) else cmd
        result = subprocess.run(cmd_list, capture_output=True, text=True)
        return result
    except Exception as e:
        print(f"❌ Error running command: {e}")
        return None

def validate_test_files():
    """Validate that all test files exist and are executable"""
    test_files = [
        "test_comprehensive.py", 
        "test_csrf_security.py", 
        "test_enhanced_security.py", 
        "test_security_hardening.py",
        "run_comprehensive_tests.py"
    ]
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
    """Run the comprehensive test suite and validate results"""
    cmd = "python run_comprehensive_tests.py"
    result = run_command(cmd, "Running comprehensive test suite")
    
    if not result:
        return False, 0, 0
    
    if result.returncode != 0:
        print(f"❌ Comprehensive test suite failed with return code {result.returncode}")
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        return False, 0, 0
    
    # Parse the comprehensive test output for totals
    output_lines = result.stdout.split('\n')
    
    # Look for the final summary line
    passed_suites = 0
    total_suites = 0
    for line in output_lines:
        if "test suites passed" in line:
            # Extract numbers from "📈 Overall Results: 14/14 test suites passed"
            if "/" in line:
                parts = line.split()
                for part in parts:
                    if "/" in part:
                        passed_suites, total_suites = map(int, part.split("/"))
                        break
    
    print(f"✅ Comprehensive test suite completed")
    print(f"📊 Test suites passed: {passed_suites}/{total_suites}")
    
    failed_suites = total_suites - passed_suites
    return True, passed_suites, failed_suites

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
    """Validate that we have the expected number of test suites"""
    # We now use comprehensive test suites instead of individual test counts
    expected_test_suites = 14
    expected_core_suites = 10
    expected_security_suites = 3  # CSRF, Enhanced, Hardening
    expected_rate_limiting_suites = 1
    
    print(f"📊 Test suite validation:")
    print(f"   Expected test suites: {expected_test_suites}")
    print(f"   - Core functionality suites: {expected_core_suites}")
    print(f"   - Security test suites: {expected_security_suites}")
    print(f"   - Rate limiting suites: {expected_rate_limiting_suites}")
    
    # Run comprehensive test suite to validate structure
    cmd = "python run_comprehensive_tests.py"
    result = run_command(cmd, "Validating comprehensive test suite structure")
    
    if not result or result.returncode != 0:
        print("❌ Could not validate comprehensive test suite")
        return False
    
    # Parse the output to count passed suites
    output_lines = result.stdout.split('\n')
    passed_suites = 0
    total_suites = 0
    
    for line in output_lines:
        if "test suites passed" in line and "/" in line:
            # Extract from "📈 Overall Results: 14/14 test suites passed"
            parts = line.split()
            for part in parts:
                if "/" in part:
                    passed_suites, total_suites = map(int, part.split("/"))
                    break
    
    print(f"   Actual test suites: {passed_suites}/{total_suites}")
    
    if total_suites != expected_test_suites:
        print(f"⚠️  Test suite count mismatch! Expected {expected_test_suites}, got {total_suites}")
        print("   This might indicate changes in test structure")
        return False
    
    if passed_suites != total_suites:
        print(f"❌ Not all test suites passed! {passed_suites}/{total_suites}")
        return False
    
    print("✅ Test suite validation passed")
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
