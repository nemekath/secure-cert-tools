#!/usr/bin/env python
"""
Final tests to reach 95% coverage
Targets remaining uncovered lines in app.py and csr.py
"""

import unittest
import os
import tempfile
from unittest.mock import Mock, patch, mock_open


class TestHTTPSSetupFunctions(unittest.TestCase):
    """Test HTTPS setup functions that are currently uncovered."""
    
    def test_create_self_signed_cert(self):
        """Test self-signed certificate creation function."""
        from app import create_self_signed_cert
        
        # Create temporary directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_file = os.path.join(temp_dir, "test.crt")
            key_file = os.path.join(temp_dir, "test.key")
            
            # Test certificate creation
            create_self_signed_cert(temp_dir, cert_file, key_file)
            
            # Verify files were created
            self.assertTrue(os.path.exists(cert_file))
            self.assertTrue(os.path.exists(key_file))
            
            # Verify certificate contains expected content
            with open(cert_file, 'r') as f:
                cert_content = f.read()
                self.assertIn('-----BEGIN CERTIFICATE-----', cert_content)
                self.assertIn('-----END CERTIFICATE-----', cert_content)
            
            # Verify private key contains expected content (may be RSA or generic format)
            with open(key_file, 'r') as f:
                key_content = f.read()
                # Accept either format since the implementation may use either
                self.assertTrue('-----BEGIN PRIVATE KEY-----' in key_content or '-----BEGIN RSA PRIVATE KEY-----' in key_content)
                self.assertTrue('-----END PRIVATE KEY-----' in key_content or '-----END RSA PRIVATE KEY-----' in key_content)

    def test_setup_https_new_certificates(self):
        """Test HTTPS setup when certificates don't exist."""
        from app import setup_https
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Change working directory temporarily
            original_cwd = os.getcwd()
            os.chdir(temp_dir)
            
            try:
                # Test when certs directory doesn't exist
                cert_file, key_file = setup_https()
                
                # Verify files were created
                self.assertTrue(os.path.exists(cert_file))
                self.assertTrue(os.path.exists(key_file))
                self.assertTrue(os.path.exists("./certs"))
                
            finally:
                os.chdir(original_cwd)

    def test_setup_https_existing_certificates(self):
        """Test HTTPS setup when certificates already exist."""
        from app import setup_https
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Change working directory temporarily
            original_cwd = os.getcwd()
            os.chdir(temp_dir)
            
            try:
                # Create certs directory and files
                certs_dir = "./certs"
                os.makedirs(certs_dir)
                
                cert_file = os.path.join(certs_dir, "server.crt")
                key_file = os.path.join(certs_dir, "server.key")
                
                # Create dummy certificate files
                with open(cert_file, 'w') as f:
                    f.write("dummy cert content")
                with open(key_file, 'w') as f:
                    f.write("dummy key content")
                
                # Test when certificates already exist
                returned_cert, returned_key = setup_https()
                
                # Should return existing files
                self.assertEqual(returned_cert, cert_file)
                self.assertEqual(returned_key, key_file)
                
            finally:
                os.chdir(original_cwd)


class TestValidationEdgeCases(unittest.TestCase):
    """Test validation edge cases in CsrGenerator._validate method."""
    
    def test_validate_country_validation_errors(self):
        """Test country validation errors in _validate method."""
        from csr import CsrGenerator
        
        # Test invalid country code (lines that trigger specific validation errors)
        with self.assertRaises(ValueError) as context:
            CsrGenerator({
                'CN': 'test.example.com',
                'C': 'INVALID_COUNTRY_CODE_TOO_LONG',  # More than 2 characters
                'ST': 'California',
                'L': 'San Francisco',
                'O': 'Test Org',
                'OU': 'Test OU'
            })
        
        # Check that the error mentions the field or length issue
        self.assertTrue('C exceeds maximum length' in str(context.exception) or 'Country' in str(context.exception))

    def test_validate_organization_validation_errors(self):
        """Test organization validation errors in _validate method."""
        from csr import CsrGenerator
        
        # Test extremely long organization name (line 218)
        with self.assertRaises(ValueError) as context:
            CsrGenerator({
                'CN': 'test.example.com',
                'C': 'US',
                'ST': 'California',
                'L': 'San Francisco',
                'O': 'A' * 100,  # Extremely long organization name
                'OU': 'Test OU'
            })
        
        self.assertIn('Organization', str(context.exception))

    def test_validate_organizational_unit_validation_errors(self):
        """Test organizational unit validation errors in _validate method."""
        from csr import CsrGenerator
        
        # Test extremely long OU name (line 231)
        with self.assertRaises(ValueError) as context:
            CsrGenerator({
                'CN': 'test.example.com',
                'C': 'US',
                'ST': 'California',
                'L': 'San Francisco',
                'O': 'Test Org',
                'OU': 'B' * 100  # Extremely long OU name
            })
        
        self.assertIn('Organizational Unit', str(context.exception))

    def test_validate_state_validation_errors(self):
        """Test state validation errors in _validate method."""
        from csr import CsrGenerator
        
        # Test extremely long state name (line 234)
        with self.assertRaises(ValueError) as context:
            CsrGenerator({
                'CN': 'test.example.com',
                'C': 'US',
                'ST': 'C' * 150,  # Extremely long state name
                'L': 'San Francisco',
                'O': 'Test Org',
                'OU': 'Test OU'
            })
        
        self.assertIn('State', str(context.exception))

    def test_validate_locality_validation_errors(self):
        """Test locality validation errors in _validate method."""
        from csr import CsrGenerator
        
        # Test extremely long locality name (line 241)
        with self.assertRaises(ValueError) as context:
            CsrGenerator({
                'CN': 'test.example.com',
                'C': 'US',
                'ST': 'California',
                'L': 'D' * 150,  # Extremely long locality name
                'O': 'Test Org',
                'OU': 'Test OU'
            })
        
        self.assertIn('Locality', str(context.exception))


class TestDomainValidationSpecificErrors(unittest.TestCase):
    """Test specific domain validation errors that trigger uncovered lines."""
    
    def test_validate_domain_rfc_compliance_specific_errors(self):
        """Test specific domain validation errors."""
        from csr import CsrGenerator
        
        # Test domain with specific RFC violation patterns (lines 100, 104)
        with self.assertRaises(ValueError) as context:
            CsrGenerator({
                'CN': '-invalid-start.example.com',  # Domain starting with hyphen
                'C': 'US',
                'ST': 'California',
                'L': 'San Francisco',
                'O': 'Test Org',
                'OU': 'Test OU'
            })
        
        # Test domain ending with hyphen (line 120)
        with self.assertRaises(ValueError) as context:
            CsrGenerator({
                'CN': 'invalid-end-.example.com',  # Domain ending with hyphen
                'C': 'US',
                'ST': 'California',
                'L': 'San Francisco',
                'O': 'Test Org',
                'OU': 'Test OU'
            })
        
        # Test very long domain label (line 148)
        long_label = 'a' * 70
        with self.assertRaises(ValueError) as context:
            CsrGenerator({
                'CN': f'{long_label}.example.com',  # Label too long
                'C': 'US',
                'ST': 'California',
                'L': 'San Francisco',
                'O': 'Test Org',
                'OU': 'Test OU'
            })
        
        # Test domain with invalid characters (line 150)
        with self.assertRaises(ValueError) as context:
            CsrGenerator({
                'CN': 'test_invalid_char.example.com',  # Underscore not allowed
                'C': 'US',
                'ST': 'California',
                'L': 'San Francisco',
                'O': 'Test Org',
                'OU': 'Test OU'
            })
        
        # Test IP address validation (line 169)
        with self.assertRaises(ValueError) as context:
            CsrGenerator({
                'CN': '999.999.999.999',  # Invalid IP address
                'C': 'US',
                'ST': 'California',
                'L': 'San Francisco',
                'O': 'Test Org',
                'OU': 'Test OU',
                'allowPrivateDomains': 'true'  # String value as expected by the code
            })

    def test_validate_subject_alt_names_errors(self):
        """Test SAN validation errors (line 205)."""
        from csr import CsrGenerator
        
        # Test invalid SAN format
        with self.assertRaises(ValueError) as context:
            CsrGenerator({
                'CN': 'test.example.com',
                'C': 'US',
                'ST': 'California',
                'L': 'San Francisco',
                'O': 'Test Org',
                'OU': 'Test OU',
                'subjectAltName': 'DNS:invalid..domain.com'  # Invalid domain in SAN
            })


class TestKeyValidationErrorPaths(unittest.TestCase):
    """Test key validation error paths in _analyze_public_key."""
    
    def test_analyze_public_key_dsa_key_error(self):
        """Test DSA key handling that triggers error path (lines 422-423)."""
        from csr import CsrGenerator
        
        # Create a mock key that returns DSA type but causes errors
        mock_key = Mock()
        mock_key.type.return_value = 116  # DSA type
        mock_key.bits.side_effect = Exception("DSA key error")
        
        result = CsrGenerator._analyze_public_key(mock_key)
        
        # Should handle DSA key error gracefully
        self.assertEqual(result['type'], 'DSA')
        self.assertIn('error', result)

    def test_analyze_public_key_unknown_key_type_error(self):
        """Test unknown key type handling (line 425)."""
        from csr import CsrGenerator
        
        # Create a mock key with unknown type
        mock_key = Mock()
        mock_key.type.return_value = 999  # Unknown type
        mock_key.bits.side_effect = Exception("Unknown key error")
        
        result = CsrGenerator._analyze_public_key(mock_key)
        
        # Should handle unknown key type
        self.assertEqual(result['type'], 'Unknown')
        self.assertIn('error', result)

    def test_analyze_public_key_ecdsa_curve_error(self):
        """Test ECDSA curve extraction error (lines 432-433)."""
        from csr import CsrGenerator
        
        # Create a mock ECDSA key that causes curve extraction errors
        mock_key = Mock()
        mock_key.type.return_value = 408  # ECDSA type
        mock_key.bits.return_value = 256
        
        # Mock the key to raise an exception when trying to get curve info
        with patch('csr.CsrGenerator._get_ecdsa_curve_from_key') as mock_get_curve:
            mock_get_curve.side_effect = Exception("Curve extraction error")
            
            result = CsrGenerator._analyze_public_key(mock_key)
            
            # Should handle ECDSA curve error
            self.assertEqual(result['type'], 'ECDSA')
            self.assertIn('curve', result)


class TestExtensionParsingSpecificErrors(unittest.TestCase):
    """Test specific extension parsing errors."""
    
    def test_extract_extensions_cryptography_error(self):
        """Test cryptography library error path (line 504)."""
        from csr import CsrGenerator
        
        # Mock a CSR that causes cryptography parsing to fail
        mock_csr = Mock()
        
        with patch('csr.x509.load_pem_x509_csr') as mock_load:
            mock_load.side_effect = Exception("Cryptography parsing failed")
            
            # Mock the CSR to have extension count but cause errors
            mock_csr.get_extension_count.return_value = 1
            mock_ext = Mock()
            mock_ext.get_short_name.return_value = b'basicConstraints'
            mock_ext.get_critical.return_value = True
            mock_ext.__str__ = Mock(return_value='CA:FALSE')
            mock_csr.get_extension.return_value = mock_ext
            
            extensions_info = CsrGenerator._extract_extensions(mock_csr)
            
            # Should fall back to pyOpenSSL method
            self.assertIsInstance(extensions_info, dict)
            self.assertIn('count', extensions_info)

    def test_extract_extensions_fallback_error(self):
        """Test fallback extension parsing error (lines 515-567)."""
        from csr import CsrGenerator
        
        mock_csr = Mock()
        
        # First make cryptography fail
        with patch('csr.x509.load_pem_x509_csr') as mock_load:
            mock_load.side_effect = Exception("Cryptography failed")
            
            # Then make pyOpenSSL fallback also have issues
            mock_csr.get_extension_count.side_effect = Exception("Extension count error")
            
            extensions_info = CsrGenerator._extract_extensions(mock_csr)
            
            # Should handle all errors gracefully
            self.assertIsInstance(extensions_info, dict)
            self.assertEqual(extensions_info['count'], 0)


if __name__ == '__main__':
    unittest.main()
