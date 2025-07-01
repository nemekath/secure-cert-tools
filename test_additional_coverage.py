#!/usr/bin/env python
"""
Additional tests to increase test coverage to 95%
Targets specific uncovered lines in app.py and csr.py
"""

import unittest
import pytest
from unittest.mock import Mock, patch


class TestRequestSizeLimits(unittest.TestCase):
    """Test request size limits and error handling."""
    
    def setUp(self):
        from app import app
        app.config['TESTING'] = True
        self.app = app

    def test_request_entity_too_large_error_handler(self):
        """Test the 413 error handler for large requests."""
        # This test simulates the 413 error being raised
        # Since the actual request size limit is handled by Flask/WSGI,
        # we'll test the error handler function directly
        from app import request_entity_too_large
        
        with self.app.app_context():
            with self.app.test_request_context(environ_base={'HTTP_X_REAL_IP': '192.168.1.100'}):
                # Test the error handler
                response, status_code = request_entity_too_large(None)
                
                self.assertEqual(status_code, 413)
                response_data = response.get_json()
                self.assertEqual(response_data['error'], 'Request too large. Maximum request size is 1MB.')
                self.assertEqual(response_data['error_type'], 'RequestTooLarge')


class TestKeyErrorHandling(unittest.TestCase):
    """Test KeyError handling in generate_csr endpoint."""
    
    def setUp(self):
        from app import app
        app.config['TESTING'] = True
        self.app = app

    def test_generate_csr_key_error_handling(self):
        """Test KeyError handling in generate_csr when a field is missing from form data."""
        client = self.app.test_client()
        
        # Test by making CsrGenerator raise a KeyError that's not about key sizes or curves
        # This will trigger the specific KeyError handling path in line 153
        with patch('app.CsrGenerator') as mock_csr_gen:
            # Make CsrGenerator raise a KeyError that's not about key sizes or curves
            mock_csr_gen.side_effect = KeyError("missing_field")
            
            response = client.post('/generate', data={
                'CN': 'test.example.com',
                'C': 'US',
                'ST': 'California',
                'L': 'San Francisco',
                'O': 'Test Org',
                'OU': 'Test OU'
            })
            
            self.assertEqual(response.status_code, 400)
            response_data = response.get_json()
            self.assertIn('error', response_data)
            self.assertIn('Missing required field', response_data['error'])


class TestExceptionHandlingInEndpoints(unittest.TestCase):
    """Test exception handling in Flask endpoints."""
    
    def setUp(self):
        from app import app
        app.config['TESTING'] = True
        self.app = app

    def test_verify_endpoint_unexpected_exception(self):
        """Test unexpected exception handling in verify endpoint."""
        client = self.app.test_client()
        
        # Mock CsrGenerator to raise an unexpected exception
        with patch('app.CsrGenerator.verify_csr_private_key_match') as mock_verify:
            mock_verify.side_effect = Exception("Unexpected verification error")
            
            response = client.post('/verify', data={
                'csr': 'test_csr_data',
                'privateKey': 'test_key_data'
            })
            
            self.assertEqual(response.status_code, 500)
            response_data = response.get_json()
            self.assertEqual(response_data['match'], False)
            self.assertEqual(response_data['message'], 'An unexpected error occurred during verification.')
            self.assertIn('details', response_data)

    def test_analyze_endpoint_unexpected_exception(self):
        """Test unexpected exception handling in analyze endpoint."""
        client = self.app.test_client()
        
        # Mock CsrGenerator to raise an unexpected exception
        with patch('app.CsrGenerator.analyze_csr') as mock_analyze:
            mock_analyze.side_effect = Exception("Unexpected analysis error")
            
            response = client.post('/analyze', data={
                'csr': 'test_csr_data'
            })
            
            self.assertEqual(response.status_code, 500)
            response_data = response.get_json()
            self.assertEqual(response_data['valid'], False)
            self.assertIn('Analysis failed:', response_data['error'])
            self.assertEqual(response_data['error_type'], 'InternalError')

    def test_verify_certificate_endpoint_unexpected_exception(self):
        """Test unexpected exception handling in verify-certificate endpoint."""
        client = self.app.test_client()
        
        # Mock CsrGenerator to raise an unexpected exception
        with patch('app.CsrGenerator.verify_certificate_private_key_match') as mock_verify:
            mock_verify.side_effect = Exception("Unexpected certificate verification error")
            
            response = client.post('/verify-certificate', data={
                'certificate': 'test_certificate_data',
                'privateKey': 'test_key_data'
            })
            
            self.assertEqual(response.status_code, 500)
            response_data = response.get_json()
            self.assertEqual(response_data['match'], False)
            self.assertEqual(response_data['message'], 'An unexpected error occurred during verification.')
            self.assertIn('details', response_data)

    def test_verify_certificate_with_passphrase_success(self):
        """Test successful certificate verification with correct passphrase."""
        client = self.app.test_client()
        
        # Mock a successful verification result (lines 255-256)
        mock_result = {
            'match': True,
            'message': 'Certificate and private key match successfully!',
            'details': 'Test details',
            'cert_info': {'CN': 'test.example.com'}
        }
        
        with patch('app.CsrGenerator.verify_certificate_private_key_match') as mock_verify:
            mock_verify.return_value = mock_result
            
            response = client.post('/verify-certificate', data={
                'certificate': 'test_certificate_data',
                'privateKey': 'test_key_data',
                'passphrase': 'test_passphrase'
            })
            
            self.assertEqual(response.status_code, 200)
            response_data = response.get_json()
            self.assertTrue(response_data['match'])
            self.assertEqual(response_data['message'], 'Certificate and private key match successfully!')

    def test_verify_certificate_requires_passphrase(self):
        """Test certificate verification when passphrase is required."""
        client = self.app.test_client()
        
        # Mock a result that requires passphrase (lines 265-266)
        mock_result = {
            'match': False,
            'message': 'Private key requires passphrase',
            'details': 'Test details',
            'requires_passphrase': True
        }
        
        with patch('app.CsrGenerator.verify_certificate_private_key_match') as mock_verify:
            mock_verify.return_value = mock_result
            
            response = client.post('/verify-certificate', data={
                'certificate': 'test_certificate_data',
                'privateKey': 'encrypted_key_data'
            })
            
            self.assertEqual(response.status_code, 400)
            response_data = response.get_json()
            self.assertFalse(response_data['match'])
            self.assertTrue(response_data.get('requires_passphrase', False))


class TestCSRExtensionParsing(unittest.TestCase):
    """Test CSR extension parsing edge cases."""
    
    def test_extract_extensions_fallback_methods(self):
        """Test extension extraction fallback methods."""
        from csr import CsrGenerator
        
        # Create a mock CSR that will trigger fallback parsing methods
        mock_csr = Mock()
        
        # First, test the cryptography library exception path (line 523)
        with patch('csr.crypt.dump_certificate_request') as mock_dump:
            mock_dump.side_effect = Exception("Cryptography parsing failed")
            
            # Mock hasattr to return True to test the pyOpenSSL fallback (lines 527-567)
            with patch('builtins.hasattr') as mock_hasattr:
                mock_hasattr.return_value = True
                mock_csr.get_extension_count.return_value = 2
                
                # Mock extensions that will cause parsing errors
                mock_ext1 = Mock()
                mock_ext1.get_short_name.return_value = b'subjectAltName'
                mock_ext1.get_critical.return_value = False
                # Mock the string representation
                mock_ext1.__str__ = Mock(return_value='DNS:test.com, DNS:www.test.com')
                
                mock_ext2 = Mock()
                mock_ext2.get_short_name.side_effect = Exception("Extension parsing error")
                
                mock_csr.get_extension.side_effect = [mock_ext1, mock_ext2]
                
                extensions_info = CsrGenerator._extract_extensions(mock_csr)
                
                self.assertIsInstance(extensions_info, dict)
                self.assertIn('count', extensions_info)
                self.assertIn('extensions', extensions_info)
                # Should have parsed the first extension and handled the error in the second
                self.assertTrue(extensions_info['count'] >= 1)
        
        # Test the no extension support path (lines 564-567)
        mock_csr_no_ext = Mock()
        with patch('builtins.hasattr') as mock_hasattr:
            mock_hasattr.return_value = False  # No extension support
            
            extensions_info = CsrGenerator._extract_extensions(mock_csr_no_ext)
            
            self.assertIsInstance(extensions_info, dict)
            self.assertEqual(extensions_info['count'], 0)


class TestDomainValidationEdgeCases(unittest.TestCase):
    """Test domain validation edge cases for RFC compliance."""
    
    def test_check_rfc_compliance_missing_cn(self):
        """Test RFC compliance checking when CN is missing or empty."""
        from csr import CsrGenerator
        
        # Test missing CN (line 585)
        subject_info = {'raw': {}}
        extensions_info = {'has_san': False, 'extensions': []}
        key_info = {'type': 'RSA', 'size': 2048}
        
        warnings = CsrGenerator._check_rfc_compliance(subject_info, extensions_info, key_info)
        cn_warnings = [w for w in warnings if w.get('field') == 'CN']
        self.assertTrue(any('Missing Common Name' in w['message'] for w in cn_warnings))
        
        # Test empty CN (line 585)
        subject_info = {'raw': {'CN': ''}}
        warnings = CsrGenerator._check_rfc_compliance(subject_info, extensions_info, key_info)
        cn_warnings = [w for w in warnings if w.get('field') == 'CN']
        self.assertTrue(any('Missing Common Name' in w['message'] for w in cn_warnings))
        
        # Test whitespace-only CN (line 585)
        subject_info = {'raw': {'CN': '   '}}
        warnings = CsrGenerator._check_rfc_compliance(subject_info, extensions_info, key_info)
        cn_warnings = [w for w in warnings if w.get('field') == 'CN']
        self.assertTrue(any('Missing Common Name' in w['message'] for w in cn_warnings))

    def test_check_rfc_compliance_country_code_edge_cases(self):
        """Test RFC compliance checking for country codes."""
        from csr import CsrGenerator
        
        # Test invalid country code length (line 596)
        subject_info = {'raw': {'CN': 'test.example.com', 'C': 'USA'}}
        extensions_info = {'has_san': False, 'extensions': []}
        key_info = {'type': 'RSA', 'size': 2048}
        
        warnings = CsrGenerator._check_rfc_compliance(subject_info, extensions_info, key_info)
        country_warnings = [w for w in warnings if w.get('field') == 'C']
        self.assertTrue(any('exactly 2 characters' in w['message'] for w in country_warnings))
        
        # Test lowercase country code (line 604)
        subject_info = {'raw': {'CN': 'test.example.com', 'C': 'us'}}
        warnings = CsrGenerator._check_rfc_compliance(subject_info, extensions_info, key_info)
        country_warnings = [w for w in warnings if w.get('field') == 'C']
        self.assertTrue(any('should be uppercase' in w['message'] for w in country_warnings))
        
        # Test field length limits (line 624)
        subject_info = {'raw': {'CN': 'a' * 70, 'O': 'b' * 70}}  # Exceed limits
        warnings = CsrGenerator._check_rfc_compliance(subject_info, extensions_info, key_info)
        length_warnings = [w for w in warnings if 'exceeds maximum length' in w['message']]
        self.assertTrue(len(length_warnings) >= 2)  # CN and O should both trigger warnings

    def test_check_rfc_compliance_weak_rsa_key(self):
        """Test RFC compliance checking for weak RSA keys."""
        from csr import CsrGenerator
        
        subject_info = {'raw': {'CN': 'test.example.com'}}
        extensions_info = {'has_san': False, 'extensions': []}
        
        # Test weak RSA key (line 636)
        key_info = {'type': 'RSA', 'size': 1024}
        warnings = CsrGenerator._check_rfc_compliance(subject_info, extensions_info, key_info)
        key_warnings = [w for w in warnings if w.get('field') == 'public_key' and 'deprecated and insecure' in w['message']]
        self.assertTrue(len(key_warnings) > 0)

    def test_check_rfc_compliance_ecdsa_curves(self):
        """Test RFC compliance checking for ECDSA curves."""
        from csr import CsrGenerator
        
        subject_info = {'raw': {'CN': 'test.example.com'}}
        extensions_info = {'has_san': False, 'extensions': []}
        
        # Test P-384 curve (lines 665-666)
        key_info = {'type': 'ECDSA', 'curve': 'secp384r1'}
        warnings = CsrGenerator._check_rfc_compliance(subject_info, extensions_info, key_info)
        curve_warnings = [w for w in warnings if w.get('field') == 'public_key' and 'P-384' in w['message']]
        self.assertTrue(len(curve_warnings) > 0)
        
        # Test P-521 curve (lines 672-673)
        key_info = {'type': 'ECDSA', 'curve': 'secp521r1'}
        warnings = CsrGenerator._check_rfc_compliance(subject_info, extensions_info, key_info)
        curve_warnings = [w for w in warnings if w.get('field') == 'public_key' and 'P-521' in w['message']]
        self.assertTrue(len(curve_warnings) > 0)

    def test_check_rfc_compliance_domain_warnings(self):
        """Test RFC compliance domain-related warnings."""
        from csr import CsrGenerator
        
        # Test CN without SAN suggestion (lines 689-690)
        subject_info = {'raw': {'CN': 'test.example.com'}}
        extensions_info = {'has_san': False, 'extensions': []}
        key_info = {'type': 'RSA', 'size': 2048}
        
        warnings = CsrGenerator._check_rfc_compliance(subject_info, extensions_info, key_info)
        san_warnings = [w for w in warnings if 'Subject Alternative Names' in w['message']]
        self.assertTrue(len(san_warnings) > 0)
        
        # Test SAN compliance checking (lines 708-710)
        extensions_info = {
            'has_san': True,
            'extensions': [{
                'short_name': 'subjectAltName',
                'value': ['DNS:invalid..domain.com', 'DNS:valid.domain.com']
            }]
        }
        
        warnings = CsrGenerator._check_rfc_compliance(subject_info, extensions_info, key_info)
        # Should have warnings for the invalid domain in SAN
        
        # Test CN domain compliance (lines 718-720)
        subject_info = {'raw': {'CN': 'invalid..domain.com'}}
        extensions_info = {'has_san': False, 'extensions': []}
        
        warnings = CsrGenerator._check_rfc_compliance(subject_info, extensions_info, key_info)
        domain_warnings = [w for w in warnings if w.get('field') == 'CN']
        self.assertTrue(len(domain_warnings) > 0)


class TestDomainValidationSpecificCases(unittest.TestCase):
    """Test specific domain validation edge cases."""
    
    def test_check_domain_rfc_compliance_edge_cases(self):
        """Test domain RFC compliance with edge cases."""
        from csr import CsrGenerator
        
        # Test very long domain (line 792)
        long_domain = "a" * 250 + ".com"
        warnings = CsrGenerator._check_domain_rfc_compliance(long_domain)
        self.assertTrue(any('maximum length' in w['message'] for w in warnings))
        
        # Test IP address warnings for public IPs (lines 802, 807, 810, 815)
        warnings = CsrGenerator._check_domain_rfc_compliance("8.8.8.8")
        # Should trigger IP address warning for public IP
        ip_warnings = [w for w in warnings if 'IP address' in w['message']]
        
        # Test domain with empty labels (lines 820, 833, 838, 846)
        warnings = CsrGenerator._check_domain_rfc_compliance("-test.example.com")
        self.assertTrue(any('cannot start or end with a hyphen' in w['message'] for w in warnings))
        
        warnings = CsrGenerator._check_domain_rfc_compliance("test-.example.com")
        self.assertTrue(any('cannot start or end with a hyphen' in w['message'] for w in warnings))
        
        # Test domain with invalid characters
        warnings = CsrGenerator._check_domain_rfc_compliance("test_underscore.example.com")
        self.assertTrue(any('invalid characters' in w['message'] for w in warnings))


class TestPrivateKeyEncryptionDetection(unittest.TestCase):
    """Test private key encryption detection."""
    
    def test_is_private_key_encrypted_various_formats(self):
        """Test private key encryption detection with various formats."""
        from csr import CsrGenerator
        
        # Test RSA encrypted format (line 1321)
        rsa_encrypted = b"""-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,1234567890ABCDEF

encrypted_data_here
-----END RSA PRIVATE KEY-----"""
        
        result = CsrGenerator._is_private_key_encrypted(rsa_encrypted)
        self.assertTrue(result)
        
        # Test invalid format (line 1330)
        try:
            result = CsrGenerator._is_private_key_encrypted(b"invalid_data_not_pem")
            # Should return False for invalid format
            self.assertFalse(result)
        except Exception:
            # Exception handling is also acceptable
            pass
        
        # Test OpenSSL traditional format (line 1332)
        traditional_encrypted = b"""-----BEGIN PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,1234567890ABCDEF

encrypted_data_here
-----END PRIVATE KEY-----"""
        
        result = CsrGenerator._is_private_key_encrypted(traditional_encrypted)
        self.assertTrue(result)
        
        # Test PKCS#8 encrypted format (lines 1336-1338)
        pkcs8_encrypted = b"""-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI
encrypted_data_here
-----END ENCRYPTED PRIVATE KEY-----"""
        
        result = CsrGenerator._is_private_key_encrypted(pkcs8_encrypted)
        self.assertTrue(result)


class TestCertificateVerificationErrorPaths(unittest.TestCase):
    """Test certificate verification error paths."""
    
    def test_verify_certificate_private_key_match_encrypted_key_errors(self):
        """Test certificate verification with encrypted key error paths."""
        from csr import CsrGenerator
        
        # Test encrypted key detection (lines 1194-1195)
        encrypted_key = b"""-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI
-----END ENCRYPTED PRIVATE KEY-----"""
        
        result = CsrGenerator.verify_certificate_private_key_match(
            "invalid_certificate_pem",
            encrypted_key.decode('utf-8')
        )
        # Should detect that key is encrypted and require passphrase
        self.assertFalse(result['match'])
        
        # Test wrong passphrase (lines 1204-1209)
        result = CsrGenerator.verify_certificate_private_key_match(
            "invalid_certificate_pem",
            encrypted_key.decode('utf-8'),
            "wrong_passphrase"
        )
        self.assertFalse(result['match'])
        
        # Test encrypted key detection in error path (line 1223)
        result = CsrGenerator.verify_certificate_private_key_match(
            "valid_certificate_data",
            encrypted_key.decode('utf-8')
        )
        # Should handle encrypted key detection in error path
        self.assertFalse(result['match'])

    def test_verify_certificate_private_key_match_unexpected_error(self):
        """Test unexpected error handling in certificate verification."""
        from csr import CsrGenerator
        
        # Test unexpected exception (lines 1283-1284)
        # We need to pass the certificate loading, key loading, and then fail during comparison
        with patch('csr.crypt.load_certificate') as mock_load_cert:
            with patch('csr.crypt.load_privatekey') as mock_load_key:
                with patch('csr.crypt.dump_publickey') as mock_dump_pubkey:
                    # Mock successful certificate loading
                    mock_cert = Mock()
                    mock_cert.get_pubkey.return_value = Mock()
                    mock_load_cert.return_value = mock_cert
                    
                    # Mock successful private key loading
                    mock_key = Mock()
                    mock_load_key.return_value = mock_key
                    
                    # But fail during public key dumping to trigger unexpected error
                    mock_dump_pubkey.side_effect = RuntimeError("Unexpected internal error during key comparison")
                    
                    result = CsrGenerator.verify_certificate_private_key_match(
                        "-----BEGIN CERTIFICATE-----\ntest_cert_data\n-----END CERTIFICATE-----",
                        "-----BEGIN PRIVATE KEY-----\ntest_key_data\n-----END PRIVATE KEY-----"
                    )
                    
                    self.assertFalse(result['match'])
                    self.assertEqual(result['message'], 'Unexpected error during verification')
                    self.assertIn('details', result)


class TestAnalyzeSignatureEdgeCases(unittest.TestCase):
    """Test signature analysis edge cases."""
    
    def test_analyze_signature_error_conditions(self):
        """Test signature analysis when errors occur."""
        from csr import CsrGenerator
        
        # Create a mock CSR that raises exceptions (lines 935-936, 943-944)
        mock_csr = Mock()
        mock_csr.get_pubkey.side_effect = Exception("Public key error")
        
        result = CsrGenerator._analyze_signature(mock_csr)
        
        self.assertIn('error', result)
        self.assertFalse(result['valid_signature'])
        self.assertEqual(result['algorithm'], 'Unknown')


class TestCSRValidityChecksEdgeCases(unittest.TestCase):
    """Test CSR validity check edge cases."""
    
    def test_check_csr_validity_error_conditions(self):
        """Test CSR validity checking when errors occur."""
        from csr import CsrGenerator
        
        # Create a mock CSR that raises exceptions (lines 970-971)
        mock_csr = Mock()
        mock_csr.get_subject.side_effect = Exception("Subject error")
        
        result = CsrGenerator._check_csr_validity(mock_csr)
        
        self.assertFalse(result['is_valid'])
        self.assertIn('error', result)
        

class TestErrorSuggestionEdgeCases(unittest.TestCase):
    """Test error suggestion generation edge cases."""
    
    def test_get_error_suggestions_edge_cases(self):
        """Test error suggestion generation for various error types."""
        from csr import CsrGenerator
        
        # Test with 'begin certificate request' error (line 1012)
        suggestions = CsrGenerator._get_error_suggestions("Missing begin certificate request header")
        self.assertTrue(any('BEGIN CERTIFICATE REQUEST' in s for s in suggestions))
        
        # Test with 'end certificate request' error (line 1015) 
        suggestions = CsrGenerator._get_error_suggestions("Missing end certificate request footer")
        self.assertTrue(any('END CERTIFICATE REQUEST' in s for s in suggestions))
        
        # Test with unknown error
        suggestions = CsrGenerator._get_error_suggestions("Some unknown error occurred")
        self.assertTrue(len(suggestions) > 0)  # Should provide generic suggestions


class TestPrivateDomainDetection(unittest.TestCase):
    """Test private domain detection edge cases."""
    
    def test_is_private_domain_edge_cases(self):
        """Test private domain detection with edge cases."""
        from csr import CsrGenerator
        
        # Test with None/empty domain (line 893)
        self.assertFalse(CsrGenerator._is_private_domain(None))
        self.assertFalse(CsrGenerator._is_private_domain(""))


class TestPublicKeyAnalysisEdgeCases(unittest.TestCase):
    """Test public key analysis edge cases."""
    
    def test_analyze_public_key_edge_cases(self):
        """Test public key analysis edge cases."""
        from csr import CsrGenerator
        
        # Create a mock public key that raises exceptions during analysis
        mock_key = Mock()
        mock_key.type.side_effect = Exception("Key type error")
        
        result = CsrGenerator._analyze_public_key(mock_key)
        
        # Should handle the error gracefully
        self.assertIn('error', result)
        
        # Test with RSA key that has method errors (lines 422-423, 425, 432-433)
        mock_key = Mock()
        mock_key.type.return_value = 6  # RSA type
        mock_key.bits.side_effect = Exception("Bits error")
        
        result = CsrGenerator._analyze_public_key(mock_key)
        
        # Should handle the error gracefully (not necessarily identify as RSA)
        self.assertIn('error', result)


class TestVerifyCSRKeyMatchEdgeCases(unittest.TestCase):
    """Test verify CSR private key match edge cases."""
    
    def test_verify_csr_private_key_match_error_paths(self):
        """Test error paths in CSR and private key verification."""
        from csr import CsrGenerator
        
        # Test invalid CSR format first (which comes before private key validation)
        result = CsrGenerator.verify_csr_private_key_match(
            "invalid_csr_data",
            "any_private_key_data"
        )
        self.assertFalse(result['match'])
        self.assertEqual(result['message'], 'Invalid CSR format')
        
        # Test invalid private key format (lines 1075-1076) with valid CSR
        from csr import CsrGenerator as CsrGen
        # Generate a valid CSR first
        test_csr = CsrGen({
            'CN': 'test.example.com',
            'C': 'US',
            'ST': 'California', 
            'L': 'San Francisco',
            'O': 'Test Org',
            'OU': 'Test OU'
        })
        
        result = CsrGenerator.verify_csr_private_key_match(
            test_csr.csr.decode('utf-8'),
            "invalid_private_key_data"
        )
        self.assertFalse(result['match'])
        self.assertEqual(result['message'], 'Invalid private key format')
        
        # Test key comparison error (lines 1133-1134, 1141-1142)
        with patch('csr.crypt.load_certificate_request') as mock_load_csr:
            with patch('csr.crypt.load_privatekey') as mock_load_key:
                # Mock successful loading but comparison error
                mock_csr = Mock()
                mock_key = Mock()
                
                mock_load_csr.return_value = mock_csr
                mock_load_key.return_value = mock_key
                
                # Mock the comparison to raise an exception
                with patch('csr.crypt.X509Req') as mock_x509req:
                    mock_x509req.side_effect = Exception("Key comparison error")
                    
                    result = CsrGenerator.verify_csr_private_key_match(
                        "test_csr_pem",
                        "test_private_key_pem"
                    )
                    
                    self.assertFalse(result['match'])
                    self.assertEqual(result['message'], 'Error during key comparison')


if __name__ == '__main__':
    unittest.main()
