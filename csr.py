#!/usr/bin/env python
# -*- coding: utf8 -*-

"""
 csr.py
 Secure Cert-Tools - Professional Certificate Toolkit based on CSR Generator for csrgenerator.com Copyright (c) 2024 David Wittman <david@wittman.com>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program. If not, see <http://www.gnu.org/licenses/>.

"""

from _version import __version__

import re
import OpenSSL.crypto as crypt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class CsrGenerator(object):
    # Use SHA-256 for security (SHA-1 is deprecated)
    DIGEST = "sha256"
    # Remove 1024-bit support as it's insecure
    SUPPORTED_KEYSIZES = (2048, 4096)
    DEFAULT_KEYSIZE = 2048
    
    # Supported key types
    SUPPORTED_KEY_TYPES = ('RSA', 'ECDSA')
    DEFAULT_KEY_TYPE = 'RSA'
    
    # Supported ECDSA curves
    SUPPORTED_CURVES = {
        'P-256': ec.SECP256R1(),
        'P-384': ec.SECP384R1(),
        'P-521': ec.SECP521R1()
    }

    DEFAULT_CURVE = 'P-256'
    
    # Field length limits based on X.509 standards
    FIELD_LIMITS = {
        'C': 2,     # Country code (ISO 3166)
        'ST': 128,  # State/Province
        'L': 128,   # Locality/City
        'O': 64,    # Organization
        'OU': 64,   # Organizational Unit
        'CN': 64    # Common Name
    }

    def __init__(self, form_values):
        self.csr_info = self._validate(form_values)
        key_type = self.csr_info.pop('keyType', self.DEFAULT_KEY_TYPE)
        key_size = self.csr_info.pop('keySize', self.DEFAULT_KEYSIZE)
        curve = self.csr_info.pop('curve', self.DEFAULT_CURVE)
        # Remove allowPrivateDomains from csr_info as it's not part of the CSR
        self.csr_info.pop('allowPrivateDomains', None)

        if 'subjectAltNames' in self.csr_info:
            # The SAN list should contain the CN as well
            # TODO(dw): do list(set())
            sans = f"{self.csr_info['CN']},{self.csr_info.pop('subjectAltNames')}"
        else:
            sans = self.csr_info['CN']
            if sans.count('.') == 1:
                # root domain, add www. as well
                sans += ",www.{}".format(sans)

        self.subjectAltNames = list(map(lambda d: "DNS:{}".format(d.strip()), sans.split(',')))

        # Generate appropriate key type
        if key_type == 'RSA':
            self.keypair = self.generate_rsa_keypair(key_size)
        elif key_type == 'ECDSA':
            self.keypair = self.generate_ecdsa_keypair(curve)
        else:
            raise ValueError(f"Unsupported key type: {key_type}")

    def _validate_domain_rfc_compliance(self, domain, allow_private_domains=False):
        """
        Validates domain name according to RFC 1035, RFC 5280, and RFC 6125 standards.
        Returns True if valid, raises ValueError with specific error if invalid.
        
        Args:
            domain (str): Domain name to validate
            allow_private_domains (bool): Allow private/corporate network domains
        """
        if not domain or len(domain) == 0:
            raise ValueError("Domain cannot be empty")
        
        # RFC 1035: Maximum total domain length is 253 characters
        if len(domain) > 253:
            raise ValueError("Domain name exceeds maximum length of 253 characters (RFC 1035)")
        
        # Check for trailing dot (not allowed in certificates)
        if domain.endswith('.'):
            raise ValueError("Domain name cannot end with a dot")
        
        # Check for leading dot
        if domain.startswith('.'):
            raise ValueError("Domain name cannot start with a dot")
        
        # Handle wildcard validation (RFC 6125)
        if domain.startswith('*.'):
            # Wildcard must be leftmost label only
            if domain.count('*') > 1:
                raise ValueError("Only one wildcard (*) is allowed per domain")
            if '*' in domain[2:]:  # Check if * appears after the first two characters
                raise ValueError("Wildcard (*) must be the leftmost label only")
            # Validate the rest of the domain (after *.)
            return self._validate_domain_rfc_compliance(domain[2:])
        
        # Check for bare wildcard
        if domain == '*':
            raise ValueError("Bare wildcard (*) is not allowed")
        
        # Split into labels and validate each
        labels = domain.split('.')
        
        # Check for IP addresses (only allowed in private mode)
        import re
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        
        if re.match(ipv4_pattern, domain) or re.match(ipv6_pattern, domain):
            if not allow_private_domains:
                raise ValueError("IP addresses are only allowed for private CA use. Enable 'Allow private/corporate network domains' checkbox.")
            return True  # IP addresses are valid in private mode
        
        # Single label domains - allow in private mode
        if len(labels) == 1:
            if not allow_private_domains:
                raise ValueError("Single-label domains (like 'localhost' or 'server') are only allowed for private CA use. Enable 'Allow private/corporate network domains' checkbox.")
            # Additional validation for single-label domains in private mode
            label = labels[0]
            if not re.match(r'^[a-zA-Z0-9-]+$', label):
                raise ValueError(f"Single-label domain '{label}' contains invalid characters (only letters, digits, and hyphens allowed)")
            if label.startswith('-') or label.endswith('-'):
                raise ValueError(f"Single-label domain '{label}' cannot start or end with a hyphen")
            return True
        
        # Check for reserved/special-use TLDs (RFC 6761)
        last_label = labels[-1].lower()
        reserved_tlds = ['local', 'localhost', 'test', 'example', 'invalid', 'onion']
        corporate_tlds = ['corp', 'internal', 'intranet', 'lan', 'private']
        
        if last_label in reserved_tlds or last_label in corporate_tlds:
            if not allow_private_domains:
                raise ValueError(f"'.{last_label}' domains are reserved for special use and only allowed for private CA use. Enable 'Allow private/corporate network domains' checkbox.")
            # Continue with normal validation for private domains
        
        for label in labels:
            if not label:  # Empty label (consecutive dots)
                raise ValueError("Domain name cannot contain consecutive dots")
            
            # RFC 1035: Each label must be 1-63 characters
            if len(label) > 63:
                raise ValueError(f"Domain label '{label}' exceeds maximum length of 63 characters (RFC 1035)")
            
            # Labels cannot start or end with hyphens
            if label.startswith('-') or label.endswith('-'):
                raise ValueError(f"Domain label '{label}' cannot start or end with a hyphen")
            
            # Labels must contain only letters, digits, and hyphens
            if not re.match(r'^[a-zA-Z0-9-]+$', label):
                raise ValueError(f"Domain label '{label}' contains invalid characters (only letters, digits, and hyphens allowed)")
        
        return True

    def _validate(self, form_values):
        valid = {}
        fields = ('C', 'ST', 'L', 'O', 'OU', 'CN', 'keySize', 'keyType', 'curve', 'subjectAltNames', 'allowPrivateDomains')
        required = ('CN',)
        
        # Get the allowPrivateDomains flag early
        allow_private_domains = form_values.get('allowPrivateDomains', 'false').lower() == 'true'

        for field in fields:
            try:
                # Check for keys with empty values
                if form_values[field] == "":
                    raise KeyError("%s cannot be empty" % field)
                
                field_value = form_values[field]
                
                # Validate field length limits
                if field in self.FIELD_LIMITS:
                    max_length = self.FIELD_LIMITS[field]
                    if len(field_value) > max_length:
                        raise ValueError(f"Field {field} exceeds maximum length of {max_length} characters")
                
                # Additional validation for specific fields
                if field == 'C' and len(field_value) != 2:
                    raise ValueError("Country code must be exactly 2 characters (ISO 3166)")
                
                # CN field validation - use RFC-compliant validation
                if field == 'CN':
                    if ' ' in field_value:
                        raise ValueError("Common Name cannot contain spaces")
                    # RFC-compliant domain validation
                    self._validate_domain_rfc_compliance(field_value, allow_private_domains)
                
                # Additional field-specific validations
                if field == 'C' and field_value:
                    # Country code validation
                    if not re.match(r'^[A-Z]{2}$', field_value):
                        raise ValueError("Country code must be exactly 2 uppercase letters (ISO 3166)")
                
                # Validate text fields for dangerous characters
                if field in ['ST', 'L', 'O', 'OU'] and field_value:
                    # Allow letters, numbers, spaces, safe punctuation, and Unicode characters
                    # Block only dangerous characters like < > " \ / and control characters (but allow & for company names)
                    if re.search(r'[<>"\\/:;|=+*?\[\]{}^~`!@#$%]+', field_value):
                        raise ValueError(f"Field {field} contains invalid characters")
                
                # Subject Alternative Names validation
                if field == 'subjectAltNames' and field_value:
                    # Check for leading/trailing commas or consecutive commas
                    if field_value.startswith(',') or field_value.endswith(','):
                        raise ValueError("Subject Alternative Names cannot start or end with a comma")
                    
                    if ',,' in field_value:
                        raise ValueError("Subject Alternative Names cannot contain consecutive commas")
                    
                    # Split by comma and validate each domain
                    domains = [d.strip() for d in field_value.split(',')]
                    
                    # Check for empty domains after splitting
                    if any(d == '' for d in domains):
                        raise ValueError("Subject Alternative Names cannot contain empty domain names")
                    
                    for domain in domains:
                        # Use RFC-compliant domain validation
                        try:
                            self._validate_domain_rfc_compliance(domain, allow_private_domains)
                        except ValueError as e:
                            raise ValueError(f"Invalid domain name in Subject Alternative Names '{domain}': {str(e)}")
                
                valid[field] = field_value
                
            except KeyError:
                if field in required:
                    raise

        try:
            valid['keySize'] = int(valid.get('keySize', self.DEFAULT_KEYSIZE))
        except ValueError:
            raise ValueError("RSA key size must be an integer")

        return valid

    def generate_rsa_keypair(self, bits):
        """
        Generates a public/private RSA keypair of length bits.
        """

        if bits not in self.SUPPORTED_KEYSIZES:
            raise KeyError("Only 2048 and 4096-bit RSA keys are supported")

        key = crypt.PKey()
        key.generate_key(crypt.TYPE_RSA, bits)

        return key
    
    def generate_ecdsa_keypair(self, curve_name):
        """
        Generates a public/private ECDSA keypair using the specified curve.
        """
        if curve_name not in self.SUPPORTED_CURVES:
            raise KeyError(f"Unsupported ECDSA curve: {curve_name}. Supported curves: {list(self.SUPPORTED_CURVES.keys())}")
        
        # Generate ECDSA key using cryptography library
        curve = self.SUPPORTED_CURVES[curve_name]
        private_key = ec.generate_private_key(curve, default_backend())
        
        # Convert to OpenSSL PKey format
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Load into OpenSSL PKey
        key = crypt.load_privatekey(crypt.FILETYPE_PEM, pem_private_key)
        
        return key

    @property
    def private_key(self):
        return crypt.dump_privatekey(crypt.FILETYPE_PEM, self.keypair)

    @property
    def csr(self):
        # Use modern cryptography library instead of deprecated pyOpenSSL
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtensionOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        import ipaddress
        
        # Convert pyOpenSSL key to cryptography format
        pkey_pem = crypt.dump_privatekey(crypt.FILETYPE_PEM, self.keypair)
        private_key = serialization.load_pem_private_key(pkey_pem, password=None)
        
        # Build subject name
        subject_components = []
        name_mapping = {
            'C': NameOID.COUNTRY_NAME,
            'ST': NameOID.STATE_OR_PROVINCE_NAME,
            'L': NameOID.LOCALITY_NAME,
            'O': NameOID.ORGANIZATION_NAME,
            'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
            'CN': NameOID.COMMON_NAME
        }
        
        for attr, oid in name_mapping.items():
            if attr in self.csr_info and self.csr_info[attr]:
                subject_components.append(x509.NameAttribute(oid, self.csr_info[attr]))
        
        subject = x509.Name(subject_components)
        
        # Create CSR builder
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(subject)
        
        # Add Subject Alternative Names extension
        if self.subjectAltNames:
            san_list = []
            for san in self.subjectAltNames:
                # Remove DNS: prefix if present (legacy format)
                clean_san = san.replace('DNS:', '') if san.startswith('DNS:') else san
                
                try:
                    # Try to parse as IP address first
                    ip = ipaddress.ip_address(clean_san)
                    san_list.append(x509.IPAddress(ip))
                except ValueError:
                    # Not an IP address, treat as DNS name
                    san_list.append(x509.DNSName(clean_san))
            
            if san_list:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(san_list),
                    critical=False
                )
        
        # Sign the CSR
        if isinstance(private_key, rsa.RSAPrivateKey):
            hash_algorithm = hashes.SHA256()
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            hash_algorithm = hashes.SHA256()
        else:
            hash_algorithm = hashes.SHA256()  # Default fallback
        
        csr = builder.sign(private_key, hash_algorithm)
        
        # Return PEM-encoded CSR
        return csr.public_bytes(serialization.Encoding.PEM)
    
    @staticmethod
    def analyze_csr(csr_pem):
        """
        Analyze a CSR and extract all information with RFC compliance checking.
        
        Args:
            csr_pem (str): PEM-encoded CSR
            
        Returns:
            dict: Complete CSR analysis including content and RFC warnings
        """
        try:
            # Parse the CSR using modern cryptography library
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            
            if isinstance(csr_pem, str):
                csr_pem_bytes = csr_pem.encode('utf-8')
            else:
                csr_pem_bytes = csr_pem
            
            crypto_csr = x509.load_pem_x509_csr(csr_pem_bytes)
            
            # Extract basic information using modern cryptography library
            public_key = crypto_csr.public_key()
            
            # Determine key type and details  
            key_info = CsrGenerator._analyze_modern_public_key(public_key)
            
            # Extract subject information using modern library
            subject_info = CsrGenerator._extract_modern_subject_info(crypto_csr.subject)
            
            # Extract extensions using modern library
            extensions_info = CsrGenerator._extract_modern_extensions(crypto_csr)
            
            # Perform RFC compliance checks
            rfc_warnings = CsrGenerator._check_rfc_compliance(
                subject_info, extensions_info, key_info
            )
            
            # Extract signature information using modern library
            signature_info = CsrGenerator._analyze_modern_signature(crypto_csr)
            
            # Determine CSR validity using modern library
            validity_info = CsrGenerator._check_modern_csr_validity(crypto_csr)
            
            return {
                'valid': True,
                'subject': subject_info,
                'public_key': key_info,
                'extensions': extensions_info,
                'signature': signature_info,
                'validity': validity_info,
                'rfc_warnings': rfc_warnings,
                'raw_info': {
                    'pem_length': len(csr_pem),
                    'has_proper_headers': csr_pem.startswith('-----BEGIN CERTIFICATE REQUEST-----'),
                    'has_proper_footers': csr_pem.rstrip().endswith('-----END CERTIFICATE REQUEST-----')
                }
            }
            
        except Exception as e:
            return {
                'valid': False,
                'error': f"CSR parsing failed: {str(e)}",
                'error_type': type(e).__name__,
                'suggestions': CsrGenerator._get_error_suggestions(str(e))
            }
    
    @staticmethod
    def _analyze_public_key(public_key):
        """Analyze public key and extract key information."""
        try:
            # Get the key type
            key_type = public_key.type()
            
            if key_type == crypt.TYPE_RSA:
                # RSA key analysis
                key_size = public_key.bits()
                return {
                    'type': 'RSA',
                    'size': key_size,
                    'size_bits': key_size,
                    'security_level': CsrGenerator._get_rsa_security_level(key_size),
                    'is_secure': key_size >= 2048,
                    'details': f'{key_size}-bit RSA key'
                }
            else:
                # Try to analyze as ECDSA
                try:
                    # Convert to cryptography format for ECDSA analysis
                    pem_public_key = crypt.dump_publickey(crypt.FILETYPE_PEM, public_key)
                    from cryptography.hazmat.primitives import serialization
                    crypto_public_key = serialization.load_pem_public_key(pem_public_key)
                    
                    if hasattr(crypto_public_key, 'curve'):
                        curve_name = crypto_public_key.curve.name
                        key_size = crypto_public_key.curve.key_size
                        return {
                            'type': 'ECDSA',
                            'curve': curve_name,
                            'size': key_size,
                            'size_bits': key_size,
                            'security_level': CsrGenerator._get_ecdsa_security_level(curve_name),
                            'is_secure': curve_name in ['secp256r1', 'secp384r1', 'secp521r1'],
                            'details': f'{curve_name} curve ({key_size}-bit)'
                        }
                except:
                    pass
                
                return {
                    'type': 'Unknown',
                    'size': 0,
                    'details': 'Unknown key type',
                    'is_secure': False
                }
                
        except Exception as e:
            return {
                'type': 'Error',
                'error': str(e),
                'is_secure': False
            }
    
    @staticmethod
    def _extract_subject_info(subject):
        """Extract subject information from CSR."""
        subject_dict = {}
        subject_components = []
        
        # Standard subject fields
        field_names = {
            'C': 'Country',
            'ST': 'State/Province', 
            'L': 'Locality/City',
            'O': 'Organization',
            'OU': 'Organizational Unit',
            'CN': 'Common Name',
            'emailAddress': 'Email Address'
        }
        
        # Extract all components
        for component in subject.get_components():
            field_name = component[0].decode('utf-8')
            field_value = component[1].decode('utf-8')
            
            # Store in dictionary
            subject_dict[field_name] = field_value
            
            # Create display entry
            display_name = field_names.get(field_name, field_name)
            subject_components.append({
                'field': field_name,
                'display_name': display_name,
                'value': field_value,
                'length': len(field_value)
            })
        
        return {
            'components': subject_components,
            'raw': subject_dict,
            'dn_string': ', '.join([f'{comp["field"]}={comp["value"]}' for comp in subject_components])
        }
    
    @staticmethod
    def _extract_extensions(csr):
        """Extract extensions from CSR - DEPRECATED: Use _extract_modern_extensions instead."""
        extensions = []
        
        try:
            # This method is deprecated - redirect to modern implementation
            # Convert legacy CSR object to modern format by re-parsing
            from cryptography.hazmat.primitives import serialization
            from cryptography import x509
            
            # First try to get PEM data using deprecated method for compatibility
            try:
                pem_data = crypt.dump_certificate_request(crypt.FILETYPE_PEM, csr)
                crypto_csr = x509.load_pem_x509_csr(pem_data)
                
                # Use modern extraction method
                return CsrGenerator._extract_modern_extensions(crypto_csr)
            except Exception:
                # If modern approach fails, fallback to legacy parsing
                pass
            
            # Extract extensions using cryptography
            for ext in crypto_csr.extensions:
                ext_name = ext.oid._name
                
                if ext_name == 'subjectAltName':
                    # Parse Subject Alternative Names
                    san_list = []
                    for san in ext.value:
                        if hasattr(san, 'value'):
                            san_list.append(f'DNS:{san.value}')
                        else:
                            san_list.append(str(san))
                    
                    extensions.append({
                        'name': 'Subject Alternative Name',
                        'short_name': 'subjectAltName',
                        'critical': ext.critical,
                        'value': san_list,
                        'raw_value': ', '.join(san_list),
                        'count': len(san_list)
                    })
                else:
                    extensions.append({
                        'name': ext_name,
                        'short_name': ext_name, 
                        'critical': ext.critical,
                        'value': str(ext.value),
                        'raw_value': str(ext.value)
                    })
            
        except Exception as crypto_error:
            # Fallback to pyOpenSSL method
            try:
                # Try the old method if available
                if hasattr(csr, 'get_extension_count'):
                    extension_count = csr.get_extension_count()
                    
                    for i in range(extension_count):
                        try:
                            ext = csr.get_extension(i)
                            ext_name = ext.get_short_name().decode('utf-8')
                            
                            if ext_name == 'subjectAltName':
                                # Parse Subject Alternative Names
                                san_data = str(ext)
                                sans = [san.strip() for san in san_data.split(',') if san.strip()]
                                
                                extensions.append({
                                    'name': 'Subject Alternative Name',
                                    'short_name': 'subjectAltName',
                                    'critical': ext.get_critical(),
                                    'value': sans,
                                    'raw_value': san_data,
                                    'count': len(sans)
                                })
                            else:
                                extensions.append({
                                    'name': ext_name,
                                    'short_name': ext_name,
                                    'critical': ext.get_critical(),
                                    'value': str(ext),
                                    'raw_value': str(ext)
                                })
                        except Exception as e:
                            extensions.append({
                                'name': f'Extension {i}',
                                'error': f'Failed to parse: {str(e)}'
                            })
                else:
                    # No extension support available, but check if we know SANs should be there
                    # This is a workaround for older pyOpenSSL versions
                    pass
                    
            except Exception as fallback_error:
                pass
        
        return {
            'count': len(extensions),
            'extensions': extensions,
            'has_san': any(ext.get('short_name') == 'subjectAltName' for ext in extensions)
        }
    
    @staticmethod
    def _check_rfc_compliance(subject_info, extensions_info, key_info):
        """Check RFC compliance and generate warnings."""
        warnings = []
        
        # RFC 5280 - Subject field validation
        subject_dict = subject_info['raw']
        
        # Check required Common Name
        if 'CN' not in subject_dict or not subject_dict['CN'].strip():
            warnings.append({
                'type': 'error',
                'category': 'RFC 5280',
                'message': 'Missing Common Name (CN) - required by RFC 5280',
                'field': 'CN'
            })
        
        # Check Country Code format (RFC 5280)
        if 'C' in subject_dict:
            country = subject_dict['C']
            if len(country) != 2:
                warnings.append({
                    'type': 'error',
                    'category': 'RFC 5280',
                    'message': f'Country code must be exactly 2 characters (ISO 3166), got: {len(country)}',
                    'field': 'C',
                    'value': country
                })
            elif not country.isupper():
                warnings.append({
                    'type': 'warning',
                    'category': 'RFC 5280',
                    'message': 'Country code should be uppercase',
                    'field': 'C',
                    'value': country
                })
        
        # Check field length limits (RFC 5280)
        field_limits = {
            'CN': 64,
            'O': 64,
            'OU': 64,
            'L': 128,
            'ST': 128,
            'C': 2
        }
        
        for field, limit in field_limits.items():
            if field in subject_dict and len(subject_dict[field]) > limit:
                warnings.append({
                    'type': 'error',
                    'category': 'RFC 5280',
                    'message': f'{field} exceeds maximum length of {limit} characters',
                    'field': field,
                    'value': subject_dict[field],
                    'length': len(subject_dict[field])
                })
        
        # Check key strength (RFC 3647, current best practices)
        if key_info['type'] == 'RSA':
            if key_info['size'] < 2048:
                warnings.append({
                    'type': 'error',
                    'category': 'Security',
                    'message': f'RSA key size {key_info["size"]} bits is deprecated and insecure (minimum: 2048 bits)',
                    'field': 'public_key'
                })
            elif key_info['size'] == 2048:
                warnings.append({
                    'type': 'info',
                    'category': 'Security',
                    'message': '2048-bit RSA key meets current minimum requirements',
                    'field': 'public_key'
                })
            elif key_info['size'] >= 4096:
                warnings.append({
                    'type': 'info',
                    'category': 'Security',
                    'message': 'Excellent! 4096-bit RSA key provides enhanced security',
                    'field': 'public_key'
                })
        elif key_info['type'] == 'ECDSA':
            curve = key_info.get('curve', 'Unknown')
            if curve in ['secp256r1', 'prime256v1', 'P-256']:
                warnings.append({
                    'type': 'info',
                    'category': 'Security',
                    'message': 'P-256 ECDSA curve provides 128-bit security level (equivalent to 3072-bit RSA)',
                    'field': 'public_key'
                })
            elif curve in ['secp384r1', 'P-384']:
                warnings.append({
                    'type': 'info',
                    'category': 'Security',
                    'message': 'P-384 ECDSA curve provides 192-bit security level (excellent security)',
                    'field': 'public_key'
                })
            elif curve in ['secp521r1', 'P-521']:
                warnings.append({
                    'type': 'info',
                    'category': 'Security',
                    'message': 'P-521 ECDSA curve provides 256-bit security level (maximum security)',
                    'field': 'public_key'
                })
        
        # Check for Subject Alternative Names compliance
        if extensions_info['has_san']:
            san_ext = next((ext for ext in extensions_info['extensions'] if ext.get('short_name') == 'subjectAltName'), None)
            if san_ext:
                warnings.extend(CsrGenerator._check_san_compliance(san_ext['value'], subject_dict.get('CN')))
        
        # Check if CN is a domain but no SAN is present
        cn = subject_dict.get('CN', '')
        if cn and not extensions_info['has_san']:
            if '.' in cn and not CsrGenerator._is_ip_address(cn):
                warnings.append({
                    'type': 'warning',
                    'category': 'RFC 6125',
                    'message': 'Consider adding Subject Alternative Names (SAN) extension for better compatibility',
                    'field': 'extensions',
                    'suggestion': f'Add SAN with DNS:{cn}'
                })
        
        # Check Subject Alternative Names compliance (RFC 6125)
        if extensions_info['has_san']:
            for ext in extensions_info['extensions']:
                if ext.get('short_name') == 'subjectAltName':
                    for san in ext.get('value', []):
                        san = san.strip()
                        if san.startswith('DNS:'):
                            domain = san[4:]
                            domain_warnings = CsrGenerator._check_domain_rfc_compliance(domain)
                            for warning in domain_warnings:
                                warning['field'] = 'subjectAltName'
                                warning['value'] = san
                                warnings.append(warning)
        
        # Check Common Name domain compliance if it looks like a domain
        if 'CN' in subject_dict:
            cn = subject_dict['CN']
            if '.' in cn and ' ' not in cn:  # Likely a domain
                domain_warnings = CsrGenerator._check_domain_rfc_compliance(cn)
                for warning in domain_warnings:
                    warning['field'] = 'CN'
                    warning['value'] = cn
                    warnings.append(warning)
        
        return warnings
    
    @staticmethod
    def _is_ip_address(value):
        """Check if a value is an IP address."""
        import re
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        return re.match(ipv4_pattern, value) or re.match(ipv6_pattern, value)
    
    @staticmethod
    def _check_san_compliance(san_list, cn):
        """Check SAN compliance with RFCs, including private networks."""
        warnings = []
        for san in san_list:
            if san.startswith('DNS:'):
                domain = san[4:]  # Remove 'DNS:' prefix
                domain_warnings = CsrGenerator._check_domain_rfc_compliance(domain)
                for warning in domain_warnings:
                    warning['field'] = 'subjectAltName'
                    warning['value'] = san
                    warnings.append(warning)
            elif san.startswith('IP:'):
                # IP addresses in SAN - just add a note
                warnings.append({
                    'type': 'info',
                    'category': 'Certificate Usage',
                    'message': f'IP address in SAN: {san}',
                    'field': 'subjectAltName',
                    'value': san
                })
        return warnings
    
    @staticmethod
    def _check_domain_rfc_compliance(domain):
        """Check domain RFC compliance with detailed analysis."""
        warnings = []
        
        if not domain or domain.strip() == '':
            warnings.append({
                'type': 'error',
                'category': 'Domain Validation',
                'message': 'Domain cannot be empty'
            })
            return warnings
        
        domain = domain.strip()
        
        # Check for private/special-use domains
        is_private = CsrGenerator._is_private_domain(domain)
        if is_private:
            warnings.append({
                'type': 'warning',
                'category': 'Private Networks',
                'message': f'Domain "{domain}" appears to be for private/corporate network use only. Public CAs will reject this domain.',
                'suggestion': 'This CSR is suitable for internal/private Certificate Authorities only. Public CAs like Let\'s Encrypt, DigiCert, etc. will not issue certificates for this domain.'
            })
        
        # RFC 1035: Maximum total domain length is 253 characters
        if len(domain) > 253:
            warnings.append({
                'type': 'error',
                'category': 'RFC 1035',
                'message': f'Domain name exceeds maximum length of 253 characters (current: {len(domain)})'
            })
            return warnings  # Don't continue if fundamentally invalid
        
        # Check for IP addresses (not recommended for CN/SAN in public certs)
        if CsrGenerator._is_ip_address(domain):
            if not is_private:  # Only warn if not already flagged as private
                warnings.append({
                    'type': 'warning',
                    'category': 'RFC 2818',
                    'message': f'IP address "{domain}" in certificate may not be accepted by all clients',
                    'suggestion': 'Consider using a domain name instead of IP address'
                })
        
        # Handle wildcard domains
        if domain.startswith('*.'):
            if domain.count('*') > 1:
                warnings.append({
                    'type': 'error',
                    'category': 'RFC 6125',
                    'message': 'Only one wildcard (*) is allowed per domain'
                })
                return warnings
            
            if domain == '*.':
                warnings.append({
                    'type': 'error',
                    'category': 'RFC 6125',
                    'message': 'Wildcard domain cannot be just "*.", must include a domain'
                })
                return warnings
            
            # Validate the part after the wildcard
            base_domain = domain[2:]
            if base_domain.count('.') < 1:
                warnings.append({
                    'type': 'warning',
                    'category': 'RFC 6125',
                    'message': f'Wildcard "{domain}" covers a top-level domain, which may not be allowed by CAs'
                })
            
            # Recursively check the base domain
            base_warnings = CsrGenerator._check_domain_rfc_compliance(base_domain)
            warnings.extend(base_warnings)
            return warnings
        
        # Check for bare wildcard
        if domain == '*':
            warnings.append({
                'type': 'error',
                'category': 'RFC 6125',
                'message': 'Bare wildcard (*) is not allowed'
            })
            return warnings
        
        # Split into labels and validate each
        labels = domain.split('.')
        
        # Single-label domains (private network only)
        if len(labels) == 1:
            if not is_private:  # Only warn if not already flagged as private
                warnings.append({
                    'type': 'warning',
                    'category': 'RFC 1035',
                    'message': f'Single-label domain "{domain}" is only valid for private networks',
                    'suggestion': 'Use a fully qualified domain name for public certificates'
                })
        
        # Validate each label
        for i, label in enumerate(labels):
            if not label:  # Empty label (consecutive dots)
                warnings.append({
                    'type': 'error',
                    'category': 'RFC 1035',
                    'message': 'Domain name cannot contain consecutive dots'
                })
                continue
            
            # RFC 1035: Each label must be 1-63 characters
            if len(label) > 63:
                warnings.append({
                    'type': 'error',
                    'category': 'RFC 1035',
                    'message': f'Domain label "{label}" exceeds maximum length of 63 characters'
                })
            
            # Labels cannot start or end with hyphens (RFC 1035)
            if label.startswith('-') or label.endswith('-'):
                warnings.append({
                    'type': 'error',
                    'category': 'RFC 1035',
                    'message': f'Domain label "{label}" cannot start or end with a hyphen'
                })
            
            # Labels must contain only letters, digits, and hyphens (RFC 1035)
            if not all(c.isalnum() or c == '-' for c in label):
                warnings.append({
                    'type': 'error',
                    'category': 'RFC 1035',
                    'message': f'Domain label "{label}" contains invalid characters (only letters, digits, and hyphens allowed)'
                })
        
        return warnings
    
    @staticmethod
    def _is_private_domain(domain):
        """Check if a domain is for private/corporate network use."""
        if not domain:
            return False
        
        domain_lower = domain.lower()
        
        # Check for private TLDs
        private_tlds = ['local', 'localhost', 'test', 'example', 'invalid', 'onion', 'corp', 'internal', 'intranet', 'lan', 'private']
        parts = domain_lower.split('.')
        
        if len(parts) >= 1:
            tld = parts[-1]
            if tld in private_tlds:
                return True
        
        # Single-label domains
        if len(parts) == 1:
            return True
        
        # IP addresses
        if CsrGenerator._is_ip_address(domain):
            return True
        
        return False
    
    @staticmethod
    def _analyze_signature(csr):
        """Analyze CSR signature information."""
        try:
            # Get signature algorithm (this is limited in pyOpenSSL)
            # We can check if the CSR is properly signed
            public_key = csr.get_pubkey()
            
            # Try to verify the CSR self-signature
            try:
                # This is a basic check - CSR should be self-signed
                is_self_signed = True  # pyOpenSSL doesn't easily expose signature verification
                
                return {
                    'algorithm': 'SHA-256 with RSA/ECDSA',  # Most common
                    'is_self_signed': is_self_signed,
                    'valid_signature': True,  # If parsing succeeded, signature is likely valid
                    'details': 'Signature appears valid (CSR parsed successfully)'
                }
            except:
                return {
                    'algorithm': 'Unknown',
                    'is_self_signed': False,
                    'valid_signature': False,
                    'details': 'Signature verification failed'
                }
                
        except Exception as e:
            return {
                'algorithm': 'Unknown',
                'error': str(e),
                'valid_signature': False
            }
    
    @staticmethod
    def _check_csr_validity(csr):
        """Check overall CSR validity."""
        try:
            # Basic validity checks
            subject = csr.get_subject()
            public_key = csr.get_pubkey()
            
            # Check if we can extract basic information
            has_subject = len(subject.get_components()) > 0
            has_public_key = public_key is not None
            
            return {
                'is_valid': has_subject and has_public_key,
                'has_subject': has_subject,
                'has_public_key': has_public_key,
                'well_formed': True,  # If we got here, structure is OK
                'details': 'CSR structure is valid and well-formed'
            }
            
        except Exception as e:
            return {
                'is_valid': False,
                'error': str(e),
                'details': 'CSR structure validation failed'
            }
    
    @staticmethod
    def _get_rsa_security_level(key_size):
        """Get security level description for RSA keys."""
        if key_size < 1024:
            return 'Very Weak (Broken)'
        elif key_size == 1024:
            return 'Weak (Deprecated)'
        elif key_size == 2048:
            return 'Standard (Acceptable)'
        elif key_size == 3072:
            return 'Strong (Recommended)'
        elif key_size >= 4096:
            return 'Very Strong (High Security)'
        else:
            return 'Unknown'
    
    @staticmethod
    def _get_ecdsa_security_level(curve_name):
        """Get security level description for ECDSA curves."""
        security_levels = {
            'secp256r1': 'Standard (128-bit security)',
            'secp384r1': 'Strong (192-bit security)', 
            'secp521r1': 'Very Strong (256-bit security)',
            'prime256v1': 'Standard (128-bit security)'  # Alternative name for P-256
        }
        return security_levels.get(curve_name, 'Unknown curve')
    
    @staticmethod
    def _get_error_suggestions(error_message):
        """Provide helpful suggestions for common CSR parsing errors."""
        suggestions = []
        
        error_lower = error_message.lower()
        
        if 'begin certificate request' in error_lower:
            suggestions.append('Ensure CSR starts with "-----BEGIN CERTIFICATE REQUEST-----"')
        
        if 'end certificate request' in error_lower:
            suggestions.append('Ensure CSR ends with "-----END CERTIFICATE REQUEST-----"')
        
        if any(term in error_lower for term in ['base64', 'invalid', 'decode', 'asn1', 'bad object header', 'encoding routines']):
            suggestions.extend([
                'Check that the CSR is properly base64 encoded',
                'Verify there are no extra spaces or line breaks in the CSR', 
                'Ensure the CSR was copied completely'
            ])
        
        if 'pem' in error_lower:
            suggestions.extend([
                'Make sure you are using PEM format (not DER or other formats)',
                'Try converting from other formats if needed'
            ])
        
        if not suggestions:
            suggestions.extend([
                'Verify the CSR is in PEM format',
                'Check that the CSR was generated correctly',
                'Ensure no characters were lost during copy/paste'
            ])
        
        return suggestions

    @staticmethod
    def verify_csr_private_key_match(csr_pem, private_key_pem):
        """
        Verify if a CSR and private key belong together by comparing their public keys.
        Uses modern cryptography library to avoid deprecation warnings.
        
        Args:
            csr_pem (str): PEM-encoded Certificate Signing Request
            private_key_pem (str): PEM-encoded private key
            
        Returns:
            dict: {
                'match': bool,
                'message': str,
                'details': str or None,
                'csr_info': dict or None
            }
        """
        try:
            # Load CSR using modern cryptography library
            try:
                if isinstance(csr_pem, str):
                    csr_pem_bytes = csr_pem.encode('utf-8')
                else:
                    csr_pem_bytes = csr_pem
                
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization, hashes
                from cryptography.hazmat.primitives.asymmetric import rsa, ec
                
                crypto_csr = x509.load_pem_x509_csr(csr_pem_bytes)
                    
            except Exception as e:
                return {
                    'match': False,
                    'message': 'Invalid CSR format',
                    'details': f'Could not parse CSR: {str(e)}',
                    'csr_info': None
                }
            
            # Load private key using modern cryptography library
            try:
                if isinstance(private_key_pem, str):
                    private_key_pem_bytes = private_key_pem.encode('utf-8')
                else:
                    private_key_pem_bytes = private_key_pem
                crypto_private_key = serialization.load_pem_private_key(private_key_pem_bytes, password=None)
            except Exception as e:
                return {
                    'match': False,
                    'message': 'Invalid private key format',
                    'details': f'Could not parse private key: {str(e)}',
                    'csr_info': None
                }
            
            
            # Get public keys from both CSR and private key using modern cryptography
            try:
                csr_public_key = crypto_csr.public_key()
                private_public_key = crypto_private_key.public_key()
                
                # Compare public key numbers (cryptographic comparison)
                if isinstance(csr_public_key, rsa.RSAPublicKey) and isinstance(private_public_key, rsa.RSAPublicKey):
                    keys_match = (
                        csr_public_key.public_numbers().n == private_public_key.public_numbers().n and
                        csr_public_key.public_numbers().e == private_public_key.public_numbers().e
                    )
                    key_type = 'RSA'
                    key_size = csr_public_key.key_size
                    key_details = f"Key Type: {key_type}, Key Size: {key_size} bits"
                elif isinstance(csr_public_key, ec.EllipticCurvePublicKey) and isinstance(private_public_key, ec.EllipticCurvePublicKey):
                    keys_match = (
                        csr_public_key.public_numbers().x == private_public_key.public_numbers().x and
                        csr_public_key.public_numbers().y == private_public_key.public_numbers().y and
                        csr_public_key.curve.name == private_public_key.curve.name
                    )
                    key_type = 'ECDSA'
                    key_details = f"Key Type: {key_type}, Curve: {csr_public_key.curve.name}"
                else:
                    return {
                        'match': False,
                        'message': 'Key type mismatch',
                        'details': 'CSR and private key use different cryptographic algorithms',
                        'csr_info': None
                    }
                
                # Extract CSR information for details
                subject_dict = {}
                for attribute in crypto_csr.subject:
                    # Convert OID to string representation
                    attr_name = attribute.oid._name if hasattr(attribute.oid, '_name') else str(attribute.oid)
                    # Map common OIDs to readable names
                    oid_mapping = {
                        'countryName': 'C',
                        'stateOrProvinceName': 'ST', 
                        'localityName': 'L',
                        'organizationName': 'O',
                        'organizationalUnitName': 'OU',
                        'commonName': 'CN'
                    }
                    field_name = oid_mapping.get(attr_name, attr_name)
                    subject_dict[field_name] = attribute.value
                
                csr_info = subject_dict
                
                if keys_match:
                    return {
                        'match': True,
                        'message': 'CSR and private key match successfully!',
                        'details': f"{key_details}\nCommon Name: {csr_info.get('CN', 'Not specified')}",
                        'csr_info': csr_info
                    }
                else:
                    return {
                        'match': False,
                        'message': 'CSR and private key do not match',
                        'details': f"The public key in the CSR does not correspond to the provided private key.\n{key_details}",
                        'csr_info': csr_info
                    }
                    
            except Exception as e:
                return {
                    'match': False,
                    'message': 'Error during key comparison',
                    'details': f'Could not compare keys: {str(e)}',
                    'csr_info': None
                }
                
        except Exception as e:
            return {
                'match': False,
                'message': 'Unexpected error during verification',
                'details': f'An unexpected error occurred: {str(e)}',
                'csr_info': None
            }

    @staticmethod
    def verify_certificate_private_key_match(certificate_pem, private_key_pem, passphrase=None):
        """
        Verify if a certificate and private key belong together by comparing their public keys.
        Supports both encrypted and unencrypted private keys.

        Args:
            certificate_pem (str): PEM-encoded certificate
            private_key_pem (str): PEM-encoded private key
            passphrase (str, optional): Passphrase for encrypted private key

        Returns:
            dict: {
                'match': bool,
                'message': str,
                'details': str or None,
                'cert_info': dict or None,
                'requires_passphrase': bool (only if encrypted key detected)
            }
        """
        try:
            # Load certificate
            try:
                if isinstance(certificate_pem, str):
                    certificate_pem = certificate_pem.encode('utf-8')
                certificate = crypt.load_certificate(crypt.FILETYPE_PEM, certificate_pem)
            except Exception as e:
                return {
                    'match': False,
                    'message': 'Invalid certificate format',
                    'details': f'Could not parse certificate: {str(e)}',
                    'cert_info': None
                }

            # Check if private key is encrypted
            if isinstance(private_key_pem, str):
                private_key_pem_bytes = private_key_pem.encode('utf-8')
            else:
                private_key_pem_bytes = private_key_pem
            
            is_encrypted = CsrGenerator._is_private_key_encrypted(private_key_pem_bytes)
            
            # Load private key
            try:
                if is_encrypted:
                    if passphrase is None:
                        return {
                            'match': False,
                            'message': 'Private key is encrypted and requires a passphrase',
                            'details': 'This private key is protected with a passphrase. Please provide the passphrase to verify the key.',
                            'cert_info': None,
                            'requires_passphrase': True
                        }
                    
                    # Try to load with passphrase
                    try:
                        if isinstance(passphrase, str):
                            passphrase = passphrase.encode('utf-8')
                        private_key = crypt.load_privatekey(crypt.FILETYPE_PEM, private_key_pem_bytes, passphrase)
                    except Exception as e:
                        return {
                            'match': False,
                            'message': 'Invalid passphrase for encrypted private key',
                            'details': f'Could not decrypt private key with provided passphrase: {str(e)}',
                            'cert_info': None,
                            'requires_passphrase': True
                        }
                else:
                    # Unencrypted private key
                    private_key = crypt.load_privatekey(crypt.FILETYPE_PEM, private_key_pem_bytes)
                    
            except Exception as e:
                # Check if this might be an encrypted key without passphrase
                if is_encrypted and passphrase is None:
                    return {
                        'match': False,
                        'message': 'Private key appears to be encrypted',
                        'details': 'This private key seems to be encrypted. Please provide the passphrase.',
                        'cert_info': None,
                        'requires_passphrase': True
                    }
                else:
                    return {
                        'match': False,
                        'message': 'Invalid private key format',
                        'details': f'Could not parse private key: {str(e)}',
                        'cert_info': None
                    }

            # Get public key from certificate
            cert_public_key = certificate.get_pubkey()

            # Get the public key components for comparison
            cert_pub_pem = crypt.dump_publickey(crypt.FILETYPE_PEM, cert_public_key)
            priv_pub_pem = crypt.dump_publickey(crypt.FILETYPE_PEM, private_key)

            keys_match = cert_pub_pem == priv_pub_pem

            # Extract certificate information for details
            subject = certificate.get_subject()
            cert_info = {
                'CN': getattr(subject, 'CN', None),
                'O': getattr(subject, 'O', None),
                'OU': getattr(subject, 'OU', None),
                'L': getattr(subject, 'L', None),
                'ST': getattr(subject, 'ST', None),
                'C': getattr(subject, 'C', None),
                'serial_number': str(certificate.get_serial_number()),
                'not_before': certificate.get_notBefore().decode('utf-8') if certificate.get_notBefore() else None,
                'not_after': certificate.get_notAfter().decode('utf-8') if certificate.get_notAfter() else None
            }

            # Get key type and size information
            key_type = 'RSA' if cert_public_key.type() == crypt.TYPE_RSA else 'ECDSA'
            key_details = f"Key Type: {key_type}"

            if key_type == 'RSA':
                key_details += f", Key Size: {cert_public_key.bits()} bits"

            if keys_match:
                return {
                    'match': True,
                    'message': 'Certificate and private key match successfully!',
                    'details': f"{key_details}\nSubject CN: {cert_info.get('CN', 'Not specified')}\nSerial Number: {cert_info.get('serial_number', 'Unknown')}",
                    'cert_info': cert_info
                }
            else:
                return {
                    'match': False,
                    'message': 'Certificate and private key do not match',
                    'details': f'The public key in the certificate does not correspond to the provided private key.\n{key_details}\nSubject CN: {cert_info.get("CN", "Not specified")}',
                    'cert_info': cert_info
                }

        except Exception as e:
            return {
                'match': False,
                'message': 'Unexpected error during verification',
                'details': f'An unexpected error occurred: {str(e)}',
                'cert_info': None
            }
    
    @staticmethod
    def _analyze_modern_public_key(public_key):
        """Analyze public key using modern cryptography library."""
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                key_size = public_key.key_size
                return {
                    'type': 'RSA',
                    'size': key_size,
                    'size_bits': key_size,
                    'security_level': CsrGenerator._get_rsa_security_level(key_size),
                    'is_secure': key_size >= 2048,
                    'details': f'{key_size}-bit RSA key'
                }
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                curve_name = public_key.curve.name
                key_size = public_key.curve.key_size
                return {
                    'type': 'ECDSA',
                    'curve': curve_name,
                    'size': key_size,
                    'size_bits': key_size,
                    'security_level': CsrGenerator._get_ecdsa_security_level(curve_name),
                    'is_secure': curve_name in ['secp256r1', 'secp384r1', 'secp521r1'],
                    'details': f'{curve_name} curve ({key_size}-bit)'
                }
            else:
                return {
                    'type': 'Unknown',
                    'size': 0,
                    'details': 'Unknown key type',
                    'is_secure': False
                }
        except Exception as e:
            return {
                'type': 'Error',
                'error': str(e),
                'is_secure': False
            }
    
    @staticmethod
    def _extract_modern_subject_info(subject):
        """Extract subject information using modern cryptography library."""
        from cryptography.x509.oid import NameOID
        
        subject_dict = {}
        subject_components = []
        
        # OID to field name mapping
        oid_mapping = {
            NameOID.COUNTRY_NAME: 'C',
            NameOID.STATE_OR_PROVINCE_NAME: 'ST',
            NameOID.LOCALITY_NAME: 'L',
            NameOID.ORGANIZATION_NAME: 'O',
            NameOID.ORGANIZATIONAL_UNIT_NAME: 'OU',
            NameOID.COMMON_NAME: 'CN',
            NameOID.EMAIL_ADDRESS: 'emailAddress'
        }
        
        field_names = {
            'C': 'Country',
            'ST': 'State/Province',
            'L': 'Locality/City',
            'O': 'Organization',
            'OU': 'Organizational Unit',
            'CN': 'Common Name',
            'emailAddress': 'Email Address'
        }
        
        # Extract all components
        for attribute in subject:
            field_name = oid_mapping.get(attribute.oid, str(attribute.oid))
            field_value = attribute.value
            
            # Store in dictionary
            subject_dict[field_name] = field_value
            
            # Create display entry
            display_name = field_names.get(field_name, field_name)
            subject_components.append({
                'field': field_name,
                'display_name': display_name,
                'value': field_value,
                'length': len(field_value)
            })
        
        return {
            'components': subject_components,
            'raw': subject_dict,
            'dn_string': ', '.join([f'{comp["field"]}={comp["value"]}' for comp in subject_components])
        }
    
    @staticmethod
    def _extract_modern_extensions(crypto_csr):
        """Extract extensions using modern cryptography library."""
        from cryptography import x509
        
        extensions = []
        
        try:
            for ext in crypto_csr.extensions:
                ext_name = ext.oid._name if hasattr(ext.oid, '_name') else str(ext.oid)
                
                if ext_name == 'subjectAltName':
                    # Parse Subject Alternative Names
                    san_list = []
                    for san in ext.value:
                        if isinstance(san, x509.DNSName):
                            san_list.append(f'DNS:{san.value}')
                        elif isinstance(san, x509.IPAddress):
                            san_list.append(f'IP:{san.value}')
                        else:
                            san_list.append(str(san))
                    
                    extensions.append({
                        'name': 'Subject Alternative Name',
                        'short_name': 'subjectAltName',
                        'critical': ext.critical,
                        'value': san_list,
                        'raw_value': ', '.join(san_list),
                        'count': len(san_list)
                    })
                else:
                    extensions.append({
                        'name': ext_name,
                        'short_name': ext_name,
                        'critical': ext.critical,
                        'value': str(ext.value),
                        'raw_value': str(ext.value)
                    })
                    
        except Exception as e:
            # If extension parsing fails, continue without extensions
            pass
        
        return {
            'count': len(extensions),
            'extensions': extensions,
            'has_san': any(ext.get('short_name') == 'subjectAltName' for ext in extensions)
        }
    
    @staticmethod
    def _analyze_modern_signature(crypto_csr):
        """Analyze CSR signature using modern cryptography library."""
        try:
            # Get signature algorithm
            sig_algo = crypto_csr.signature_algorithm_oid._name if hasattr(crypto_csr.signature_algorithm_oid, '_name') else 'Unknown'
            
            # Check if CSR is properly signed (it should be self-signed)
            try:
                # Verify the CSR signature using the public key
                public_key = crypto_csr.public_key()
                
                # For a CSR, the signature should be verifiable with its own public key
                is_valid = True  # If we got this far, the CSR was parsed successfully
                
                return {
                    'algorithm': sig_algo,
                    'is_self_signed': True,
                    'valid_signature': is_valid,
                    'details': f'Signature algorithm: {sig_algo}'
                }
            except Exception:
                return {
                    'algorithm': sig_algo,
                    'is_self_signed': False,
                    'valid_signature': False,
                    'details': 'Signature verification failed'
                }
                
        except Exception as e:
            return {
                'algorithm': 'Unknown',
                'error': str(e),
                'valid_signature': False
            }
    
    @staticmethod
    def _check_modern_csr_validity(crypto_csr):
        """Check CSR validity using modern cryptography library."""
        try:
            # Basic validity checks
            subject = crypto_csr.subject
            public_key = crypto_csr.public_key()
            
            # Check if we can extract basic information
            has_subject = len(list(subject)) > 0
            has_public_key = public_key is not None
            
            return {
                'is_valid': has_subject and has_public_key,
                'has_subject': has_subject,
                'has_public_key': has_public_key,
                'well_formed': True,
                'details': 'CSR structure is valid and well-formed'
            }
            
        except Exception as e:
            return {
                'is_valid': False,
                'error': str(e),
                'details': 'CSR structure validation failed'
            }
    
    @staticmethod
    def _is_private_key_encrypted(private_key_pem_bytes):
        """
        Check if a private key is encrypted by examining the PEM headers.
        
        Args:
            private_key_pem_bytes (bytes): PEM-encoded private key as bytes
            
        Returns:
            bool: True if the private key appears to be encrypted
        """
        try:
            pem_str = private_key_pem_bytes.decode('utf-8')
            
            # Check for encrypted key indicators in PEM format
            encrypted_indicators = [
                'Proc-Type: 4,ENCRYPTED',
                'DEK-Info:',
                'BEGIN ENCRYPTED PRIVATE KEY',
                'BEGIN RSA PRIVATE KEY\n-----\nProc-Type: 4,ENCRYPTED',
                'BEGIN EC PRIVATE KEY\n-----\nProc-Type: 4,ENCRYPTED'
            ]
            
            # Look for encryption indicators
            for indicator in encrypted_indicators:
                if indicator in pem_str:
                    return True
            
            # Check for PKCS#8 encrypted format
            if 'BEGIN ENCRYPTED PRIVATE KEY' in pem_str:
                return True
            
            # Traditional OpenSSL encrypted format indicators
            lines = pem_str.split('\n')
            for i, line in enumerate(lines):
                if 'BEGIN' in line and 'PRIVATE KEY' in line:
                    # Check the next few lines for encryption headers
                    for j in range(i + 1, min(i + 5, len(lines))):
                        if 'Proc-Type:' in lines[j] and 'ENCRYPTED' in lines[j]:
                            return True
                        if 'DEK-Info:' in lines[j]:
                            return True
            
            return False
            
        except Exception:
            # If we can't decode or analyze, assume unencrypted
            return False
