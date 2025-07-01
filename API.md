# API Documentation

## Overview

Secure Cert-Tools provides REST API endpoints for programmatic access to CSR generation, verification, and analysis functionality. All endpoints accept form-encoded data and return JSON responses.

## Base URL

```
https://localhost:5555
```

## Authentication

No authentication is required for API endpoints. However, rate limiting and request size restrictions apply.

## Request Limits

- Maximum request size: 1MB
- Content-Type: `application/x-www-form-urlencoded`

## Endpoints

### Generate CSR

Generate a new Certificate Signing Request with private key.

**Endpoint:** `POST /generate`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| CN | string | Yes | Common Name (domain or FQDN) |
| C | string | No | Country (2-letter ISO code) |
| ST | string | No | State or Province |
| L | string | No | Locality or City |
| O | string | No | Organization name |
| OU | string | No | Organizational Unit |
| keyType | string | No | Key type: "RSA" or "ECDSA" (default: "RSA") |
| keySize | integer | No | RSA key size: 2048 or 4096 (default: 2048) |
| curve | string | No | ECDSA curve: "P-256", "P-384", or "P-521" (default: "P-256") |
| subjectAltNames | string | No | Comma-separated list of SAN domains |
| allowPrivateDomains | boolean | No | Allow private/internal domains (default: false) |

**Example Request:**

```bash
curl -X POST https://localhost:5555/generate \
  -d "CN=example.com" \
  -d "C=US" \
  -d "ST=California" \
  -d "L=San Francisco" \
  -d "O=Example Corp" \
  -d "keyType=RSA" \
  -d "keySize=2048"
```

**Success Response (200):**

```json
{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
}
```

**Error Response (400):**

```json
{
  "error": "Common Name (CN) is required"
}
```

### Verify CSR and Private Key Match

Verify that a CSR and private key pair match.

**Endpoint:** `POST /verify`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| csr | string | Yes | PEM-encoded Certificate Signing Request |
| privateKey | string | Yes | PEM-encoded private key |

**Example Request:**

```bash
curl -X POST https://localhost:5555/verify \
  -d "csr=-----BEGIN CERTIFICATE REQUEST-----..." \
  -d "privateKey=-----BEGIN PRIVATE KEY-----..."
```

**Success Response (200):**

```json
{
  "match": true,
  "message": "CSR and private key match successfully",
  "details": {
    "key_type": "RSA",
    "key_size": 2048
  }
}
```

**Error Response (400):**

```json
{
  "match": false,
  "message": "CSR and private key do not match",
  "details": "Public key mismatch"
}
```

### Analyze CSR

Analyze a CSR and extract detailed information with RFC compliance checking.

**Endpoint:** `POST /analyze`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| csr | string | Yes | PEM-encoded Certificate Signing Request |

**Example Request:**

```bash
curl -X POST https://localhost:5555/analyze \
  -d "csr=-----BEGIN CERTIFICATE REQUEST-----..."
```

**Success Response (200):**

```json
{
  "subject": {
    "CN": "example.com",
    "C": "US",
    "ST": "California",
    "L": "San Francisco",
    "O": "Example Corp"
  },
  "public_key": {
    "algorithm": "RSA",
    "key_size": 2048
  },
  "signature_algorithm": "sha256WithRSAEncryption",
  "extensions": {
    "subject_alt_names": ["example.com", "www.example.com"]
  },
  "rfc_compliance": {
    "compliant": true,
    "issues": []
  }
}
```

### Verify Certificate and Private Key Match

Verify that a certificate and private key pair match.

**Endpoint:** `POST /verify-certificate`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| certificate | string | Yes | PEM-encoded X.509 certificate |
| privateKey | string | Yes | PEM-encoded private key |
| passphrase | string | No | Passphrase for encrypted private keys |

**Example Request:**

```bash
curl -X POST https://localhost:5555/verify-certificate \
  -d "certificate=-----BEGIN CERTIFICATE-----..." \
  -d "privateKey=-----BEGIN PRIVATE KEY-----..."
```

**Success Response (200):**

```json
{
  "match": true,
  "message": "Certificate and private key match successfully",
  "details": {
    "key_type": "RSA",
    "key_size": 2048,
    "subject": "CN=example.com",
    "issuer": "CN=Example CA"
  }
}
```

### Version Information

Get application version and security information.

**Endpoint:** `GET /version`

**Example Request:**

```bash
curl https://localhost:5555/version
```

**Response (200):**

```json
{
  "version": "2.4.0",
  "release_date": "2024-07-01",
  "project_name": "Secure Cert-Tools",
  "description": "Professional Certificate Toolkit",
  "security_fixes": [
    "CVE-2024-6345",
    "CVE-2023-45853"
  ]
}
```

## Error Handling

### HTTP Status Codes

- `200` - Success
- `400` - Bad Request (invalid input)
- `413` - Request Entity Too Large
- `500` - Internal Server Error

### Error Response Format

```json
{
  "error": "Error description",
  "error_type": "ErrorType"
}
```

### Common Error Types

- `RequestTooLarge` - Request exceeds size limit
- `ValidationError` - Input validation failed
- `CryptographicError` - Key/certificate operation failed
- `ParseError` - Failed to parse PEM data

## Security Considerations

### Input Validation
- All inputs are validated and sanitized
- Maximum field lengths enforced
- PEM format validation performed

### Rate Limiting
Consider implementing rate limiting in production deployments.

### HTTPS
Always use HTTPS in production environments.

### Logging
All API requests are logged with sanitized parameters for security monitoring.

## Examples

### Complete CSR Generation Workflow

```bash
# Generate CSR
response=$(curl -s -X POST https://localhost:5555/generate \
  -d "CN=api.example.com" \
  -d "O=Example Corp" \
  -d "keyType=RSA" \
  -d "keySize=2048")

# Extract CSR and private key
csr=$(echo "$response" | jq -r '.csr')
private_key=$(echo "$response" | jq -r '.private_key')

# Verify they match
curl -X POST https://localhost:5555/verify \
  -d "csr=$csr" \
  -d "privateKey=$private_key"

# Analyze the CSR
curl -X POST https://localhost:5555/analyze \
  -d "csr=$csr"
```
