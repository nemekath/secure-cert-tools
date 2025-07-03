/**
 * Session-Based Cryptography Implementation
 * 
 * Provides session-specific encryption for private keys using WebCrypto API
 * and ECDH key exchange to protect against malicious root access.
 * 
 * Security Features:
 * - Browser-generated session entropy
 * - ECDH key exchange with server
 * - AES-GCM encryption for private keys
 * - Session-specific encryption keys
 */

class SessionCrypto {
    constructor() {
        this.sessionEntropy = null;
        this.sessionKeyPair = null;
        this.sharedSecret = null;
        this.encryptionKey = null;
        this.sessionId = null;
        this.isInitialized = false;
    }
    
    /**
     * Check if browser supports session-based cryptography
     */
    static isSupported() {
        return !!(
            window.crypto &&
            window.crypto.subtle &&
            window.crypto.subtle.generateKey &&
            window.crypto.subtle.deriveKey &&
            window.crypto.subtle.deriveBits &&
            window.location.protocol === 'https:'
        );
    }
    
    /**
     * Initialize session with browser-generated entropy and ECDH key pair
     */
    async initializeSession() {
        try {
            console.log('🔐 Initializing session-based encryption...');
            
            // Generate high-entropy session seed (256-bit)
            this.sessionEntropy = window.crypto.getRandomValues(new Uint8Array(32));
            
            // Generate ECDH key pair for session key exchange
            this.sessionKeyPair = await window.crypto.subtle.generateKey(
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                false, // Private key not extractable for security
                ["deriveKey", "deriveBits"]
            );
            
            // Export public key for server
            const publicKeyData = await window.crypto.subtle.exportKey(
                "raw",
                this.sessionKeyPair.publicKey
            );
            
            // Generate unique session ID
            this.sessionId = this.generateSessionId();
            this.isInitialized = true;
            
            console.log(`✅ Session initialized: ${this.sessionId.substring(0, 8)}...`);
            
            return {
                sessionId: this.sessionId,
                publicKey: Array.from(new Uint8Array(publicKeyData)),
                entropy: Array.from(this.sessionEntropy)
            };
            
        } catch (error) {
            console.error('❌ Session initialization failed:', error);
            throw new Error(`Session initialization failed: ${error.message}`);
        }
    }
    
    /**
     * Derive shared secret from server's public key and create session encryption key
     */
    async deriveSharedSecret(serverPublicKeyData) {
        if (!this.isInitialized) {
            throw new Error('Session not initialized. Call initializeSession() first.');
        }
        
        try {
            console.log('🔑 Deriving shared secret with server...');
            
            // Import server's public key
            const serverPublicKey = await window.crypto.subtle.importKey(
                "raw",
                new Uint8Array(serverPublicKeyData),
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                false,
                []
            );
            
            // Perform ECDH key exchange to get shared secret
            const sharedSecretBits = await window.crypto.subtle.deriveBits(
                {
                    name: "ECDH",
                    public: serverPublicKey
                },
                this.sessionKeyPair.privateKey,
                256 // 256 bits shared secret
            );
            
            // Import shared secret for HKDF key derivation
            const hkdfKey = await window.crypto.subtle.importKey(
                "raw",
                sharedSecretBits,
                "HKDF",
                false,
                ["deriveKey"]
            );
            
            // Derive session encryption key using HKDF
            const sessionKey = await window.crypto.subtle.deriveKey(
                {
                    name: "HKDF",
                    hash: "SHA-256",
                    salt: this.sessionEntropy,
                    info: new TextEncoder().encode("PrivateKeyEncryption")
                },
                hkdfKey,
                {
                    name: "AES-GCM",
                    length: 256
                },
                false, // Key not extractable
                ["encrypt", "decrypt"]
            );
            
            console.log('✅ Shared secret derived successfully');
            return sessionKey;
            
        } catch (error) {
            console.error('❌ Shared secret derivation failed:', error);
            throw new Error(`Shared secret derivation failed: ${error.message}`);
        }
    }
    
    /**
     * Decrypt private key received from server
     */
    async decryptPrivateKey(encryptedData, iv, serverPublicKeyData) {
        try {
            console.log('🔓 Decrypting private key...');
            
            // Derive session encryption key
            const sessionKey = await this.deriveSharedSecret(serverPublicKeyData);
            
            // Decrypt private key using AES-GCM
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: new Uint8Array(iv)
                },
                sessionKey,
                new Uint8Array(encryptedData)
            );
            
            const decryptedPrivateKey = new TextDecoder().decode(decryptedBuffer);
            
            console.log('✅ Private key decrypted successfully');
            
            // Validate decrypted private key format
            if (!this.validatePrivateKeyFormat(decryptedPrivateKey)) {
                throw new Error('Decrypted private key has invalid format');
            }
            
            return decryptedPrivateKey;
            
        } catch (error) {
            console.error('❌ Private key decryption failed:', error);
            throw new Error(`Private key decryption failed: ${error.message}`);
        }
    }
    
    /**
     * Generate cryptographically secure session ID
     */
    generateSessionId() {
        const timestamp = Date.now().toString(36);
        const random = window.crypto.getRandomValues(new Uint8Array(16));
        const randomHex = Array.from(random)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
        return `${timestamp}_${randomHex}`;
    }
    
    /**
     * Validate private key format
     */
    validatePrivateKeyFormat(privateKeyPEM) {
        const validHeaders = [
            '-----BEGIN PRIVATE KEY-----',           // PKCS#8
            '-----BEGIN RSA PRIVATE KEY-----',       // Traditional RSA
            '-----BEGIN EC PRIVATE KEY-----',        // Traditional EC
            '-----BEGIN ENCRYPTED PRIVATE KEY-----'  // PKCS#8 encrypted
        ];
        
        return validHeaders.some(header => privateKeyPEM.includes(header)) &&
               privateKeyPEM.includes('-----END');
    }
    
    /**
     * Clean up session data (called on page unload)
     */
    cleanup() {
        console.log('🧹 Cleaning up session crypto data...');
        
        this.sessionEntropy = null;
        this.sessionKeyPair = null;
        this.sharedSecret = null;
        this.encryptionKey = null;
        this.sessionId = null;
        this.isInitialized = false;
        
        // Force garbage collection hint
        if (window.gc) {
            window.gc();
        }
    }
    
    /**
     * Get session status for debugging
     */
    getStatus() {
        return {
            isSupported: SessionCrypto.isSupported(),
            isInitialized: this.isInitialized,
            sessionId: this.sessionId ? this.sessionId.substring(0, 8) + '...' : null,
            hasEntropy: !!this.sessionEntropy,
            hasKeyPair: !!this.sessionKeyPair
        };
    }
}

/**
 * Enhanced CSR Generator with Session-Based Encryption
 */
class SecureCSRGenerator extends SecureCertTools {
    constructor() {
        super();
        this.sessionCrypto = new SessionCrypto();
        this.sessionCryptoEnabled = SessionCrypto.isSupported();
        
        // Add cleanup on page unload
        window.addEventListener('beforeunload', () => {
            this.sessionCrypto.cleanup();
        });
        
        console.log(`🔐 Session crypto ${this.sessionCryptoEnabled ? 'ENABLED' : 'DISABLED'}`);
    }
    
    /**
     * Enhanced CSR generation with session-based encryption
     */
    async handleGenerate(e) {
        e.preventDefault();
        this.showLoading(true);
        
        try {
            const formData = new FormData(this.generateForm);
            const data = this.formDataToObject(formData);
            
            if (this.sessionCryptoEnabled) {
                return await this.generateWithSessionEncryption(data);
            } else {
                console.warn('⚠️ Session crypto not supported, using standard generation');
                return await this.generateStandard(data);
            }
            
        } catch (error) {
            console.error('❌ CSR generation failed:', error);
            this.showError(`CSR generation failed: ${error.message}`);
        } finally {
            this.showLoading(false);
        }
    }
    
    /**
     * Generate CSR with session-based encryption
     */
    async generateWithSessionEncryption(data) {
        try {
            console.log('🔐 Generating CSR with session encryption...');
            
            // Initialize session encryption
            const sessionData = await this.sessionCrypto.initializeSession();
            
            // Add session data to request
            data.sessionEncryption = 'true';
            data.sessionId = sessionData.sessionId;
            data.clientPublicKey = JSON.stringify(sessionData.publicKey);
            data.sessionEntropy = JSON.stringify(sessionData.entropy);
            
            // Make request to server
            const response = await this.makeRequest('/generate', data);
            const result = await response.json();
            
            if (response.ok) {
                if (result.encryption === 'session-based') {
                    console.log('🔓 Decrypting private key...');
                    
                    // Decrypt private key on client side
                    const decryptedPrivateKey = await this.sessionCrypto.decryptPrivateKey(
                        result.encryptedPrivateKey,
                        result.encryptionIV,
                        result.serverPublicKey
                    );
                    
                    // Update result with decrypted key for display
                    result.private_key = decryptedPrivateKey;
                    
                    // Clean up encrypted data from result
                    delete result.encryptedPrivateKey;
                    delete result.encryptionIV;
                    delete result.serverPublicKey;
                    
                    console.log('✅ CSR generated with session encryption');
                    
                    // Add security indicator
                    result.securityLevel = 'session-encrypted';
                } else {
                    console.warn('⚠️ Server returned non-encrypted response');
                }
                
                this.lastGenerationData = data;
                this.showResultModal('🔐 CSR Generated Securely', this.formatCSRResult(result));
                
            } else {
                throw new Error(result.error || 'Server returned error');
            }
            
        } catch (error) {
            console.warn('⚠️ Session encryption failed, attempting fallback:', error);
            
            // Fallback to standard generation
            return await this.generateStandard(data);
        }
    }
    
    /**
     * Standard CSR generation (fallback)
     */
    async generateStandard(data) {
        console.log('🔧 Using standard CSR generation...');
        
        // Remove session-specific fields
        delete data.sessionEncryption;
        delete data.sessionId;
        delete data.clientPublicKey;
        delete data.sessionEntropy;
        
        const response = await this.makeRequest('/generate', data);
        const result = await response.json();
        
        if (response.ok) {
            console.log('✅ CSR generated with standard method');
            result.securityLevel = 'standard';
            
            this.lastGenerationData = data;
            this.showResultModal('🔐 CSR Generated', this.formatCSRResult(result));
        } else {
            throw new Error(result.error || 'Failed to generate CSR');
        }
    }
    
    /**
     * Enhanced result formatting with security indicators
     */
    formatCSRResult(result) {
        const baseResult = super.formatCSRResult(result);
        
        // Add security level indicator
        const securityBadge = result.securityLevel === 'session-encrypted' 
            ? '<div class="security-badge session-encrypted">🛡️ Session Encrypted</div>'
            : '<div class="security-badge standard">⚠️ Standard Generation</div>';
        
        return securityBadge + baseResult;
    }
    
    /**
     * Get session crypto status for debugging
     */
    getSessionStatus() {
        return {
            ...this.sessionCrypto.getStatus(),
            enabled: this.sessionCryptoEnabled
        };
    }
}

// Feature detection and initialization
document.addEventListener('DOMContentLoaded', () => {
    // Check if we should use session crypto
    if (SessionCrypto.isSupported()) {
        console.log('🔐 Initializing Secure CSR Generator with session encryption');
        window.csrGenerator = new SecureCSRGenerator();
    } else {
        console.warn('⚠️ Session crypto not supported, using standard generator');
        console.warn('Requirements: HTTPS, WebCrypto API, modern browser');
        
        // Fallback to standard implementation
        window.csrGenerator = new SecureCertTools();
    }
    
    // Debug info
    if (window.location.search.includes('debug=crypto')) {
        console.log('🔍 Session Crypto Debug Info:', window.csrGenerator.getSessionStatus?.());
    }
});

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SessionCrypto, SecureCSRGenerator };
}
