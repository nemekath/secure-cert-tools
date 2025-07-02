class SecureCertTools {
    constructor() {
        this.init();
    }

    init() {
        this.tabs = document.querySelectorAll('.tab');
        this.panels = document.querySelectorAll('.panel');
        this.generateForm = document.getElementById('generate-form');
        this.verifyForm = document.getElementById('verify-form');
        this.analyzeForm = document.getElementById('analyze-form');
        this.verifyCertForm = document.getElementById('verify-cert-form');
        this.resultModal = document.getElementById('result-modal');
        this.loadingOverlay = document.getElementById('loading-overlay');
        this.themeToggle = document.getElementById('theme-toggle');

        this.bindEvents();
        this.setupTheme();
    }

    bindEvents() {
        // Tab switching
        this.tabs.forEach(tab => {
            tab.addEventListener('click', () => this.switchTab(tab));
        });

        // Radio button changes for key type
        const keyTypeRadios = document.querySelectorAll('input[name="keyType"]');
        keyTypeRadios.forEach(radio => {
            radio.addEventListener('change', () => this.handleKeyTypeChange());
        });

        // Form validation on input
        this.setupInputValidation();

        // Form submissions
        if (this.generateForm) {
            this.generateForm.addEventListener('submit', (e) => this.handleGenerate(e));
        }
        if (this.verifyForm) {
            this.verifyForm.addEventListener('submit', (e) => this.handleVerify(e));
        }
        if (this.analyzeForm) {
            this.analyzeForm.addEventListener('submit', (e) => this.handleAnalyze(e));
        }
        if (this.verifyCertForm) {
            this.verifyCertForm.addEventListener('submit', (e) => this.handleVerifyCert(e));
        }

        // Modal close handlers
        if (this.resultModal) {
            // Close button in header
            const closeBtn = this.resultModal.querySelector('.modal__close');
            if (closeBtn) {
                closeBtn.addEventListener('click', () => {
                    this.closeModal();
                });
            }
            
            // Close button in footer
            const footerCloseBtn = this.resultModal.querySelector('.modal__actions .modal__close');
            if (footerCloseBtn) {
                footerCloseBtn.addEventListener('click', () => {
                    this.closeModal();
                });
            }
            
            // ESC key to close modal
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && this.resultModal.hasAttribute('open')) {
                    this.closeModal();
                }
            });
        }

        // Theme toggle
        if (this.themeToggle) {
            this.themeToggle.addEventListener('click', () => this.toggleTheme());
        }
        
        // Initialize key type visibility
        this.handleKeyTypeChange();
    }

    switchTab(activeTab) {
        this.tabs.forEach(t => {
            t.classList.remove('tab--active');
            t.setAttribute('aria-selected', 'false');
        });
        
        activeTab.classList.add('tab--active');
        activeTab.setAttribute('aria-selected', 'true');

        const panelId = activeTab.getAttribute('data-tab');
        this.panels.forEach(p => {
            p.classList.remove('panel--active');
            p.setAttribute('aria-hidden', 'true');
        });
        
        const activePanel = document.getElementById(`${panelId}-panel`);
        if (activePanel) {
            activePanel.classList.add('panel--active');
            activePanel.setAttribute('aria-hidden', 'false');
        }
    }

    handleKeyTypeChange() {
        const keyType = document.querySelector('input[name="keyType"]:checked')?.value;
        const rsaOptions = document.getElementById('rsa-options');
        const ecdsaOptions = document.getElementById('ecdsa-options');
        
        if (rsaOptions && ecdsaOptions) {
            if (keyType === 'RSA') {
                rsaOptions.style.display = 'block';
                ecdsaOptions.style.display = 'none';
            } else if (keyType === 'ECDSA') {
                rsaOptions.style.display = 'none';
                ecdsaOptions.style.display = 'block';
            }
        }
    }

    async handleGenerate(e) {
        e.preventDefault();
        this.showLoading(true);
        
        try {
            const formData = new FormData(this.generateForm);
            const data = this.formDataToObject(formData);
            
            const response = await this.makeRequest('/generate', data);
            const result = await response.json();
            
            if (response.ok) {
                // Store form data for filename generation
                this.lastGenerationData = data;
                this.showResultModal('🔐 CSR Generated Successfully', this.formatCSRResult(result));
            } else {
                this.showError(result.error || 'Failed to generate CSR');
            }
        } catch (error) {
            this.showError('Network error: Failed to generate CSR');
        } finally {
            this.showLoading(false);
        }
    }

    async handleVerify(e) {
        e.preventDefault();
        this.showLoading(true);
        
        try {
            const formData = new FormData(this.verifyForm);
            const data = this.formDataToObject(formData);
            
            const response = await this.makeRequest('/verify', data);
            const result = await response.json();
            
            const icon = result.match ? '✅' : '❌';
            const title = `${icon} Verification Result`;
            
            if (result.match) {
                // Show enhanced information for successful matches
                this.showResultModal(title, this.formatVerificationResult(result));
            } else {
                // Show basic message for failed matches
                this.showResultModal(title, result.message);
            }
        } catch (error) {
            this.showError('Network error: Failed to verify keys');
        } finally {
            this.showLoading(false);
        }
    }

    async handleAnalyze(e) {
        e.preventDefault();
        this.showLoading(true);
        
        try {
            const formData = new FormData(this.analyzeForm);
            const data = this.formDataToObject(formData);
            
            const response = await this.makeRequest('/analyze', data);
            const result = await response.json();
            
            if (result.valid) {
                this.showResultModal('📋 CSR Analysis Results', this.formatAnalysisResult(result));
            } else {
                this.showError(result.error || 'Failed to analyze CSR');
            }
        } catch (error) {
            this.showError('Network error: Failed to analyze CSR');
        } finally {
            this.showLoading(false);
        }
    }

    async handleVerifyCert(e) {
        e.preventDefault();
        this.showLoading(true);
        
        try {
            const formData = new FormData(this.verifyCertForm);
            const data = this.formDataToObject(formData);
            
            const response = await this.makeRequest('/verify-certificate', data);
            const result = await response.json();
            
            const icon = result.match ? '✅' : '❌';
            const title = `${icon} Certificate Verification Result`;
            
            if (result.match) {
                // Hide passphrase field on success
                this.hidePassphraseField();
                // Show enhanced information for successful matches
                this.showResultModal(title, this.formatCertificateVerificationResult(result));
            } else {
                // Check if we need to show passphrase field
                if (result.requires_passphrase) {
                    this.showPassphraseField();
                    this.showError('Private key is encrypted. Please enter the passphrase and try again.');
                } else {
                    // Hide passphrase field for other errors
                    this.hidePassphraseField();
                    // Show basic message for failed matches
                    this.showResultModal(title, result.message);
                }
            }
        } catch (error) {
            this.showError('Network error: Failed to verify certificate and private key');
        } finally {
            this.showLoading(false);
        }
    }

    async makeRequest(url, data) {
        // Get CSRF token from meta tag or form
        const csrfToken = this.getCSRFToken();
        
        // Add CSRF token to data
        if (csrfToken) {
            data.csrf_token = csrfToken;
        }
        
        return fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRFToken': csrfToken || ''
            },
            body: new URLSearchParams(data)
        });
    }
    
    getCSRFToken() {
        // Try to get CSRF token from meta tag first
        const metaToken = document.querySelector('meta[name="csrf-token"]');
        if (metaToken) {
            return metaToken.getAttribute('content');
        }
        
        // Fall back to getting from form hidden input
        const tokenInput = document.querySelector('input[name="csrf_token"]');
        if (tokenInput) {
            return tokenInput.value;
        }
        
        return null;
    }

    formDataToObject(formData) {
        const obj = {};
        for (let [key, value] of formData.entries()) {
            obj[key] = value;
        }
        return obj;
    }

    formatCSRResult(result) {
        const containerId = 'result-' + Date.now();
        
        setTimeout(() => {
            // Add event listeners after DOM is updated
            const copyCSRBtn = document.getElementById(`copy-csr-${containerId}`);
            const copyKeyBtn = document.getElementById(`copy-key-${containerId}`);
            const downloadCSRBtn = document.getElementById(`download-csr-${containerId}`);
            const downloadKeyBtn = document.getElementById(`download-key-${containerId}`);
            
            if (copyCSRBtn) {
                copyCSRBtn.addEventListener('click', () => {
                    this.copyToClipboard(result.csr, copyCSRBtn, 'CSR copied!');
                });
            }
            
            if (copyKeyBtn) {
                copyKeyBtn.addEventListener('click', () => {
                    this.copyToClipboard(result.private_key, copyKeyBtn, 'Private key copied!');
                });
            }
            
            if (downloadCSRBtn) {
                downloadCSRBtn.addEventListener('click', () => {
                    const csrFilename = this.generateFilename('CertificateRequest', 'csr');
                    this.downloadFile(result.csr, csrFilename, 'application/x-x509-ca-cert');
                });
            }
            
            if (downloadKeyBtn) {
                downloadKeyBtn.addEventListener('click', () => {
                    const keyFilename = this.generateFilename('PrivateKey', 'key');
                    this.downloadFile(result.private_key, keyFilename, 'application/x-pem-file');
                });
            }
        }, 100);
        
        return `
            <div class="result-container">
                <div class="result-section">
                    <h4>Certificate Signing Request (CSR)</h4>
                    <textarea readonly class="result-textarea" id="csr-${containerId}">${result.csr}</textarea>
                    <button class="btn btn--sm" id="copy-csr-${containerId}">📋 Copy CSR</button>
                </div>
                <div class="result-section">
                    <h4>Private Key</h4>
                    <textarea readonly class="result-textarea" id="key-${containerId}">${result.private_key}</textarea>
                    <button class="btn btn--sm" id="copy-key-${containerId}">🔑 Copy Private Key</button>
                </div>
                <div class="result-section">
                    <h4>Download Files</h4>
                    <button class="btn btn--sm" id="download-csr-${containerId}">💾 Download CSR</button>
                    <button class="btn btn--sm" id="download-key-${containerId}">💾 Download Private Key</button>
                </div>
            </div>
        `;
    }

    formatVerificationResult(result) {
        let html = '<div class="verification-result">';
        
        // Basic success message
        html += `<div class="verification-success">`;
        html += `<p class="success-message">✅ <strong>${result.message}</strong></p>`;
        html += `</div>`;
        
        // Key details section
        if (result.details) {
            html += `<div class="key-details">`;
            html += `<h4>🔐 Key Information</h4>`;
            
            // Parse details for better formatting
            const detailLines = result.details.split('\n');
            html += `<div class="details-list">`;
            detailLines.forEach(line => {
                if (line.trim()) {
                    html += `<div class="detail-item">`;
                    html += `<span class="detail-text">${line.trim()}</span>`;
                    html += `</div>`;
                }
            });
            html += `</div>`;
            html += `</div>`;
        }
        
        // CSR subject information section
        if (result.csr_info) {
            html += `<div class="csr-subject">`;
            html += `<h4>📋 Certificate Subject Information</h4>`;
            html += `<div class="subject-grid">`;
            
            const subjectFields = [
                { key: 'CN', label: 'Common Name', icon: '🌐' },
                { key: 'O', label: 'Organization', icon: '🏢' },
                { key: 'OU', label: 'Organizational Unit', icon: '🏪' },
                { key: 'L', label: 'Locality/City', icon: '📍' },
                { key: 'ST', label: 'State/Province', icon: '🗺️' },
                { key: 'C', label: 'Country', icon: '🌎' }
            ];
            
            subjectFields.forEach(field => {
                const value = result.csr_info[field.key];
                if (value) {
                    html += `<div class="subject-item">`;
                    html += `<span class="subject-icon">${field.icon}</span>`;
                    html += `<span class="subject-label">${field.label}:</span>`;
                    html += `<span class="subject-value">${value}</span>`;
                    html += `</div>`;
                }
            });
            
            html += `</div>`;
            html += `</div>`;
        }
        
        // Security notice
        html += `<div class="security-notice">`;
        html += `<h4>🔒 Security Notes</h4>`;
        html += `<ul>`;
        html += `<li>✅ The CSR and private key are cryptographically matched</li>`;
        html += `<li>🔐 This confirms the private key can be used to sign certificates for this CSR</li>`;
        html += `<li>⚡ The verification process compared the public key components without exposing the private key</li>`;
        html += `</ul>`;
        html += `</div>`;
        
        html += '</div>';
        return html;
    }

    formatCertificateVerificationResult(result) {
        let html = '<div class="certificate-verification-result">';
        
        // Basic success message
        html += `<div class="verification-success">`;
        html += `<p class="success-message">✅ <strong>${result.message}</strong></p>`;
        html += `</div>`;
        
        // Key details section
        if (result.details) {
            html += `<div class="key-details">`;
            html += `<h4>🔐 Key Information</h4>`;
            
            // Parse details for better formatting
            const detailLines = result.details.split('\n');
            html += `<div class="details-list">`;
            detailLines.forEach(line => {
                if (line.trim()) {
                    html += `<div class="detail-item">`;
                    html += `<span class="detail-text">${line.trim()}</span>`;
                    html += `</div>`;
                }
            });
            html += `</div>`;
            html += `</div>`;
        }
        
        // Certificate information section
        if (result.cert_info) {
            html += `<div class="cert-subject">`;
            html += `<h4>📜 Certificate Information</h4>`;
            html += `<div class="subject-grid">`;
            
            const certFields = [
                { key: 'CN', label: 'Common Name', icon: '🌐' },
                { key: 'O', label: 'Organization', icon: '🏢' },
                { key: 'OU', label: 'Organizational Unit', icon: '🏪' },
                { key: 'L', label: 'Locality/City', icon: '📍' },
                { key: 'ST', label: 'State/Province', icon: '🗺️' },
                { key: 'C', label: 'Country', icon: '🌎' },
                { key: 'serial_number', label: 'Serial Number', icon: '🔢' }
            ];
            
            certFields.forEach(field => {
                const value = result.cert_info[field.key];
                if (value) {
                    html += `<div class="subject-item">`;
                    html += `<span class="subject-icon">${field.icon}</span>`;
                    html += `<span class="subject-label">${field.label}:</span>`;
                    html += `<span class="subject-value">${value}</span>`;
                    html += `</div>`;
                }
            });
            
            // Certificate validity dates
            if (result.cert_info.not_before || result.cert_info.not_after) {
                html += `<div class="cert-validity">`;
                html += `<h5>📅 Certificate Validity</h5>`;
                if (result.cert_info.not_before) {
                    html += `<div class="validity-item">`;
                    html += `<span class="validity-label">Valid From:</span>`;
                    html += `<span class="validity-value">${result.cert_info.not_before}</span>`;
                    html += `</div>`;
                }
                if (result.cert_info.not_after) {
                    html += `<div class="validity-item">`;
                    html += `<span class="validity-label">Valid Until:</span>`;
                    html += `<span class="validity-value">${result.cert_info.not_after}</span>`;
                    html += `</div>`;
                }
                html += `</div>`;
            }
            
            html += `</div>`;
            html += `</div>`;
        }
        
        // Security notice
        html += `<div class="security-notice">`;
        html += `<h4>🔒 Security Notes</h4>`;
        html += `<ul>`;
        html += `<li>✅ The certificate and private key are cryptographically matched</li>`;
        html += `<li>🔐 This confirms the private key can be used with this certificate for SSL/TLS connections</li>`;
        html += `<li>⚡ The verification process compared the public key components without exposing the private key</li>`;
        html += `<li>📜 This is a CA-signed certificate ready for production use</li>`;
        html += `</ul>`;
        html += `</div>`;
        
        html += '</div>';
        return html;
    }

    formatAnalysisResult(result) {
        let html = '<div class="analysis-result">';
        
        // Overall validity summary
        if (result.validity) {
            const isValid = result.validity.is_valid;
            const icon = isValid ? '✅' : '❌';
            const statusClass = isValid ? 'success' : 'error';
            
            html += `<div class="validity-summary ${statusClass}">`;
            html += `<h3>${icon} CSR Validity Status</h3>`;
            html += `<p>${result.validity.details || 'CSR validation completed'}</p>`;
            
            // Add scroll banner for detailed analysis
            const hasWarnings = result.rfc_warnings && result.rfc_warnings.length > 0;
            const hasExtensions = result.extensions && result.extensions.count > 0;
            
            if (isValid && (hasWarnings || hasExtensions)) {
                html += `<div class="scroll-banner">`;
                html += `<div class="scroll-banner-content">`;
                html += `<span class="scroll-icon">📋</span>`;
                html += `<div class="scroll-text">`;
                html += `<strong>Detailed Analysis Available</strong><br>`;
                
                if (hasWarnings) {
                    // Count different types of RFC warnings
                    const errors = result.rfc_warnings.filter(w => w.type === 'error');
                    const warnings = result.rfc_warnings.filter(w => w.type === 'warning');
                    const infos = result.rfc_warnings.filter(w => w.type === 'info');
                    
                    let detailParts = [];
                    
                    if (errors.length > 0) {
                        detailParts.push(`${errors.length} Error${errors.length !== 1 ? 's' : ''}`);
                    }
                    
                    if (warnings.length > 0) {
                        detailParts.push(`${warnings.length} Warning${warnings.length !== 1 ? 's' : ''}`);
                    }
                    
                    if (infos.length > 0) {
                        detailParts.push(`${infos.length} Information`);
                    }
                    
                    const detailText = detailParts.length > 0 ? detailParts.join(' • ') : 'RFC Compliance Items';
                    html += `<span class="scroll-details">RFC Compliance & Security Analysis: <strong>${detailText}</strong></span>`;
                } else {
                    html += `<span class="scroll-details">Certificate Extensions & Technical Details</span>`;
                }
                
                html += `</div>`;
                html += `<div class="scroll-arrow">`;
                html += `<svg viewBox="0 0 24 24" fill="currentColor" class="scroll-arrow-icon">`;
                html += `<path d="M7 10l5 5 5-5z"/>`;
                html += `</svg>`;
                html += `<span class="scroll-text-arrow">Scroll Down</span>`;
                html += `</div>`;
                html += `</div>`;
                html += `</div>`;
            }
            
            html += `</div>`;
        }
        
        // Subject Information
        if (result.subject) {
            html += '<div class="analysis-section">';
            html += '<h4>📋 Subject Information</h4>';
            
            if (result.subject.components && result.subject.components.length > 0) {
                html += '<div class="subject-grid">';
                result.subject.components.forEach(comp => {
                    const icons = {
                        'CN': '🌐',
                        'O': '🏢',
                        'OU': '🏪',
                        'L': '📍',
                        'ST': '🗺️',
                        'C': '🌎',
                        'emailAddress': '📧'
                    };
                    const icon = icons[comp.field] || '📄';
                    
                    html += `<div class="subject-item">`;
                    html += `<span class="subject-icon">${icon}</span>`;
                    html += `<span class="subject-label">${comp.display_name}:</span>`;
                    html += `<span class="subject-value">${comp.value}</span>`;
                    html += `</div>`;
                });
                html += '</div>';
            } else {
                html += '<p class="warning">⚠️ No subject information found</p>';
            }
            html += '</div>';
        }
        
        // Public Key Information
        if (result.public_key) {
            const isSecure = result.public_key.is_secure;
            const securityIcon = isSecure ? '🔒' : '⚠️';
            
            html += '<div class="analysis-section">';
            html += `<h4>${securityIcon} Public Key Information</h4>`;
            
            html += '<div class="key-info-grid">';
            html += `<div class="key-info-item">`;
            html += `<span class="key-label">Type:</span>`;
            html += `<span class="key-value">${result.public_key.type}</span>`;
            html += `</div>`;
            
            if (result.public_key.size) {
                html += `<div class="key-info-item">`;
                html += `<span class="key-label">Size:</span>`;
                html += `<span class="key-value">${result.public_key.size} bits</span>`;
                html += `</div>`;
            }
            
            if (result.public_key.curve) {
                html += `<div class="key-info-item">`;
                html += `<span class="key-label">Curve:</span>`;
                html += `<span class="key-value">${result.public_key.curve}</span>`;
                html += `</div>`;
            }
            
            if (result.public_key.security_level) {
                html += `<div class="key-info-item">`;
                html += `<span class="key-label">Security Level:</span>`;
                html += `<span class="key-value">${result.public_key.security_level}</span>`;
                html += `</div>`;
            }
            html += '</div>';
            html += '</div>';
        }
        
        // Extensions Information
        if (result.extensions && result.extensions.count > 0) {
            html += '<div class="analysis-section">';
            html += '<h4>🔧 Extensions</h4>';
            
            result.extensions.extensions.forEach(ext => {
                html += '<div class="extension-item">';
                html += `<div class="extension-header">`;
                html += `<span class="extension-name">${ext.name}</span>`;
                if (ext.critical) {
                    html += `<span class="extension-critical">CRITICAL</span>`;
                }
                html += `</div>`;
                
                if (ext.short_name === 'subjectAltName' && ext.value) {
                    html += '<div class="san-list">';
                    ext.value.forEach(san => {
                        const domain = san.startsWith('DNS:') ? san.substring(4) : san;
                        const isPrivateDomain = this.isPrivateDomain(domain);
                        const warningIcon = isPrivateDomain ? '⚠️' : '';
                        
                        html += `<div class="san-item">`;
                        html += `<span class="san-value">${san}</span>`;
                        if (isPrivateDomain) {
                            html += `<span class="san-warning" title="Private/corporate domain">${warningIcon}</span>`;
                        }
                        html += `</div>`;
                    });
                    html += '</div>';
                } else if (ext.raw_value) {
                    html += `<div class="extension-value">${ext.raw_value}</div>`;
                }
                html += '</div>';
            });
            html += '</div>';
        }
        
        // RFC Compliance Warnings
        if (result.rfc_warnings && result.rfc_warnings.length > 0) {
            html += '<div class="analysis-section warnings-section">';
            html += '<h4>⚠️ RFC Compliance & Security Analysis</h4>';
            
            const errors = result.rfc_warnings.filter(w => w.type === 'error');
            const warnings = result.rfc_warnings.filter(w => w.type === 'warning');
            const infos = result.rfc_warnings.filter(w => w.type === 'info');
            
            if (errors.length > 0) {
                html += '<div class="warning-group error-group">';
                html += '<h5>🚨 Errors</h5>';
                errors.forEach(warning => {
                    html += this.formatWarning(warning);
                });
                html += '</div>';
            }
            
            if (warnings.length > 0) {
                html += '<div class="warning-group warning-group-warnings">';
                html += '<h5>⚠️ Warnings</h5>';
                warnings.forEach(warning => {
                    html += this.formatWarning(warning);
                });
                html += '</div>';
            }
            
            if (infos.length > 0) {
                html += '<div class="warning-group info-group">';
                html += '<h5>ℹ️ Information</h5>';
                infos.forEach(info => {
                    html += this.formatWarning(info);
                });
                html += '</div>';
            }
            
            html += '</div>';
        } else {
            html += '<div class="analysis-section">';
            html += '<div class="no-warnings">✅ No RFC compliance issues found</div>';
            html += '</div>';
        }
        
        // Signature Information
        if (result.signature) {
            html += '<div class="analysis-section">';
            html += '<h4>✍️ Signature Information</h4>';
            html += '<div class="signature-info">';
            
            if (result.signature.algorithm) {
                html += `<p><strong>Algorithm:</strong> ${result.signature.algorithm}</p>`;
            }
            
            if (result.signature.valid_signature !== undefined) {
                const validIcon = result.signature.valid_signature ? '✅' : '❌';
                html += `<p><strong>Signature Valid:</strong> ${validIcon} ${result.signature.valid_signature ? 'Yes' : 'No'}</p>`;
            }
            
            if (result.signature.details) {
                html += `<p class="signature-details">${result.signature.details}</p>`;
            }
            
            html += '</div>';
            html += '</div>';
        }
        
        html += '</div>';
        return html;
    }
    
    formatWarning(warning) {
        const icons = {
            'error': '🚨',
            'warning': '⚠️',
            'info': 'ℹ️'
        };
        
        const icon = icons[warning.type] || '📝';
        
        let html = `<div class="warning-item ${warning.type}">`;
        html += `<div class="warning-header">`;
        html += `<span class="warning-icon">${icon}</span>`;
        html += `<span class="warning-category">${warning.category}</span>`;
        html += `</div>`;
        html += `<div class="warning-message">${warning.message}</div>`;
        
        if (warning.field) {
            html += `<div class="warning-field">Field: ${warning.field}</div>`;
        }
        
        if (warning.value) {
            html += `<div class="warning-value">Value: <code>${warning.value}</code></div>`;
        }
        
        if (warning.suggestion) {
            html += `<div class="warning-suggestion">💡 Suggestion: ${warning.suggestion}</div>`;
        }
        
        html += `</div>`;
        return html;
    }
    
    isPrivateDomain(domain) {
        if (!domain) return false;
        
        const privateTlds = ['local', 'localhost', 'test', 'example', 'invalid', 'onion', 'corp', 'internal', 'intranet', 'lan', 'private'];
        const lowerDomain = domain.toLowerCase();
        
        // Check for private TLDs
        const parts = lowerDomain.split('.');
        const tld = parts[parts.length - 1];
        
        if (privateTlds.includes(tld)) {
            return true;
        }
        
        // Check for single-label domains
        if (parts.length === 1) {
            return true;
        }
        
        // Check for IP addresses
        const ipv4Pattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (ipv4Pattern.test(domain)) {
            return true;
        }
        
        return false;
    }

    showResultModal(title, content) {
        if (this.resultModal) {
            this.resultModal.querySelector('.modal__title').textContent = title;
            this.resultModal.querySelector('#modal-description').innerHTML = content;
            
            // Use proper modal display method
            this.resultModal.setAttribute('open', '');
            this.resultModal.style.display = 'flex';
            
            // Force centering with additional inline styles as backup
            this.resultModal.style.alignItems = 'center';
            this.resultModal.style.justifyContent = 'center';
            this.resultModal.style.position = 'fixed';
            this.resultModal.style.top = '0';
            this.resultModal.style.left = '0';
            this.resultModal.style.width = '100%';
            this.resultModal.style.height = '100%';
            this.resultModal.style.zIndex = '9999';
            
            // Ensure body doesn't scroll when modal is open
            document.body.style.overflow = 'hidden';
        }
    }

    showError(message) {
        this.showToast(message, 'error');
    }

    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast toast--${type}`;
        toast.textContent = message;
        
        const container = document.getElementById('toast-container');
        if (container) {
            container.appendChild(toast);
            
            setTimeout(() => {
                toast.remove();
            }, 5000);
        }
    }

    closeModal() {
        if (this.resultModal) {
            this.resultModal.removeAttribute('open');
            this.resultModal.style.display = 'none';
            
            // Restore body scrolling
            document.body.style.overflow = '';
        }
    }

    showLoading(show) {
        if (this.loadingOverlay) {
            this.loadingOverlay.setAttribute('aria-hidden', show ? 'false' : 'true');
        }
    }

    setupTheme() {
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
    }

    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
    }

    async copyToClipboard(text, button, successMessage) {
        try {
            await navigator.clipboard.writeText(text);
            
            // Visual feedback
            const originalText = button.textContent;
            button.textContent = '✅ ' + successMessage;
            button.classList.add('btn--success');
            
            setTimeout(() => {
                button.textContent = originalText;
                button.classList.remove('btn--success');
            }, 2000);
            
        } catch (err) {
            // Fallback for older browsers
            this.fallbackCopyTextToClipboard(text, button, successMessage);
        }
    }

    fallbackCopyTextToClipboard(text, button, successMessage) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.top = '0';
        textArea.style.left = '0';
        textArea.style.width = '2em';
        textArea.style.height = '2em';
        textArea.style.padding = '0';
        textArea.style.border = 'none';
        textArea.style.outline = 'none';
        textArea.style.boxShadow = 'none';
        textArea.style.background = 'transparent';
        
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            document.execCommand('copy');
            
            // Visual feedback
            const originalText = button.textContent;
            button.textContent = '✅ ' + successMessage;
            button.classList.add('btn--success');
            
            setTimeout(() => {
                button.textContent = originalText;
                button.classList.remove('btn--success');
            }, 2000);
            
        } catch (err) {
            this.showError('Failed to copy to clipboard');
        }
        
        document.body.removeChild(textArea);
    }

    downloadFile(content, filename, mimeType = 'text/plain') {
        const blob = new Blob([content], { type: mimeType });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }

    generateFilename(prefix, extension) {
        if (!this.lastGenerationData) {
            // Fallback to simple naming if generation data is not available
            const now = new Date();
            const dateStr = now.getFullYear().toString() + 
                           (now.getMonth() + 1).toString().padStart(2, '0') + 
                           now.getDate().toString().padStart(2, '0');
            const timeStr = now.getHours().toString().padStart(2, '0') + 
                           now.getMinutes().toString().padStart(2, '0');
            return `unknown_${prefix}_${dateStr}_${timeStr}.${extension}`;
        }

        // Extract form data
        const data = this.lastGenerationData;
        const cn = data.CN || 'unknown';
        const keyType = data.keyType || 'RSA';
        
        // Determine key size/curve
        let keySize;
        if (keyType === 'RSA') {
            keySize = data.keySize || '2048';
        } else if (keyType === 'ECDSA') {
            keySize = data.curve || 'P-256';
        } else {
            keySize = 'unknown';
        }
        
        // Generate date and time strings
        const now = new Date();
        const dateStr = now.getFullYear().toString() + 
                       (now.getMonth() + 1).toString().padStart(2, '0') + 
                       now.getDate().toString().padStart(2, '0');
        const timeStr = now.getHours().toString().padStart(2, '0') + 
                       now.getMinutes().toString().padStart(2, '0');
        
        // Clean CN for filename (remove invalid characters)
        const cleanCN = cn.replace(/[^a-zA-Z0-9.-]/g, '_');
        
        // Determine file type suffix based on prefix
        let fileTypeSuffix;
        if (prefix === 'CertificateRequest') {
            fileTypeSuffix = 'CSR';
        } else if (prefix === 'PrivateKey') {
            fileTypeSuffix = 'Private_KEY';
        } else {
            fileTypeSuffix = prefix;
        }
        
        // Format: CN_FILETYPE_KEYTYPE_KEYSIZE_DATE_TIME.EXTENSION
        return `${cleanCN}_${fileTypeSuffix}_${keyType}_${keySize}_${dateStr}_${timeStr}.${extension}`;
    }

    setupInputValidation() {
        // Field limits matching backend FIELD_LIMITS
        const fieldLimits = {
            'C': 2,     // Country code (ISO 3166)
            'ST': 128,  // State/Province
            'L': 128,   // Locality/City
            'O': 64,    // Organization
            'OU': 64,   // Organizational Unit
            'CN': 64    // Common Name
        };

        // Country field validation
        const countryField = document.getElementById('country');
        if (countryField) {
            countryField.addEventListener('input', (e) => {
                this.validateCountryField(e.target);
            });
            countryField.addEventListener('blur', (e) => {
                this.validateCountryField(e.target);
            });
        }

        // State/Province validation
        const stateField = document.getElementById('state');
        if (stateField) {
            stateField.addEventListener('input', (e) => {
                this.validateTextField(e.target, 'ST', fieldLimits.ST);
            });
        }

        // City/Locality validation
        const localityField = document.getElementById('locality');
        if (localityField) {
            localityField.addEventListener('input', (e) => {
                this.validateTextField(e.target, 'L', fieldLimits.L);
            });
        }

        // Organization validation
        const organizationField = document.getElementById('organization');
        if (organizationField) {
            organizationField.addEventListener('input', (e) => {
                this.validateTextField(e.target, 'O', fieldLimits.O);
            });
        }

        // Organizational Unit validation
        const ouField = document.getElementById('organizational-unit');
        if (ouField) {
            ouField.addEventListener('input', (e) => {
                this.validateTextField(e.target, 'OU', fieldLimits.OU);
            });
        }

        // Common Name validation (RFC compliant domain)
        const cnField = document.getElementById('common-name');
        if (cnField) {
            cnField.addEventListener('input', (e) => {
                this.validateCommonNameField(e.target);
            });
            cnField.addEventListener('blur', (e) => {
                this.validateCommonNameField(e.target);
            });
        }

        // Subject Alternative Names validation
        const sanField = document.getElementById('san');
        if (sanField) {
            sanField.addEventListener('input', (e) => {
                this.validateSANField(e.target);
            });
            sanField.addEventListener('blur', (e) => {
                this.validateSANField(e.target);
            });
        }
        
        // File upload functionality for verify panel
        this.setupFileUpload();
    }
    
    setupFileUpload() {
        // CSR file upload (verify panel)
        const csrFileInput = document.getElementById('csr-file-input');
        const csrUploadBtn = document.getElementById('csr-upload-btn');
        const csrTextarea = document.getElementById('verify-csr');
        const csrStatus = document.getElementById('csr-upload-status');
        
        if (csrUploadBtn && csrFileInput) {
            csrUploadBtn.addEventListener('click', () => {
                csrFileInput.click();
            });
            
            csrFileInput.addEventListener('change', (e) => {
                this.handleFileUpload(e.target, csrTextarea, csrStatus, 'CSR');
            });
        }
        
        // Private key file upload
        const keyFileInput = document.getElementById('key-file-input');
        const keyUploadBtn = document.getElementById('key-upload-btn');
        const keyTextarea = document.getElementById('verify-key');
        const keyStatus = document.getElementById('key-upload-status');
        
        if (keyUploadBtn && keyFileInput) {
            keyUploadBtn.addEventListener('click', () => {
                keyFileInput.click();
            });
            
            keyFileInput.addEventListener('change', (e) => {
                this.handleFileUpload(e.target, keyTextarea, keyStatus, 'Private Key');
            });
        }
        
        // CSR file upload (analyze panel)
        const analyzeCSRFileInput = document.getElementById('analyze-csr-file-input');
        const analyzeCSRUploadBtn = document.getElementById('analyze-csr-upload-btn');
        const analyzeCSRTextarea = document.getElementById('analyze-csr');
        const analyzeCSRStatus = document.getElementById('analyze-csr-upload-status');
        
        if (analyzeCSRUploadBtn && analyzeCSRFileInput) {
            analyzeCSRUploadBtn.addEventListener('click', () => {
                analyzeCSRFileInput.click();
            });
            
            analyzeCSRFileInput.addEventListener('change', (e) => {
                this.handleFileUpload(e.target, analyzeCSRTextarea, analyzeCSRStatus, 'CSR');
            });
        }
        
        // Certificate file upload (verify certificate panel)
        const certFileInput = document.getElementById('cert-file-input');
        const certUploadBtn = document.getElementById('cert-upload-btn');
        const certTextarea = document.getElementById('verify-cert-certificate');
        const certStatus = document.getElementById('cert-upload-status');
        
        if (certUploadBtn && certFileInput) {
            certUploadBtn.addEventListener('click', () => {
                certFileInput.click();
            });
            
            certFileInput.addEventListener('change', (e) => {
                this.handleFileUpload(e.target, certTextarea, certStatus, 'Certificate');
            });
        }
        
        // Private key file upload (verify certificate panel)
        const certKeyFileInput = document.getElementById('cert-key-file-input');
        const certKeyUploadBtn = document.getElementById('cert-key-upload-btn');
        const certKeyTextarea = document.getElementById('verify-cert-key');
        const certKeyStatus = document.getElementById('cert-key-upload-status');
        
        if (certKeyUploadBtn && certKeyFileInput) {
            certKeyUploadBtn.addEventListener('click', () => {
                certKeyFileInput.click();
            });
            
            certKeyFileInput.addEventListener('change', (e) => {
                this.handleFileUpload(e.target, certKeyTextarea, certKeyStatus, 'Private Key');
            });
        }
    }
    
    handleFileUpload(fileInput, textarea, statusElement, fileType) {
        const file = fileInput.files[0];
        
        if (!file) {
            return;
        }
        
        // Validate file size (max 1MB)
        const maxSize = 1024 * 1024; // 1MB
        if (file.size > maxSize) {
            this.showFileUploadStatus(statusElement, 'error', 'File too large (max 1MB)');
            fileInput.value = ''; // Clear the input
            return;
        }
        
        // Validate file type
        const allowedExtensions = ['.csr', '.pem', '.txt', '.key', '.crt', '.cer'];
        const fileName = file.name.toLowerCase();
        const hasValidExtension = allowedExtensions.some(ext => fileName.endsWith(ext));
        
        if (!hasValidExtension) {
            this.showFileUploadStatus(statusElement, 'error', 'Invalid file type');
            fileInput.value = ''; // Clear the input
            return;
        }
        
        // Show loading status
        this.showFileUploadStatus(statusElement, 'loading', 'Reading file...');
        
        // Read file content
        const reader = new FileReader();
        reader.onload = (e) => {
            const content = e.target.result;
            
            // Basic validation for CSR/Key/Certificate format
            if (fileType === 'CSR') {
                if (!content.includes('-----BEGIN CERTIFICATE REQUEST-----')) {
                    this.showFileUploadStatus(statusElement, 'error', 'Invalid CSR format');
                    fileInput.value = '';
                    return;
                }
            } else if (fileType === 'Certificate') {
                if (!content.includes('-----BEGIN CERTIFICATE-----')) {
                    this.showFileUploadStatus(statusElement, 'error', 'Invalid certificate format');
                    fileInput.value = '';
                    return;
                }
            } else if (fileType === 'Private Key') {
                const validKeyHeaders = [
                    '-----BEGIN PRIVATE KEY-----',           // PKCS#8 format
                    '-----BEGIN RSA PRIVATE KEY-----',       // Traditional RSA format
                    '-----BEGIN EC PRIVATE KEY-----',        // Traditional EC format
                    '-----BEGIN ENCRYPTED PRIVATE KEY-----'  // PKCS#8 encrypted format
                ];
                const hasValidHeader = validKeyHeaders.some(header => content.includes(header));
                if (!hasValidHeader) {
                    this.showFileUploadStatus(statusElement, 'error', 'Invalid private key format');
                    fileInput.value = '';
                    return;
                }
            }
            
            // Set textarea content
            textarea.value = content;
            
            // Show success status
            this.showFileUploadStatus(statusElement, 'success', `${fileType} loaded (${file.name})`);
            
            // Clear the file input to allow re-uploading the same file
            fileInput.value = '';
            
            // Trigger any validation on the textarea
            const event = new Event('input', { bubbles: true });
            textarea.dispatchEvent(event);
        };
        
        reader.onerror = () => {
            this.showFileUploadStatus(statusElement, 'error', 'Failed to read file');
            fileInput.value = '';
        };
        
        reader.readAsText(file);
    }
    
    showFileUploadStatus(statusElement, type, message) {
        if (!statusElement) return;
        
        // Clear existing classes
        statusElement.className = 'file-upload-status';
        
        // Add new class and show message
        statusElement.classList.add(type);
        statusElement.textContent = message;
        
        // Auto-hide success/error messages after 5 seconds
        if (type === 'success' || type === 'error') {
            setTimeout(() => {
                statusElement.className = 'file-upload-status';
                statusElement.textContent = '';
            }, 5000);
        }
    }

    validateCountryField(input) {
        const value = input.value.toUpperCase();
        input.value = value; // Auto-convert to uppercase
        const errorElement = document.getElementById('country-error');
        
        // Clear previous error state
        this.clearFieldError(input, errorElement);
        
        if (value && value.length > 0) {
            // Must be exactly 2 uppercase letters
            if (!/^[A-Z]{2}$/.test(value)) {
                this.setFieldError(input, errorElement, 'Country code must be exactly 2 uppercase letters (e.g., US, DE, FR)');
                return false;
            }
        }
        
        return true;
    }

    validateTextField(input, fieldName, maxLength) {
        const value = input.value;
        const errorElement = document.getElementById(`${input.id}-error`);
        
        // Clear previous error state
        this.clearFieldError(input, errorElement);
        
        if (value) {
            // Length validation
            if (value.length > maxLength) {
                this.setFieldError(input, errorElement, `${fieldName} field exceeds maximum length of ${maxLength} characters`);
                return false;
            }
            
            // Character validation - block dangerous characters
            if (/[<>"\\/:;|=+*?\[\]{}^~`!@#$%]+/.test(value)) {
                this.setFieldError(input, errorElement, `${fieldName} field contains invalid characters`);
                return false;
            }
        }
        
        return true;
    }

    validateCommonNameField(input) {
        const value = input.value.trim();
        const errorElement = document.getElementById('cn-error');
        
        // Clear previous error state
        this.clearFieldError(input, errorElement);
        
        if (!value) {
            this.setFieldError(input, errorElement, 'Common Name is required');
            return false;
        }
        
        // Check for spaces
        if (/\s/.test(value)) {
            this.setFieldError(input, errorElement, 'Common Name cannot contain spaces');
            return false;
        }
        
        // Length validation
        if (value.length > 64) {
            this.setFieldError(input, errorElement, 'Common Name exceeds maximum length of 64 characters');
            return false;
        }
        
        // RFC-compliant domain validation
        const domainValidation = this.validateDomainRFCCompliance(value);
        if (!domainValidation.valid) {
            this.setFieldError(input, errorElement, domainValidation.error);
            return false;
        }
        
        return true;
    }

    validateSANField(input) {
        const value = input.value.trim();
        const errorElement = document.getElementById('san-error');
        
        // Clear previous error state
        this.clearFieldError(input, errorElement);
        
        if (!value) {
            return true; // SAN is optional
        }
        
        // Check for leading/trailing commas or multiple consecutive commas
        if (value.startsWith(',') || value.endsWith(',')) {
            this.setFieldError(input, errorElement, 'Subject Alternative Names cannot start or end with a comma');
            return false;
        }
        
        if (value.includes(',,')) {
            this.setFieldError(input, errorElement, 'Subject Alternative Names cannot contain consecutive commas');
            return false;
        }
        
        // Split by comma and validate each domain
        const domains = value.split(',').map(d => d.trim());
        
        // Check for empty domains after splitting
        if (domains.some(d => d === '')) {
            this.setFieldError(input, errorElement, 'Subject Alternative Names cannot contain empty domain names');
            return false;
        }
        
        for (let domain of domains) {
            const domainValidation = this.validateDomainRFCCompliance(domain);
            if (!domainValidation.valid) {
                this.setFieldError(input, errorElement, `Invalid domain '${domain}': ${domainValidation.error}`);
                return false;
            }
        }
        
        return true;
    }

    validateDomainRFCCompliance(domain) {
        if (!domain || domain.length === 0) {
            return { valid: false, error: "Domain cannot be empty" };
        }
        
        // Check if private domains are allowed
        const allowPrivateCheckbox = document.getElementById('allow-private-domains');
        const allowPrivateDomains = allowPrivateCheckbox && allowPrivateCheckbox.checked;
        
        // RFC 1035: Maximum total domain length is 253 characters
        if (domain.length > 253) {
            return { valid: false, error: "Domain name exceeds maximum length of 253 characters (RFC 1035)" };
        }
        
        // Check for trailing/leading dots
        if (domain.endsWith('.')) {
            return { valid: false, error: "Domain name cannot end with a dot" };
        }
        if (domain.startsWith('.')) {
            return { valid: false, error: "Domain name cannot start with a dot" };
        }
        
        // Check for IP addresses (only allowed in private mode)
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        
        if (ipv4Regex.test(domain) || ipv6Regex.test(domain)) {
            if (!allowPrivateDomains) {
                return { valid: false, error: "IP addresses are only allowed for private CA use. Enable 'Allow private/corporate network domains' checkbox." };
            }
            return { valid: true, error: null }; // IP addresses are valid in private mode
        }
        
        // Handle wildcard validation (RFC 6125)
        if (domain.startsWith('*.')) {
            if ((domain.match(/\*/g) || []).length > 1) {
                return { valid: false, error: "Only one wildcard (*) is allowed per domain" };
            }
            if (domain.indexOf('*', 2) !== -1) {
                return { valid: false, error: "Wildcard (*) must be the leftmost label only" };
            }
            // Validate the rest of the domain (after *.)
            return this.validateDomainRFCCompliance(domain.substring(2));
        }
        
        // Check for bare wildcard
        if (domain === '*') {
            return { valid: false, error: "Bare wildcard (*) is not allowed" };
        }
        
        // Split into labels and validate each
        const labels = domain.split('.');
        
        // Single-label domains - allow in private mode
        if (labels.length === 1) {
            if (!allowPrivateDomains) {
                return { valid: false, error: "Single-label domains (like 'localhost' or 'server') are only allowed for private CA use. Enable 'Allow private/corporate network domains' checkbox." };
            }
            // Additional validation for single-label domains in private mode
            const label = labels[0];
            if (!/^[a-zA-Z0-9-]+$/.test(label)) {
                return { valid: false, error: `Single-label domain '${label}' contains invalid characters (only letters, digits, and hyphens allowed)` };
            }
            if (label.startsWith('-') || label.endsWith('-')) {
                return { valid: false, error: `Single-label domain '${label}' cannot start or end with a hyphen` };
            }
            return { valid: true, error: null };
        }
        
        // Check for reserved/special-use TLDs (RFC 6761)
        const lastLabel = labels[labels.length - 1].toLowerCase();
        const reservedTlds = ['local', 'localhost', 'test', 'example', 'invalid', 'onion'];
        const corporateTlds = ['corp', 'internal', 'intranet', 'lan', 'private'];
        
        if (reservedTlds.includes(lastLabel) || corporateTlds.includes(lastLabel)) {
            if (!allowPrivateDomains) {
                return { valid: false, error: `'.${lastLabel}' domains are reserved for special use and only allowed for private CA use. Enable 'Allow private/corporate network domains' checkbox.` };
            }
            // Continue with normal validation for private domains
        }
        
        for (let label of labels) {
            if (!label) { // Empty label (consecutive dots)
                return { valid: false, error: "Domain name cannot contain consecutive dots" };
            }
            
            // RFC 1035: Each label must be 1-63 characters
            if (label.length > 63) {
                return { valid: false, error: `Domain label '${label}' exceeds maximum length of 63 characters (RFC 1035)` };
            }
            
            // Labels cannot start or end with hyphens
            if (label.startsWith('-') || label.endsWith('-')) {
                return { valid: false, error: `Domain label '${label}' cannot start or end with a hyphen` };
            }
            
            // Labels must contain only letters, digits, and hyphens
            if (!/^[a-zA-Z0-9-]+$/.test(label)) {
                return { valid: false, error: `Domain label '${label}' contains invalid characters (only letters, digits, and hyphens allowed)` };
            }
        }
        
        return { valid: true, error: null };
    }

    setFieldError(input, errorElement, message) {
        input.classList.add('form__input--error');
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.style.display = 'block';
        }
    }

    clearFieldError(input, errorElement) {
        input.classList.remove('form__input--error');
        if (errorElement) {
            errorElement.style.display = 'none';
            errorElement.textContent = '';
        }
    }
    
    showPassphraseField() {
        const passphraseGroup = document.getElementById('passphrase-group');
        const passphraseInput = document.getElementById('verify-cert-passphrase');
        
        if (passphraseGroup) {
            passphraseGroup.style.display = 'block';
            passphraseGroup.setAttribute('aria-hidden', 'false');
        }
        
        if (passphraseInput) {
            passphraseInput.setAttribute('required', 'true');
            passphraseInput.focus(); // Focus on the passphrase field
        }
    }
    
    hidePassphraseField() {
        const passphraseGroup = document.getElementById('passphrase-group');
        const passphraseInput = document.getElementById('verify-cert-passphrase');
        
        if (passphraseGroup) {
            passphraseGroup.style.display = 'none';
            passphraseGroup.setAttribute('aria-hidden', 'true');
        }
        
        if (passphraseInput) {
            passphraseInput.removeAttribute('required');
            passphraseInput.value = ''; // Clear the passphrase field
        }
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    new SecureCertTools();
});

