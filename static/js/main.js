function toggleKeyOptions() {
    const keyType = $('input[name="keyType"]:checked').val();
    if (keyType === 'RSA') {
        $('#rsa-options').show();
        $('#ecdsa-options').hide();
    } else if (keyType === 'ECDSA') {
        $('#rsa-options').hide();
        $('#ecdsa-options').show();
    }
}

function showGenerateMode() {
    $('#generate-mode').show();
    $('#verify-mode').hide();
    $('#analyze-mode').hide();
    $('#generate-mode-btn').removeClass('btn-secondary').addClass('btn-primary');
    $('#verify-mode-btn').removeClass('btn-primary').addClass('btn-secondary');
    $('#analyze-mode-btn').removeClass('btn-primary').addClass('btn-secondary');
    $('#verification-result').hide();
    $('#analysis-result').hide();
}

function showVerifyMode() {
    $('#generate-mode').hide();
    $('#verify-mode').show();
    $('#analyze-mode').hide();
    $('#verify-mode-btn').removeClass('btn-secondary').addClass('btn-primary');
    $('#generate-mode-btn').removeClass('btn-primary').addClass('btn-secondary');
    $('#analyze-mode-btn').removeClass('btn-primary').addClass('btn-secondary');
    $('#verification-result').hide();
    $('#analysis-result').hide();
}

function showAnalyzeMode() {
    $('#generate-mode').hide();
    $('#verify-mode').hide();
    $('#analyze-mode').show();
    $('#analyze-mode-btn').removeClass('btn-secondary').addClass('btn-primary');
    $('#generate-mode-btn').removeClass('btn-primary').addClass('btn-secondary');
    $('#verify-mode-btn').removeClass('btn-primary').addClass('btn-secondary');
    $('#verification-result').hide();
    $('#analysis-result').hide();
}

function showVerificationResult(isMatch, message, details) {
    const resultDiv = $('#verification-result');
    const modalCard = resultDiv.find('.result-modal-card');
    const title = $('#result-title');
    const messageDiv = $('#result-message');
    
    if (isMatch) {
        modalCard.css('background', '#28a745'); // Green for success
        title.text('✅ Keys Match!');
    } else {
        modalCard.css('background', '#dc3545'); // Red for error
        title.text('❌ Keys Do Not Match');
    }
    
    let fullMessage = message;
    if (details) {
        fullMessage += '\n\nDetails:\n' + details;
    }
    
    messageDiv.text(fullMessage);
    resultDiv.show();
    
    // Auto-hide after 10 seconds for success, keep visible for errors
    if (isMatch) {
        setTimeout(() => {
            resultDiv.fadeOut();
        }, 10000);
    }
}

$(function() {
    // Initialize in generate mode
    showGenerateMode();
    
    $(".close").on("click", function() {
        $(this).closest(".modal").removeClass("active");
    });
    
    // Handle CSR generation form (only for generate mode)
    $("#generate-mode form").submit(function(e) {
        e.preventDefault();
        $.post("/generate", $(this).serialize(), function(response) {
            $("#csr").val(response.csr);
            $("#private-key").val(response.private_key);
            $("#csr-modal").addClass("active");
        }).fail(function(xhr) {
            const error = xhr.responseJSON?.error || "An error occurred while generating the CSR.";
            alert(error);
        });
    });
    
    // Handle verification form
    $("#verify-form").submit(function(e) {
        e.preventDefault();
        
        const formData = {
            csr: $("#csr-input").val().trim(),
            privateKey: $("#private-key-input").val().trim()
        };
        
        if (!formData.csr || !formData.privateKey) {
            showVerificationResult(false, 'Please provide both CSR and Private Key.', null);
            return;
        }
        
        $.ajax({
            url: '/verify',
            method: 'POST',
            data: formData,
            success: function(response) {
                showVerificationResult(response.match, response.message, response.details);
            },
            error: function(xhr) {
                let errorMessage = 'An error occurred during verification.';
                if (xhr.responseJSON && xhr.responseJSON.error) {
                    errorMessage = xhr.responseJSON.error;
                }
                showVerificationResult(false, errorMessage, null);
            }
        });
    });
    
    // Handle analysis form
    $("#analyze-form").submit(function(e) {
        e.preventDefault();
        
        const csrData = $("#analyze-csr-input").val().trim();
        
        if (!csrData) {
            showAnalysisResult({
                valid: false,
                error: 'Please provide a CSR for analysis.',
                error_type: 'ValidationError'
            });
            return;
        }
        
        // Show loading state
        const submitBtn = $(this).find('button[type="submit"]');
        const originalText = submitBtn.html();
        submitBtn.html('🔄 Analyzing...');
        submitBtn.prop('disabled', true);
        
        $.ajax({
            url: '/analyze',
            method: 'POST',
            data: { csr: csrData },
            success: function(response) {
                showAnalysisResult(response);
            },
            error: function(xhr) {
                let errorResponse = {
                    valid: false,
                    error: 'An error occurred during CSR analysis.',
                    error_type: 'NetworkError'
                };
                if (xhr.responseJSON) {
                    errorResponse = xhr.responseJSON;
                }
                showAnalysisResult(errorResponse);
            },
            complete: function() {
                // Restore button state
                submitBtn.html(originalText);
                submitBtn.prop('disabled', false);
            }
        });
    });
    
    $("#csr").on("click focus", function() { this.select() } );
    $("#private-key").on("click focus", function() { this.select() } );
});

// Copy to clipboard function with visual feedback
function copyToClipboard(elementId, buttonElement) {
    const element = document.querySelector(elementId);
    if (element) {
        element.select();
        element.setSelectionRange(0, 99999); // For mobile devices
        
        try {
            document.execCommand('copy');
            
            // Visual feedback on button
            const originalText = buttonElement.innerHTML;
            buttonElement.innerHTML = '<i class="icon icon-check"></i> Copied!';
            buttonElement.classList.add('btn-success');
            buttonElement.classList.remove('btn-primary', 'btn-error');
            
            setTimeout(() => {
                buttonElement.innerHTML = originalText;
                buttonElement.classList.remove('btn-success');
                if (elementId === '#csr') {
                    buttonElement.classList.add('btn-primary');
                } else {
                    buttonElement.classList.add('btn-error');
                }
            }, 2000);
            
        } catch (err) {
            console.error('Failed to copy: ', err);
            alert('Copy failed. Please select and copy manually.');
        }
    }
}

// Download CSR function
function downloadCSR() {
    const csrContent = document.getElementById('csr').value;
    if (csrContent) {
        downloadFile(csrContent, 'certificate_request.csr', 'application/x-x509-ca-cert');
    }
}

// Download Private Key function
function downloadPrivateKey() {
    const keyContent = document.getElementById('private-key').value;
    if (keyContent) {
        downloadFile(keyContent, 'private_key.key', 'application/x-pem-file');
    }
}

// Generic download function
function downloadFile(content, filename, mimeType) {
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

// RFC-compliant domain validation function
function validateDomainRFCCompliance(domain) {
    if (!domain || domain.length === 0) {
        return { valid: false, error: "Domain cannot be empty" };
    }
    
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
    
    // Handle wildcard validation (RFC 6125)
    if (domain.startsWith('*.')) {
        if ((domain.match(/\*/g) || []).length > 1) {
            return { valid: false, error: "Only one wildcard (*) is allowed per domain" };
        }
        if (domain.indexOf('*', 2) !== -1) {
            return { valid: false, error: "Wildcard (*) must be the leftmost label only" };
        }
        // Validate the rest of the domain (after *.)
        return validateDomainRFCCompliance(domain.substring(2));
    }
    
    // Check for bare wildcard
    if (domain === '*') {
        return { valid: false, error: "Bare wildcard (*) is not allowed" };
    }
    
    // Split into labels and validate each
    const labels = domain.split('.');
    
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

// Validate CN field using RFC-compliant validation
function validateCNField(input) {
    const value = input.value;
    const errorElement = document.getElementById('cn-error');
    
    if (!value) {
        // Empty is handled by required attribute
        input.classList.remove('is-error');
        errorElement.style.display = 'none';
        input.setCustomValidity('');
        return;
    }
    
    // Check for spaces
    if (/\s/.test(value)) {
        input.classList.add('is-error');
        errorElement.style.display = 'block';
        input.setCustomValidity('Common Name cannot contain spaces');
        return;
    }
    
    // RFC-compliant domain validation
    const validation = validateDomainRFCCompliance(value);
    if (!validation.valid) {
        input.classList.add('is-error');
        errorElement.style.display = 'block';
        input.setCustomValidity(validation.error);
    } else {
        input.classList.remove('is-error');
        errorElement.style.display = 'none';
        input.setCustomValidity('');
    }
}

// Validate Country field (2 uppercase letters)
function validateCountryField(input) {
    let value = input.value.toUpperCase();
    input.value = value; // Auto-convert to uppercase
    const errorElement = document.getElementById('country-error');
    
    const validPattern = /^[A-Z]{0,2}$/.test(value);
    
    if (value && (!validPattern || value.length !== 2)) {
        input.classList.add('is-error');
        errorElement.style.display = 'block';
        input.setCustomValidity('Country code must be exactly 2 uppercase letters');
    } else {
        input.classList.remove('is-error');
        errorElement.style.display = 'none';
        input.setCustomValidity('');
    }
}

// Generic text field validation
function validateTextField(input, errorId) {
    const value = input.value;
    const errorElement = document.getElementById(errorId);
    
    // Allow letters, numbers, spaces, and common punctuation
    const validPattern = /^[a-zA-Z0-9\s\-\.,'&()]*$/.test(value);
    
    if (value && !validPattern) {
        input.classList.add('is-error');
        errorElement.style.display = 'block';
        input.setCustomValidity('Invalid characters detected');
    } else {
        input.classList.remove('is-error');
        errorElement.style.display = 'none';
        input.setCustomValidity('');
    }
}

// Validate Subject Alternative Names field using RFC-compliant validation
function validateSANField(input) {
    const value = input.value;
    const errorElement = document.getElementById('san-error');
    
    if (!value) {
        // Empty is valid
        input.classList.remove('is-error');
        errorElement.style.display = 'none';
        input.setCustomValidity('');
        return;
    }
    
    // Split by comma and validate each domain
    const domains = value.split(',').map(d => d.trim());
    let firstError = null;
    
    for (let domain of domains) {
        if (domain === '') continue; // Skip empty domains
        
        // Use RFC-compliant domain validation
        const validation = validateDomainRFCCompliance(domain);
        if (!validation.valid) {
            firstError = `Invalid domain '${domain}': ${validation.error}`;
            break;
        }
    }
    
    if (firstError) {
        input.classList.add('is-error');
        errorElement.style.display = 'block';
        input.setCustomValidity(firstError);
    } else {
        input.classList.remove('is-error');
        errorElement.style.display = 'none';
        input.setCustomValidity('');
    }
}

// Display CSR analysis results
function showAnalysisResult(result) {
    const resultDiv = $('#analysis-result');
    const modalCard = resultDiv.find('.result-modal-card');
    const titleElement = $('#analysis-title');
    const contentElement = $('#analysis-content');
    
    if (!result.valid) {
        // Handle invalid CSR - use error styling
        modalCard.css('background', '#dc3545'); // Red for error
        titleElement.html('❌ CSR Analysis Failed');
        let errorHtml = `
            <div style="color: white; background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; margin-bottom: 15px;">
                <strong>Error:</strong> ${result.error || 'Unknown error occurred'}
            </div>
        `;
        
        if (result.suggestions && result.suggestions.length > 0) {
            errorHtml += `
                <div style="color: white; background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px;">
                    <h6 style="color: white; margin-bottom: 10px;">Suggestions:</h6>
                    <ul style="color: white; margin: 0; padding-left: 20px;">
                        ${result.suggestions.map(suggestion => `<li>${suggestion}</li>`).join('')}
                    </ul>
                </div>
            `;
        }
        
        contentElement.html(errorHtml);
        resultDiv.show();
        return;
    } else {
        // Handle valid CSR - use blue styling
        modalCard.css('background', '#007bff'); // Blue for success/info
        titleElement.html('📋 CSR Analysis Results');
    }
    
    // Handle valid CSR - use form layout similar to generation
    titleElement.html('CSR Analysis Results');
    
    let contentHtml = `
        <div class="centered column col-10 bg-grey">
            <form class="analysis-form-display">
    `;
    
    // Subject fields - improved layout with field labels and values
    if (result.subject) {
        const subjectFields = {
            'C': 'Country',
            'ST': 'State/Province', 
            'L': 'Locality/City',
            'O': 'Organization',
            'OU': 'Organizational Unit',
            'CN': 'Common Name'
        };
        
        Object.entries(subjectFields).forEach(([fieldKey, fieldLabel]) => {
            const component = result.subject.components.find(c => c.field === fieldKey);
            const value = component ? component.value : '';
            const hasValue = value && value.trim() !== '';
            
            contentHtml += `
                <div class="form-group">
                    <label class="form-label">${fieldLabel} (${fieldKey})</label>
                    <div class="input-group">
                        <span class="input-group-addon">${hasValue ? '✓' : ''}</span>
                        <input class="form-input input-lg" type="text" value="${value || 'Not specified'}" readonly style="${hasValue ? '' : 'color: #6c757d; font-style: italic;'}" />
                    </div>
                </div>
            `;
        });
    }
    
    // Subject Alternative Names
    const sanExtension = result.extensions?.extensions?.find(ext => ext.short_name === 'subjectAltName');
    if (sanExtension && Array.isArray(sanExtension.value)) {
        const sanList = sanExtension.value.map(san => san.replace('DNS:', '')).join(', ');
        contentHtml += `
            <div class="form-group">
                <label class="form-label">Subject Alternative Names (SAN)</label>
                <div class="input-group">
                    <span class="input-group-addon">✓</span>
                    <input class="form-input input-lg" type="text" value="${sanList}" readonly />
                </div>
            </div>
        `;
    } else {
        contentHtml += `
            <div class="form-group">
                <label class="form-label">Subject Alternative Names (SAN)</label>
                <div class="input-group">
                    <span class="input-group-addon"></span>
                    <input class="form-input input-lg" type="text" value="Not specified" readonly style="color: #6c757d; font-style: italic;" />
                </div>
            </div>
        `;
    }
    
    // Key Type and Size
    if (result.public_key) {
        const key = result.public_key;
        
        contentHtml += `
            <div class="form-group">
                <label class="form-label">Key Type</label>
                <div class="input-group">
                    <span class="input-group-addon">✓</span>
                    <input class="form-input input-lg" type="text" value="${key.type}" readonly />
                </div>
            </div>
        `;
        
        if (key.type === 'RSA') {
            contentHtml += `
                <div class="form-group">
                    <label class="form-label">RSA Key Size</label>
                    <div class="input-group">
                        <span class="input-group-addon">✓</span>
                        <input class="form-input input-lg" type="text" value="${key.size} bits" readonly />
                    </div>
                </div>
            `;
        } else if (key.type === 'ECDSA' && key.curve) {
            contentHtml += `
                <div class="form-group">
                    <label class="form-label">ECDSA Curve</label>
                    <div class="input-group">
                        <span class="input-group-addon">✓</span>
                        <input class="form-input input-lg" type="text" value="${key.curve} (${key.size}-bit)" readonly />
                    </div>
                </div>
            `;
        }
        
        // Security Status
        contentHtml += `
            <div class="form-group">
                <label class="form-label">Security Level</label>
                <div class="input-group">
                    <span class="input-group-addon">${key.is_secure ? '✓' : '⚠'}</span>
                    <input class="form-input input-lg ${key.is_secure ? '' : 'text-error'}" type="text" value="${key.security_level}" readonly />
                </div>
            </div>
        `;
    }
    
    contentHtml += `
            </form>
        </div>
    `;
    
    // RFC Warnings (if any)
    if (result.rfc_warnings && result.rfc_warnings.length > 0) {
        const errors = result.rfc_warnings.filter(w => w.type === 'error');
        const warnings = result.rfc_warnings.filter(w => w.type === 'warning');
        
        if (errors.length > 0 || warnings.length > 0) {
            contentHtml += `
                <div class="mt-2">
                    <div class="toast ${errors.length > 0 ? 'toast-error' : 'toast-warning'}">
                        <div class="toast-body">
                            <strong>${errors.length > 0 ? 'RFC Violations Found' : 'RFC Warnings'}:</strong><br>
                            ${[...errors, ...warnings].map(issue => `• ${issue.message}`).join('<br>')}
                        </div>
                    </div>
                </div>
            `;
        }
    } else {
        contentHtml += `
            <div class="mt-2">
                <div class="toast toast-success">
                    <div class="toast-body">
                        <strong>RFC Compliant:</strong> This CSR meets all RFC standards.
                    </div>
                </div>
            </div>
        `;
    }
    
    contentElement.html(contentHtml);
    resultDiv.show();
    
    // Scroll to results
    resultDiv[0].scrollIntoView({ behavior: 'smooth', block: 'start' });
}
