/**
 * Password Strength Auditor - Frontend Application Logic
 * 
 * Implements debounced real-time analysis, strength meter updates,
 * password generation, visibility toggling, and audit logging.
 */

document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const passwordInput = document.getElementById('passwordInput');
    const togglePasswordBtn = document.getElementById('togglePasswordBtn');
    const eyeIcon = document.getElementById('eyeIcon');
    const eyeOffIcon = document.getElementById('eyeOffIcon');
    const copyPasswordBtn = document.getElementById('copyPasswordBtn');
    const generateBtn = document.getElementById('generateBtn');
    const logAuditBtn = document.getElementById('logAuditBtn');

    // Display Elements
    const scoreValue = document.getElementById('scoreValue');
    const levelBadge = document.getElementById('levelBadge');
    const progressBarFill = document.getElementById('progressBarFill');
    const progressBarContainer = document.getElementById('progressBarContainer');
    const charCountLabel = document.getElementById('charCountLabel');
    const auditStatusLabel = document.getElementById('auditStatusLabel');
    const hashDisplay = document.getElementById('hashDisplay');
    const alertsContainer = document.getElementById('alertsContainer');
    const suggestionsList = document.getElementById('suggestionsList');
    const toast = document.getElementById('toast');

    // Checklist Elements
    const reqLength8 = document.getElementById('req-length8');
    const reqLength12 = document.getElementById('req-length12');
    const reqUpper = document.getElementById('req-upper');
    const reqLower = document.getElementById('req-lower');
    const reqDigit = document.getElementById('req-digit');
    const reqSymbol = document.getElementById('req-symbol');

    let debounceTimer = null;
    let autoLogTimer = null;
    let lastEvaluatedPassword = '';

    // -----------------------------------------------------------------------
    // UI Helpers
    // -----------------------------------------------------------------------
    function showToast(message, duration = 3000) {
        if (!toast) return;
        toast.textContent = message;
        toast.classList.add('show');
        setTimeout(() => {
            toast.classList.remove('show');
        }, duration);
    }

    function updateChecklistItem(element, isValid) {
        if (!element) return;
        const icon = element.querySelector('.check-icon');
        if (isValid) {
            element.classList.add('valid');
            if (icon) icon.textContent = '✓';
        } else {
            element.classList.remove('valid');
            if (icon) icon.textContent = '✕';
        }
    }

    function setMeterLevel(score, level) {
        // Clamp score between 0 and 100
        const clampedScore = Math.max(0, Math.min(100, score));
        scoreValue.textContent = clampedScore;
        levelBadge.textContent = level;

        // Progress bar width matches score%
        progressBarFill.style.width = `${clampedScore}%`;
        progressBarContainer.setAttribute('aria-valuenow', clampedScore);

        // Reset classes
        levelBadge.className = 'level-badge';
        progressBarFill.className = 'progress-bar-fill';

        if (clampedScore <= 40) {
            levelBadge.classList.add('level-weak');
            progressBarFill.classList.add('fill-weak');
        } else if (clampedScore <= 70) {
            levelBadge.classList.add('level-fair');
            progressBarFill.classList.add('fill-fair');
        } else {
            levelBadge.classList.add('level-strong');
            progressBarFill.classList.add('fill-strong');
        }
    }

    function renderAlertsAndSuggestions(issues, suggestions, isCommon) {
        // Render Vulnerability Alerts
        alertsContainer.innerHTML = '';
        if (!issues || issues.length === 0) {
            alertsContainer.innerHTML = `
                <div class="alert-card alert-warning" style="background: rgba(16, 185, 129, 0.1); border-color: rgba(16, 185, 129, 0.3); color: #6ee7b7;">
                    <span class="alert-icon">✓</span>
                    <div><strong>Zero Vulnerabilities Detected:</strong> Password complies with standard security policies.</div>
                </div>
            `;
        } else {
            issues.forEach(issue => {
                const isCrit = isCommon && issue.toLowerCase().includes('common');
                const card = document.createElement('div');
                card.className = `alert-card ${isCrit ? 'alert-danger' : 'alert-warning'}`;
                card.innerHTML = `
                    <span class="alert-icon">${isCrit ? '🚨' : '⚠️'}</span>
                    <div>${issue}</div>
                `;
                alertsContainer.appendChild(card);
            });
        }

        // Render Suggestions
        suggestionsList.innerHTML = '';
        if (suggestions && suggestions.length > 0) {
            suggestions.forEach(sug => {
                const li = document.createElement('li');
                li.textContent = sug;
                suggestionsList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = 'Excellent configuration. No additional changes needed.';
            suggestionsList.appendChild(li);
        }
    }

    function resetUI() {
        setMeterLevel(0, 'WEAK');
        charCountLabel.textContent = 'Length: 0 characters';
        auditStatusLabel.textContent = 'Ready to analyze';
        hashDisplay.textContent = 'e3b0c442...b855 (empty)';

        updateChecklistItem(reqLength8, false);
        updateChecklistItem(reqLength12, false);
        updateChecklistItem(reqUpper, false);
        updateChecklistItem(reqLower, false);
        updateChecklistItem(reqDigit, false);
        updateChecklistItem(reqSymbol, false);

        alertsContainer.innerHTML = '<div class="alert-empty">Type a password above to begin security analysis.</div>';
        suggestionsList.innerHTML = '<li>Enter a secure password of at least 12 characters with mixed casing, digits, and symbols.</li>';
    }

    // -----------------------------------------------------------------------
    // Core Real-Time API Evaluation
    // -----------------------------------------------------------------------
    async function evaluatePassword(password, logAudit = false) {
        if (!password) {
            resetUI();
            return;
        }

        charCountLabel.textContent = `Length: ${password.length} characters`;
        auditStatusLabel.textContent = logAudit ? 'Logging audit...' : 'Analyzing live...';

        try {
            const response = await fetch('/check', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    password: password,
                    log_audit: logAudit
                })
            });

            if (!response.ok) {
                const err = await response.json();
                auditStatusLabel.textContent = 'Validation error';
                console.warn('Evaluation rejected:', err);
                return;
            }

            const data = await response.json();

            // Update Score and Meter
            setMeterLevel(data.score, data.level);

            // Update Checklist
            updateChecklistItem(reqLength8, data.length >= 8);
            updateChecklistItem(reqLength12, data.length >= 12);
            updateChecklistItem(reqUpper, data.has_upper);
            updateChecklistItem(reqLower, data.has_lower);
            updateChecklistItem(reqDigit, data.has_digit);
            updateChecklistItem(reqSymbol, data.has_symbol);

            // Update SHA-256 preview
            if (data.truncated_hash) {
                hashDisplay.textContent = `${data.truncated_hash}`;
            }

            // Update Alerts and Suggestions
            renderAlertsAndSuggestions(data.issues, data.suggestions, data.is_common);

            // Update status text
            if (data.logged) {
                auditStatusLabel.textContent = '✓ Logged to PostgreSQL';
                showToast('Password audit successfully recorded to database.');
            } else {
                auditStatusLabel.textContent = 'Live preview active';
            }

            lastEvaluatedPassword = password;

        } catch (error) {
            console.error('Failed to communicate with auditor backend:', error);
            auditStatusLabel.textContent = 'Backend offline';
        }
    }

    // -----------------------------------------------------------------------
    // Event Listeners
    // -----------------------------------------------------------------------
    
    // Real-time typing event with 300ms debounce
    passwordInput.addEventListener('input', (e) => {
        const password = e.target.value;

        // Clear existing debounce timer
        clearTimeout(debounceTimer);
        clearTimeout(autoLogTimer);

        if (!password) {
            resetUI();
            return;
        }

        // Live preview check without flooding the database
        debounceTimer = setTimeout(() => {
            evaluatePassword(password, false);
        }, 300);

        // Auto-save audit after user stops typing for 1.5 seconds
        autoLogTimer = setTimeout(() => {
            if (password && password.length >= 3) {
                evaluatePassword(password, true);
            }
        }, 1500);
    });

    // Explicit manual audit button
    logAuditBtn.addEventListener('click', () => {
        const password = passwordInput.value;
        if (!password) {
            showToast('Please enter a password before saving an audit.');
            passwordInput.focus();
            return;
        }
        evaluatePassword(password, true);
    });

    // Toggle password visibility (show/hide)
    togglePasswordBtn.addEventListener('click', () => {
        const isPassword = passwordInput.getAttribute('type') === 'password';
        if (isPassword) {
            passwordInput.setAttribute('type', 'text');
            eyeIcon.classList.add('hidden');
            eyeOffIcon.classList.remove('hidden');
            togglePasswordBtn.setAttribute('aria-label', 'Hide password');
        } else {
            passwordInput.setAttribute('type', 'password');
            eyeIcon.classList.remove('hidden');
            eyeOffIcon.classList.add('hidden');
            togglePasswordBtn.setAttribute('aria-label', 'Show password');
        }
    });

    // Copy to clipboard
    copyPasswordBtn.addEventListener('click', async () => {
        const password = passwordInput.value;
        if (!password) {
            showToast('No password entered to copy.');
            return;
        }

        try {
            await navigator.clipboard.writeText(password);
            showToast('Password copied to clipboard.');
        } catch (err) {
            // Fallback for environments where clipboard API is restricted
            passwordInput.select();
            document.execCommand('copy');
            showToast('Password copied to clipboard.');
        }
    });

    // Generate Strong Password
    generateBtn.addEventListener('click', async () => {
        try {
            const response = await fetch('/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            if (response.ok) {
                const data = await response.json();
                passwordInput.value = data.generated_password;
                // Reveal generated password so the user can see what was generated
                passwordInput.setAttribute('type', 'text');
                eyeIcon.classList.add('hidden');
                eyeOffIcon.classList.remove('hidden');
                // Run immediate evaluation and save
                evaluatePassword(data.generated_password, true);
                showToast('Strong random password generated and evaluated.');
            }
        } catch (err) {
            console.error('Password generation failed:', err);
            showToast('Could not generate password.');
        }
    });

    // Initial state
    resetUI();
});
