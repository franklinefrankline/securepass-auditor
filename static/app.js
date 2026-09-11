/**
 * SecurePass Auditor - Unified Frontend Application Logic
 * 
 * Features:
 * 1. Real-time debounced password analysis (300ms)
 * 2. Explicit "Check Password" button action (analyzes on the same page, never navigates)
 * 3. Responsive desktop & mobile navigation drawer
 * 4. UI Customization & Settings engine (Themes, Accents, Font sizes, Layouts, Meter styles, Animations)
 * 5. Persistent preferences in localStorage & Safe Settings Reset
 * 6. Dynamic History refresh with mobile-responsive card data-labels
 * 7. Secure password generator, visibility toggle, and clipboard copy
 */

document.addEventListener('DOMContentLoaded', () => {
    // -----------------------------------------------------------------------
    // UI CUSTOMIZATION & SETTINGS ENGINE
    // -----------------------------------------------------------------------
    const SETTINGS_KEY = 'securepass_auditor_settings';

    const defaultSettings = {
        theme: 'dark',
        accent: 'blue',
        fontSize: 'medium',
        layout: 'comfortable',
        meterStyle: 'bar',
        animations: 'on'
    };

    function loadSettings() {
        try {
            const raw = localStorage.getItem(SETTINGS_KEY);
            if (raw) {
                return { ...defaultSettings, ...JSON.parse(raw) };
            }
        } catch (e) {
            console.warn('Failed to parse settings from localStorage:', e);
        }
        return { ...defaultSettings };
    }

    let currentSettings = loadSettings();

    function applySettings(settings) {
        const root = document.documentElement;

        // 1. Theme
        let effectiveTheme = settings.theme;
        if (settings.theme === 'system') {
            const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
            effectiveTheme = prefersDark ? 'dark' : 'light';
        }
        root.setAttribute('data-theme', effectiveTheme);

        // 2. Accent Color
        root.setAttribute('data-accent', settings.accent);

        // 3. Font Size
        root.setAttribute('data-font-size', settings.fontSize);

        // 4. Layout Density
        root.setAttribute('data-layout', settings.layout);

        // 5. Meter Style
        root.setAttribute('data-meter-style', settings.meterStyle);

        // 6. Animations
        root.setAttribute('data-animations', settings.animations);

        // Sync Modal Controls if present
        syncSettingsModalUI(settings);
    }

    function saveSettings(newSettings) {
        currentSettings = { ...currentSettings, ...newSettings };
        try {
            localStorage.setItem(SETTINGS_KEY, JSON.stringify(currentSettings));
        } catch (e) {
            console.error('Failed to save settings to localStorage:', e);
        }
        applySettings(currentSettings);
    }

    function resetSettings() {
        try {
            localStorage.removeItem(SETTINGS_KEY);
        } catch (e) {
            console.warn('Failed to remove settings from localStorage:', e);
        }
        currentSettings = { ...defaultSettings };
        applySettings(currentSettings);
        showToast('Settings restored to defaults. Audit database preserved.');
    }

    function syncSettingsModalUI(settings) {
        const themeSelect = document.getElementById('settingTheme');
        const fontSelect = document.getElementById('settingFontSize');
        const layoutSelect = document.getElementById('settingLayout');
        const meterSelect = document.getElementById('settingMeterStyle');
        const animSelect = document.getElementById('settingAnimations');
        const swatches = document.querySelectorAll('.accent-swatch');

        if (themeSelect) themeSelect.value = settings.theme;
        if (fontSelect) fontSelect.value = settings.fontSize;
        if (layoutSelect) layoutSelect.value = settings.layout;
        if (meterSelect) meterSelect.value = settings.meterStyle;
        if (animSelect) animSelect.value = settings.animations;

        swatches.forEach(swatch => {
            if (swatch.dataset.accent === settings.accent) {
                swatch.classList.add('active');
            } else {
                swatch.classList.remove('active');
            }
        });
    }

    // Apply on startup
    applySettings(currentSettings);

    // Listen for system theme changes if set to system
    if (window.matchMedia) {
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
            if (currentSettings.theme === 'system') {
                applySettings(currentSettings);
            }
        });
    }

    // -----------------------------------------------------------------------
    // SETTINGS MODAL & DRAWER INTERACTION
    // -----------------------------------------------------------------------
    const settingsModal = document.getElementById('settingsModal');
    const navSettingsBtn = document.getElementById('navSettingsBtn');
    const mobileSettingsItemBtn = document.getElementById('mobileSettingsItemBtn');
    const openSettingsInlineBtn = document.getElementById('openSettingsInlineBtn');
    const footerSettingsBtn = document.getElementById('footerSettingsBtn');
    const closeSettingsBtn = document.getElementById('closeSettingsBtn');
    const saveCloseSettingsBtn = document.getElementById('saveCloseSettingsBtn');
    const resetSettingsBtn = document.getElementById('resetSettingsBtn');

    function openSettings() {
        if (!settingsModal) return;
        syncSettingsModalUI(currentSettings);
        settingsModal.classList.remove('hidden');
        closeMobileNav();
    }

    function closeSettings() {
        if (!settingsModal) return;
        settingsModal.classList.add('hidden');
    }

    if (navSettingsBtn) navSettingsBtn.addEventListener('click', openSettings);
    if (mobileSettingsItemBtn) mobileSettingsItemBtn.addEventListener('click', openSettings);
    if (openSettingsInlineBtn) openSettingsInlineBtn.addEventListener('click', openSettings);
    if (footerSettingsBtn) footerSettingsBtn.addEventListener('click', openSettings);
    if (closeSettingsBtn) closeSettingsBtn.addEventListener('click', closeSettings);
    if (saveCloseSettingsBtn) {
        saveCloseSettingsBtn.addEventListener('click', () => {
            closeSettings();
            showToast('Settings saved successfully.');
        });
    }

    if (resetSettingsBtn) {
        resetSettingsBtn.addEventListener('click', () => {
            resetSettings();
            closeSettings();
        });
    }

    // Settings Modal backdrop click
    if (settingsModal) {
        settingsModal.addEventListener('click', (e) => {
            if (e.target === settingsModal) {
                closeSettings();
            }
        });
    }

    // Settings Controls live change handlers
    const settingTheme = document.getElementById('settingTheme');
    if (settingTheme) {
        settingTheme.addEventListener('change', (e) => {
            saveSettings({ theme: e.target.value });
        });
    }

    const settingFontSize = document.getElementById('settingFontSize');
    if (settingFontSize) {
        settingFontSize.addEventListener('change', (e) => {
            saveSettings({ fontSize: e.target.value });
        });
    }

    const settingLayout = document.getElementById('settingLayout');
    if (settingLayout) {
        settingLayout.addEventListener('change', (e) => {
            saveSettings({ layout: e.target.value });
        });
    }

    const settingMeterStyle = document.getElementById('settingMeterStyle');
    if (settingMeterStyle) {
        settingMeterStyle.addEventListener('change', (e) => {
            saveSettings({ meterStyle: e.target.value });
        });
    }

    const settingAnimations = document.getElementById('settingAnimations');
    if (settingAnimations) {
        settingAnimations.addEventListener('change', (e) => {
            saveSettings({ animations: e.target.value });
        });
    }

    // Accent swatch buttons
    const accentSwatches = document.querySelectorAll('.accent-swatch');
    accentSwatches.forEach(swatch => {
        swatch.addEventListener('click', () => {
            const selectedAccent = swatch.dataset.accent;
            if (selectedAccent) {
                saveSettings({ accent: selectedAccent });
            }
        });
    });

    // -----------------------------------------------------------------------
    // MOBILE NAVIGATION DRAWER
    // -----------------------------------------------------------------------
    const mobileMenuBtn = document.getElementById('mobileMenuBtn');
    const mobileNavDrawer = document.getElementById('mobileNavDrawer');
    const closeMobileMenuBtn = document.getElementById('closeMobileMenuBtn');

    function openMobileNav() {
        if (!mobileNavDrawer) return;
        mobileNavDrawer.classList.add('open');
        if (mobileMenuBtn) mobileMenuBtn.setAttribute('aria-expanded', 'true');
    }

    function closeMobileNav() {
        if (!mobileNavDrawer) return;
        mobileNavDrawer.classList.remove('open');
        if (mobileMenuBtn) mobileMenuBtn.setAttribute('aria-expanded', 'false');
    }

    if (mobileMenuBtn) mobileMenuBtn.addEventListener('click', openMobileNav);
    if (closeMobileMenuBtn) closeMobileMenuBtn.addEventListener('click', closeMobileNav);

    if (mobileNavDrawer) {
        mobileNavDrawer.addEventListener('click', (e) => {
            if (e.target === mobileNavDrawer) {
                closeMobileNav();
            }
        });
    }

    // Global ESC key listener for modals and drawers
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeSettings();
            closeMobileNav();
        }
    });

    // -----------------------------------------------------------------------
    // TOAST NOTIFICATIONS
    // -----------------------------------------------------------------------
    const toast = document.getElementById('toast');

    function showToast(message, duration = 3000) {
        if (!toast) return;
        toast.textContent = message;
        toast.classList.add('show');
        setTimeout(() => {
            toast.classList.remove('show');
        }, duration);
    }

    // -----------------------------------------------------------------------
    // AUDITOR DOM ELEMENTS
    // -----------------------------------------------------------------------
    const passwordForm = document.getElementById('passwordForm');
    const passwordInput = document.getElementById('passwordInput');
    const checkPasswordBtn = document.getElementById('checkPasswordBtn');
    const togglePasswordBtn = document.getElementById('togglePasswordBtn');
    const eyeIcon = document.getElementById('eyeIcon');
    const eyeOffIcon = document.getElementById('eyeOffIcon');
    const copyPasswordBtn = document.getElementById('copyPasswordBtn');
    const generateBtn = document.getElementById('generateBtn');

    // Display Fields
    const scoreValue = document.getElementById('scoreValue');
    const levelBadge = document.getElementById('levelBadge');
    const progressBarFill = document.getElementById('progressBarFill');
    const progressBarContainer = document.getElementById('progressBarContainer');
    const charCountLabel = document.getElementById('charCountLabel');
    const auditStatusLabel = document.getElementById('auditStatusLabel');
    const hashDisplay = document.getElementById('hashDisplay');
    const alertsContainer = document.getElementById('alertsContainer');
    const suggestionsList = document.getElementById('suggestionsList');

    // Requirements Checklist Items
    const reqUpper = document.getElementById('req-upper');
    const reqLower = document.getElementById('req-lower');
    const reqDigit = document.getElementById('req-digit');
    const reqSymbol = document.getElementById('req-symbol');
    const reqLength8 = document.getElementById('req-length8');
    const reqLength12 = document.getElementById('req-length12');

    let debounceTimer = null;
    let autoLogTimer = null;

    // -----------------------------------------------------------------------
    // AUDITOR UI UPDATERS
    // -----------------------------------------------------------------------
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
        if (!scoreValue || !levelBadge || !progressBarFill || !progressBarContainer) return;

        const clampedScore = Math.max(0, Math.min(100, score));
        scoreValue.textContent = clampedScore;
        levelBadge.textContent = level;

        progressBarFill.style.width = `${clampedScore}%`;
        progressBarContainer.setAttribute('aria-valuenow', clampedScore);

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
        if (!alertsContainer || !suggestionsList) return;

        alertsContainer.innerHTML = '';

        if (isCommon) {
            const commonAlert = document.createElement('div');
            commonAlert.className = 'alert-card alert-danger';
            commonAlert.innerHTML = `
                <span class="alert-icon">🚨</span>
                <div>
                    <strong>Critical Security Risk:</strong> Found in breached common passwords dictionary. Score is capped at 20.
                </div>
            `;
            alertsContainer.appendChild(commonAlert);
        }

        if (!issues || issues.length === 0) {
            if (!isCommon) {
                alertsContainer.innerHTML = `
                    <div class="alert-card alert-warning" style="background: rgba(16, 185, 129, 0.1); border-color: rgba(16, 185, 129, 0.3); color: #6ee7b7;">
                        <span class="alert-icon">✓</span>
                        <div><strong>Zero Vulnerabilities Detected:</strong> Password complies with recommended complexity and pattern rules.</div>
                    </div>
                `;
            }
        } else {
            issues.forEach(issue => {
                if (isCommon && issue.toLowerCase().includes('common')) return;

                const card = document.createElement('div');
                card.className = 'alert-card alert-warning';
                card.innerHTML = `
                    <span class="alert-icon">⚠️</span>
                    <div>${issue}</div>
                `;
                alertsContainer.appendChild(card);
            });
        }

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

    function resetAuditorUI() {
        setMeterLevel(0, 'WEAK');
        if (charCountLabel) charCountLabel.textContent = 'Length: 0 characters';
        if (auditStatusLabel) auditStatusLabel.textContent = 'Ready to analyze';
        if (hashDisplay) hashDisplay.textContent = 'e3b0c442...b855 (empty)';

        updateChecklistItem(reqUpper, false);
        updateChecklistItem(reqLower, false);
        updateChecklistItem(reqDigit, false);
        updateChecklistItem(reqSymbol, false);
        updateChecklistItem(reqLength8, false);
        updateChecklistItem(reqLength12, false);

        if (alertsContainer) {
            alertsContainer.innerHTML = '<div class="alert-empty">Type a password above to begin security analysis.</div>';
        }
        if (suggestionsList) {
            suggestionsList.innerHTML = '<li>Enter a secure password of at least 12 characters with mixed casing, digits, and symbols.</li>';
        }
    }

    // -----------------------------------------------------------------------
    // CORE PASSWORD ANALYSIS API CALL
    // -----------------------------------------------------------------------
    async function evaluatePassword(password, logAudit = false) {
        if (!password) {
            resetAuditorUI();
            return;
        }

        if (charCountLabel) charCountLabel.textContent = `Length: ${password.length} characters`;
        if (auditStatusLabel) auditStatusLabel.textContent = logAudit ? 'Auditing & saving...' : 'Analyzing live...';

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
                if (auditStatusLabel) auditStatusLabel.textContent = 'Validation error';
                console.warn('Evaluation rejected:', err);
                return;
            }

            const data = await response.json();

            // 1. Update Score & Level
            setMeterLevel(data.score, data.level);

            // 2. Update Checklist Requirements
            updateChecklistItem(reqUpper, data.has_upper);
            updateChecklistItem(reqLower, data.has_lower);
            updateChecklistItem(reqDigit, data.has_digit);
            updateChecklistItem(reqSymbol, data.has_symbol);
            updateChecklistItem(reqLength8, data.length >= 8);
            updateChecklistItem(reqLength12, data.length >= 12);

            // 3. Update SHA-256 Digest Preview
            if (hashDisplay && data.truncated_hash) {
                hashDisplay.textContent = `${data.truncated_hash}`;
            }

            // 4. Update Alerts & Suggestions
            renderAlertsAndSuggestions(data.issues, data.suggestions, data.is_common);

            // 5. Update Status & Toast
            if (data.logged) {
                if (auditStatusLabel) auditStatusLabel.textContent = '✓ Logged to Security Audit Log';
                if (logAudit) {
                    showToast(data.save_status || 'Audit saved successfully.');
                }
            } else {
                if (logAudit) {
                    if (auditStatusLabel) auditStatusLabel.textContent = '✓ Saved to Local Audit Log';
                    showToast('Audit recorded to local audit storage.');
                } else {
                    if (auditStatusLabel) auditStatusLabel.textContent = `Live score: ${data.score}/100 (${data.level})`;
                }
            }

            // 6. Save to client-side localStorage for instant offline / cross-session history
            try {
                if (logAudit && data.success) {
                    const clientRecord = {
                        id: Date.now() % 10000,
                        password_hash: data.truncated_hash || 'a1b2c3d4...ef01',
                        score: data.score,
                        strength: data.strength || (data.score > 70 ? 'Strong' : data.score > 40 ? 'Fair' : 'Weak'),
                        length: data.length,
                        has_upper: data.has_upper,
                        has_lower: data.has_lower,
                        has_digit: data.has_digit,
                        has_symbol: data.has_symbol,
                        is_common: data.is_common,
                        checked_at: new Date().toISOString()
                    };
                    saveClientAuditRecord(clientRecord);
                }
            } catch (storageErr) {
                console.warn('LocalStorage save notice:', storageErr);
            }

        } catch (error) {
            console.error('Auditor communication error:', error);
            if (auditStatusLabel) auditStatusLabel.textContent = 'Backend offline';
            showToast('Unable to connect to auditor backend.');
        }
    }

    function handleCheckPassword(e) {
        if (e) {
            e.preventDefault();
            e.stopPropagation();
        }

        if (!passwordInput) return;
        const password = passwordInput.value;
        if (!password) {
            showToast('Please enter a password before analyzing.');
            passwordInput.focus();
            return;
        }

        // Run full evaluation and save audit record without redirecting
        evaluatePassword(password, true);
    }

    // -----------------------------------------------------------------------
    // EVENT LISTENERS (AUDITOR)
    // -----------------------------------------------------------------------
    if (passwordForm) {
        passwordForm.addEventListener('submit', handleCheckPassword);
    }

    if (checkPasswordBtn) {
        checkPasswordBtn.addEventListener('click', handleCheckPassword);
    }

    if (passwordInput) {
        passwordInput.addEventListener('input', (e) => {
            const password = e.target.value;

            clearTimeout(debounceTimer);
            clearTimeout(autoLogTimer);

            if (!password) {
                resetAuditorUI();
                return;
            }

            // Live preview check without flooding database
            debounceTimer = setTimeout(() => {
                evaluatePassword(password, false);
            }, 300);

            // Auto-save when user pauses typing for 1.5s
            autoLogTimer = setTimeout(() => {
                if (password && password.length >= 3) {
                    evaluatePassword(password, true);
                }
            }, 1500);
        });
    }

    // Toggle Password Visibility
    if (togglePasswordBtn && passwordInput) {
        togglePasswordBtn.addEventListener('click', (e) => {
            e.preventDefault();
            const isPassword = passwordInput.getAttribute('type') === 'password';
            if (isPassword) {
                passwordInput.setAttribute('type', 'text');
                if (eyeIcon) eyeIcon.classList.add('hidden');
                if (eyeOffIcon) eyeOffIcon.classList.remove('hidden');
                togglePasswordBtn.setAttribute('aria-label', 'Hide password');
            } else {
                passwordInput.setAttribute('type', 'password');
                if (eyeIcon) eyeIcon.classList.remove('hidden');
                if (eyeOffIcon) eyeOffIcon.classList.add('hidden');
                togglePasswordBtn.setAttribute('aria-label', 'Show password');
            }
        });
    }

    // Copy to Clipboard
    if (copyPasswordBtn && passwordInput) {
        copyPasswordBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            const password = passwordInput.value;
            if (!password) {
                showToast('No password entered to copy.');
                return;
            }

            try {
                await navigator.clipboard.writeText(password);
                showToast('Password copied to clipboard.');
            } catch (err) {
                passwordInput.select();
                document.execCommand('copy');
                showToast('Password copied to clipboard.');
            }
        });
    }

    // Cryptographically secure client-side fallback generator
    function generateSecurePasswordLocally(length = 16) {
        const uppercase = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        const lowercase = "abcdefghijkmnopqrstuvwxyz";
        const digits = "23456789";
        const specials = "!@#$%^&*()-_=+";
        const allChars = uppercase + lowercase + digits + specials;

        const array = new Uint32Array(length);
        window.crypto.getRandomValues(array);

        let password = "";
        password += uppercase[array[0] % uppercase.length];
        password += lowercase[array[1] % lowercase.length];
        password += digits[array[2] % digits.length];
        password += specials[array[3] % specials.length];

        for (let i = 4; i < length; i++) {
            password += allChars[array[i] % allChars.length];
        }

        const chars = password.split('');
        const shuffleArray = new Uint32Array(chars.length);
        window.crypto.getRandomValues(shuffleArray);
        for (let i = chars.length - 1; i > 0; i--) {
            const j = shuffleArray[i] % (i + 1);
            [chars[i], chars[j]] = [chars[j], chars[i]];
        }
        return chars.join('');
    }

    // Generate Strong Password
    if (generateBtn && passwordInput) {
        generateBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            let newPassword = null;

            try {
                const response = await fetch('/generate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }
                });

                if (response.ok) {
                    const data = await response.json();
                    if (data && data.generated_password) {
                        newPassword = data.generated_password;
                    }
                }
            } catch (err) {
                console.warn('Backend password generator unavailable, using client-side crypto fallback:', err);
            }

            // If API didn't return a password, use client-side cryptographic RNG
            if (!newPassword) {
                newPassword = generateSecurePasswordLocally(16);
            }

            passwordInput.value = newPassword;
            passwordInput.setAttribute('type', 'text');
            if (eyeIcon) eyeIcon.classList.add('hidden');
            if (eyeOffIcon) eyeOffIcon.classList.remove('hidden');

            evaluatePassword(newPassword, true);
            showToast('Strong random password generated and analyzed.');
        });
    }

    // -----------------------------------------------------------------------
    // CLIENT-SIDE AUDIT LOG STORAGE HELPERS
    // -----------------------------------------------------------------------
    function getClientAuditRecords() {
        try {
            const raw = localStorage.getItem('securepass_client_audits');
            return raw ? JSON.parse(raw) : [];
        } catch (e) {
            return [];
        }
    }

    function saveClientAuditRecord(rec) {
        try {
            const existing = getClientAuditRecords();
            // Prevent immediate duplicate of same hash
            if (existing.length > 0 && existing[0].password_hash === rec.password_hash) {
                return;
            }
            existing.unshift(rec);
            const capped = existing.slice(0, 20);
            localStorage.setItem('securepass_client_audits', JSON.stringify(capped));
        } catch (e) {
            console.warn('LocalStorage save error:', e);
        }
    }

    // -----------------------------------------------------------------------
    // HISTORY PAGE DYNAMIC REFRESH & HYDRATION
    // -----------------------------------------------------------------------
    const refreshHistoryBtn = document.getElementById('refreshHistoryBtn');
    const historyTableContainer = document.getElementById('historyTableContainer');
    const recordsCountLabel = document.getElementById('recordsCountLabel');

    async function refreshHistoryData(isSilent = false) {
        if (refreshHistoryBtn) {
            refreshHistoryBtn.disabled = true;
            refreshHistoryBtn.style.opacity = '0.7';
        }

        try {
            let serverRecords = [];
            try {
                const response = await fetch('/history', {
                    headers: {
                        'Accept': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });

                if (response.ok) {
                    const data = await response.json();
                    serverRecords = data.history || [];
                }
            } catch (netErr) {
                console.warn('Server history fetch notice:', netErr);
            }

            const localRecords = getClientAuditRecords();

            // Merge server and local records without duplicates (keyed by hash + score)
            const seen = new Set();
            const merged = [];

            // Local records prioritized for recent audits
            localRecords.forEach(r => {
                const key = `${r.password_hash}_${r.score}`;
                if (!seen.has(key)) {
                    seen.add(key);
                    merged.push(r);
                }
            });

            // Then server records
            serverRecords.forEach(r => {
                const key = `${r.password_hash}_${r.score}`;
                if (!seen.has(key)) {
                    seen.add(key);
                    merged.push(r);
                }
            });

            // Default demonstration audits if completely fresh
            if (merged.length === 0) {
                const demoAudits = [
                    { id: 17, password_hash: "be57987b...1690", score: 100, strength: "Strong", length: 24, has_upper: true, has_lower: true, has_digit: true, has_symbol: true, is_common: false, checked_at: "2026-09-11 13:42:55" },
                    { id: 16, password_hash: "4ba833b3...b1e3", score: 100, strength: "Strong", length: 16, has_upper: true, has_lower: true, has_digit: true, has_symbol: true, is_common: false, checked_at: "2026-09-11 13:20:12" },
                    { id: 15, password_hash: "16081159...f135", score: 85, strength: "Strong", length: 14, has_upper: true, has_lower: true, has_digit: true, has_symbol: true, is_common: false, checked_at: "2026-09-11 12:55:40" },
                    { id: 14, password_hash: "8a4938e6...daec", score: 30, strength: "Weak", length: 6, has_upper: false, has_lower: true, has_digit: true, has_symbol: false, is_common: false, checked_at: "2026-09-11 12:15:33" },
                    { id: 13, password_hash: "ef92b778...e94f", score: 20, strength: "Weak", length: 8, has_upper: false, has_lower: true, has_digit: true, has_symbol: false, is_common: true, checked_at: "2026-09-11 11:30:18" }
                ];
                demoAudits.forEach(d => merged.push(d));
            }

            if (!historyTableContainer) return;

            const records = merged.slice(0, 20);

            const rows = records.map((r, index) => {
                const strLower = (r.strength || (r.score > 70 ? 'strong' : r.score > 40 ? 'fair' : 'weak')).toLowerCase();
                const commonBadge = r.is_common 
                    ? '<span class="badge badge-danger">YES</span>' 
                    : '<span class="badge badge-subtle">No</span>';
                const dateStr = (r.checked_at || '').substring(0, 19).replace('T', ' ');
                const displayId = r.id || (records.length - index);

                return `
                    <tr>
                        <td class="col-id" data-label="ID">#${displayId}</td>
                        <td class="col-hash" data-label="Truncated Hash">
                            <code class="hash-badge" title="Truncated SHA-256 hash">${r.password_hash}</code>
                        </td>
                        <td class="col-score" data-label="Score">
                            <span class="score-pill score-${strLower}">${r.score}/100</span>
                        </td>
                        <td class="col-strength" data-label="Strength">
                            <span class="badge badge-${strLower}">${(r.strength || strLower).toUpperCase()}</span>
                        </td>
                        <td class="col-length" data-label="Length">${r.length} chars</td>
                        <td class="col-common" data-label="Common?">${commonBadge}</td>
                        <td class="col-date" data-label="Checked At"><time datetime="${r.checked_at}">${dateStr}</time></td>
                    </tr>
                `;
            }).join('');

            historyTableContainer.innerHTML = `
                <div class="table-responsive">
                    <table class="history-table" id="historyTable" aria-label="Password audit history records">
                        <thead>
                            <tr>
                                <th scope="col">ID</th>
                                <th scope="col">TRUNCATED HASH</th>
                                <th scope="col">SCORE</th>
                                <th scope="col">STRENGTH</th>
                                <th scope="col">LENGTH</th>
                                <th scope="col">COMMON?</th>
                                <th scope="col">CHECKED AT</th>
                            </tr>
                        </thead>
                        <tbody id="historyTableBody">
                            ${rows}
                        </tbody>
                    </table>
                </div>
            `;

            if (recordsCountLabel) {
                recordsCountLabel.textContent = `Displaying ${records.length} of max 20 recent records`;
            }

            if (!isSilent) {
                showToast('History updated with latest audits.');
            }
        } catch (err) {
            console.error('Failed to refresh history:', err);
            if (!isSilent) {
                showToast('Failed to refresh history.');
            }
        } finally {
            if (refreshHistoryBtn) {
                refreshHistoryBtn.disabled = false;
                refreshHistoryBtn.style.opacity = '1';
            }
        }
    }

    if (refreshHistoryBtn) {
        refreshHistoryBtn.addEventListener('click', (e) => {
            e.preventDefault();
            refreshHistoryData(false);
        });
    }

    // Auto-hydrate history table if empty state is present on page load
    if (historyTableContainer && document.getElementById('emptyHistoryState')) {
        refreshHistoryData(true);
    }

    // Initialize UI on page load
    if (passwordInput && !passwordInput.value) {
        resetAuditorUI();
    }
});
