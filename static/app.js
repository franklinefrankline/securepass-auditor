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
                if (auditStatusLabel) auditStatusLabel.textContent = '✓ Logged to PostgreSQL';
                showToast(`Analysis complete: Score ${data.score}/100 (${data.level}) & saved.`);
            } else {
                if (auditStatusLabel) auditStatusLabel.textContent = `Live score: ${data.score}/100 (${data.level})`;
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

    // Generate Strong Password
    if (generateBtn && passwordInput) {
        generateBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            try {
                const response = await fetch('/generate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });

                if (response.ok) {
                    const data = await response.json();
                    passwordInput.value = data.generated_password;
                    passwordInput.setAttribute('type', 'text');
                    if (eyeIcon) eyeIcon.classList.add('hidden');
                    if (eyeOffIcon) eyeOffIcon.classList.remove('hidden');

                    evaluatePassword(data.generated_password, true);
                    showToast('Strong random password generated and analyzed.');
                }
            } catch (err) {
                console.error('Password generation error:', err);
                showToast('Could not generate password.');
            }
        });
    }

    // -----------------------------------------------------------------------
    // HISTORY PAGE DYNAMIC REFRESH
    // -----------------------------------------------------------------------
    const refreshHistoryBtn = document.getElementById('refreshHistoryBtn');
    const historyTableContainer = document.getElementById('historyTableContainer');
    const recordsCountLabel = document.getElementById('recordsCountLabel');

    async function refreshHistoryData() {
        if (!refreshHistoryBtn) return;
        refreshHistoryBtn.disabled = true;
        refreshHistoryBtn.style.opacity = '0.7';

        try {
            const response = await fetch('/history', {
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });

            if (!response.ok) {
                throw new Error('Network response was not ok');
            }

            const data = await response.json();
            const records = data.history || [];

            if (!historyTableContainer) return;

            if (records.length === 0) {
                historyTableContainer.innerHTML = `
                    <div class="empty-state" id="emptyHistoryState">
                        <div class="empty-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                <circle cx="12" cy="12" r="10"/>
                                <line x1="8" y1="12" x2="16" y2="12"/>
                            </svg>
                        </div>
                        <h3 class="empty-title">No password audits found</h3>
                        <p class="empty-description">Audit records will appear here once you analyze passwords in the auditor.</p>
                        <a href="/" class="btn btn-primary" style="margin-top: 1rem;">Perform First Password Audit</a>
                    </div>
                `;
            } else {
                const rows = records.map(r => {
                    const strLower = (r.strength || 'weak').toLowerCase();
                    const commonBadge = r.is_common 
                        ? '<span class="badge badge-danger">YES</span>' 
                        : '<span class="badge badge-subtle">No</span>';
                    const dateStr = (r.checked_at || '').substring(0, 19).replace('T', ' ');

                    return `
                        <tr>
                            <td class="col-id" data-label="ID">#${r.id}</td>
                            <td class="col-hash" data-label="Truncated Hash">
                                <code class="hash-badge" title="Truncated SHA-256 hash">${r.password_hash}</code>
                            </td>
                            <td class="col-score" data-label="Score">
                                <span class="score-pill score-${strLower}">${r.score}/100</span>
                            </td>
                            <td class="col-strength" data-label="Strength">
                                <span class="badge badge-${strLower}">${(r.strength || '').toUpperCase()}</span>
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
            }

            if (recordsCountLabel) {
                recordsCountLabel.textContent = `Displaying ${records.length} of max 20 recent records`;
            }

            showToast('History refreshed successfully.');
        } catch (err) {
            console.error('Failed to refresh history:', err);
            showToast('Failed to refresh history.');
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
            refreshHistoryData();
        });
    }

    // Initialize UI on page load
    if (passwordInput && !passwordInput.value) {
        resetAuditorUI();
    }
});
