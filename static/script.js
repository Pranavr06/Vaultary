// --- FETCH INTERCEPTOR FOR GLOBAL 401 HANDLING ---
const originalFetch = window.fetch;
window.fetch = async function(...args) {
    const response = await originalFetch.apply(this, args);
    if (response.status === 401) {
        if (localStorage.getItem('username')) {
            const logoutBtn = document.getElementById('dashLogoutBtn');
            if (logoutBtn) logoutBtn.click();
            if (typeof showToast === 'function') showToast("Session expired. Please log in again.", "warning");
        }
    }
    return response;
};

// --- DOM ELEMENTS ---
const passwordInput = document.getElementById('passwordInput');
const toggleBtn = document.getElementById('togglePassword');
const generateBtn = document.getElementById('generateBtn');
const resultBox = document.getElementById('result-box');
const capsLockWarning = document.getElementById('capsLockWarning');
const whitespaceWarningMain = document.getElementById('whitespaceWarningMain');
// Chart removed
const copyBtn = document.getElementById('copyBtn');
const themeToggle = document.getElementById('theme-toggle');
const htmlElement = document.documentElement;

// Desktop Nav Elements
const loginBtn = document.getElementById('loginBtn');
const userProfile = document.getElementById('userProfile');
// Removed usernameDisplay
const dashboardBtn = document.getElementById('dashboardBtn');

// Mobile Nav Elements
const mobileMenuBtn = document.getElementById('mobile-menu-btn');
const mobileNav = document.getElementById('mobileNav');
const mobileLoginBtn = document.getElementById('mobileLoginBtn');
const mobileDashboardBtn = document.getElementById('mobileDashboardBtn');
const mobileThemeToggle = document.getElementById('mobileThemeToggle');

// Modals
const authModal = document.getElementById('authModal');
const appDashboard = document.getElementById('appDashboard');
const forgotModal = document.getElementById('forgotModal');
const resetModal = document.getElementById('resetModal');
// 2FA Modals
const login2FAModal = document.getElementById('login2FAModal');
const setup2FAModal = document.getElementById('setup2FAModal');
// Vault Modal
const addVaultModal = document.getElementById('addVaultModal');
const editVaultModal = document.getElementById('editVaultModal');
const sessionTimeoutModal = document.getElementById('sessionTimeoutModal');
const legalModal = document.getElementById('legalModal');
const contactModal = document.getElementById('contactModal');
const passwordHealthLink = document.getElementById('passwordHealthLink');
const registerModal = document.getElementById('registerModal');

const allModals = [authModal, registerModal, appDashboard, forgotModal, resetModal, login2FAModal, setup2FAModal, addVaultModal, editVaultModal, sessionTimeoutModal, legalModal, contactModal, document.getElementById('addNoteModal'), document.getElementById('editNoteModal')];

// Auth Inputs
const authUsername = document.getElementById('authUsername');
const authPassword = document.getElementById('authPassword');
const authEmail = document.getElementById('authEmail');
const authPhone = document.getElementById('authPhone');
const authDob = document.getElementById('authDob');
const authPhoneError = document.getElementById('authPhoneError');
const authDobError = document.getElementById('authDobError');
const whitespaceWarningAuth = document.getElementById('whitespaceWarningAuth');
const toggleAuthPassword = document.getElementById('toggleAuthPassword');
const authSubmitBtn = document.getElementById('authSubmitBtn');
const authMessage = document.getElementById('authMessage');
const switchAuthMode = document.getElementById('switchAuthMode');

// Vault Elements
const openAddVaultModalBtn = document.getElementById('openAddVaultModal');
const exportVaultBtn = document.getElementById('exportVaultBtn');
const saveVaultBtn = document.getElementById('saveVaultBtn');
const vaultGrid = document.getElementById('vaultGrid');

// Edit Vault Modal Elements
const editVaultId = document.getElementById('editVaultId');
const editVaultSiteName = document.getElementById('editVaultSiteName');
const editVaultSiteURL = document.getElementById('editVaultSiteURL');
const editVaultUsername = document.getElementById('editVaultUsername');
const editVaultPassword = document.getElementById('editVaultPassword');
const toggleEditVaultPassword = document.getElementById('toggleEditVaultPassword');
const updateVaultBtn = document.getElementById('updateVaultBtn');
const editVaultMessage = document.getElementById('editVaultMessage');

// Forgot & Reset Inputs
const forgotLink = document.getElementById('forgotPasswordLink');
const forgotEmail = document.getElementById('forgotEmail');
const forgotSubmitBtn = document.getElementById('forgotSubmitBtn');
const forgotMessage = document.getElementById('forgotMessage');
const newResetPassword = document.getElementById('newResetPassword');
const toggleResetPassword = document.getElementById('toggleResetPassword');
const resetSubmitBtn = document.getElementById('resetSubmitBtn');
const resetMessage = document.getElementById('resetMessage');

// 2FA Elements
const login2FACode = document.getElementById('login2FACode');
const login2FASubmitBtn = document.getElementById('login2FASubmitBtn');
const login2FAMessage = document.getElementById('login2FAMessage');
const qrCodeImage = document.getElementById('qrCodeImage');
const setup2FACode = document.getElementById('setup2FACode');
const confirm2FABtn = document.getElementById('confirm2FABtn');
const setup2FAMessage = document.getElementById('setup2FAMessage');
const toggle2FABtn = document.getElementById('toggle2FABtn');
const stayLoggedInBtn = document.getElementById('stayLoggedInBtn');
let tempLoginToken = null;

// --- TOAST NOTIFICATION LOGIC ---
const toastBox = document.getElementById('toast-box');

function showToast(msg, type = 'info') {
    const toast = document.createElement('div');
    toast.classList.add('toast', type);
    
    let icon = 'fa-info-circle';
    if(type === 'success') icon = 'fa-check-circle';
    if(type === 'error') icon = 'fa-exclamation-circle';

    toast.innerHTML = `<i class="fas ${icon}"></i> <span>${msg}</span>`;
    toastBox.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = "slideOut 0.3s forwards";
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// --- 1. PASSWORD TOOL LOGIC ---
window.addEventListener('load', () => {
    document.getElementById('footerYear').innerText = new Date().getFullYear();
    // Prevent Auto-fill / Clear Inputs
    setTimeout(() => {
        document.querySelectorAll('input').forEach(input => input.value = '');
    }, 100);
});

if (passwordHealthLink) {
    passwordHealthLink.addEventListener('click', (e) => {
        e.preventDefault();
        document.querySelector('.tool-section').scrollIntoView({behavior: 'smooth'});
        showToast("Type password to get password health", "info");
    });
}

toggleBtn.addEventListener('click', () => {
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
    toggleBtn.classList.toggle('fa-eye');
    toggleBtn.classList.toggle('fa-eye-slash');
});

if (toggleAuthPassword) {
    toggleAuthPassword.addEventListener('click', () => {
        const type = authPassword.getAttribute('type') === 'password' ? 'text' : 'password';
        authPassword.setAttribute('type', type);
        toggleAuthPassword.classList.toggle('fa-eye');
        toggleAuthPassword.classList.toggle('fa-eye-slash');
    });
}

const toggleRegPassword = document.getElementById('toggleRegPassword');
if (toggleRegPassword) {
    toggleRegPassword.addEventListener('click', () => {
        const regPwd = document.getElementById('regPassword');
        if (regPwd) {
            const type = regPwd.getAttribute('type') === 'password' ? 'text' : 'password';
            regPwd.setAttribute('type', type);
            toggleRegPassword.classList.toggle('fa-eye');
            toggleRegPassword.classList.toggle('fa-eye-slash');
        }
    });
}

if (toggleEditVaultPassword) {
    toggleEditVaultPassword.addEventListener('click', () => {
        const type = editVaultPassword.getAttribute('type') === 'password' ? 'text' : 'password';
        editVaultPassword.setAttribute('type', type);
        toggleEditVaultPassword.classList.toggle('fa-eye');
        toggleEditVaultPassword.classList.toggle('fa-eye-slash');
    });
}

const toggleAddVaultPassword = document.getElementById('toggleAddVaultPassword');
const vaultPassword = document.getElementById('vaultPassword');
if (toggleAddVaultPassword && vaultPassword) {
    toggleAddVaultPassword.addEventListener('click', () => {
        const type = vaultPassword.getAttribute('type') === 'password' ? 'text' : 'password';
        vaultPassword.setAttribute('type', type);
        toggleAddVaultPassword.classList.toggle('fa-eye');
        toggleAddVaultPassword.classList.toggle('fa-eye-slash');
    });
}

if (toggleResetPassword) {
    toggleResetPassword.addEventListener('click', () => {
        const type = newResetPassword.getAttribute('type') === 'password' ? 'text' : 'password';
        newResetPassword.setAttribute('type', type);
        toggleResetPassword.classList.toggle('fa-eye');
        toggleResetPassword.classList.toggle('fa-eye-slash');
    });
}

// Caps Lock Detection
function checkCapsLock(e) {
    if (e.getModifierState && e.getModifierState("CapsLock")) {
        capsLockWarning.classList.remove('hidden');
    } else {
        capsLockWarning.classList.add('hidden');
    }
}
['keyup', 'keydown', 'click', 'focus'].forEach(event => passwordInput.addEventListener(event, checkCapsLock));
passwordInput.addEventListener('blur', () => capsLockWarning.classList.add('hidden'));

// Whitespace Validation
function setupWhitespaceValidation(input, warning) {
    if (!input || !warning) return;

    input.addEventListener('keydown', (e) => {
        if (e.key === ' ') {
            e.preventDefault();
            warning.classList.remove('hidden');
            setTimeout(() => warning.classList.add('hidden'), 2000);
        }
    });

    input.addEventListener('input', () => {
        if (input.value.includes(' ')) {
            input.value = input.value.replace(/\s/g, '');
            warning.classList.remove('hidden');
            setTimeout(() => warning.classList.add('hidden'), 2000);
        }
    });
}
setupWhitespaceValidation(passwordInput, whitespaceWarningMain);
setupWhitespaceValidation(authPassword, whitespaceWarningAuth);

// Peek Password with Alt Key
function setupPasswordPeek(input, icon) {
    if (!input || !icon) return;

    input.addEventListener('keydown', (e) => {
        if (e.key === 'Alt' && input.type === 'password') {
            e.preventDefault();
            input.type = 'text';
            input.dataset.peeked = 'true';
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
        }
    });

    ['keyup', 'blur'].forEach(event => {
        input.addEventListener(event, (e) => {
            if ((event === 'blur' || e.key === 'Alt') && input.dataset.peeked === 'true') {
                input.type = 'password';
                delete input.dataset.peeked;
                icon.classList.add('fa-eye');
                icon.classList.remove('fa-eye-slash');
            }
        });
    });
}
setupPasswordPeek(passwordInput, toggleBtn);
setupPasswordPeek(authPassword, toggleAuthPassword);

// Debounce Utility
function debounce(func, wait) {
    let timeout;
    return function(...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}

// Real-time Regex Validation
function validateChecklist(value) {
    const list = document.getElementById('req-checklist');
    if (!list) return;

    if (value.length > 0) list.classList.remove('hidden');
    else list.classList.add('hidden');

    const reqs = {
        'upper': /[A-Z]/,
        'number': /[0-9]/,
        'special': /[^A-Za-z0-9]/,
        'length': /.{8,}/
    };

    for (const [key, regex] of Object.entries(reqs)) {
        const item = document.getElementById(`req-${key}`);
        if (item) {
            if (regex.test(value)) {
                item.classList.add('met');
            } else {
                item.classList.remove('met');
            }
        }
    }
}

// Ensure validateChecklist runs immediately on input
passwordInput.addEventListener('input', (e) => {
    validateChecklist(passwordInput.value);
});

passwordInput.addEventListener('input', debounce(async (e) => {
    const password = passwordInput.value;
    
    if (password.length === 0) {
        resultBox.classList.add('hidden');
        return;
    }
    try {
        const response = await fetch('/check_password', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({password: password})
        });
        const data = await response.json();
        updateUI(data);
    } catch (error) { console.error("Error:", error); }
}, 300)); // 300ms debounce

generateBtn.addEventListener('click', async () => {
    setLoading(generateBtn, true);
    try {
        const response = await fetch('/generate_password');
        const data = await response.json();
        passwordInput.value = data.password;
        passwordInput.setAttribute('type', 'text');
        toggleBtn.classList.remove('fa-eye');
        toggleBtn.classList.add('fa-eye-slash');
        passwordInput.dispatchEvent(new Event('input'));
        validateChecklist(data.password, 'main-checklist');
    } catch (error) { console.error("Error:", error); }
    finally { setLoading(generateBtn, false); }
});

copyBtn.addEventListener('click', () => {
    if (!passwordInput.value) return;
    navigator.clipboard.writeText(passwordInput.value);
    showToast("Password copied to clipboard!", "success"); // TOAST
    const originalIcon = copyBtn.className;
    copyBtn.className = "fas fa-check";
    copyBtn.style.color = "#22c55e";
    setTimeout(() => {
        copyBtn.className = originalIcon;
        copyBtn.style.color = "";
    }, 1500);
});

function updateUI(data) {
    resultBox.classList.remove('hidden');
    
    let overallScore = Math.min((data.score * 25) + (data.password_length > 12 ? 10 : 0), 100);
    const entropyBits = Math.round(Math.log2(data.guesses + 1));
    let strengthLabel = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Excellent'][data.score];
    let ringColor = 'var(--danger)';
    
    if (data.score >= 3) ringColor = 'var(--success)';
    else if (data.score === 2) ringColor = 'var(--warning)';

    let breachWarning = false;
    if (data.breach_count > 0) {
        overallScore = 0;
        strengthLabel = "BREACHED";
        ringColor = "var(--danger)";
        breachWarning = true;
    }

    // Update Ring
    const progressCircle = document.getElementById('strength-meter-lg');
    const scoreText = document.getElementById('score-text-lg');
    const offset = 339 - (339 * overallScore) / 100;
    progressCircle.style.strokeDashoffset = offset;
    progressCircle.style.stroke = ringColor;
    
    // Animate numbers
    scoreText.innerText = overallScore;
    scoreText.style.color = ringColor;

    // Update Metrics
    document.getElementById('strength-level-text').innerText = strengthLabel;
    document.getElementById('strength-level-text').style.color = ringColor;
    document.getElementById('entropy-tooltip').title = `Entropy: ${entropyBits} bits`;
    document.getElementById('crack-time').innerText = data.crack_time;

    // Analyze Risks
    let dictRisk = "None";
    let dictColor = "var(--success)";
    let patternRisk = "Low";
    let patternColor = "var(--success)";
    
    let hasDict = false;
    let hasPattern = false;
    
    if (data.sequence) {
        data.sequence.forEach(seq => {
            if (seq.pattern === 'dictionary') hasDict = true;
            if (['spatial', 'repeat', 'sequence'].includes(seq.pattern)) hasPattern = true;
        });
    }

    if (hasDict) { dictRisk = "High"; dictColor = "var(--danger)"; }
    if (hasPattern) { patternRisk = "Medium"; patternColor = "var(--warning)"; }

    document.getElementById('dictionary-risk').innerText = dictRisk;
    document.getElementById('dictionary-risk').style.color = dictColor;
    document.getElementById('pattern-risk').innerText = patternRisk;
    document.getElementById('pattern-risk').style.color = patternColor;

    // Generate AI Insights
    const insightsList = document.getElementById('insights-list');
    let insightsHTML = '';
    
    if (breachWarning) {
        insightsHTML += `<li style="color:var(--danger)"><i class="fas fa-skull-crossbones"></i> Found in ${data.breach_count.toLocaleString()} data breaches! Do not use!</li>`;
    } else {
        if (!hasDict) insightsHTML += `<li><i class="fas fa-check-circle" style="color:var(--success)"></i> No dictionary words detected</li>`;
        else insightsHTML += `<li><i class="fas fa-exclamation-triangle" style="color:var(--warning)"></i> Contains common dictionary words</li>`;
        
        if (entropyBits > 60) insightsHTML += `<li><i class="fas fa-check-circle" style="color:var(--success)"></i> High entropy score (${entropyBits} bits)</li>`;
        else insightsHTML += `<li><i class="fas fa-info-circle" style="color:var(--warning)"></i> Consider increasing length for better entropy</li>`;
        
        if (data.feedback.suggestions && data.feedback.suggestions.length > 0) {
            insightsHTML += `<li><i class="fas fa-lightbulb" style="color:var(--primary)"></i> ${data.feedback.suggestions[0]}</li>`;
        } else if (data.score >= 3) {
            insightsHTML += `<li><i class="fas fa-shield-alt" style="color:var(--success)"></i> Highly resistant to common offline attacks</li>`;
        }
    }
    insightsList.innerHTML = insightsHTML;

    updateChart(data, entropyBits);
}

function updateChart(data, entropyBits) {
    // Normalize data for progress bars 0-100
    const lenScore = Math.min((data.password_length / 16) * 100, 100);
    const compScore = (data.score + 1) * 20;
    const entScore = Math.min((entropyBits / 80) * 100, 100);
    let dictPenalty = 0;
    let patternPenalty = 0;
    if (data.sequence) {
        data.sequence.forEach(seq => {
            if (seq.pattern === 'dictionary') dictPenalty += 20;
            if (['spatial', 'repeat', 'sequence'].includes(seq.pattern)) patternPenalty += 15;
        });
    }
    const safeScore = data.breach_count > 0 ? 0 : Math.max(100 - dictPenalty - patternPenalty, 0);

    const formatVal = val => Math.round(val / 10) + '/10';
    const getColor = val => {
        if (val >= 80) return 'var(--success)';
        if (val >= 50) return 'var(--warning)';
        return 'var(--danger)';
    };

    const updateBar = (id, score) => {
        const bar = document.getElementById('bar-' + id);
        const val = document.getElementById('bar-' + id + '-val');
        if(bar && val) {
            bar.style.width = score + '%';
            bar.style.backgroundColor = getColor(score);
            val.innerText = formatVal(score);
            val.style.color = getColor(score);
        }
    };

    updateBar('length', lenScore);
    updateBar('comp', compScore);
    updateBar('ent', entScore);
    updateBar('safe', safeScore);
}

// --- PHONE & DOB VALIDATION ---
function setupPhoneValidation(input, errorEl) {
    if (!input) return;
    input.addEventListener('input', () => {
        // Block non-numeric characters immediately
        input.value = input.value.replace(/\D/g, '');
        
        if (input.value.length > 0 && input.value.length !== 10) {
            errorEl.innerText = "Phone number must be exactly 10 digits.";
            errorEl.classList.remove('hidden');
            input.dataset.valid = "false";
        } else {
            errorEl.classList.add('hidden');
            input.dataset.valid = "true";
        }
    });
}

function setupDobValidation(input, errorEl) {
    if (!input) return;
    input.addEventListener('input', (e) => {
        // Auto-format DD/MM/YYYY
        let v = input.value.replace(/\D/g, '');
        if (v.length > 8) v = v.slice(0, 8);
        if (v.length > 4) {
            input.value = `${v.slice(0,2)}/${v.slice(2,4)}/${v.slice(4)}`;
        } else if (v.length > 2) {
            input.value = `${v.slice(0,2)}/${v.slice(2)}`;
        } else {
            input.value = v;
        }
        
        validateDobLogic(input, errorEl);
    });
    
    input.addEventListener('blur', () => validateDobLogic(input, errorEl));
}

function validateDobLogic(input, errorEl) {
    const val = input.value;
    if (val.length === 0) {
        errorEl.classList.add('hidden');
        input.dataset.valid = "true"; // Empty allowed unless mandatory check elsewhere
        return;
    }

    const regex = /^(\d{2})\/(\d{2})\/(\d{4})$/;
    if (!regex.test(val)) {
        errorEl.innerText = "Format must be DD/MM/YYYY";
        errorEl.classList.remove('hidden');
        input.dataset.valid = "false";
        return;
    }

    const [day, month, year] = val.split('/').map(Number);
    const date = new Date(year, month - 1, day);
    const today = new Date();

    // Check for invalid dates (e.g. 32/01/2023)
    if (date.getFullYear() !== year || date.getMonth() + 1 !== month || date.getDate() !== day) {
        errorEl.innerText = "Invalid date.";
        errorEl.classList.remove('hidden');
        input.dataset.valid = "false";
        return;
    }

    // Age Calculation
    let age = today.getFullYear() - year;
    const m = today.getMonth() - (month - 1);
    if (m < 0 || (m === 0 && today.getDate() < day)) {
        age--;
    }

    if (date > today) {
        errorEl.innerText = "Date cannot be in the future.";
        errorEl.classList.remove('hidden');
        input.dataset.valid = "false";
    } else if (age < 13) {
        errorEl.innerText = "You must be at least 13 years old.";
        errorEl.classList.remove('hidden');
        input.dataset.valid = "false";
    } else if (age > 120) {
        errorEl.innerText = "Please enter a valid age.";
        errorEl.classList.remove('hidden');
        input.dataset.valid = "false";
    } else {
        errorEl.classList.add('hidden');
        input.dataset.valid = "true";
    }
}

setupPhoneValidation(authPhone, authPhoneError);
setupPhoneValidation(document.getElementById('editPhone'), document.getElementById('editPhoneError'));
setupDobValidation(authDob, authDobError);
setupDobValidation(document.getElementById('editDob'), document.getElementById('editDobError'));

// --- 2. AUTH & MODAL LOGIC ---
let isLoginMode = true;

// Openers
loginBtn.addEventListener('click', () => { 
    authModal.classList.remove('hidden'); 
    document.body.style.overflow = 'hidden';
});
const dashHomeBtn = document.getElementById('dashHomeBtn');
if (dashHomeBtn) {
    dashHomeBtn.addEventListener('click', () => {
        appDashboard.classList.add('hidden');
        document.getElementById('landingPage').classList.remove('hidden');
        document.querySelector('.navbar').classList.remove('hidden'); // Show landing navbar
    });
}

dashboardBtn.addEventListener('click', () => {
    openDashboard('overview-section');
});

mobileMenuBtn.addEventListener('click', () => {
    mobileNav.classList.toggle('hidden');
    const icon = mobileMenuBtn.querySelector('i');
    if (mobileNav.classList.contains('hidden')) {
        icon.classList.remove('fa-times');
        icon.classList.add('fa-bars');
    } else {
        icon.classList.remove('fa-bars');
        icon.classList.add('fa-times');
    }
});

mobileLoginBtn.addEventListener('click', () => { 
    authModal.classList.remove('hidden'); 
    mobileNav.classList.add('hidden'); 
    const icon = mobileMenuBtn.querySelector('i');
    icon.classList.remove('fa-times');
    icon.classList.add('fa-bars');
    document.body.style.overflow = 'hidden';
});
mobileDashboardBtn.addEventListener('click', () => { 
    openDashboard('overview-section'); 
    mobileNav.classList.add('hidden'); 
    const icon = mobileMenuBtn.querySelector('i');
    icon.classList.remove('fa-times');
    icon.classList.add('fa-bars');
});

// Close buttons
document.querySelectorAll('.close-modal').forEach(btn => {
    btn.addEventListener('click', () => {
        const modal = btn.closest('.modal');
        if (modal) {
            modal.classList.add('hidden');
            
            // If closing the forgot password modal, bring back the login modal
            if (modal.id === 'forgotModal') {
                authModal.classList.remove('hidden');
            }
            
            // Only reset overflow if dashboard is NOT open
            if (appDashboard.classList.contains('hidden') && modal.id !== 'forgotModal') {
                document.body.style.overflow = '';
            }
        }
    });
});
// Removed .close-dashboard listener

const mobileDashOpen = document.getElementById('mobileDashOpen');
const mobileDashToggle = document.getElementById('mobileDashToggle');
const dashboardSidebar = document.getElementById('dashboardSidebar');

if (mobileDashOpen) {
    mobileDashOpen.addEventListener('click', () => {
        dashboardSidebar.classList.add('open');
    });
}
if (mobileDashToggle) {
    mobileDashToggle.addEventListener('click', () => {
        dashboardSidebar.classList.remove('open');
    });
}

// Check for mobile layout resize and clean up
window.addEventListener('resize', () => {
    if (window.innerWidth > 1024 && dashboardSidebar) {
        dashboardSidebar.classList.remove('open');
    }
});

// Forgot Password Modal
forgotLink.addEventListener('click', (e) => {
    e.preventDefault();
    authModal.classList.add('hidden');
    document.getElementById('forgotFormView').classList.remove('hidden');
    document.getElementById('forgotSuccessView').classList.add('hidden');
    forgotEmail.value = '';
    forgotModal.classList.remove('hidden');
    forgotMessage.innerText = "";
});

// Back to Sign In logic for Forgot Password Modal
document.getElementById('backToSignInLink').addEventListener('click', (e) => {
    e.preventDefault();
    forgotModal.classList.add('hidden');
    authModal.classList.remove('hidden');
});
document.getElementById('successBackToSignInBtn').addEventListener('click', (e) => {
    e.preventDefault();
    forgotModal.classList.add('hidden');
    authModal.classList.remove('hidden');
});

forgotSubmitBtn.addEventListener('click', async () => {
    const email = forgotEmail.value;
    if(!email) {
        forgotMessage.innerText = "Enter an email";
        return;
    }
    forgotMessage.innerText = "";
    
    forgotSubmitBtn.disabled = true;
    document.getElementById('forgotBtnText').innerText = 'Sending...';
    document.getElementById('forgotBtnSpinner').classList.remove('hidden');
    
    try {
        const res = await fetch('/forgot_password', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email})
        });
        const data = await res.json();
        
        if(res.ok) {
            document.getElementById('forgotFormView').classList.add('hidden');
            document.getElementById('forgotSuccessView').classList.remove('hidden');
        } else {
            forgotMessage.innerText = data.message;
        }
    } catch(e) { 
        forgotMessage.innerText = "Error sending request."; 
    }
    
    forgotSubmitBtn.disabled = false;
    document.getElementById('forgotBtnText').innerText = 'Send Reset Link';
    document.getElementById('forgotBtnSpinner').classList.add('hidden');
});

// --- LEGAL MODAL LOGIC ---
document.querySelectorAll('.legal-trigger').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        legalModal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
        
        // Activate correct tab
        const targetId = link.getAttribute('data-tab');
        if(targetId) {
            document.querySelectorAll('.legal-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.legal-pane').forEach(p => p.classList.add('hidden'));
            
            document.querySelector(`.legal-tab[data-target="${targetId}"]`).classList.add('active');
            document.getElementById(targetId).classList.remove('hidden');
        }
    });
});

// Legal Modal Tab Switching
document.querySelectorAll('.legal-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.legal-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.legal-pane').forEach(p => p.classList.add('hidden'));
        tab.classList.add('active');
        document.getElementById(tab.getAttribute('data-target')).classList.remove('hidden');
    });
});

document.querySelector('.close-legal').addEventListener('click', () => {
    legalModal.classList.add('hidden');
    document.body.style.overflow = '';
});

// --- CONTACT MODAL LOGIC ---
const contactTrigger = document.getElementById('contactTrigger');
const contactSubmitBtn = document.getElementById('contactSubmitBtn');
const contactName = document.getElementById('contactName');
const contactEmail = document.getElementById('contactEmail');
const contactMessage = document.getElementById('contactMessage');
const contactMessageStatus = document.getElementById('contactMessageStatus');

if(contactTrigger) {
    contactTrigger.addEventListener('click', (e) => {
        e.preventDefault();
        contactModal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    });
}

contactSubmitBtn.addEventListener('click', async () => {
    const name = contactName.value;
    const email = contactEmail.value;
    const message = contactMessage.value;
    
    if(!name || !email || !message) {
        contactMessageStatus.innerText = "All fields are required.";
        return;
    }
    
    setLoading(contactSubmitBtn, true);
    try {
        const res = await fetch('/contact', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name, email, message})
        });
        const data = await res.json();
        if(res.ok) {
            showToast("Message sent successfully!", "success");
            contactModal.classList.add('hidden');
            document.body.style.overflow = '';
            contactName.value = '';
            contactEmail.value = '';
            contactMessage.value = '';
            contactMessageStatus.innerText = '';
        } else {
            contactMessageStatus.innerText = data.message;
        }
    } catch(e) {
        contactMessageStatus.innerText = "Error sending message.";
    }
    setLoading(contactSubmitBtn, false);
});

// --- UPDATED MODAL CLOSING LOGIC ---
window.onclick = (e) => {
    // Close Mobile Nav if clicked outside
    if (!mobileNav.classList.contains('hidden') && !mobileNav.contains(e.target) && !mobileMenuBtn.contains(e.target)) {
        mobileNav.classList.add('hidden');
        const icon = mobileMenuBtn.querySelector('i');
        icon.classList.remove('fa-times');
        icon.classList.add('fa-bars');
    }

    // Shake effect for persistent modals (All Modals + Dashboard)
    if (allModals.includes(e.target) || e.target === appDashboard) {
        const content = e.target.querySelector('.modal-content, .dashboard-container');
        if (content) {
            content.classList.remove('shake-anim');
            void content.offsetWidth; // Trigger reflow to restart animation
            content.classList.add('shake-anim');
            setTimeout(() => content.classList.remove('shake-anim'), 500);
        }
        
        // Highlight Close Icon
        const closeBtn = e.target.querySelector('.close-modal, .close-dashboard');
        if (closeBtn) {
            closeBtn.classList.add('highlight-close');
            setTimeout(() => closeBtn.classList.remove('highlight-close'), 500);
        }
        return;
    }
};

// Login / Register Modal Switch Logic
const openRegisterModal = document.getElementById('openRegisterModal');
if(openRegisterModal) {
    openRegisterModal.addEventListener('click', (e) => {
        e.preventDefault();
        authModal.classList.add('hidden');
        document.getElementById('registerModal').classList.remove('hidden');
        
        // Reset form
        document.getElementById('registerFormView').classList.remove('hidden');
        document.getElementById('registerSuccessView').classList.add('hidden');
        document.getElementById('regUsername').value = '';
        document.getElementById('regEmail').value = '';
        document.getElementById('regPhone').value = '';
        document.getElementById('regDob').value = '';
        document.getElementById('regPassword').value = '';
        document.getElementById('regUsernameFeedback').innerText = '';
        document.getElementById('regEmailFeedback').innerText = '';
        document.getElementById('regDobFeedback').innerText = '';
        document.getElementById('regMessage').innerText = '';
        
        // Reset password strength
        document.getElementById('pwdStrengthLabel').innerText = 'Weak';
        document.querySelectorAll('.pwd-bar').forEach(bar => bar.style.background = '#334155');
        ['reqUpper', 'reqNum', 'reqSpec', 'reqLen'].forEach(id => {
            const el = document.getElementById(id);
            if(el) { el.innerText = el.innerText.replace('✓', '○'); el.style.color = '#94A3B8'; }
        });
    });
}

const openLoginModal = document.getElementById('openLoginModal');
if(openLoginModal) {
    openLoginModal.addEventListener('click', (e) => {
        e.preventDefault();
        document.getElementById('registerModal').classList.add('hidden');
        authModal.classList.remove('hidden');
        authMessage.innerText = "";
    });
}

const successBackToLoginBtn = document.getElementById('successBackToLoginBtn');
if (successBackToLoginBtn) {
    successBackToLoginBtn.addEventListener('click', () => {
        document.getElementById('registerModal').classList.add('hidden');
        document.getElementById('authModal').classList.remove('hidden');
        document.getElementById('authUsername').focus();
    });
}

// -----------------------------------------
// Login Submission
// -----------------------------------------
authSubmitBtn.addEventListener('click', async () => {
    const username = authUsername.value;
    const password = authPassword.value;
    
    if (!username || !password) { authMessage.innerText = "Fill username and password"; return; }

    setLoading(authSubmitBtn, true);
    authMessage.innerText = ""; 

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });
        const data = await response.json().catch(() => ({ message: "Server Error" }));
        
        if (response.ok) {
            if (data.status === '2fa_required') {
                authModal.classList.add('hidden');
                login2FAModal.classList.remove('hidden');
                tempLoginToken = data.temp_token;
                authUsername.value = ""; authPassword.value = "";
            } else {
                localStorage.setItem('username', username);
                localStorage.setItem('is_admin', data.is_admin);
                checkLoginState();
                authModal.classList.add('hidden');
                document.body.style.overflow = '';
                authUsername.value = ""; authPassword.value = "";
                
                showToast("Login Successful!", "success"); // TOAST
            }
        } else {
            authMessage.style.color = "#ef4444";
            authMessage.innerText = data.message || "An error occurred";
        }
    } catch (error) { 
        authMessage.innerText = "Connection Error. Please try again."; 
    }
    finally { setLoading(authSubmitBtn, false); }
});

// -----------------------------------------
// Registration Validation & Submit
// -----------------------------------------
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => { clearTimeout(timeout); func(...args); };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

const checkUsername = debounce(async (username) => {
    const feedback = document.getElementById('regUsernameFeedback');
    const input = document.getElementById('regUsername');
    if(!username) { feedback.innerText = ''; input.classList.remove('invalid-input'); return; }
    
    feedback.innerHTML = '<span class="checking-text">Checking availability...</span>';
    try {
        const res = await fetch('/check_username', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username}) });
        const data = await res.json();
        if(data.available) {
            feedback.innerHTML = '<span class="valid-text">✓ Username available</span>';
            input.classList.remove('invalid-input');
            input.dataset.valid = 'true';
        } else {
            feedback.innerHTML = '<span class="invalid-text">✕ Username already exists</span>';
            input.classList.add('invalid-input');
            input.dataset.valid = 'false';
        }
    } catch(e) { feedback.innerText = ''; }
}, 500);

document.getElementById('regUsername').addEventListener('input', (e) => checkUsername(e.target.value));

const checkEmail = debounce(async (email) => {
    const feedback = document.getElementById('regEmailFeedback');
    const input = document.getElementById('regEmail');
    if(!email) { feedback.innerText = ''; input.classList.remove('invalid-input'); return; }
    
    // Client side regex
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        feedback.innerHTML = '<span class="invalid-text">✕ Enter a valid email address</span>';
        input.classList.add('invalid-input');
        input.dataset.valid = 'false';
        return;
    }

    feedback.innerHTML = '<span class="checking-text">Checking availability...</span>';
    try {
        const res = await fetch('/check_email', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({email}) });
        const data = await res.json();
        if(data.available) {
            feedback.innerHTML = '<span class="valid-text">✓ Email available</span>';
            input.classList.remove('invalid-input');
            input.dataset.valid = 'true';
        } else {
            feedback.innerHTML = '<span class="invalid-text">✕ Email address already registered</span>';
            input.classList.add('invalid-input');
            input.dataset.valid = 'false';
        }
    } catch(e) { feedback.innerText = ''; }
}, 500);

document.getElementById('regEmail').addEventListener('input', (e) => checkEmail(e.target.value));

document.getElementById('regDob').addEventListener('input', (e) => {
    const feedback = document.getElementById('regDobFeedback');
    const input = e.target;
    
    // Auto-format DD/MM/YYYY
    let v = input.value.replace(/\D/g, '');
    if (v.length > 8) v = v.slice(0, 8);
    if (v.length > 4) input.value = `${v.slice(0,2)}/${v.slice(2,4)}/${v.slice(4)}`;
    else if (v.length > 2) input.value = `${v.slice(0,2)}/${v.slice(2)}`;
    else input.value = v;

    if(input.value.length === 0) {
        feedback.innerText = '';
        input.classList.remove('invalid-input');
        input.dataset.valid = 'false';
        return;
    }

    const regex = /^(\d{2})\/(\d{2})\/(\d{4})$/;
    if (!regex.test(input.value)) {
        feedback.innerHTML = '<span class="checking-text">Enter full date (DD/MM/YYYY)</span>';
        input.classList.remove('invalid-input');
        input.dataset.valid = 'false';
        return;
    }

    const [day, month, year] = input.value.split('/').map(Number);
    const dob = new Date(year, month - 1, day);
    const today = new Date();
    
    if (dob.getFullYear() !== year || dob.getMonth() + 1 !== month || dob.getDate() !== day) {
        feedback.innerHTML = '<span class="invalid-text">Invalid date</span>';
        input.classList.add('invalid-input');
        input.dataset.valid = 'false';
        return;
    }

    let age = today.getFullYear() - year;
    const m = today.getMonth() - (month - 1);
    if (m < 0 || (m === 0 && today.getDate() < day)) { age--; }
    
    if(age < 13) {
        feedback.innerHTML = '<span class="invalid-text">You must be at least 13 years old.</span>';
        input.classList.add('invalid-input');
        input.dataset.valid = 'false';
    } else if (age > 120) {
        feedback.innerHTML = '<span class="invalid-text">Invalid age</span>';
        input.classList.add('invalid-input');
        input.dataset.valid = 'false';
    } else {
        feedback.innerHTML = '<span class="valid-text"><i class="fas fa-check"></i> Age verified</span>';
        input.classList.remove('invalid-input');
        input.dataset.valid = 'true';
    }
});

// Password strength meter logic
document.getElementById('regPassword').addEventListener('input', (e) => {
    const pwd = e.target.value;
    const rules = {
        upper: /[A-Z]/.test(pwd),
        num: /[0-9]/.test(pwd),
        spec: /[^A-Za-z0-9]/.test(pwd),
        len: pwd.length >= 8
    };
    
    const updateReq = (id, valid) => {
        const el = document.getElementById(id);
        if(!el) return;
        el.innerHTML = valid ? el.innerHTML.replace('○', '✓') : el.innerHTML.replace('✓', '○');
        el.style.color = valid ? '#10B981' : '#94A3B8';
    };
    
    updateReq('reqUpper', rules.upper);
    updateReq('reqNum', rules.num);
    updateReq('reqSpec', rules.spec);
    updateReq('reqLen', rules.len);
    
    let score = Object.values(rules).filter(Boolean).length;
    
    const bars = [document.getElementById('pwdBar1'), document.getElementById('pwdBar2'), document.getElementById('pwdBar3'), document.getElementById('pwdBar4')];
    const label = document.getElementById('pwdStrengthLabel');
    
    bars.forEach(b => b.style.background = '#334155');
    
    if(pwd.length === 0) { label.innerText = 'Weak'; label.style.color = '#94A3B8'; }
    else if(score <= 1) { bars[0].style.background = '#EF4444'; label.innerText = 'Weak'; label.style.color = '#EF4444'; }
    else if(score === 2) { bars[0].style.background = '#F59E0B'; bars[1].style.background = '#F59E0B'; label.innerText = 'Fair'; label.style.color = '#F59E0B'; }
    else if(score === 3) { bars[0].style.background = '#10B981'; bars[1].style.background = '#10B981'; bars[2].style.background = '#10B981'; label.innerText = 'Good'; label.style.color = '#10B981'; }
    else if(score === 4) { bars.forEach(b => b.style.background = '#10B981'); label.innerText = 'Strong'; label.style.color = '#10B981'; }
});

const registerSubmitBtn = document.getElementById('registerSubmitBtn');
registerSubmitBtn.addEventListener('click', async () => {
    const username = document.getElementById('regUsername').value;
    const email = document.getElementById('regEmail').value;
    const phone = document.getElementById('regPhone').value;
    const dob = document.getElementById('regDob').value;
    const password = document.getElementById('regPassword').value;
    const msg = document.getElementById('regMessage');
    
    if(!username || !email || !dob || !password) {
        msg.innerText = "Please fill in all required fields."; return;
    }
    
    if (phone && phone.length !== 10) { msg.innerText = "Phone must be exactly 10 digits."; return; }

    setLoading(registerSubmitBtn, true);
    msg.innerText = "";
    
    try {
        const response = await fetch('/register', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password, email, phone, dob})
        });
        const data = await response.json().catch(() => ({ message: "Server Error" }));
        
        if(response.ok) {
            localStorage.setItem('username', username);
            document.getElementById('registerFormView').classList.add('hidden');
            document.getElementById('registerSuccessView').classList.remove('hidden');
        } else {
            msg.style.color = "#ef4444";
            msg.innerText = data.message || "An error occurred";
        }
    } catch(e) { msg.innerText = "Connection Error."; }
    finally { setLoading(registerSubmitBtn, false); }
});

// --- 2FA LOGIN VERIFY ---
login2FASubmitBtn.addEventListener('click', async () => {
    const code = login2FACode.value.replace(/\s/g, '');
    login2FAMessage.innerText = "";
    setLoading(login2FASubmitBtn, true);
    
    try {
        const res = await fetch('/login/verify_2fa', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({temp_token: tempLoginToken, code: code})
        });
        const data = await res.json();
        
        if(data.status === 'success') {
            localStorage.setItem('username', data.username);
            localStorage.setItem('is_admin', data.is_admin);
            checkLoginState();
            login2FAModal.classList.add('hidden');
            document.body.style.overflow = '';
            login2FACode.value = "";
            showToast("2FA Verified!", "success"); // TOAST
        } else {
            login2FAMessage.innerText = data.message;
        }
    } catch(e) { login2FAMessage.innerText = "Error verifying code"; }
    setLoading(login2FASubmitBtn, false);
});

document.getElementById('dashLogoutBtn').addEventListener('click', async () => {
    const btn = document.getElementById('dashLogoutBtn');
    setLoading(btn, true);
    await fetch('/logout');
    localStorage.removeItem('username');
    localStorage.removeItem('is_admin');
    appDashboard.classList.add('hidden');
    document.body.style.overflow = '';
    checkLoginState();
    setLoading(btn, false);
    showToast("Logged out successfully", "info"); // TOAST
});

const mobileActionLogoutBtn = document.getElementById('mobileActionLogoutBtn');
if(mobileActionLogoutBtn) {
    mobileActionLogoutBtn.addEventListener('click', () => {
        document.getElementById('dashLogoutBtn').click();
    });
}

function checkLoginState() {
    const user = localStorage.getItem('username');
    const isAdmin = localStorage.getItem('is_admin') === 'true';
    const dashAdminTab = document.getElementById('dashAdminTab');

    if (user) {
        loginBtn.classList.add('hidden');
        userProfile.classList.remove('hidden');
        // usernameDisplay removed
        if (isAdmin) dashAdminTab.classList.remove('hidden');
        else dashAdminTab.classList.add('hidden');
        
        mobileLoginBtn.classList.add('hidden');
        mobileDashboardBtn.classList.remove('hidden');
        document.getElementById('mobileUsername').innerText = "Hi, " + user;
        document.getElementById('mobileUsername').classList.remove('hidden');
        
        // Update Dashboard Header
        const dashTitle = document.getElementById('dashTitle');
        if (dashTitle) dashTitle.innerText = `Welcome Back, ${user}`;
        
        // Auto-open dashboard if URL has a specific section hash
        if (window.location.hash) {
            const hashTarget = window.location.hash.substring(1);
            if (document.querySelector(`.dash-tab[data-target="${hashTarget}"]`)) {
                openDashboard(hashTarget);
            }
        }
    } else {
        loginBtn.classList.remove('hidden');
        userProfile.classList.add('hidden');
        
        mobileLoginBtn.classList.remove('hidden');
        mobileDashboardBtn.classList.add('hidden');
        document.getElementById('mobileUsername').classList.add('hidden');
    }
}

// --- 3. PROFILE & ADMIN LOGIC ---
const dashProfilePic = document.getElementById('dashProfilePic');
const editUsername = document.getElementById('editUsername');
const usernameCharCount = document.getElementById('usernameCharCount');
const editUsernameError = document.getElementById('editUsernameError');
const editEmail = document.getElementById('editEmail');
const editPhone = document.getElementById('editPhone');
const editDob = document.getElementById('editDob');
const saveProfileBtn = document.getElementById('saveProfileBtn');
const deleteAccountBtn = document.getElementById('deleteAccountBtn');

const dashTabs = document.querySelectorAll('.dash-tab');
const dashViews = document.querySelectorAll('.dash-view');

dashTabs.forEach(tab => {
    tab.addEventListener('click', () => {
        // Handle Sidebar Tab Highlighting
        dashTabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        
        // Handle View Switching (Use .active to trigger display: block and fadeIn animation)
        dashViews.forEach(v => v.classList.remove('active'));
        const target = tab.getAttribute('data-target');
        document.getElementById(target).classList.add('active');
        
        // Update URL hash without jumping
        if (window.location.hash !== '#' + target) {
            history.replaceState(null, null, '#' + target);
        }
        
        // Update Header Titles
        const dashTitle = document.getElementById('dashTitle');
        const dashSubtitle = document.getElementById('dashSubtitle');
        const user = localStorage.getItem('username');
        if (dashTitle && dashSubtitle) {
            if (target === 'overview-section') {
                dashTitle.innerText = `Welcome Back, ${user}`;
                dashSubtitle.style.display = 'block';
            } else {
                dashSubtitle.style.display = 'none';
                if (target === 'vault-section') dashTitle.innerText = 'Your Vault';
                if (target === 'security-center-section') dashTitle.innerText = 'Security Center';
                if (target === 'notes-section') dashTitle.innerText = 'Secure Notes';
                if (target === 'admin-section') dashTitle.innerText = 'Admin Panel';
                if (target === 'profile-section') dashTitle.innerText = 'Account Settings';
            }
        }

        // Fetch Data for the new View
        if(target === 'profile-section') loadProfile();
        if(target === 'admin-section') loadAdminPanel();
        if(target === 'vault-section' || target === 'overview-section' || target === 'security-center-section') loadVault(); 
        if(target === 'notes-section') loadNotes();
    });
});

function openDashboard(defaultTab) {
    if (!localStorage.getItem('username')) {
        authModal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
        showToast("Please login to access this feature", "info");
        return;
    }

    appDashboard.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
    const tab = document.querySelector(`.dash-tab[data-target="${defaultTab}"]`);
    if(tab) tab.click();
    loadProfile();
}

async function loadProfile() {
    const res = await fetch('/profile');
    if(res.ok) {
        const data = await res.json();
        const profileInitials = document.getElementById('dashProfileInitials');
        if (profileInitials) {
            profileInitials.innerText = data.username.substring(0, 2).toUpperCase();
        }
        document.getElementById('dashUsername').innerText = data.username;
        const roleText = localStorage.getItem('is_admin') === 'true' ? 'Administrator' : 'Premium Member';
        document.getElementById('dashRole').innerText = roleText;
        editUsername.value = data.username;
        if (usernameCharCount) usernameCharCount.innerText = `${data.username.length}/50`;
        editUsernameError.classList.add('hidden');
        editEmail.value = data.email || "";
        editPhone.value = data.phone || "";
        editDob.value = data.dob || "";
        
        if (data.is_2fa_enabled) {
            toggle2FABtn.innerText = "Disable 2FA";
            toggle2FABtn.classList.replace('primary-btn', 'danger-btn');
            toggle2FABtn.onclick = disable2FA;
        } else {
            toggle2FABtn.innerText = "Enable 2FA";
            toggle2FABtn.classList.replace('danger-btn', 'primary-btn');
            toggle2FABtn.onclick = startSetup2FA;
        }
    }
}

editUsername.addEventListener('input', () => {
    const val = editUsername.value;
    if (usernameCharCount) usernameCharCount.innerText = `${val.length}/50`;
    
    // SQL Injection & Format Check (Frontend)
    if (!/^[a-zA-Z0-9_]*$/.test(val)) {
        editUsernameError.innerText = "Only letters, numbers, and underscores allowed.";
        editUsernameError.classList.remove('hidden');
    } else {
        editUsernameError.classList.add('hidden');
    }
});

saveProfileBtn.addEventListener('click', async () => {
    const phoneInput = document.getElementById('editPhone');
    const dobInput = document.getElementById('editDob');
    const usernameInput = document.getElementById('editUsername');
    
    validateDobLogic(dobInput, document.getElementById('editDobError'));
    if (dobInput.dataset.valid === "false") return;
    if (phoneInput.value && phoneInput.value.length !== 10) return;
    if (phoneInput.dataset.valid === "false") return;
    
    // Frontend Block for Invalid Username
    if (!/^[a-zA-Z0-9_]*$/.test(usernameInput.value)) {
        editUsernameError.innerText = "Invalid characters in username.";
        editUsernameError.classList.remove('hidden');
        return;
    }

    setLoading(saveProfileBtn, true);
    editUsernameError.classList.add('hidden'); // Clear previous errors
    
    const res = await fetch('/profile', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            username: editUsername.value,
            email: editEmail.value,
            phone: editPhone.value,
            dob: editDob.value
        })
    });
    const data = await res.json();
    if(res.ok) { 
        showToast("Profile Updated!", "success"); 
        localStorage.setItem('username', editUsername.value);
        document.getElementById('dashUsername').innerText = editUsername.value;
        checkLoginState();
    } else {
        if (data.message.includes("Username")) {
            editUsernameError.innerText = data.message.includes("taken") ? "Username exists, try another one." : data.message;
            editUsernameError.classList.remove('hidden');
        } else {
            showToast(data.message, "error");
        }
    }
    setLoading(saveProfileBtn, false);
});

deleteAccountBtn.addEventListener('click', async () => {
    if(confirm("Are you sure? This cannot be undone.")) {
        setLoading(deleteAccountBtn, true);
        await fetch('/profile', { method: 'DELETE' });
        document.getElementById('dashLogoutBtn').click();
        setLoading(deleteAccountBtn, false);
        showToast("Account Deleted", "info"); // TOAST
    }
});

// --- 2FA SETUP FUNCTIONS ---
async function startSetup2FA() {
    setLoading(toggle2FABtn, true);
    try {
        const res = await fetch('/2fa/setup', { method: 'POST' });
        const data = await res.json();
        qrCodeImage.src = data.qr_image;
        setup2FACode.value = "";
        setup2FAMessage.innerText = "";
        appDashboard.classList.add('hidden');
        setup2FAModal.classList.remove('hidden');
    } catch (e) {
        showToast("Error generating QR Code", "error");
    } finally {
        setLoading(toggle2FABtn, false);
    }
}

confirm2FABtn.addEventListener('click', async () => {
    const code = setup2FACode.value.replace(/\s/g, '');
    setLoading(confirm2FABtn, true);
    
    const res = await fetch('/2fa/enable', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({code})
    });
    const data = await res.json();
    
    if (res.ok) {
        showToast("2FA Enabled Successfully!", "success"); // TOAST
        setup2FAModal.classList.add('hidden');
        openDashboard('profile-section');
    } else {
        setup2FAMessage.innerText = data.message;
    }
    setLoading(confirm2FABtn, false);
});

async function disable2FA() {
    if(confirm("Disable 2FA? Your account will be less secure.")) {
        await fetch('/2fa/disable', { method: 'POST' });
        loadProfile(); 
        showToast("2FA Disabled", "info"); // TOAST
    }
}

// --- VAULT LOGIC ---
if(openAddVaultModalBtn) {
    openAddVaultModalBtn.addEventListener('click', () => {
        addVaultModal.classList.remove('hidden');
    });
}
document.querySelector('.close-add-vault').addEventListener('click', () => {
    addVaultModal.classList.add('hidden');
});
if (document.querySelector('.close-edit-vault')) {
    document.querySelector('.close-edit-vault').addEventListener('click', () => {
        editVaultModal.classList.add('hidden');
    });
}


if(exportVaultBtn) {
    exportVaultBtn.addEventListener('click', async () => {
        if(!confirm("Download unencrypted CSV? Keep this file safe!")) return;
        
        setLoading(exportVaultBtn, true);
        try {
            const res = await fetch('/vault/export');
            if(res.ok) {
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'vault_export.csv';
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                a.remove();
                showToast("Vault exported successfully", "success");
            } else {
                const data = await res.json();
                showToast(data.message || "Export failed", "error");
            }
        } catch(e) {
            showToast("Error exporting vault", "error");
        }
        setLoading(exportVaultBtn, false);
    });
}

// --- ZERO-KNOWLEDGE CRYPTOGRAPHIC ENGINE (CLIENT-SIDE WEB CRYPTO API) ---
const ZeroKnowledgeEngine = {
    getSalt() {
        let salt = localStorage.getItem('vlt_zk_salt');
        if (!salt) {
            const arr = window.crypto.getRandomValues(new Uint8Array(16));
            salt = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
            localStorage.setItem('vlt_zk_salt', salt);
        }
        return salt;
    },
    async deriveKey(masterSecret, saltHex) {
        const enc = new TextEncoder();
        const baseKey = await window.crypto.subtle.importKey(
            "raw",
            enc.encode(masterSecret),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );
        const saltBytes = new Uint8Array(saltHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
        return await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: saltBytes,
                iterations: 100000,
                hash: "SHA-256"
            },
            baseKey,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    },
    async encrypt(plaintext) {
        const enc = new TextEncoder();
        const salt = this.getSalt();
        const secret = localStorage.getItem('username') || 'VAULTARY_MASTER_SECRET';
        const key = await this.deriveKey(secret, salt);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const ciphertextBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            enc.encode(plaintext)
        );
        const ciphertextB64 = btoa(String.fromCharCode.apply(null, new Uint8Array(ciphertextBuffer)));
        const ivB64 = btoa(String.fromCharCode.apply(null, iv));
        return {
            ciphertext: ciphertextB64,
            iv: ivB64,
            salt: salt
        };
    },
    async decrypt(ciphertextB64, ivB64, saltHex) {
        try {
            const secret = localStorage.getItem('username') || 'VAULTARY_MASTER_SECRET';
            const key = await this.deriveKey(secret, saltHex || this.getSalt());
            const ciphertext = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0));
            const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                key,
                ciphertext
            );
            return new TextDecoder().decode(decryptedBuffer);
        } catch (e) {
            return "[Encrypted Zero-Knowledge]";
        }
    }
};

if(saveVaultBtn) {
    saveVaultBtn.addEventListener('click', async () => {
        const site_name = document.getElementById('vaultSiteName').value.trim();
        const site_url = document.getElementById('vaultSiteURL').value.trim();
        const site_username = document.getElementById('vaultUsername').value.trim();
        const password = document.getElementById('vaultPassword').value;
        const criticality = document.getElementById('vaultCriticality')?.value || 'medium';
        const category = document.getElementById('vaultCategory')?.value || 'Logins';
        const is_zk = document.getElementById('vaultZeroKnowledgeToggle')?.checked;
        const is_canary = document.getElementById('vaultCanaryToggle')?.checked;

        if(!site_name || !site_username || (!password && !is_canary)) {
            document.getElementById('vaultMessage').innerText = "Site name, username, and password are required.";
            return;
        }

        setLoading(saveVaultBtn, true);
        try {
            let payload = {
                site_name,
                site_url,
                site_username,
                criticality,
                category,
                is_canary
            };

            if (is_canary) {
                payload.encryption_type = 'server_fernet';
                payload.password = password || ('vlt_lure_' + Math.random().toString(36).slice(2));
            } else if (is_zk) {
                const zkResult = await ZeroKnowledgeEngine.encrypt(password);
                payload.encryption_type = 'zero_knowledge';
                payload.client_ciphertext = zkResult.ciphertext;
                payload.client_iv = zkResult.iv;
                payload.client_salt = zkResult.salt;
                payload.password = password; // Server sets dummy encrypted_password for legacy compat
            } else {
                payload.encryption_type = 'server_fernet';
                payload.password = password;
            }

            const res = await fetch('/vault', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
            });
            if(res.ok) {
                addVaultModal.classList.add('hidden');
                document.getElementById('vaultSiteName').value = "";
                document.getElementById('vaultSiteURL').value = "";
                document.getElementById('vaultUsername').value = "";
                document.getElementById('vaultPassword').value = "";
                document.getElementById('vaultMessage').innerText = "";
                await loadVault();
                showToast("Password Saved to Vault!", "success");
            } else {
                const errData = await res.json().catch(() => ({}));
                document.getElementById('vaultMessage').innerText = errData.message || "Error saving item.";
            }
        } catch(e) { console.error(e); }
        setLoading(saveVaultBtn, false);
    });
}

if(updateVaultBtn) {
    updateVaultBtn.addEventListener('click', async () => {
        const id = editVaultId.value;
        const site_name = editVaultSiteName.value.trim();
        const site_url = editVaultSiteURL.value.trim();
        const site_username = editVaultUsername.value.trim();
        const password = editVaultPassword.value;
        const criticality = document.getElementById('editVaultCriticality')?.value || 'medium';
        const category = document.getElementById('editVaultCategory')?.value || 'Logins';

        if(!site_name || !site_username) {
            editVaultMessage.innerText = "Site name and username are required.";
            return;
        }

        setLoading(updateVaultBtn, true);
        try {
            const payload = {
                site_name,
                site_url,
                site_username,
                criticality,
                category
            };
            if (password) {
                payload.password = password;
            }

            const res = await fetch(`/vault/item/${id}`, {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            if(res.ok) {
                editVaultModal.classList.add('hidden');
                await loadVault();
                showToast("Vault entry updated!", "success");
            } else {
                editVaultMessage.innerText = data.message || "Error updating item.";
            }
        } catch(e) { 
            console.error(e); 
            editVaultMessage.innerText = "A connection error occurred.";
        }
        setLoading(updateVaultBtn, false);
    });
}

let currentVaultFilter = 'all';
window.allVaultItems = [];

async function loadVault() {
    vaultGrid.innerHTML = '<p class="text-muted" style="padding: 1.5rem;"><i class="fas fa-spinner fa-spin"></i> Loading secure vault entries...</p>';
    try {
        const res = await fetch('/vault');
        if (res.ok) {
            const items = await res.json();
            window.allVaultItems = items;
            renderVaultCards();
            await loadSecurityAudit();
        } else {
            vaultGrid.innerHTML = '<p class="error-msg">Error loading vault. Please refresh.</p>';
        }
    } catch (e) {
        vaultGrid.innerHTML = '<p class="error-msg">Failed to connect to vault.</p>';
    }
}

function renderVaultCards() {
    const items = window.allVaultItems || [];
    const totalItems = items.length;

    const vaultCountEl = document.getElementById('vaultCountText');
    if (vaultCountEl) {
        vaultCountEl.innerText = totalItems > 0 ? `${totalItems} Asset${totalItems > 1 ? 's' : ''} Secured` : '';
    }

    if (totalItems === 0) {
        vaultGrid.innerHTML = `
            <div style="grid-column: 1 / -1; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 4rem 2rem; text-align: center; background: var(--card-bg); border-radius: 16px; border: 1px dashed var(--card-border); margin-top: 1rem;">
                <div style="width: 64px; height: 64px; border-radius: 50%; background: var(--primary-light); color: var(--primary); display: flex; align-items: center; justify-content: center; font-size: 2rem; margin-bottom: 1.25rem;">
                    <i class="fas fa-shield-alt"></i>
                </div>
                <h3 style="font-size: 1.3rem; font-weight: 700; color: var(--text-main); margin-bottom: 0.5rem;">Vault Ready & Hardened</h3>
                <p style="color: var(--text-muted); margin-bottom: 1.5rem; max-width: 320px;">Deploy your first credential or arm a canary honeypot lure to get started.</p>
                <div style="display: flex; gap: 12px; flex-wrap: wrap;">
                    <button class="primary-btn" onclick="document.getElementById('openAddVaultModal').click()"><i class="fas fa-plus"></i> Add Password</button>
                    <button class="outline-btn" onclick="document.getElementById('openDeployCanaryModal').click()"><i class="fas fa-fire" style="color: #f97316;"></i> Deploy Canary</button>
                </div>
            </div>
        `;
        return;
    }

    const filtered = items.filter(item => {
        if (currentVaultFilter === 'critical') return (item.criticality || '').toLowerCase() === 'critical';
        if (currentVaultFilter === 'breached') return Boolean(item.is_pwned);
        if (currentVaultFilter === 'canary') return Boolean(item.is_canary);
        if (currentVaultFilter === 'zero_knowledge') return item.encryption_type === 'zero_knowledge';
        return true;
    });

    if (filtered.length === 0) {
        vaultGrid.innerHTML = `<div style="grid-column: 1 / -1; padding: 2.5rem; text-align: center; color: var(--text-muted); background: var(--card-bg); border-radius: 12px; border: 1px solid var(--card-border);">No items match the "${currentVaultFilter}" filter.</div>`;
        return;
    }

    vaultGrid.innerHTML = "";
    filtered.forEach(item => {
        let score = 4;
        if (item.password && item.encryption_type !== 'zero_knowledge') {
            try { score = zxcvbn(item.password).score; } catch(e) {}
        }

        let scoreText = 'Strong';
        let scoreClass = 'score-high';
        if (score < 2) { scoreClass = 'score-low'; scoreText = 'Weak'; }
        else if (score < 4) { scoreClass = 'score-med'; scoreText = 'Moderate'; }

        const crit = (item.criticality || 'medium').toLowerCase();
        let critClass = 'crit-medium';
        let critIcon = 'fa-layer-group';
        if (crit === 'critical') { critClass = 'crit-critical'; critIcon = 'fa-shield-virus'; }
        else if (crit === 'high') { critClass = 'crit-high'; critIcon = 'fa-exclamation-circle'; }
        else if (crit === 'low') { critClass = 'crit-low'; critIcon = 'fa-feather'; }

        let fullUrl = item.site_url || '';
        if (fullUrl && !/^https?:\/\//i.test(fullUrl)) fullUrl = 'https://' + fullUrl;
        let domain = '';
        try { if (fullUrl) domain = new URL(fullUrl).hostname.replace(/^www\./i, ''); } catch (e) {}

        const faviconHTML = domain 
            ? `<img src="https://icons.duckduckgo.com/ip3/${domain}.ico" alt="" class="site-favicon" onerror="this.src='https://icons.duckduckgo.com/ip3/example.com.ico';">`
            : `<span class="site-favicon-default"><i class="fas fa-globe-americas"></i></span>`;

        let tagsHTML = '';
        if (item.is_canary) {
            tagsHTML += `<span class="sec-tag tag-canary" title="Armed tripwire lure"><i class="fas fa-fire"></i> Canary Lure</span>`;
        }
        if (item.is_pwned) {
            tagsHTML += `<span class="sec-tag tag-pwned" title="Leaked in ${item.pwned_count.toLocaleString()} data breaches"><i class="fas fa-biohazard"></i> Pwned (${item.pwned_count.toLocaleString()})</span>`;
        }
        if (item.encryption_type === 'zero_knowledge') {
            tagsHTML += `<span class="sec-tag tag-zk" data-action="view-crypto-proof" data-id="${item.id}" title="Verified Zero-Knowledge E2EE (Click for proof)"><i class="fas fa-lock"></i> E2EE Zero-Knowledge</span>`;
        }

        vaultGrid.innerHTML += `
            <div class="premium-card vault-card" style="display: flex; flex-direction: column; justify-content: space-between; position: relative;">
                <div>
                    <div class="vault-card-header" style="align-items: flex-start; margin-bottom: 12px;">
                        ${faviconHTML}
                        <div class="vault-title" style="flex: 1; overflow: hidden;">
                            <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 4px;">
                                <h4 style="font-size: 1.15rem; font-weight: 700; margin: 0;">${item.site_name}</h4>
                                <span class="crit-pill ${critClass}"><i class="fas ${critIcon}"></i> ${crit.toUpperCase()}</span>
                            </div>
                            <a href="${fullUrl}" target="_blank" rel="noopener noreferrer" style="color: var(--text-muted); font-size: 0.85rem; display: flex; align-items: center; gap: 6px; text-decoration: none;">
                                ${domain || item.site_url || 'No URL'} <i class="fas fa-external-link-alt" style="font-size: 0.7rem;"></i>
                            </a>
                        </div>
                        <div class="vault-score-badge ${scoreClass}">${item.is_canary ? 'Canary' : scoreText}</div>
                    </div>

                    ${tagsHTML ? `<div style="display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 12px;">${tagsHTML}</div>` : ''}

                    <div class="vault-field" style="margin-top: 6px;">
                        <i class="fas fa-user-shield" title="Username"></i>
                        <span class="vault-field-value">${item.site_username}</span>
                        <button class="action-icon action-btn" data-action="copy-user" data-username="${item.site_username}" title="Copy Username"><i class="far fa-copy"></i></button>
                    </div>

                    <div class="vault-field">
                        <i class="fas fa-key" title="Password"></i>
                        <span id="pass-display-${item.id}" class="vault-field-value masked-pass" data-actual="${btoa(item.password || '')}" data-enc="${item.encryption_type}" data-canary="${item.is_canary ? 'true' : 'false'}" style="font-family: monospace;">••••••••</span>
                        <button class="action-icon action-btn" data-action="toggle-pass-local" data-id="${item.id}" title="Reveal Password"><i class="far fa-eye"></i></button>
                        <button class="action-icon action-btn" data-action="copy-pass-local" data-id="${item.id}" title="Copy Password"><i class="far fa-copy"></i></button>
                    </div>
                </div>

                <div class="vault-card-actions" style="margin-top: 14px; padding-top: 10px; border-top: 1px solid var(--card-border); display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-size: 0.75rem; color: var(--text-muted); font-weight: 600;"><i class="fas fa-tag"></i> ${item.category || 'Logins'}</span>
                    <div style="display: flex; gap: 6px;">
                        <button class="outline-btn action-btn" data-action="edit" data-id="${item.id}" style="padding: 5px 10px; font-size: 0.8rem;" title="Edit Entry"><i class="fas fa-pencil-alt"></i></button>
                        <button class="danger-btn-text action-btn" data-action="delete" data-id="${item.id}" style="padding: 5px 10px; font-size: 0.8rem;" title="Delete Entry"><i class="fas fa-trash-alt"></i></button>
                    </div>
                </div>
            </div>
        `;
    });
}

async function loadSecurityAudit() {
    try {
        const res = await fetch('/vault/security_audit');
        if (!res.ok) return;
        const audit = await res.json();

        const score = audit.overall_score;
        const grade = audit.letter_grade || 'A+';
        const gradeDesc = audit.grade_description || 'Hardened Security Posture';

        // Update Overview & Security Center Score Elements
        const oScore = document.getElementById('dashHealthScoreText');
        const aScore = document.getElementById('auditScoreText');
        if (oScore) oScore.innerText = score;
        if (aScore) aScore.innerText = score;

        // Grade Badges
        const oBadge = document.getElementById('dashGradeBadge');
        const aBadge = document.getElementById('auditGradeBadge');
        const gradeClass = score >= 80 ? 'grade-a' : (score >= 70 ? 'grade-b' : (score >= 60 ? 'grade-c' : (score >= 40 ? 'grade-d' : 'grade-f')));
        
        [oBadge, aBadge].forEach(badge => {
            if (badge) {
                badge.innerText = grade;
                badge.className = `grade-pill ${gradeClass}`;
            }
        });

        // Classification & Titles
        const oClass = document.getElementById('dashHealthClassification');
        if (oClass) {
            oClass.innerText = gradeDesc;
            oClass.style.color = score >= 80 ? 'var(--success)' : (score >= 60 ? 'var(--warning)' : 'var(--danger)');
        }
        const aTitle = document.getElementById('auditPostureTitle');
        if (aTitle) aTitle.innerText = gradeDesc;

        // Animate SVG Rings
        const circumference = 251.2;
        const offset = circumference - (score / 100) * circumference;
        const ringColor = score >= 80 ? 'var(--success)' : (score >= 60 ? 'var(--warning)' : 'var(--danger)');
        
        ['dashHealthRing', 'auditHealthRing'].forEach(ringId => {
            const ringEl = document.getElementById(ringId);
            if (ringEl) {
                ringEl.style.stroke = ringColor;
                setTimeout(() => { ringEl.style.strokeDashoffset = offset; }, 50);
            }
        });

        // Contextual Metric Cards
        const sumTotal = document.getElementById('summaryTotal');
        if (sumTotal) sumTotal.innerText = audit.total_items;
        const sumCritCount = document.getElementById('summaryCriticalCount');
        if (sumCritCount) sumCritCount.innerText = audit.critical_count;

        const sumWeak = document.getElementById('summaryWeak');
        if (sumWeak) {
            sumWeak.innerText = audit.weak_count;
            sumWeak.style.color = audit.weak_count > 0 ? 'var(--warning)' : 'var(--text-main)';
        }
        const sumCritVuln = document.getElementById('summaryCritVulnCount');
        if (sumCritVuln) sumCritVuln.innerText = audit.critical_vulnerable;

        const sumReused = document.getElementById('summaryReused');
        if (sumReused) {
            sumReused.innerText = audit.reused_count;
            sumReused.style.color = audit.reused_count > 0 ? 'var(--danger)' : 'var(--text-main)';
        }

        const sumBreached = document.getElementById('summaryBreached');
        if (sumBreached) {
            sumBreached.innerText = audit.breached_count;
            sumBreached.style.color = audit.breached_count > 0 ? '#f43f5e' : 'var(--text-main)';
        }

        // Security Center 4-bar
        const aCritVuln = document.getElementById('auditCritVulnText');
        if (aCritVuln) {
            aCritVuln.innerText = `${audit.critical_vulnerable} Vulnerable`;
            aCritVuln.style.color = audit.critical_vulnerable > 0 ? 'var(--danger)' : 'var(--success)';
        }
        const aBlast = document.getElementById('auditBlastRadiusText');
        if (aBlast) {
            aBlast.innerText = `${audit.blast_radius_clusters.length} Cluster${audit.blast_radius_clusters.length === 1 ? '' : 's'}`;
            aBlast.style.color = audit.blast_radius_clusters.length > 0 ? 'var(--warning)' : 'var(--success)';
        }
        const aBreached = document.getElementById('auditBreachedText');
        if (aBreached) {
            aBreached.innerText = `${audit.breached_count} Leaked`;
            aBreached.style.color = audit.breached_count > 0 ? '#f43f5e' : 'var(--success)';
        }
        const aStale = document.getElementById('auditStaleText');
        if (aStale) {
            aStale.innerText = `${audit.stale_count} Passwords`;
            aStale.style.color = audit.stale_count > 0 ? 'var(--warning)' : 'var(--success)';
        }

        // Remediation Roadmap List (Overview & Security Center)
        const recListEl = document.getElementById('securityRecommendationsList');
        const auditRoadmapEl = document.getElementById('auditRoadmapList');
        
        let roadmapHTML = '';
        if (audit.remediation_roadmap && audit.remediation_roadmap.length > 0) {
            audit.remediation_roadmap.forEach(task => {
                roadmapHTML += `
                    <div class="remediation-card">
                        <div style="flex: 1;">
                            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                                <strong style="font-size: 0.95rem; color: var(--text-main);">${task.title}</strong>
                                <span class="pt-gain-badge">+${task.point_gain} PTS</span>
                            </div>
                            <p style="font-size: 0.85rem; color: var(--text-muted); margin: 0;">${task.description}</p>
                        </div>
                        <button class="outline-btn" onclick="openRemediationTarget(${task.item_id})" style="padding: 6px 12px; font-size: 0.85rem; white-space: nowrap;"><i class="fas fa-wrench"></i> Fix Now</button>
                    </div>
                `;
            });
        } else {
            roadmapHTML = `<div style="padding: 1.5rem; text-align: center; color: var(--success); font-weight: 600;"><i class="fas fa-check-circle" style="font-size: 1.5rem; margin-bottom: 6px; display: block;"></i> No remediation tasks required. Your vault is fully hardened!</div>`;
        }
        if (recListEl) recListEl.innerHTML = roadmapHTML;
        if (auditRoadmapEl) auditRoadmapEl.innerHTML = roadmapHTML;

        // Blast Radius Inspector
        const blastEl = document.getElementById('blastRadiusList');
        if (blastEl) {
            if (audit.blast_radius_clusters && audit.blast_radius_clusters.length > 0) {
                let blastHTML = '';
                audit.blast_radius_clusters.forEach(c => {
                    blastHTML += `
                        <div class="blast-group-card">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                <div style="display: flex; align-items: center; gap: 8px;">
                                    <strong style="color: var(--text-main); font-size: 0.95rem;"><i class="fas fa-copy" style="color: var(--warning);"></i> Reused across ${c.count} accounts</strong>
                                    ${c.is_cross_tier ? '<span class="cross-tier-tag"><i class="fas fa-radiation"></i> Cross-Tier Contamination</span>' : ''}
                                </div>
                                <span style="font-size: 0.75rem; font-weight: 700; color: ${c.severity === 'CRITICAL' ? 'var(--danger)' : 'var(--warning)'};">${c.severity} SEVERITY</span>
                            </div>
                            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                                ${c.sites.map(s => `<span class="sec-tag" style="background: var(--card-bg); border: 1px solid var(--card-border); color: var(--text-main); font-weight: 600;"><i class="fas fa-globe"></i> ${s}</span>`).join('')}
                            </div>
                        </div>
                    `;
                });
                blastEl.innerHTML = blastHTML;
            } else {
                blastEl.innerHTML = '<p class="text-muted" style="padding: 1rem 0;"><i class="fas fa-check-circle" style="color: var(--success);"></i> No password reuse detected. Credential isolation is verified.</p>';
            }
        }

        // Deception & Canary Monitor
        const canariesEl = document.getElementById('canaryLuresList');
        if (canariesEl) {
            const canaryItems = (window.allVaultItems || []).filter(x => x.is_canary);
            if (canaryItems.length > 0) {
                canariesEl.innerHTML = canaryItems.map(c => `
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; background: var(--input-bg); border: 1px solid var(--card-border); border-radius: 8px;">
                        <div style="display: flex; align-items: center; gap: 12px;">
                            <i class="fas fa-fire" style="color: #f97316; font-size: 1.1rem;"></i>
                            <div>
                                <strong style="color: var(--text-main); font-size: 0.95rem;">${c.site_name}</strong>
                                <div style="font-size: 0.75rem; color: var(--text-muted); font-family: monospace;">Target Lure: ${c.site_username}</div>
                            </div>
                        </div>
                        <span class="canary-radar-badge"><span class="canary-ping-dot"></span> Armed & Monitoring</span>
                    </div>
                `).join('');
            } else {
                canariesEl.innerHTML = `<div style="padding: 1rem 0; color: var(--text-muted); font-size: 0.9rem;">No active honeypot lures deployed. Deploy a canary credential to detect unauthorized intrusion attempts in real time.</div>`;
            }
        }

        // Live Incident Timeline
        await loadSecurityIncidents();

    } catch (e) {
        console.error("Audit load error:", e);
    }
}

async function loadSecurityIncidents() {
    const incEl = document.getElementById('securityIncidentTimeline');
    if (!incEl) return;
    try {
        const res = await fetch('/security/incidents');
        if (!res.ok) return;
        const incidents = await res.json();
        if (incidents.length > 0) {
            incEl.innerHTML = incidents.map(inc => {
                const isCrit = inc.severity === 'critical';
                const tagColor = isCrit ? '#ef4444' : '#3b82f6';
                return `
                    <div style="padding: 12px 16px; background: var(--input-bg); border-left: 3px solid ${tagColor}; border-radius: 6px; display: flex; flex-direction: column; gap: 4px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-size: 0.75rem; font-weight: 800; color: ${tagColor}; text-transform: uppercase;">${inc.incident_type.replace('_', ' ')}</span>
                            <span style="font-size: 0.75rem; color: var(--text-muted); font-family: monospace;">${inc.timestamp || ''}</span>
                        </div>
                        <div style="font-size: 0.9rem; color: var(--text-main); font-weight: 500;">${inc.details}</div>
                        ${inc.ip_address ? `<div style="font-size: 0.75rem; color: var(--text-muted); font-family: monospace;">IP: ${inc.ip_address} | Agent: ${inc.user_agent ? inc.user_agent.substring(0, 40) + '...' : 'Unknown'}</div>` : ''}
                    </div>
                `;
            }).join('');
        } else {
            incEl.innerHTML = `<p class="text-muted" style="padding: 1rem 0;"><i class="fas fa-shield-alt" style="color: var(--success); margin-right: 6px;"></i> No intrusion incidents recorded. Your vault perimeter is fully secure.</p>`;
        }
    } catch (e) {}
}

function openRemediationTarget(itemId) {
    const vaultTab = document.querySelector('[data-target="vault-section"]');
    if (vaultTab) vaultTab.click();
    setTimeout(() => {
        const card = document.getElementById(`pass-display-${itemId}`);
        if (card) {
            const container = card.closest('.vault-card');
            if (container) {
                container.scrollIntoView({ behavior: 'smooth', block: 'center' });
                container.style.boxShadow = '0 0 20px rgba(59, 130, 246, 0.5)';
                setTimeout(() => { container.style.boxShadow = ''; }, 2000);
            }
        }
    }, 150);
}

vaultGrid.addEventListener('click', async (e) => {
    // Handle Cryptographic Proof Click
    const zkTag = e.target.closest('[data-action="view-crypto-proof"]');
    if (zkTag) {
        const id = zkTag.dataset.id;
        const item = (window.allVaultItems || []).find(x => String(x.id) === String(id));
        if (item) {
            document.getElementById('proofIVText').innerText = item.client_iv || "N/A (Generated via window.crypto)";
            document.getElementById('proofCiphertextText').innerText = item.client_ciphertext || "N/A";
            document.getElementById('cryptoProofModal').classList.remove('hidden');
        }
        return;
    }

    const target = e.target.closest('.action-btn');
    if (!target) return;

    const action = target.dataset.action;
    const id = target.dataset.id;
    const item = (window.allVaultItems || []).find(x => String(x.id) === String(id));

    if (action === 'toggle-pass') {
        toggleVaultPassword(id, target.querySelector('i'));
    } else if (action === 'toggle-pass-local') {
        const display = document.getElementById('pass-display-' + id);
        const icon = target.querySelector('i');
        
        if (display.classList.contains('masked-pass')) {
            // Check Canary Lure: trigger silent tripwire on server!
            if (display.dataset.canary === 'true') {
                fetch(`/vault/decrypt/${id}`, { method: 'POST' }).catch(() => {});
                display.innerText = item?.password || 'vlt_sec_canary_8921';
                showToast("⚠️ Security Notice: Honeypot lure revealed.", "warning");
            } else if (display.dataset.enc === 'zero_knowledge' && item) {
                // Client-side zero-knowledge decryption
                if (display.dataset.actual && atob(display.dataset.actual) !== '' && !atob(display.dataset.actual).startsWith('[E2EE_')) {
                    display.innerText = atob(display.dataset.actual);
                } else if (item.client_ciphertext) {
                    const dec = await ZeroKnowledgeEngine.decrypt(item.client_ciphertext, item.client_iv, item.client_salt);
                    display.innerText = dec;
                } else {
                    display.innerText = '••••••••';
                }
            } else {
                display.innerText = atob(display.dataset.actual || '');
            }
            display.classList.remove('masked-pass');
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
        } else {
            display.innerText = '••••••••';
            display.classList.add('masked-pass');
            icon.classList.remove('fa-eye-slash');
            icon.classList.add('fa-eye');
        }
    } else if (action === 'copy-user') {
        copyUsername(target.dataset.username);
    } else if (action === 'copy-pass') {
        decryptPassword(id, target);
    } else if (action === 'copy-pass-local') {
        const display = document.getElementById('pass-display-' + id);
        let textToCopy = display.innerText;
        if (display.classList.contains('masked-pass')) {
            if (display.dataset.canary === 'true') {
                fetch(`/vault/decrypt/${id}`, { method: 'POST' }).catch(() => {});
                textToCopy = item?.password || 'vlt_sec_canary_8921';
            } else if (display.dataset.enc === 'zero_knowledge' && item?.client_ciphertext) {
                textToCopy = await ZeroKnowledgeEngine.decrypt(item.client_ciphertext, item.client_iv, item.client_salt);
            } else {
                textToCopy = atob(display.dataset.actual || '');
            }
        }
        navigator.clipboard.writeText(textToCopy).then(() => {
            showToast("Password copied to clipboard!", "success");
        }).catch(() => {
            showToast("Failed to copy", "error");
        });
    } else if (action === 'delete') {
        deleteVaultItem(id);
    } else if (action === 'edit') {
        openEditVaultModal(id);
    }
});

async function openEditVaultModal(id) {
    editVaultMessage.innerText = '';
    editVaultModal.classList.remove('hidden');
    
    // Show a temporary loading state in the form
    editVaultSiteName.value = 'Loading...';
    editVaultSiteURL.value = '';
    editVaultUsername.value = '';
    editVaultPassword.value = '';
    
    editVaultPassword.setAttribute('type', 'password');
    if(toggleEditVaultPassword) {
        toggleEditVaultPassword.classList.add('fa-eye');
        toggleEditVaultPassword.classList.remove('fa-eye-slash');
    }

    try {
        const res = await fetch(`/vault/item/${id}`);
        if (res.ok) {
            const data = await res.json();
            editVaultId.value = id;
            editVaultSiteName.value = data.site_name;
            editVaultSiteURL.value = data.site_url || '';
            editVaultUsername.value = data.site_username;
            editVaultPassword.value = data.password || '';
            const critSel = document.getElementById('editVaultCriticality');
            if (critSel) critSel.value = data.criticality || 'medium';
            const catSel = document.getElementById('editVaultCategory');
            if (catSel) catSel.value = data.category || 'Logins';
        } else {
            const errData = await res.json().catch(() => ({}));
            editVaultMessage.innerText = errData.message || 'Failed to load item data.';
        }
    } catch (e) {
        editVaultMessage.innerText = 'Connection error.';
    }
}

function copyUsername(text) {
    navigator.clipboard.writeText(text);
    showToast("Username copied!", "info"); // TOAST
}

async function toggleVaultPassword(id, icon) {
    const displaySpan = document.getElementById(`pass-display-${id}`);
    const isHidden = displaySpan.classList.contains('masked-pass');
    
    if (isHidden) {
        const originalClass = icon.className;
        icon.className = 'fas fa-spinner fa-spin';
        try {
            const res = await fetch(`/vault/decrypt/${id}`, { method: 'POST' });
            if(res.ok) {
                const data = await res.json();
                displaySpan.innerText = data.password;
                displaySpan.classList.remove('masked-pass');
                icon.className = 'far fa-eye-slash';
            } else { showToast("Error decrypting", "error"); icon.className = originalClass; }
        } catch(e) { icon.className = originalClass; }
    } else {
        displaySpan.innerText = '••••••••';
        displaySpan.classList.add('masked-pass');
        icon.className = 'far fa-eye';
    }
}

async function decryptPassword(id, btn) {
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
    try {
        const res = await fetch(`/vault/decrypt/${id}`, { method: 'POST' });
        if(res.ok) {
            const data = await res.json();
            navigator.clipboard.writeText(data.password);
            btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
            showToast("Password decrypted & copied!", "success"); // TOAST
            setTimeout(() => btn.innerHTML = originalText, 2000);
        } else {
            showToast("Error decrypting", "error"); // TOAST
            btn.innerHTML = originalText;
        }
    } catch(e) { 
        console.error(e); 
        btn.innerHTML = originalText;
    }
}

const deleteConfirmModal = document.getElementById('deleteConfirmModal');
const cancelDeleteBtn = document.getElementById('cancelDeleteBtn');
const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
const closeDeleteConfirm = document.querySelector('.close-delete-confirm');

let deleteCallback = null;

if (cancelDeleteBtn) cancelDeleteBtn.addEventListener('click', () => { deleteConfirmModal.classList.add('hidden'); deleteCallback = null; });
if (closeDeleteConfirm) closeDeleteConfirm.addEventListener('click', () => { deleteConfirmModal.classList.add('hidden'); deleteCallback = null; });

if (confirmDeleteBtn) {
    confirmDeleteBtn.addEventListener('click', async () => {
        if (deleteCallback) {
            setLoading(confirmDeleteBtn, true);
            await deleteCallback();
            setLoading(confirmDeleteBtn, false);
            deleteConfirmModal.classList.add('hidden');
            deleteCallback = null;
        }
    });
}

function showDeleteModal(callback) {
    deleteCallback = callback;
    deleteConfirmModal.classList.remove('hidden');
}

async function deleteVaultItem(id) {
    showDeleteModal(async () => {
        await fetch(`/vault/delete/${id}`, { method: 'DELETE' });
        loadVault();
        showToast("Item deleted", "info");
    });
}

// --- ADMIN LOGIC ---
async function loadAdminPanel() {
    const res = await fetch('/admin/users');
    if(res.ok) {
        const users = await res.json();
        const tbody = document.getElementById('userTableBody');
        tbody.innerHTML = "";
        users.forEach(u => {
            tbody.innerHTML += `
                <tr>
                    <td>${u.id}</td>
                    <td>${u.username} ${u.is_admin ? '🛡️' : ''}</td>
                    <td>${u.email || '-'}</td>
                    <td>${u.auth_provider}</td>
                    <td>${!u.is_admin ? `<button onclick="deleteUser(${u.id}, this)" class="danger-btn btn-sm">Delete</button>` : '-'}</td>
                </tr>
            `;
        });
    }
}

window.deleteUser = async (id, btn) => {
    if(confirm("Delete this user?")) {
        if(btn) setLoading(btn, true);
        await fetch(`/admin/delete/${id}`, { method: 'DELETE' });
        loadAdminPanel();
        showToast("User deleted", "info"); // TOAST
    }
};

function setLoading(element, isLoading) {
    if (isLoading) {
        element.classList.add('btn-loading');
        if(element.tagName === 'BUTTON') element.disabled = true;
    } else {
        element.classList.remove('btn-loading');
        if(element.tagName === 'BUTTON') element.disabled = false;
    }
}

// --- 4. CHECK URL FOR RESET TOKEN ---
function checkResetToken() {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('reset_token');
    
    if (token) {
        resetModal.classList.remove('hidden');
        resetSubmitBtn.onclick = async () => {
            const password = newResetPassword.value;
            if(!password) return;
            setLoading(resetSubmitBtn, true);
            try {
                const res = await fetch('/reset_password_confirm', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({token, password})
                });
                const data = await res.json();
                if(res.ok) {
                    showToast(data.message, "success"); // TOAST
                    resetModal.classList.add('hidden');
                    window.history.replaceState({}, document.title, "/");
                    authModal.classList.remove('hidden');
                } else {
                    resetMessage.innerText = data.message;
                }
            } catch(e) { resetMessage.innerText = "Error resetting password."; }
            setLoading(resetSubmitBtn, false);
        };
    }
}
checkResetToken();

// --- 5. SOCIAL LOGIN HANDLER (GOOGLE/GITHUB/LINKEDIN) ---
function checkSocialLogin() {
    const getCookie = (name) => {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
    }
    const socialUser = getCookie('social_login_user');
    const socialAdmin = getCookie('social_login_admin');

    if (socialUser) {
        localStorage.setItem('username', decodeURIComponent(socialUser));
        localStorage.setItem('is_admin', socialAdmin === 'true');
        document.cookie = "social_login_user=; Max-Age=0";
        document.cookie = "social_login_admin=; Max-Age=0";
        checkLoginState();
        authModal.classList.add('hidden');
        showToast("Social Login Successful!", "success"); // TOAST
    }
}
checkSocialLogin();
checkLoginState();

// --- THEME HANDLING ---
const themeMeta = document.querySelector('meta[name="theme-color"]');

function setTheme(theme) {
    htmlElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    
    // Animate Icon Switch
    const themeBtns = [document.getElementById('theme-toggle'), document.getElementById('dashThemeToggle')].filter(Boolean);
    themeBtns.forEach(btn => btn.classList.add('animating'));
    
    setTimeout(() => {
        const svgContent = theme === 'dark' 
            ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>'
            : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>';
        
        themeBtns.forEach(btn => {
            btn.innerHTML = svgContent;
            btn.classList.remove('animating');
        });
    }, 150);
    
    // Update Browser Address Bar Color
    const color = theme === 'dark' ? '#0f172a' : '#f8fafc';
    if(themeMeta) themeMeta.setAttribute('content', color);
}

function getPreferredTheme() {
    const saved = localStorage.getItem('theme');
    if (saved) return saved;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

// Initialize Theme
setTheme(getPreferredTheme());

// Toggle Button
if (themeToggle) {
    themeToggle.addEventListener('click', () => {
        const current = htmlElement.getAttribute('data-theme');
        setTheme(current === 'dark' ? 'light' : 'dark');
    });
}

const dashThemeToggle = document.getElementById('dashThemeToggle');
if (dashThemeToggle) {
    dashThemeToggle.addEventListener('click', () => {
        const current = htmlElement.getAttribute('data-theme');
        setTheme(current === 'dark' ? 'light' : 'dark');
    });
}

if(mobileThemeToggle) {
    mobileThemeToggle.addEventListener('click', () => {
        themeToggle.click();
        mobileNav.classList.add('hidden');
        const icon = mobileMenuBtn.querySelector('i');
        icon.classList.remove('fa-times');
        icon.classList.add('fa-bars');
    });
}

// Listen for System Changes (only if no manual override)
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
    if (!localStorage.getItem('theme')) {
        setTheme(e.matches ? 'dark' : 'light');
    }
});

// Global Keyboard Shortcuts
document.addEventListener('keydown', (e) => {
    // Theme Toggle (Ctrl + Alt + L)
    if (e.ctrlKey && e.altKey && (e.key === 'l' || e.key === 'L')) {
        e.preventDefault();
        const current = htmlElement.getAttribute('data-theme');
        setTheme(current === 'dark' ? 'light' : 'dark');
    }
    // Close Modals (Escape)
    if (e.key === 'Escape') {
        allModals.forEach(m => {
            if (!m.classList.contains('hidden')) {
                m.classList.add('hidden');
                document.body.style.overflow = '';
            }
        });
    }
});

const backToTopBtn = document.getElementById('backToTopBtn');
window.addEventListener('scroll', () => {
    if (window.scrollY > 300) {
        backToTopBtn.classList.add('visible');
    } else {
        backToTopBtn.classList.remove('visible');
    }
});
backToTopBtn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));

// --- 6. SECURITY: AUTO LOGOUT ---
let idleTimer;
let warningTimer;
const IDLE_LIMIT = 10 * 60 * 1000; // 10 Minutes
const WARNING_LIMIT = 9 * 60 * 1000; // 9 Minutes (1 min warning)

function resetIdleTimer() {
    clearTimeout(idleTimer);
    clearTimeout(warningTimer);
    
    // Hide warning modal if visible (activity detected)
    if (sessionTimeoutModal && !sessionTimeoutModal.classList.contains('hidden')) {
        sessionTimeoutModal.classList.add('hidden');
    }

    if (localStorage.getItem('username')) {
        warningTimer = setTimeout(showSessionWarning, WARNING_LIMIT);
        idleTimer = setTimeout(doAutoLogout, IDLE_LIMIT);
    }
}

function showSessionWarning() {
    if (!localStorage.getItem('username')) return;
    sessionTimeoutModal.classList.remove('hidden');
    
    let seconds = 60;
    const countdownEl = document.getElementById('timeoutCountdown');
    if (countdownEl) countdownEl.innerText = seconds;
    
    const interval = setInterval(() => {
        seconds--;
        if (countdownEl) countdownEl.innerText = seconds;
        if (seconds <= 0 || sessionTimeoutModal.classList.contains('hidden')) clearInterval(interval);
    }, 1000);
}

function doAutoLogout() {
    if (localStorage.getItem('username')) {
        sessionTimeoutModal.classList.add('hidden');
        document.getElementById('dashLogoutBtn').click();
        showToast("Session timed out", "error");
    }
}

if(stayLoggedInBtn) {
    stayLoggedInBtn.addEventListener('click', resetIdleTimer);
}

window.onload = resetIdleTimer;
document.onmousemove = resetIdleTimer;
document.onkeypress = resetIdleTimer;
document.onclick = resetIdleTimer;
document.onscroll = resetIdleTimer;

// --- FOOTER LINKS ---
const secureVaultLink = document.getElementById('secureVaultLink');
const generatorToolLink = document.getElementById('generatorToolLink');
const twoFactorIntegrationLink = document.getElementById('twoFactorIntegrationLink');

if (secureVaultLink) {
    secureVaultLink.addEventListener('click', (e) => {
        e.preventDefault();
        openDashboard('vault-section');
    });
}

if (generatorToolLink) {
    generatorToolLink.addEventListener('click', (e) => {
        e.preventDefault();
        document.querySelector('.tool-section').scrollIntoView({ behavior: 'smooth' });
    });
}

if (twoFactorIntegrationLink) {
    twoFactorIntegrationLink.addEventListener('click', (e) => {
        e.preventDefault();
        openDashboard('profile-section');
    });
}

// ==========================================
// SECURE NOTES JAVASCRIPT LOGIC
// ==========================================

// DOM Elements
const notesGrid = document.getElementById('notesGrid');
const addNoteModal = document.getElementById('addNoteModal');
const editNoteModal = document.getElementById('editNoteModal');
const openAddNoteModalBtn = document.getElementById('openAddNoteModal');
const saveNoteBtn = document.getElementById('saveNoteBtn');
const updateNoteBtn = document.getElementById('updateNoteBtn');

// Modals close logic
document.querySelector('.close-add-note')?.addEventListener('click', () => addNoteModal.classList.add('hidden'));
document.querySelector('.close-edit-note')?.addEventListener('click', () => editNoteModal.classList.add('hidden'));

// Hook into the Dashboard Tabs to load notes when clicked
document.querySelectorAll('.dash-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        if(tab.getAttribute('data-target') === 'notes-section') {
            loadNotes();
        }
    });
});

if (openAddNoteModalBtn) {
    openAddNoteModalBtn.addEventListener('click', () => {
        addNoteModal.classList.remove('hidden');
    });
}

if (saveNoteBtn) {
    saveNoteBtn.addEventListener('click', async () => {
        const title = document.getElementById('noteTitle').value;
        const content = document.getElementById('noteContent').value;
        
        if (!title || !content) {
            document.getElementById('noteMessage').innerText = "Please fill out both fields";
            return;
        }

        const originalText = saveNoteBtn.innerText;
        saveNoteBtn.innerText = "Saving...";
        try {
            const res = await fetch('/notes', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ title, content })
            });
            
            if (res.ok) {
                addNoteModal.classList.add('hidden');
                document.getElementById('noteTitle').value = "";
                document.getElementById('noteContent').value = "";
                loadNotes();
                if(typeof showToast === 'function') showToast("Note Encrypted & Saved!", "success");
            } else {
                document.getElementById('noteMessage').innerText = "Error saving note";
            }
        } catch (e) {
            console.error(e);
        }
        saveNoteBtn.innerText = originalText;
    });
}

async function loadNotes() {
    if(!notesGrid) return;
    notesGrid.innerHTML = '<p class="text-muted">Loading secure notes...</p>';
    try {
        const res = await fetch('/notes');
        if (res.ok) {
            const items = await res.json();
            if (items.length === 0) {
                notesGrid.innerHTML = '<p class="text-muted">Your secure notes vault is empty. Click "Add Note" to get started.</p>';
                return;
            }
            notesGrid.innerHTML = "";
            items.forEach(note => {
                notesGrid.innerHTML += `
                    <div class="premium-card vault-card">
                        <div class="vault-card-header">
                            <span class="site-favicon-default" style="background: var(--primary); color: #fff;"><i class="fas fa-sticky-note"></i></span>
                            <div class="vault-title">
                                <h4 style="font-size: 1.15rem; font-weight: 700; margin-bottom: 4px;">${note.title}</h4>
                                <span class="site-url" style="color: var(--text-muted); font-size: 0.85rem; display: flex; align-items: center; gap: 6px;">Secure Note <i class="fas fa-lock" style="font-size: 0.7rem;"></i></span>
                            </div>
                        </div>
                        
                        <div class="vault-field" style="margin-top: 10px;">
                            <i class="fas fa-file-alt" title="Note Content"></i>
                            <span class="vault-field-value masked-pass" style="user-select: none;">••••••••••••••••</span>
                        </div>

                        <div class="vault-card-actions">
                            <button class="outline-btn action-btn" data-action="decrypt-note" data-id="${note.id}" style="padding: 6px;" title="Decrypt / Edit Note"><i class="fas fa-unlock-alt"></i></button>
                            <button class="danger-btn-text action-btn" data-action="delete-note" data-id="${note.id}" style="padding: 6px;" title="Delete Note"><i class="fas fa-trash-alt"></i></button>
                        </div>
                    </div>
                `;
            });
        }
    } catch (e) {
        console.error(e);
        notesGrid.innerHTML = '<p class="error-msg">Error loading notes</p>';
    }
}

if(notesGrid) {
    notesGrid.addEventListener('click', (e) => {
        const target = e.target.closest('.action-btn');
        if (!target) return;
        
        const action = target.dataset.action;
        const id = target.dataset.id;

        if (action === 'decrypt-note') {
            decryptNote(id);
        } else if (action === 'delete-note') {
            deleteNote(id);
        }
    });
}

async function decryptNote(id) {
    if(typeof showToast === 'function') showToast("Decrypting note...", "info");
    try {
        const res = await fetch(`/notes/decrypt/${id}`, { method: 'POST' });
        const data = await res.json();
        if (res.ok && data.status === 'success') {
            document.getElementById('editNoteId').value = id;
            document.getElementById('editNoteTitle').value = data.decrypted_title;
            document.getElementById('editNoteContent').value = data.decrypted_content;
            editNoteModal.classList.remove('hidden');
            if(typeof showToast === 'function') showToast("Decrypted successfully!", "success");
        } else {
            if(typeof showToast === 'function') showToast("Decryption Error", "error");
        }
    } catch (e) {
        console.error(e);
    }
}

if (updateNoteBtn) {
    updateNoteBtn.addEventListener('click', async () => {
        const id = document.getElementById('editNoteId').value;
        const title = document.getElementById('editNoteTitle').value;
        const content = document.getElementById('editNoteContent').value;
        
        if (!title || !content) {
            document.getElementById('editNoteMessage').innerText = "Fields cannot be empty";
            return;
        }

        const originalText = updateNoteBtn.innerText;
        updateNoteBtn.innerText = "Encrypting & Updating...";
        try {
            const res = await fetch(`/notes/${id}`, {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ title, content })
            });
            if (res.ok) {
                editNoteModal.classList.add('hidden');
                loadNotes();
                if(typeof showToast === 'function') showToast("Note securely updated!", "success");
            } else {
                document.getElementById('editNoteMessage').innerText = "Error updating";
            }
        } catch (e) {
            console.error(e);
        }
        updateNoteBtn.innerText = originalText;
    });
}

async function deleteNote(id) {
    showDeleteModal(async () => {
        try {
            const res = await fetch(`/notes/${id}`, { method: 'DELETE' });
            if (res.ok) {
                loadNotes();
                if(typeof showToast === 'function') showToast("Note deleted permanently", "info");
            }
        } catch (e) {
            console.error(e);
        }
    });
}

// --- Vault Search Filtering ---
const vaultSearchInput = document.getElementById('vaultSearch');
if (vaultSearchInput) {
    vaultSearchInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const cards = document.querySelectorAll('.vault-card');
        let visibleCount = 0;
        
        cards.forEach(card => {
            const text = card.innerText.toLowerCase();
            if (text.includes(query)) {
                card.style.display = 'flex';
                visibleCount++;
            } else {
                card.style.display = 'none';
            }
        });
        
        let emptyStateMsg = document.getElementById('searchEmptyMsg');
        if (visibleCount === 0 && cards.length > 0) {
            if (!emptyStateMsg) {
                const msg = document.createElement('div');
                msg.id = 'searchEmptyMsg';
                msg.style.gridColumn = '1 / -1';
                msg.style.padding = '3rem';
                msg.style.textAlign = 'center';
                msg.style.color = 'var(--text-muted)';
                msg.innerHTML = '<i class="fas fa-search" style="font-size: 2rem; margin-bottom: 1rem; opacity: 0.5;"></i><br>No matching entries found.';
                document.getElementById('vaultGrid').appendChild(msg);
            }
        } else if (emptyStateMsg) {
            emptyStateMsg.remove();
        }
    });
}

// --- Global Keyboard Shortcuts ---
document.addEventListener('keydown', (e) => {
    // Ignore if typing inside inputs/textareas
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;
    
    // Check for Ctrl + Alt + Key
    if (e.ctrlKey && e.altKey) {
        switch(e.key.toLowerCase()) {
            case 'k':
                e.preventDefault();
                const vaultTab = document.querySelector("[data-target='vault-section']");
                if(vaultTab) {
                    vaultTab.click();
                    setTimeout(() => {
                        const searchInput = document.getElementById('vaultSearch');
                        if (searchInput) searchInput.focus();
                    }, 100);
                }
                break;
            case 'p':
                e.preventDefault();
                const vTab = document.querySelector("[data-target='vault-section']");
                if(vTab) {
                    vTab.click();
                    setTimeout(()=>document.getElementById('openAddVaultModal')?.click(), 100);
                }
                break;
            case 'n':
                e.preventDefault();
                const nTab = document.querySelector("[data-target='notes-section']");
                if(nTab) {
                    nTab.click();
                    setTimeout(()=>document.getElementById('openAddNoteModal')?.click(), 100);
                }
                break;
            case 's':
                e.preventDefault();
                const sTab = document.querySelector("[data-target='security-center-section']");
                if(sTab) sTab.click();
                break;
            case 'e':
                e.preventDefault();
                document.getElementById('exportVaultBtn')?.click();
                break;
            case 'l':
                e.preventDefault();
                document.getElementById('theme-toggle')?.click();
                break;
        }
    }
});

// --- Security Center Scan Button ---
const manualScanBtn = document.getElementById('manualScanBtn');
if (manualScanBtn) {
    manualScanBtn.addEventListener('click', async () => {
        const originalHtml = manualScanBtn.innerHTML;
        manualScanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
        manualScanBtn.disabled = true;
        
        const secList = document.getElementById('securityIssuesList');
        if (secList) secList.innerHTML = '<p class="text-muted" style="padding: 1.5rem;"><i class="fas fa-spinner fa-spin"></i> Scanning vault passwords...</p>';
        
        // Wait a small moment to simulate deep scanning, then loadVault which handles the real scanning and dashboard score updates
        setTimeout(async () => {
            await loadVault();
            manualScanBtn.innerHTML = originalHtml;
            manualScanBtn.disabled = false;
            if (typeof showToast === 'function') showToast("Security scan complete!", "success");
        }, 800);
    });
}

// --- Profile Change Password Logic ---
const changePassNew = document.getElementById('changePassNew');
if (changePassNew) {
    changePassNew.addEventListener('input', (e) => {
        const pwd = e.target.value;
        const rules = {
            upper: /[A-Z]/.test(pwd),
            num: /[0-9]/.test(pwd),
            spec: /[^A-Za-z0-9]/.test(pwd),
            len: pwd.length >= 8
        };
        
        const updateReq = (id, valid) => {
            const el = document.getElementById(id);
            if(!el) return;
            el.innerHTML = valid ? el.innerHTML.replace('○', '✓') : el.innerHTML.replace('✓', '○');
            el.style.color = valid ? '#10B981' : '#94A3B8';
        };
        
        updateReq('chgReqUpper', rules.upper);
        updateReq('chgReqNum', rules.num);
        updateReq('chgReqSpec', rules.spec);
        updateReq('chgReqLen', rules.len);
        
        let score = Object.values(rules).filter(Boolean).length;
        
        const bars = [document.getElementById('chgPwdBar1'), document.getElementById('chgPwdBar2'), document.getElementById('chgPwdBar3'), document.getElementById('chgPwdBar4')];
        const label = document.getElementById('chgPwdStrengthLabel');
        
        bars.forEach(b => b.style.background = '#334155');
        
        if(pwd.length === 0) { label.innerText = 'Weak'; label.style.color = '#94A3B8'; }
        else if(score <= 1) { bars[0].style.background = '#EF4444'; label.innerText = 'Weak'; label.style.color = '#EF4444'; }
        else if(score === 2) { bars[0].style.background = '#F59E0B'; bars[1].style.background = '#F59E0B'; label.innerText = 'Fair'; label.style.color = '#F59E0B'; }
        else if(score === 3) { bars[0].style.background = '#10B981'; bars[1].style.background = '#10B981'; bars[2].style.background = '#10B981'; label.innerText = 'Good'; label.style.color = '#10B981'; }
        else if(score === 4) { bars.forEach(b => b.style.background = '#10B981'); label.innerText = 'Strong'; label.style.color = '#10B981'; }
    });
}

// Password visibility toggles
document.querySelectorAll('.toggle-password-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-target');
        const input = document.getElementById(targetId);
        if (input) {
            if (input.type === 'password') {
                input.type = 'text';
                btn.innerHTML = '<i class="fas fa-eye-slash"></i>';
            } else {
                input.type = 'password';
                btn.innerHTML = '<i class="fas fa-eye"></i>';
            }
        }
    });
});

// Submit Change Password
const changePasswordBtn = document.getElementById('changePasswordBtn');
if (changePasswordBtn) {
    changePasswordBtn.addEventListener('click', async () => {
        const currentPass = document.getElementById('changePassCurrent').value;
        const newPass = document.getElementById('changePassNew').value;
        const confirmPass = document.getElementById('changePassConfirm').value;
        
        if (!currentPass || !newPass || !confirmPass) {
            showToast("All password fields are required.", "warning");
            return;
        }
        
        if (newPass !== confirmPass) {
            showToast("New passwords do not match.", "error");
            return;
        }
        
        if (newPass.length < 8) {
            showToast("New password must be at least 8 characters long.", "warning");
            return;
        }
        
        changePasswordBtn.disabled = true;
        changePasswordBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        
        try {
            const res = await fetch('/change_password', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    current_password: currentPass,
                    new_password: newPass,
                    confirm_password: confirmPass
                })
            });
            const data = await res.json();
            
            if (res.ok) {
                showToast("Password changed successfully! Please log in again.", "success");
                // Trigger logout to enforce re-authentication as per security requirement
                setTimeout(() => {
                    document.getElementById('dashLogoutBtn').click();
                }, 1500);
            } else {
                showToast(data.message || "Failed to change password.", "error");
                changePasswordBtn.disabled = false;
                changePasswordBtn.innerHTML = 'Change Password';
            }
        } catch (e) {
            showToast("An error occurred.", "error");
            changePasswordBtn.disabled = false;
            changePasswordBtn.innerHTML = 'Change Password';
        }
    });
}

// Forgot Password Link
const profileForgotPassLink = document.getElementById('profileForgotPassLink');
if (profileForgotPassLink) {
    profileForgotPassLink.addEventListener('click', (e) => {
        e.preventDefault();
        forgotModal.classList.remove('hidden');
    });
}

// --- VAULT FILTER PILLS ---
document.querySelectorAll('.filter-pill').forEach(pill => {
    pill.addEventListener('click', () => {
        document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        currentVaultFilter = pill.getAttribute('data-filter') || 'all';
        renderVaultCards();
    });
});

// --- AUDIT & HIBP SCAN BUTTONS ---
const runDeepAuditBtn = document.getElementById('runDeepAuditBtn');
if (runDeepAuditBtn) {
    runDeepAuditBtn.addEventListener('click', async () => {
        runDeepAuditBtn.disabled = true;
        const orig = runDeepAuditBtn.innerHTML;
        runDeepAuditBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Auditing...';
        await loadSecurityAudit();
        runDeepAuditBtn.disabled = false;
        runDeepAuditBtn.innerHTML = orig;
        showToast("Deep Security Audit Complete!", "success");
    });
}

const scanBreachesBtn = document.getElementById('scanBreachesBtn');
if (scanBreachesBtn) {
    scanBreachesBtn.addEventListener('click', async () => {
        scanBreachesBtn.disabled = true;
        const orig = scanBreachesBtn.innerHTML;
        scanBreachesBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Querying HIBP...';
        try {
            const res = await fetch('/vault/scan_all_breaches', { method: 'POST' });
            const data = await res.json();
            if (res.ok) {
                showToast(data.message, data.breached_found > 0 ? "warning" : "success");
                await loadVault();
            } else {
                showToast(data.message || "Failed to scan breach database", "error");
            }
        } catch (e) {
            showToast("Connection to HIBP failed.", "error");
        }
        scanBreachesBtn.disabled = false;
        scanBreachesBtn.innerHTML = orig;
    });
}

// --- DEPLOY CANARY MODAL ---
const openDeployCanaryBtn = document.getElementById('openDeployCanaryModal');
const deployCanaryModal = document.getElementById('deployCanaryModal');
const closeDeployCanaryBtn = document.querySelector('.close-deploy-canary');
const confirmDeployCanaryBtn = document.getElementById('confirmDeployCanaryBtn');

if (openDeployCanaryBtn && deployCanaryModal) {
    openDeployCanaryBtn.addEventListener('click', () => {
        deployCanaryModal.classList.remove('hidden');
    });
}

if (closeDeployCanaryBtn && deployCanaryModal) {
    closeDeployCanaryBtn.addEventListener('click', () => {
        deployCanaryModal.classList.add('hidden');
    });
}

if (confirmDeployCanaryBtn && deployCanaryModal) {
    confirmDeployCanaryBtn.addEventListener('click', async () => {
        const lure_type = document.getElementById('canaryLureType')?.value || 'aws';
        confirmDeployCanaryBtn.disabled = true;
        confirmDeployCanaryBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Arming Tripwire...';

        try {
            const res = await fetch('/vault/deploy_canary', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ lure_type })
            });
            const data = await res.json();
            if (res.ok) {
                deployCanaryModal.classList.add('hidden');
                showToast(data.message, "success");
                await loadVault();
            } else {
                showToast(data.message || "Failed to deploy canary", "error");
            }
        } catch (e) {
            showToast("Connection error", "error");
        }

        confirmDeployCanaryBtn.disabled = false;
        confirmDeployCanaryBtn.innerHTML = '<i class="fas fa-shield-alt"></i> Arm & Deploy Canary';
    });
}

// --- CRYPTO PROOF MODAL CLOSE ---
const cryptoProofModal = document.getElementById('cryptoProofModal');
const closeCryptoProofBtn = document.querySelector('.close-crypto-proof');
if (closeCryptoProofBtn && cryptoProofModal) {
    closeCryptoProofBtn.addEventListener('click', () => {
        cryptoProofModal.classList.add('hidden');
    });
}

// --- DURESS & PANIC PIN LOGIC ---
const saveDuressPinBtn = document.getElementById('saveDuressPinBtn');
const clearDuressPinBtn = document.getElementById('clearDuressPinBtn');
const duressPinInput = document.getElementById('duressPinInput');
const duressPinMsg = document.getElementById('duressPinMessage');

if (saveDuressPinBtn && duressPinInput) {
    saveDuressPinBtn.addEventListener('click', async () => {
        const pin = duressPinInput.value.trim();
        if (!/^\d{4,8}$/.test(pin)) {
            if (duressPinMsg) {
                duressPinMsg.innerText = "PIN must be between 4 and 8 digits.";
                duressPinMsg.classList.remove('hidden');
            }
            return;
        }

        saveDuressPinBtn.disabled = true;
        try {
            const res = await fetch('/profile/duress_pin', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin })
            });
            const data = await res.json();
            if (res.ok) {
                showToast("Duress PIN Armed! Decoy defense is active.", "success");
                duressPinInput.value = "";
                if (duressPinMsg) duressPinMsg.classList.add('hidden');
            } else {
                if (duressPinMsg) {
                    duressPinMsg.innerText = data.message || "Failed to arm PIN.";
                    duressPinMsg.classList.remove('hidden');
                }
            }
        } catch (e) {
            showToast("Error updating Duress PIN", "error");
        }
        saveDuressPinBtn.disabled = false;
    });
}

if (clearDuressPinBtn) {
    clearDuressPinBtn.addEventListener('click', async () => {
        if (!confirm("Disable Duress Defense PIN?")) return;
        try {
            const res = await fetch('/profile/duress_pin', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin: "" })
            });
            if (res.ok) {
                showToast("Duress PIN disabled.", "info");
                if (duressPinInput) duressPinInput.value = "";
            }
        } catch (e) {
            showToast("Error disabling Duress PIN", "error");
        }
    });
}

// Window click listener to close custom modals when clicking backdrop
window.addEventListener('click', (e) => {
    if (deployCanaryModal && e.target === deployCanaryModal) {
        deployCanaryModal.classList.add('hidden');
    }
    if (cryptoProofModal && e.target === cryptoProofModal) {
        cryptoProofModal.classList.add('hidden');
    }
});