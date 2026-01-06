// --- DOM ELEMENTS ---
const passwordInput = document.getElementById('passwordInput');
const toggleBtn = document.getElementById('togglePassword');
const generateBtn = document.getElementById('generateBtn');
const resultBox = document.getElementById('result-box');
const capsLockWarning = document.getElementById('capsLockWarning');
const whitespaceWarningMain = document.getElementById('whitespaceWarningMain');
const chartContainer = document.getElementById('chart-container');
const copyBtn = document.getElementById('copyBtn');
const themeToggle = document.getElementById('theme-toggle');
const htmlElement = document.documentElement;

// Desktop Nav Elements
const loginBtn = document.getElementById('loginBtn');
const userProfile = document.getElementById('userProfile');
const usernameDisplay = document.getElementById('usernameDisplay');
const dashboardBtn = document.getElementById('dashboardBtn');

// Mobile Nav Elements
const mobileMenuBtn = document.getElementById('mobile-menu-btn');
const mobileNav = document.getElementById('mobileNav');
const mobileLoginBtn = document.getElementById('mobileLoginBtn');
const mobileDashboardBtn = document.getElementById('mobileDashboardBtn');
const mobileThemeToggle = document.getElementById('mobileThemeToggle');

// Modals
const authModal = document.getElementById('authModal');
const dashboardModal = document.getElementById('dashboardModal');
const forgotModal = document.getElementById('forgotModal');
const resetModal = document.getElementById('resetModal');
// 2FA Modals
const login2FAModal = document.getElementById('login2FAModal');
const setup2FAModal = document.getElementById('setup2FAModal');
// Vault Modal
const addVaultModal = document.getElementById('addVaultModal');
const sessionTimeoutModal = document.getElementById('sessionTimeoutModal');
const legalModal = document.getElementById('legalModal');
const contactModal = document.getElementById('contactModal');
const passwordHealthLink = document.getElementById('passwordHealthLink');

const allModals = [authModal, dashboardModal, forgotModal, resetModal, login2FAModal, setup2FAModal, addVaultModal, sessionTimeoutModal, legalModal, contactModal];

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
const rememberMe = document.getElementById('rememberMe');

// Vault Elements
const openAddVaultModalBtn = document.getElementById('openAddVaultModal');
const saveVaultBtn = document.getElementById('saveVaultBtn');
const vaultGrid = document.getElementById('vaultGrid');

// Forgot & Reset Inputs
const forgotLink = document.getElementById('forgotPasswordLink');
const forgotEmail = document.getElementById('forgotEmail');
const forgotSubmitBtn = document.getElementById('forgotSubmitBtn');
const forgotMessage = document.getElementById('forgotMessage');
const newResetPassword = document.getElementById('newResetPassword');
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
        
        // Check for saved username (Remember Me)
        const savedUser = localStorage.getItem('saved_username');
        if (savedUser) {
            authUsername.value = savedUser;
            if(rememberMe) rememberMe.checked = true;
        }
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
function validateChecklist(value, listId) {
    const list = document.getElementById(listId);
    if (!list) return;

    if (value.length > 0) list.classList.remove('hidden');
    else list.classList.add('hidden');

    const reqs = {
        'upper': /[A-Z]/,
        'number': /[0-9]/,
        'special': /[!@#$%^&*(),.?":{}|<>]/,
        'length': /.{8,}/
    };

    for (const [key, regex] of Object.entries(reqs)) {
        const item = list.querySelector(`li[data-req="${key}"]`);
        if (item) {
            if (regex.test(value)) {
                item.classList.add('valid');
                item.querySelector('i').className = "fas fa-check-circle";
            } else {
                item.classList.remove('valid');
                item.querySelector('i').className = "far fa-circle";
            }
        }
    }
}

passwordInput.addEventListener('input', debounce(async (e) => {
    const password = passwordInput.value;
    validateChecklist(password, 'main-checklist');
    
    if (password.length === 0) {
        resultBox.classList.add('hidden');
        chartContainer.classList.add('hidden');
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
    const colors = ['#ef4444', '#f97316', '#eab308', '#84cc16', '#22c55e'];
    const labels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
    
    document.getElementById('crack-time').innerText = "Crack time: " + data.crack_time;
    
    const suggestionsList = document.getElementById('suggestions');
    suggestionsList.innerHTML = "";
    if (data.feedback.suggestions) {
        data.feedback.suggestions.forEach(s => {
            let li = document.createElement('li');
            li.innerText = s;
            suggestionsList.appendChild(li);
        });
    }

    let finalColor = colors[data.score];
    let finalLabel = labels[data.score];
    let finalWarning = data.feedback.warning || "";
    const scoreText = document.getElementById('score-text');

    if (data.breach_count > 0) {
        finalColor = '#ef4444';
        finalLabel = `BREACHED (${data.breach_count.toLocaleString()})`;
        const breachMsg = `⚠️ DANGER: Found in ${data.breach_count.toLocaleString()} data breaches!`;
        finalWarning = finalWarning ? `${breachMsg}<br><br>${finalWarning}` : breachMsg;
        scoreText.style.color = '#ef4444';
    } else {
        scoreText.style.color = finalColor;
    }

    const meter = document.getElementById('strength-meter');
    meter.style.width = ((data.score + 1) * 20) + "%";
    meter.style.backgroundColor = finalColor;
    scoreText.innerText = finalLabel;
    document.getElementById('warning').innerHTML = finalWarning;
    
    const tooltip = document.getElementById('meter-tooltip');
    let tooltipText = `Score: ${data.score}/4`;
    if (data.breach_count > 0) tooltipText += " - Password Breached!";
    else if (data.feedback.warning) tooltipText += ` - ${data.feedback.warning}`;
    else if (data.score < 3) tooltipText += " - Try adding more variety.";
    else tooltipText += " - Strong password!";
    tooltip.innerText = tooltipText;

    updateChart(data);
}

let securityChart = null;
function updateChart(data) {
    const ctx = document.getElementById('strengthChart').getContext('2d');
    chartContainer.classList.remove('hidden');
    
    const chartData = [
        Math.min(data.password_length * 6, 100),
        (data.score + 1) * 20,
        Math.min(Math.log10(data.guesses + 1) * 8, 100),
        Math.max(100 - (data.sequence.length * 20), 0)
    ];

    if (securityChart) {
        securityChart.data.datasets[0].data = chartData;
        securityChart.update();
    } else {
        securityChart = new Chart(ctx, {
            type: 'radar',
            data: {
                labels: ['Length', 'Complexity', 'Entropy', 'Safety'],
                datasets: [{
                    label: 'Score',
                    data: chartData,
                    backgroundColor: 'rgba(59, 130, 246, 0.2)',
                    borderColor: '#3b82f6',
                    borderWidth: 2,
                    pointBackgroundColor: '#3b82f6'
                }]
            },
            options: {
                scales: { r: { suggestedMin: 0, suggestedMax: 100, ticks: { display: false }, grid: { color: 'rgba(148, 163, 184, 0.2)' } } },
                plugins: { legend: { display: false } },
                responsive: true, maintainAspectRatio: false
            }
        });
    }
}

// --- PHONE & DOB VALIDATION ---
function setupPhoneValidation(input, errorEl) {
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
    const savedUser = localStorage.getItem('saved_username');
    if(savedUser) {
        authUsername.value = savedUser;
        if(rememberMe) rememberMe.checked = true;
    }
});
dashboardBtn.addEventListener('click', () => openDashboard('profile-section'));

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
    const savedUser = localStorage.getItem('saved_username');
    if(savedUser) {
        authUsername.value = savedUser;
        if(rememberMe) rememberMe.checked = true;
    }
});
mobileDashboardBtn.addEventListener('click', () => { openDashboard('profile-section'); mobileNav.classList.add('hidden'); });
mobileDashboardBtn.addEventListener('click', () => { 
    openDashboard('profile-section'); 
    mobileNav.classList.add('hidden'); 
    const icon = mobileMenuBtn.querySelector('i');
    icon.classList.remove('fa-times');
    icon.classList.add('fa-bars');
});

// Close buttons
document.querySelectorAll('.close-modal').forEach(btn => {
    btn.addEventListener('click', () => {
        allModals.forEach(m => m.classList.add('hidden'));
        document.body.style.overflow = '';
    });
});
document.querySelector('.close-dashboard').addEventListener('click', () => {
    dashboardModal.classList.add('hidden');
    document.body.style.overflow = '';
});

// Forgot Password Modal
forgotLink.addEventListener('click', (e) => {
    e.preventDefault();
    authModal.classList.add('hidden');
    forgotModal.classList.remove('hidden');
    forgotMessage.innerText = "";
});

forgotSubmitBtn.addEventListener('click', async () => {
    const email = forgotEmail.value;
    if(!email) return;
    setLoading(forgotSubmitBtn, true);
    try {
        const res = await fetch('/forgot_password', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email})
        });
        const data = await res.json();
        forgotMessage.innerText = data.message;
        if(res.ok) showToast("Reset link sent to your email", "success"); // TOAST
    } catch(e) { forgotMessage.innerText = "Error sending request."; }
    setLoading(forgotSubmitBtn, false);
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

    // Shake effect for persistent modals (Auth, Dashboard, Legal, Contact)
    if (e.target === dashboardModal || e.target === authModal || e.target === legalModal || e.target === contactModal || e.target === addVaultModal || e.target === login2FAModal || e.target === setup2FAModal) {
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
    if (allModals.includes(e.target)) {
        e.target.classList.add('hidden');
        document.body.style.overflow = '';
    }
};

switchAuthMode.addEventListener('click', (e) => {
    e.preventDefault();
    isLoginMode = !isLoginMode;
    const title = document.getElementById('modalTitle');
    const switchText = document.getElementById('switchText');
    const authChecklist = document.getElementById('auth-checklist');
    
    if (isLoginMode) {
        title.innerText = "Login";
        authSubmitBtn.innerText = "Login";
        switchText.innerText = "Don't have an account?";
        switchAuthMode.innerText = "Register";
        authEmail.classList.add('hidden');
        authPhone.classList.add('hidden'); 
        authDob.classList.add('hidden');
        document.querySelector('.auth-extras').classList.remove('hidden');
        authChecklist.classList.add('hidden');
        authPassword.setAttribute('autocomplete', 'current-password');
    } else {
        title.innerText = "Create Account";
        authSubmitBtn.innerText = "Register";
        switchText.innerText = "Already have an account?";
        switchAuthMode.innerText = "Login";
        authEmail.classList.remove('hidden');
        authPhone.classList.remove('hidden'); 
        authDob.classList.remove('hidden');
        document.querySelector('.auth-extras').classList.add('hidden');
        authPassword.setAttribute('autocomplete', 'off');
    }
    authMessage.innerText = "";
});

// Auth Password Validation Listener
authPassword.addEventListener('input', (e) => {
    if (!isLoginMode) {
        validateChecklist(e.target.value, 'auth-checklist');
    }
});

authSubmitBtn.addEventListener('click', async () => {
    const username = authUsername.value;
    const password = authPassword.value;
    const email = authEmail.value;
    const phone = authPhone.value;
    const dob = authDob.value;
    const endpoint = isLoginMode ? '/login' : '/register';
    
    if (isLoginMode) {
        if (!username || !password) { authMessage.innerText = "Fill username and password"; return; }
    } else {
        if (!username || !password || !email) { authMessage.innerText = "Email is required for registration"; return; }
        
        // Validate DOB for registration
        if (!dob) { authMessage.innerText = "Date of Birth is required"; return; }
        validateDobLogic(authDob, authDobError);
        if (authDob.dataset.valid === "false") { authMessage.innerText = "Please fix Date of Birth errors"; return; }

        // Validate Phone if entered
        if (phone) {
            if (phone.length !== 10) { authMessage.innerText = "Phone must be 10 digits"; return; }
            if (authPhone.dataset.valid === "false") { authMessage.innerText = "Fix phone number errors"; return; }
        }
    }

    setLoading(authSubmitBtn, true);
    authMessage.innerText = ""; 

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password, email, phone, dob})
        });
        const data = await response.json().catch(() => ({ message: "Server Error or Rate Limit Hit" }));
        
        if (response.ok) {
            if (isLoginMode) {
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
                    
                    // Handle Remember Me
                    if (rememberMe && rememberMe.checked) {
                        localStorage.setItem('saved_username', username);
                    } else {
                        localStorage.removeItem('saved_username');
                    }
                    
                    showToast("Login Successful!", "success"); // TOAST
                }
            } else {
                authMessage.style.color = "#22c55e";
                authMessage.innerText = data.message;
                setTimeout(() => { 
                    switchAuthMode.click(); 
                    authMessage.style.color = "#ef4444"; 
                    authMessage.innerText = ""; 
                }, 3000);
            }
        } else {
            authMessage.style.color = "#ef4444";
            authMessage.innerText = data.message || "An error occurred";
        }
    } catch (error) { 
        console.error(error);
        authMessage.innerText = "Connection Error. Please try again."; 
    }
    finally { setLoading(authSubmitBtn, false); }
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
    dashboardModal.classList.add('hidden');
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
        usernameDisplay.innerText = "Hi, " + user;
        if (isAdmin) dashAdminTab.classList.remove('hidden');
        else dashAdminTab.classList.add('hidden');
        
        mobileLoginBtn.classList.add('hidden');
        mobileDashboardBtn.classList.remove('hidden');
        document.getElementById('mobileUsername').innerText = "Hi, " + user;
        document.getElementById('mobileUsername').classList.remove('hidden');
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
        dashTabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        dashViews.forEach(v => v.classList.add('hidden'));
        const target = tab.getAttribute('data-target');
        document.getElementById(target).classList.remove('hidden');
        
        if(target === 'profile-section') loadProfile();
        if(target === 'admin-section') loadAdminPanel();
        if(target === 'vault-section') loadVault(); 
    });
});

function openDashboard(defaultTab) {
    if (!localStorage.getItem('username')) {
        authModal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
        showToast("Please login to access this feature", "info");
        return;
    }

    dashboardModal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
    const tab = document.querySelector(`.dash-tab[data-target="${defaultTab}"]`);
    if(tab) tab.click();
    loadProfile();
}

async function loadProfile() {
    const res = await fetch('/profile');
    if(res.ok) {
        const data = await res.json();
        dashProfilePic.src = data.profile_pic;
        document.getElementById('dashUsername').innerText = data.username;
        document.getElementById('dashRole').innerText = localStorage.getItem('is_admin') === 'true' ? 'Administrator' : 'Member';
        editUsername.value = data.username;
        usernameCharCount.innerText = `${data.username.length}/50`;
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
    usernameCharCount.innerText = `${val.length}/50`;
    
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
        dashboardModal.classList.add('hidden');
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

if(saveVaultBtn) {
    saveVaultBtn.addEventListener('click', async () => {
        const site_name = document.getElementById('vaultSiteName').value;
        const site_url = document.getElementById('vaultSiteURL').value;
        const site_username = document.getElementById('vaultUsername').value;
        const password = document.getElementById('vaultPassword').value;

        if(!site_name || !site_username || !password) {
            document.getElementById('vaultMessage').innerText = "Fill required fields";
            return;
        }

        setLoading(saveVaultBtn, true);
        try {
            const res = await fetch('/vault', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({site_name, site_url, site_username, password})
            });
            if(res.ok) {
                addVaultModal.classList.add('hidden');
                document.getElementById('vaultSiteName').value = "";
                document.getElementById('vaultSiteURL').value = "";
                document.getElementById('vaultUsername').value = "";
                document.getElementById('vaultPassword').value = "";
                loadVault();
                showToast("Password Saved!", "success"); // TOAST
            } else {
                document.getElementById('vaultMessage').innerText = "Error saving";
            }
        } catch(e) { console.error(e); }
        setLoading(saveVaultBtn, false);
    });
}

async function loadVault() {
    vaultGrid.innerHTML = '<p class="text-muted">Loading...</p>';
    try {
        const res = await fetch('/vault');
        if(res.ok) {
            const items = await res.json();
            if(items.length === 0) {
                vaultGrid.innerHTML = '<p class="text-muted">No passwords saved yet.</p>';
                return;
            }
            vaultGrid.innerHTML = "";
            items.forEach(item => {
                vaultGrid.innerHTML += `
                    <div class="vault-card">
                        <h4>${item.site_name}</h4>
                        <a href="${item.site_url}" target="_blank" rel="noopener noreferrer" class="site-url">${item.site_url || ''}</a>
                        <div class="username-display">
                            <i class="fas fa-user"></i> ${item.site_username}
                        </div>
                        <div class="vault-actions">
                            <button class="vault-btn" onclick="copyUsername('${item.site_username}')" data-tooltip="Copy Username"><i class="fas fa-copy"></i> User</button>
                            <button class="vault-btn" onclick="decryptPassword(${item.id}, this)" data-tooltip="Copy Password"><i class="fas fa-key"></i> Copy Pass</button>
                            <button class="vault-btn delete" onclick="deleteVaultItem(${item.id})" data-tooltip="Delete" aria-label="Delete Item"><i class="fas fa-trash"></i></button>
                        </div>
                    </div>
                `;
            });
        }
    } catch(e) { vaultGrid.innerHTML = '<p class="error-msg">Error loading vault</p>'; }
}

window.copyUsername = (text) => {
    navigator.clipboard.writeText(text);
    showToast("Username copied!", "info"); // TOAST
}

window.decryptPassword = async (id, btn) => {
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
};

window.deleteVaultItem = async (id) => {
    if(confirm("Delete this password permanently?")) {
        await fetch(`/vault/delete/${id}`, { method: 'DELETE' });
        loadVault();
        showToast("Item deleted", "info"); // TOAST
    }
};

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
    
    // Update Icon
    themeToggle.innerHTML = theme === 'dark' ? '<i class="fas fa-sun"></i>' : '<i class="fas fa-moon"></i>';
    
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
themeToggle.addEventListener('click', () => {
    const current = htmlElement.getAttribute('data-theme');
    setTheme(current === 'dark' ? 'light' : 'dark');
});

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