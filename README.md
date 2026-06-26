# 🛡️ Vaultary - Identity Management & Secure Vault

![Flask](https://img.shields.io/badge/Flask-3.0+-black?style=for-the-badge&logo=flask)
![Supabase](https://img.shields.io/badge/Supabase-PostgreSQL-3ECF8E?style=for-the-badge&logo=supabase&logoColor=white)
![Authentication](https://img.shields.io/badge/Auth-JWT-orange?style=for-the-badge)
![Encryption](https://img.shields.io/badge/Encryption-AES--256-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

**Vaultary** is a comprehensive identity security platform designed to audit password strength, monitor data breaches, and securely manage credentials. Unlike standard checkers, it uses mathematical entropy analysis and k-anonymity for privacy-preserving breach detection.

🚀 **Live Demo:** [https://vaultary.vercel.app](https://vaultary.vercel.app)

---

## ✨ Features

### 🧠 Advanced Password Analysis
* **Entropy & Scoring:** Uses `zxcvbn` to calculate entropy, crack time, and security score (0-4).
* **Pattern Recognition:** Detects keyboard walks (e.g., "qwerty"), repetitions, and common substitutions.
* **Visual Analytics:** Renders a Radar Chart (Chart.js) to visualize Length, Complexity, Entropy, and Safety.

### 🛡️ Cyber Defense & Privacy
* **Real-time Breach Detection:** Integrates with the **HaveIBeenPwned API**.
* **k-Anonymity:** Protects user privacy by sending only the first 5 characters of the SHA-1 hash to the API. The full hash never leaves the server.

### 🏦 Secure Password Vault
* **AES-256 Encryption:** User credentials are encrypted using the `cryptography` library (Fernet) before storage.
* **CRUD Operations:** Securely Add, Edit, Delete, and Decrypt passwords.
* **Export Data:** Users can export their vault to CSV for backup.

### 👤 Identity Management
* **Multi-Provider OAuth:** Login with Google, GitHub, and LinkedIn (via `Authlib`).
* **2FA (Two-Factor Authentication):** Time-based One-Time Password (TOTP) support compatible with Google Authenticator.
* **Session Security:** Auto-logout after inactivity and JWT-based session management.

---

## 🏗️ Technical Architecture

### Backend Stack
* **Framework:** Python Flask
* **Database:** SQLAlchemy ORM (PostgreSQL via Supabase)
* **Authentication:**
    * **JWT:** HTTP-only cookies for session management.
    * **Flask-Bcrypt:** Secure password hashing.
    * **Authlib:** OAuth 2.0 integration.

Browser
   │
   ▼
Vaultary Frontend
   │
   ▼
Flask API
   │
   ├── PostgreSQL (Supabase)
   │
   ├── HIBP API
   │
   └── OAuth Providers

### Security Implementation
* **Encryption:** `cryptography` (Fernet) for symmetric AES-256 encryption of vault items.
* **Protection:** `Flask-Limiter` for rate limiting and `Flask-Talisman` for HTTP security headers (CSP, HSTS).

### Frontend Stack
* **Core:** HTML5, CSS3 (Custom Properties), Vanilla JavaScript.
* **Visualization:** Chart.js for security radar charts.

---

## ⚠️ Security Model & Limitations

In the spirit of transparency, here are the current architectural trade-offs:

1.  **Encryption Model:**
    * *Current State:* Server-Side Encryption. The application holds the `VAULT_KEY` in environment variables and performs decryption on the server.
    * *Trade-off:* If the server environment is compromised, the keys are accessible.
    * *Future Goal:* Move to a true Zero-Knowledge architecture where decryption happens solely in the browser.

2.  **JWT Invalidation:**
    * *Current State:* Logout clears the client-side cookie.
    * *Trade-off:* Because JWTs are stateless, the token remains valid until expiry (1 hour) even after logout.

---

## ⚙️ Installation & Setup

1.  **Clone the repository**
    ```bash
    git clone [https://github.com/Pranavr06/Vaultary.git](https://github.com/Pranavr06/Vaultary.git)
    cd Vaultary
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure Environment Variables**
    Create a `.env` file:
    ```env
    SECRET_KEY=your_secret_key
    VAULT_KEY=your_fernet_key
    DATABASE_URL=your_db_url
    # OAuth Keys...
    ```

4.  **Run the App**
    ```bash
    python app.py
    ```

---

## 🚀 Future Development

I am actively working on features to take Vaultary from a password manager to a complete digital identity fortress:

- [x] **Dark Web Monitoring** (HaveIBeenPwned Integration) ✅
- [ ] **Biometric Integration**: Implementing WebAuthn standards for fingerprint/FaceID login.
- [ ] **Secure Notes**: Extending the vault schema to store unstructured text data (API keys, recovery codes).

---

## 📄 License
Distributed under the MIT License.

---
---

## 👨‍💻 Author

**Pranav R**

- Portfolio: https://pranavr.netlify.app
- GitHub: https://github.com/Pranavr06

Built with a focus on privacy, security, and modern identity management.
