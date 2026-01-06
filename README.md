# 🛡️ Vaultary - Secure Identity & Password Manager

![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.0+-green?style=for-the-badge&logo=flask)
![Vercel](https://img.shields.io/badge/Deployed%20on-Vercel-black?style=for-the-badge&logo=vercel)
![Supabase](https://img.shields.io/badge/Database-Supabase-green?style=for-the-badge&logo=supabase)

**Vaultary** is a production-ready Identity Management System and Zero-Knowledge Password Vault. It features military-grade encryption, multi-provider OAuth authentication, and Two-Factor Authentication (2FA).

🚀 **Live Demo:** [https://vaultary.vercel.app](https://vaultary.vercel.app)

---

## ✨ Features

### 🔐 Security & Authentication
* **Multi-Provider OAuth:** Seamless login with **Google**, **GitHub**, and **LinkedIn** using OpenID Connect.
* **Two-Factor Authentication (2FA):** Custom Time-based One-Time Password (TOTP) implementation compatible with Google Authenticator.
* **Bcrypt Hashing:** Passwords are never stored in plain text.

### 🏦 Zero-Knowledge Vault
* **AES-256 Encryption:** User data (passwords, notes) is encrypted using a unique key derived from the user's master password.
* **Client-Side Privacy:** Even the database administrators cannot read the stored passwords without the user's master key.

### 🛠️ Utilities
* **Password Strength Analyzer:** Real-time feedback on password complexity (Entropy check).
* **Secure Dashboard:** Manage credentials and view security analytics.

---

## 🏗️ Tech Stack

* **Backend:** Python (Flask)
* **Database:** PostgreSQL (via Supabase)
* **Frontend:** HTML5, CSS3, JavaScript (Responsive Design)
* **Deployment:** Vercel Serverless Functions
* **Security Libs:** `cryptography`, `flask-bcrypt`, `authlib`, `pyotp`

---

## ⚙️ Installation & Setup

If you want to run this locally:

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
    Create a `.env` file in the root directory and add:
    ```env
    SECRET_KEY=your_random_secret_key
    DATABASE_URL=your_supabase_postgres_url
    
    # OAuth Credentials
    GOOGLE_CLIENT_ID=your_google_id
    GOOGLE_CLIENT_SECRET=your_google_secret
    
    GITHUB_CLIENT_ID=your_github_id
    GITHUB_CLIENT_SECRET=your_github_secret
    
    LINKEDIN_CLIENT_ID=your_linkedin_id
    LINKEDIN_CLIENT_SECRET=your_linkedin_secret
    ```

4.  **Run the App**
    ```bash
    python app.py
    ```
    Visit `http://127.0.0.1:5000`

---

## 🚀 Deployment

This project is optimized for **Vercel**.

1.  Push code to GitHub.
2.  Import project into Vercel.
3.  Set **Framework Preset** to `Other`.
4.  Add all Environment Variables in Vercel Settings.
5.  Deploy!

---

## 🤝 Contributing

1.  Fork the repository.
2.  Create a new feature branch (`git checkout -b feature/AmazingFeature`).
3.  Commit your changes.
4.  Push to the branch.
5.  Open a Pull Request.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

Made by [Pranav R](https://pranavr.netlify.app/)
