## ⚠️ Issue Description
The "Sign in with LinkedIn" feature is currently unstable in the production environment (Vercel). While the feature functions correctly on the local development server (`localhost`), it consistently triggers a **500 Internal Server Error** after deployment.

**Current Status:** 🛠️ *Under Maintenance / Fix in Progress*

## 🛑 Observed Behavior
1. User clicks "Login with LinkedIn".
2. LinkedIn correctly asks for permission (Consent Screen).
3. Upon redirection back to the app (`/login/linkedin/callback`), the server crashes.
4. **Impact:** Users cannot complete the login process via LinkedIn.

## ⚙️ Technical Diagnosis
The issue has been isolated to a conflict between the Vercel Serverless environment and the `Authlib` OAuth client.

* **Error Code:** `authlib.integrations.base_client.errors.MismatchingStateError`
* **Root Cause:** Vercel's reverse proxy does not forward the `HTTPS` headers correctly to the Flask application. This causes the OAuth callback to generate an `http://` URL, which LinkedIn rejects for security reasons (Protocol Mismatch).

## 📝 Temporary Measure
To ensure system stability for the final presentation, the **LinkedIn Login button has been temporarily hidden/disabled** in the UI.

## ✅ Proposed Fix (In Progress)
I'm currently refactoring `app.py` to force the `_scheme='https'` parameter during the OAuth handshake.

Date Detected: January 6, 2026
