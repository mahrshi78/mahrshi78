# Task 5 — Secure File Sharing System: Security Assessment

**Application:** CipherShare  
**Framework:** Python Flask  
**Database:** SQLite  
**File encryption:** Fernet authenticated encryption  
**Assessment type:** Source review and automated integration tests

## 1. Executive summary

CipherShare is a learning application that provides authenticated file upload/download, encryption at rest, role-based access, explicit file sharing, and expiring temporary links. Files are encrypted before being written to the server storage directory. The encryption key is provided independently through the FERNET_KEY environment variable.

## 2. Scope

Reviewed components:
- Authentication and registration routes.
- SQLite schema and parameterized queries.
- File upload validation and encryption.
- Download authorization and decryption.
- Owner/admin management controls.
- Per-user share grants and revocation.
- Expiring bearer-link generation and verification.
- CSRF controls, session settings, response headers, and audit events.

## 3. Security controls

| Requirement | Implementation |
|---|---|
| Authenticated upload/download | Flask-Login session authentication |
| Password protection | Werkzeug password hashing |
| Encryption before storage | Fernet encryption before writing encrypted bytes |
| Role-based access | Standard user and admin roles |
| Per-file permissions | Owner access and explicit read-share records |
| Temporary links | Cryptographically random token; SHA-256 hash stored; 1–1440 minute expiry |
| Request integrity | Flask-WTF CSRF protection |
| Safer download handling | Attachment response, no-store and nosniff headers |
| Audit trail | Upload, download, share, revoke and link-creation events |

## 4. Authorization matrix

| Action | Standard user | Admin |
|---|---|---|
| Register account | Yes | Via administrator bootstrap |
| Upload file | Yes | Yes |
| Download own file | Yes | Yes |
| Download another user's file | Only if explicitly shared | Yes |
| Share/revoke own file | Yes | Yes |
| Manage another user's file | No | Yes |
| Create temporary link | For own files | For all files |

## 5. Threats addressed

- Unauthorized file reads: downloads require ownership, administrator role, or an explicit share grant.
- Plaintext exposure on disk: file bytes are encrypted before storage.
- Path traversal: clients never choose the internal storage filename; UUID-generated names are used.
- Dangerous upload types: the application uses an extension allowlist and file-size cap.
- Cross-site request forgery: state-changing forms are protected by CSRF tokens.
- Session and browser risks: HttpOnly/SameSite session-cookie settings, CSP, frame and content-type protections.
- Temporary-token database disclosure: only a SHA-256 token hash is stored, and expiry is checked at download time.

## 6. Residual risks and limitations

- Temporary download URLs are bearer secrets. Anyone obtaining a valid URL can download the file until expiry. Keep URLs private and use HTTPS.
- No login rate limiting, MFA, malware scanning, data-loss prevention, or key-rotation workflow is implemented in this learning build.
- A single application Fernet key protects all stored files. Key loss causes permanent loss of access; key compromise exposes stored files.
- SQLite and the Flask development server are suitable for a local demonstration, not an internet-facing production deployment.
- File extensions are an input filter, not proof that file contents are safe.
- The report does not claim an independent penetration test or formal certification.

## 7. Verification

GitHub Actions verification on 3 November 2026: [Task 5 Secure File Sharing Checks](https://github.com/mahrshi78/mahrshi78/actions/runs/41600393846) completed successfully. **14 integration tests passed** and Ruff reported **All checks passed**. Tests cover registration and login, role assignment restrictions, encryption at rest, owner download, cross-user denial, administrator access, extension validation, security headers, explicit share/revoke, temporary-link success, expiry rejection, and invalid expiry handling.

The CI run verifies the application code on GitHub-hosted Linux. A local Windows browser walkthrough and genuine screenshots remain useful submission evidence and should be captured before final internship submission.
