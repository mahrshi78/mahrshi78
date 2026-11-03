# Task - 5: Secure File Sharing System

CipherShare is a standalone Python Flask secure file-sharing application for the CodSoft Cyber Security Internship. Users authenticate, upload files that are encrypted before server-side storage, download their own files, and receive read access to files explicitly shared with them. Owners and administrators can create expiring temporary download links.

## Project structure

~~~text
Task - 5/
├── app/
│   ├── __init__.py
│   ├── auth.py
│   ├── db.py
│   ├── files.py
│   ├── static/style.css
│   └── templates/
│       ├── base.html
│       ├── auth/login.html
│       ├── auth/register.html
│       └── files/index.html
├── tests/
│   ├── conftest.py
│   ├── test_auth.py
│   ├── test_files.py
│   ├── test_sharing.py
│   ├── test_temporary_links.py
│   └── test_security_headers.py
├── reports/
│   ├── SECURITY_ASSESSMENT.md
│   └── REMEDIATION_GUIDE.md
├── screenshots/README.md
├── requirements.txt
├── requirements-dev.txt
├── .env.example
└── run.py
~~~

## Features

- User registration and sign-in with Werkzeug password hashing.
- CSRF protection on state-changing forms and secure session cookie settings.
- Files are encrypted with Fernet authenticated encryption before being written to storage.
- The encryption key is held outside the database and file directory in an environment variable.
- Role-based access: standard users can access their own files and files explicitly shared with them; admins can access all files.
- Owners can grant and revoke read access by username.
- Random temporary download tokens are stored as SHA-256 hashes and expire after 1–1440 minutes.
- Audit records for uploads, downloads, shares, revocations, and temporary-link creation.
- File size limit of 10 MB and an extension allowlist.
- Security headers and attachment-only downloads.

## 1. Requirements and installation

Python 3.10 or later is recommended. Open PowerShell in the Task - 5 folder:

~~~powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
~~~

If the python command on your Windows PC opens the Microsoft Store, run the virtual environment interpreter directly:

~~~powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
~~~

## 2. Generate persistent application secrets (one time)

The application refuses to start without a session secret and a valid Fernet key. Generate them once:

~~~powershell
$secret = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
$fernet = .\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
setx SECRET_KEY "$secret"
setx FERNET_KEY "$fernet"
$env:SECRET_KEY = $secret
$env:FERNET_KEY = $fernet
~~~

The setx commands store the values for future user sessions; the last two lines make them available in the current PowerShell window too. Do not regenerate the Fernet key after uploading files: old encrypted files cannot be decrypted with a new key. Never commit or share these secrets. Keep a protected backup of the Fernet key.

## 3. Initialize the database and create an administrator

~~~powershell
.\.venv\Scripts\python.exe -m flask --app run.py init-db
.\.venv\Scripts\python.exe -m flask --app run.py create-admin
~~~

The create-admin command asks for a username and password interactively. Public registration can create standard users only; users cannot self-assign the admin role.

## 4. Start the local application

~~~powershell
.\.venv\Scripts\python.exe run.py
~~~

Open http://127.0.0.1:5000 in your browser. Register a standard user or sign in as the administrator.

## 5. Practical workflow

1. Sign in as a standard user and upload an allowed file such as a PDF or TXT document.
2. Download the file as its owner and compare the downloaded content with the uploaded file.
3. Sign out and register or sign in as a second user. Attempt to open the first user's file URL; the application should return 404.
4. Sign back in as the owner, enter the second user's username under Share & links, and grant read access.
5. Sign in as the second user and download the shared file. Sign back in as the owner and revoke access; the second user should then receive 404 again.
6. As the owner or admin, create a temporary download link with an expiry between 1 and 1440 minutes. The bearer link can download the file before expiry and returns 404 after expiry.

Temporary links grant access to anyone who possesses the URL until it expires. Share them only with the intended recipient through a trusted channel.

## 6. Run tests and lint checks

~~~powershell
.\.venv\Scripts\python.exe -m pytest tests -v
.\.venv\Scripts\python.exe -m ruff check app tests run.py
~~~

## Security notes and limitations

- Encryption is applied before the file is written to the application storage directory. The SQLite database stores metadata, not plaintext file content.
- Keep FERNET_KEY private and back it up securely. Loss of this key means stored files cannot be decrypted.
- Temporary download URLs are bearer credentials. Anyone obtaining a valid URL can download the file until expiry. Use HTTPS in any deployment beyond localhost.
- This is a learning project, not a production-ready enterprise file platform. Before internet deployment, add rate limiting, MFA, malware scanning, storage quotas, key rotation, monitored backups, and a production WSGI server behind HTTPS.
- Do not run Flask debug mode or expose the development server to a public network.
- Do not upload real confidential files during the internship demo.

## Internship

**Organization:** CodSoft  
**Domain:** Cyber Security  
**Task:** 5 — Secure File Sharing System

## Automated verification

[Task 5 Secure File Sharing Checks — successful](https://github.com/mahrshi78/mahrshi78/actions/runs/41600393846): 14 integration tests passed and Ruff reported All checks passed. Local Windows browser screenshots remain to be captured as separate internship evidence.
