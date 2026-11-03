# Task 5 — Secure File Sharing: Implementation and Operations Guide

## 1. Keep encryption keys outside the application data

Generate a Fernet key once and store it in a protected environment variable or a production secret manager. Do not place the key in source control, SQLite, or beside encrypted files. Back up the key securely. Never rotate the key without a deliberate data re-encryption plan.

## 2. Enforce access on every download

Use a central authorization check for each file request. Permit access only to the owner, an administrator, or a user with an active explicit share record. Return a generic not-found response for unauthorized file IDs to avoid disclosing whether a private file exists.

## 3. Use temporary links carefully

Generate high-entropy random bearer tokens. Store only a cryptographic hash, compare the expiry at download time, and keep the lifetime short. Do not send tokens to analytics or third-party sites. Require HTTPS for any deployment outside localhost.

## 4. Validate uploaded content

Keep an allowlist, impose a strict maximum file size, normalize the user-visible filename, and generate an independent UUID-based server filename. For production, add file-signature inspection, malware scanning, quotas, and content-disarm/reconstruction where appropriate.

## 5. Production readiness checklist

Before deployment beyond a local demonstration:
- Use HTTPS and a production WSGI server.
- Add login rate limiting, MFA, and account recovery.
- Add key rotation and tested encrypted backups.
- Add malware scanning and storage quotas.
- Monitor audit events and protect logs.
- Review dependency updates and security advisories.
- Test authorization boundaries and temporary-link leakage.
