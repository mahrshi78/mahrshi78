# Secure Coding Remediation Guide

## 1. Parameterized SQL

**Avoid:**
```python
query = f"SELECT * FROM users WHERE username = '{username}'"
connection.execute(query)
```

**Use:**
```python
connection.execute(
    "SELECT password_hash FROM users WHERE username = ?",
    (username,),
)
```

A placeholder keeps user input separate from SQL syntax.

## 2. Hash passwords

**Avoid:** Saving the user's original password in the database.

**Use:** A maintained password-hashing function such as Werkzeug's `generate_password_hash` and `check_password_hash`. Store only the resulting hash; never store or log the original password.

## 3. Validate input

Apply server-side validation before database operations. Define allowed username characters and sensible length limits. Enforce password length requirements and avoid silently truncating passwords.

## 4. Use generic authentication feedback

Return a single failure message such as "Invalid username or password." Do not reveal whether an account exists.

## 5. Add before production deployment

A network-facing service should additionally use:
- Rate limiting and monitoring for repeated failed logins.
- Multi-factor authentication where appropriate.
- Secure password recovery and session handling.
- HTTPS, security headers, backups, and access controls.
- Dependency updates and vulnerability monitoring.
- Security logging that never records passwords or authentication tokens.

The Task 3 secure app is a local demonstration and does not claim to implement all production controls.
