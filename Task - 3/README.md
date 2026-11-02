# Task - 3: Secure Code Assessment

A standalone Python + SQLite project created for the CodSoft Cyber Security Internship. Task 3 is independent: it has its own application, source code, tests, reports, and evidence folder. Task 1 and Task 2 are unchanged.

## Application selected

**User Management CLI** — a local user registration and authentication program. This assessment compares an intentionally vulnerable training sample with a secure remediated implementation.

## Project structure

```text
Task - 3/
├── app/
│   ├── __init__.py
│   ├── vulnerable_app.py
│   └── secure_app.py
├── reports/
│   ├── SECURITY_ASSESSMENT.md
│   └── REMEDIATION_GUIDE.md
├── tests/
│   ├── conftest.py
│   └── test_secure_app.py
├── requirements.txt
├── requirements-dev.txt
├── screenshots/
│   └── README.md
└── README.md
```

## Setup

Python 3.10 or newer is recommended. From the repository root:

```bash
python -m venv .venv
```

Windows PowerShell:
```powershell
.venv\Scripts\Activate.ps1
python -m pip install -r "Task - 3/requirements-dev.txt"
```

macOS/Linux:
```bash
source .venv/bin/activate
python -m pip install -r "Task - 3/requirements-dev.txt"
```

## Run the secure application

Register a training user:
```bash
python "Task - 3/app/secure_app.py" register --username alice_01
``

Authenticate:
```bash
python "Task - 3/app/secure_app.py" login --username alice_01
``

The application prompts for a password without echoing it to the terminal. The default SQLite database is `users.db` in the current working directory. Use dummy training credentials only.

## Run tests and static checks

```bash
python -m pytest "Task - 3/tests" -v
python -m bandit -q "Task - 3/app/secure_app.py"
python -m ruff check "Task - 3/app/secure_app.py" "Task - 3/tests"
``

The intentionally vulnerable source is excluded from scan pass criteria because it deliberately contains the weaknesses being assessed. Never use it with real credentials or data.

## Assessment scope

The review covers SQL query construction, password storage, input validation, authentication feedback, and login abuse controls. See `reports/SECURITY_ASSESSMENT.md` and `reports/REMEDIATION_GUIDE.md`.

## Safety

This is an offline local educational project. It does not start a network service or contact external systems. The vulnerable sample is only for demonstrating insecure coding patterns and must never be deployed.

## Internship

**Organization:** CodSoft  
**Domain:** Cyber Security  
**Task:** 3 – Secure Code Assessment
