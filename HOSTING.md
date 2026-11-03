# Website Hosting Notes

## Task 2 — Phishing Awareness Program

- Hosting: GitHub Pages, free for this public repository.
- Workflow: `.github/workflows/task-2-pages.yml`.
- One-time setup: open [Settings → Pages](https://github.com/mahrshi78/mahrshi78/settings/pages) and set **Build and deployment → Source** to **GitHub Actions**.
- Expected URL after a successful deployment: https://mahrshi78.github.io/mahrshi78/
- Deployment status: Pages is not enabled yet. The first workflow attempt failed because GitHub Pages has not been enabled for this repository.

## Task 5 — CipherShare

CipherShare is a Python Flask application with server-side authentication, SQLite metadata, and encrypted file storage. GitHub Pages cannot host it because GitHub Pages only serves static content and does not execute server-side Python.

A free application host such as Render can run Python/Flask from this GitHub repository, but its free web service has an ephemeral filesystem: local SQLite data and uploaded encrypted files are lost when the service spins down, restarts, or redeploys. Its free service also sleeps after 15 minutes without inbound traffic. Therefore this is suitable only for a disposable demo with dummy files, not for reliable file sharing or confidential documents.

For persistent CipherShare use, keep the app local until a host with durable database and file storage is arranged. Do not put Fernet keys, passwords, user files, or other secrets in GitHub.
