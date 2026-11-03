"""Application factory for the CodSoft secure file-sharing project."""
from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet
from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

from app.db import User, close_db, init_app as init_db_app

csrf = CSRFProtect()
login_manager = LoginManager()


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        FERNET_KEY=os.environ.get("FERNET_KEY"),
        DATABASE=os.path.join(app.instance_path, "secure_share.sqlite"),
        STORAGE_DIR=os.path.join(app.instance_path, "encrypted_files"),
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,
        MAX_FILE_BYTES=10 * 1024 * 1024,
        ALLOWED_EXTENSIONS={
            "pdf", "txt", "csv", "png", "jpg", "jpeg",
            "docx", "xlsx", "pptx", "zip",
        },
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        REMEMBER_COOKIE_HTTPONLY=True,
        WTF_CSRF_ENABLED=True,
    )
    if test_config:
        app.config.update(test_config)

    if not app.config.get("SECRET_KEY"):
        raise RuntimeError("Set SECRET_KEY in the environment before starting the app.")
    if not app.config.get("FERNET_KEY"):
        raise RuntimeError("Set FERNET_KEY in the environment before starting the app.")
    try:
        Fernet(app.config["FERNET_KEY"].encode() if isinstance(app.config["FERNET_KEY"], str) else app.config["FERNET_KEY"])
    except (TypeError, ValueError) as error:
        raise RuntimeError("FERNET_KEY must be a valid Fernet key.") from error

    Path(app.config["STORAGE_DIR"]).mkdir(parents=True, exist_ok=True)

    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please sign in to access this page."
    login_manager.login_message_category = "warning"

    from app.auth import bp as auth_bp
    from app.files import bp as files_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)

    init_db_app(app)
    app.teardown_appcontext(close_db)

    @login_manager.user_loader
    def load_user(user_id: str):
        from app.db import get_db

        row = get_db().execute(
            "SELECT id, username, password_hash, role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        return User.from_row(row) if row else None

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        return response

    return app
