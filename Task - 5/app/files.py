"""Encrypted upload, RBAC downloads, sharing and expiring download links."""
from __future__ import annotations

import hashlib
import io
import secrets
import time
import uuid
from functools import wraps
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from flask import (
    Blueprint, abort, current_app, flash, redirect, render_template,
    request, send_file, url_for,
)
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from app.db import get_db

bp = Blueprint("files", __name__)
MAX_LINK_MINUTES = 24 * 60


def get_fernet() -> Fernet:
    key = current_app.config["FERNET_KEY"]
    return Fernet(key.encode() if isinstance(key, str) else key)


def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    return filename.rsplit(".", 1)[1].lower() in current_app.config["ALLOWED_EXTENSIONS"]


def audit(action: str, file_id: str | None = None, actor_id: int | None = None) -> None:
    db = get_db()
    if actor_id is None and current_user.is_authenticated:
        actor_id = int(current_user.get_id())
    db.execute(
        "INSERT INTO audit_log (actor_id, action, file_id) VALUES (?, ?, ?)",
        (actor_id, action, file_id),
    )
    db.commit()


def get_file(file_id: str):
    return get_db().execute(
        """
        SELECT f.*, u.username AS owner_username
        FROM files AS f JOIN users AS u ON u.id = f.owner_id
        WHERE f.id = ?
        """,
        (file_id,),
    ).fetchone()


def can_manage(row) -> bool:
    return current_user.is_authenticated and (
        current_user.role == "admin" or int(row["owner_id"]) == int(current_user.get_id())
    )


def can_download(row) -> bool:
    if can_manage(row):
        return True
    return get_db().execute(
        "SELECT 1 FROM file_shares WHERE file_id = ? AND user_id = ?",
        (row["id"], int(current_user.get_id())),
    ).fetchone() is not None


def owner_or_admin(view):
    @wraps(view)
    @login_required
    def wrapped(file_id: str, *args, **kwargs):
        row = get_file(file_id)
        if row is None or not can_manage(row):
            abort(404)
        return view(file_id, *args, **kwargs)
    return wrapped


def encrypted_path(stored_name: str) -> Path:
    return Path(current_app.config["STORAGE_DIR"]) / stored_name


def decrypt_file(row) -> bytes:
    path = encrypted_path(row["stored_name"])
    if not path.is_file():
        abort(404)
    try:
        return get_fernet().decrypt(path.read_bytes())
    except InvalidToken:
        current_app.logger.error("Encrypted file failed authentication: %s", row["id"])
        abort(500)


def download_response(row):
    content = decrypt_file(row)
    audit("download", row["id"])
    response = send_file(
        io.BytesIO(content),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=row["original_name"],
        max_age=0,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@bp.get("/")
@login_required
def index():
    db = get_db()
    if current_user.role == "admin":
        rows = db.execute(
            """
            SELECT f.*, u.username AS owner_username, 'admin' AS access_type
            FROM files AS f JOIN users AS u ON u.id = f.owner_id
            ORDER BY f.uploaded_at DESC
            """
        ).fetchall()
    else:
        rows = db.execute(
            """
            SELECT DISTINCT f.*, u.username AS owner_username,
                CASE WHEN f.owner_id = ? THEN 'owner' ELSE 'shared' END AS access_type
            FROM files AS f
            JOIN users AS u ON u.id = f.owner_id
            LEFT JOIN file_shares AS s ON s.file_id = f.id
            WHERE f.owner_id = ? OR s.user_id = ?
            ORDER BY f.uploaded_at DESC
            """,
            (int(current_user.get_id()), int(current_user.get_id()), int(current_user.get_id())),
        ).fetchall()
    return render_template("files/index.html", files=rows)


@bp.post("/upload")
@login_required
def upload():
    item = request.files.get("file")
    if item is None or not item.filename:
        flash("Choose a file to upload.", "danger")
        return redirect(url_for("files.index"))

    safe_name = secure_filename(item.filename)
    if not safe_name or not allowed_file(safe_name):
        flash("This file type is not allowed.", "danger")
        return redirect(url_for("files.index"))

    plaintext = item.stream.read(current_app.config["MAX_FILE_BYTES"] + 1)
    if not plaintext:
        flash("Empty files are not allowed.", "danger")
        return redirect(url_for("files.index"))
    if len(plaintext) > current_app.config["MAX_FILE_BYTES"]:
        flash("File exceeds the configured size limit.", "danger")
        return redirect(url_for("files.index"))

    file_id = str(uuid.uuid4())
    stored_name = f"{file_id}.enc"
    path = encrypted_path(stored_name)
    encrypted = get_fernet().encrypt(plaintext)
    path.write_bytes(encrypted)

    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO files (id, owner_id, original_name, stored_name, size_bytes)
            VALUES (?, ?, ?, ?, ?)
            """,
            (file_id, int(current_user.get_id()), safe_name, stored_name, len(plaintext)),
        )
        db.commit()
        audit("upload", file_id)
    except Exception:
        db.rollback()
        path.unlink(missing_ok=True)
        raise

    flash("File encrypted and uploaded successfully.", "success")
    return redirect(url_for("files.index"))


@bp.get("/<file_id>/download")
@login_required
def download(file_id: str):
    row = get_file(file_id)
    if row is None or not can_download(row):
        abort(404)
    return download_response(row)


@bp.post("/<file_id>/share")
@owner_or_admin
def share(file_id: str):
    username = request.form.get("username", "").strip()
    db = get_db()
    target = db.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    row = get_file(file_id)
    if target is None:
        flash("User not found.", "danger")
    elif int(target["id"]) == int(row["owner_id"]):
        flash("The owner already has access.", "warning")
    else:
        try:
            db.execute(
                "INSERT INTO file_shares (file_id, user_id, granted_by) VALUES (?, ?, ?)",
                (file_id, target["id"], int(current_user.get_id())),
            )
            db.commit()
            audit("share", file_id)
            flash("Read access granted.", "success")
        except Exception:
            db.rollback()
            flash("This file is already shared with that user.", "warning")
    return redirect(url_for("files.index"))


@bp.post("/<file_id>/revoke/<int:user_id>")
@owner_or_admin
def revoke_share(file_id: str, user_id: int):
    db = get_db()
    db.execute(
        "DELETE FROM file_shares WHERE file_id = ? AND user_id = ?",
        (file_id, user_id),
    )
    db.commit()
    audit("revoke-share", file_id)
    flash("Share access revoked.", "success")
    return redirect(url_for("files.index"))


@bp.post("/<file_id>/temporary-link")
@owner_or_admin
def create_temporary_link(file_id: str):
    try:
        minutes = int(request.form.get("minutes", "60"))
    except ValueError:
        minutes = 0
    if not 1 <= minutes <= MAX_LINK_MINUTES:
        flash("Link expiry must be between 1 and 1440 minutes.", "danger")
        return redirect(url_for("files.index"))

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires_at = int(time.time()) + minutes * 60
    db = get_db()
    db.execute(
        """
        INSERT INTO download_links (token_hash, file_id, created_by, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        (token_hash, file_id, int(current_user.get_id()), expires_at),
    )
    db.commit()
    audit("temporary-link-created", file_id)
    link = url_for("files.temporary_download", token=token, _external=True)
    flash(f"Copy your temporary download link (valid for {minutes} minutes): {link}", "success")
    return redirect(url_for("files.index"))


@bp.get("/temporary/<token>")
def temporary_download(token: str):
    if len(token) > 256:
        abort(404)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = get_db().execute(
        """
        SELECT f.*, u.username AS owner_username, l.expires_at
        FROM download_links AS l
        JOIN files AS f ON f.id = l.file_id
        JOIN users AS u ON u.id = f.owner_id
        WHERE l.token_hash = ?
        """,
        (token_hash,),
    ).fetchone()
    if row is None or int(row["expires_at"]) < int(time.time()):
        abort(404)
    return download_response(row)
