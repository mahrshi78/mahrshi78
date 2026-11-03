"""Registration and login routes."""
from __future__ import annotations

import re
import sqlite3

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import User, get_db

bp = Blueprint("auth", __name__)
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


@bp.route("/register", methods=("GET", "POST"))
def register():
    if current_user.is_authenticated:
        return redirect(url_for("files.index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        error = None
        if not USERNAME_RE.fullmatch(username):
            error = "Username must be 3-32 characters using letters, numbers, dot, underscore or hyphen."
        elif len(password) < 12 or len(password) > 128:
            error = "Password must be 12-128 characters."
        if error:
            flash(error, "danger")
        else:
            db = get_db()
            try:
                cursor = db.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
                    (username, generate_password_hash(password)),
                )
                db.commit()
                row = db.execute(
                    "SELECT id, username, password_hash, role FROM users WHERE id = ?",
                    (cursor.lastrowid,),
                ).fetchone()
                login_user(User.from_row(row))
                flash("Your account was created.", "success")
                return redirect(url_for("files.index"))
            except sqlite3.IntegrityError:
                db.rollback()
                flash("That username is already registered.", "danger")
    return render_template("auth/register.html")


@bp.route("/login", methods=("GET", "POST"))
def login():
    if current_user.is_authenticated:
        return redirect(url_for("files.index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        row = get_db().execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if row is None or not check_password_hash(row["password_hash"], password):
            flash("Invalid username or password.", "danger")
        else:
            login_user(User.from_row(row), remember=False, fresh=True)
            flash("Signed in successfully.", "success")
            return redirect(url_for("files.index"))
    return render_template("auth/login.html")


@bp.post("/logout")
def logout():
    if current_user.is_authenticated:
        logout_user()
    flash("You have been signed out.", "success")
    return redirect(url_for("auth.login"))
