"""SQLite helpers, user model, and safe bootstrap commands."""
from __future__ import annotations

import sqlite3

import click
from flask import current_app, g
from flask_login import UserMixin
from werkzeug.security import generate_password_hash

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL UNIQUE,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS file_shares (
    file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    granted_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (file_id, user_id)
);

CREATE TABLE IF NOT EXISTS download_links (
    token_hash TEXT PRIMARY KEY,
    file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    created_by INTEGER NOT NULL REFERENCES users(id),
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    file_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


class User(UserMixin):
    def __init__(self, user_id: int, username: str, password_hash: str, role: str):
        self.id = str(user_id)
        self.username = username
        self.password_hash = password_hash
        self.role = role

    @classmethod
    def from_row(cls, row: sqlite3.Row | None):
        if row is None:
            return None
        return cls(row["id"], row["username"], row["password_hash"], row["role"])


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA busy_timeout = 5000")
    return g.db


def close_db(_error=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = get_db()
    db.executescript(SCHEMA)
    db.commit()


def init_app(app) -> None:
    app.cli.add_command(init_db_command)
    app.cli.add_command(create_admin_command)


@click.command("init-db")
def init_db_command() -> None:
    init_db()
    click.echo("Initialized the secure file-sharing database.")


@click.command("create-admin")
@click.option("--username", prompt=True)
def create_admin_command(username: str) -> None:
    """Create an administrator; roles cannot be self-selected at registration."""
    password = click.prompt("Admin password", hide_input=True, confirmation_prompt=True)
    if len(username) < 3 or len(username) > 32:
        raise click.ClickException("Username must be 3-32 characters.")
    if len(password) < 12 or len(password) > 128:
        raise click.ClickException("Password must be 12-128 characters.")
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
            (username, generate_password_hash(password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise click.ClickException("That username is already registered.") from None
    click.echo(f"Administrator {username} created.")
