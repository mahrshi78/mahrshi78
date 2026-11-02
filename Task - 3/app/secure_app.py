"""Secure-by-default local user store for the CodSoft Task 3 assessment."""
from __future__ import annotations

import argparse
import re
import sqlite3
from getpass import getpass
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128


class UserStore:
    """SQLite-backed user store with parameterized queries and password hashing."""

    def __init__(self, database_path: str | Path = "users.db") -> None:
        self.database_path = str(database_path)
        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL
                )
                """
            )

    @staticmethod
    def _validate_username(username: str) -> str:
        if not isinstance(username, str) or not USERNAME_PATTERN.fullmatch(username):
            raise ValueError(
                "Username must be 3-32 characters: letters, numbers, dot, "
                "underscore or hyphen."
            )
        return username

    @staticmethod
    def _validate_password(password: str) -> None:
        if not isinstance(password, str):
            raise TypeError("Password must be text.")
        if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
            raise ValueError(
                f"Password must be {MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} "
                "characters long."
            )

    def register(self, username: str, password: str) -> None:
        """Create an account; only a one-way password hash is stored."""
        username = self._validate_username(username)
        self._validate_password(password)
        password_hash = generate_password_hash(password)

        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash),
                )
        except sqlite3.IntegrityError:
            raise ValueError("Username is already registered.") from None

    def authenticate(self, username: str, password: str) -> bool:
        """Return a boolean and avoid revealing which credential was incorrect."""
        if not isinstance(username, str) or not isinstance(password, str):
            return False

        with self._connect() as connection:
            user = connection.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if user is None:
            return False
        return check_password_hash(user["password_hash"], password)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Local secure user registration and authentication demo."
    )
    parser.add_argument(
        "--db",
        default="users.db",
        help="SQLite database path (default: users.db)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    register_parser = subparsers.add_parser("register", help="Create a demo user")
    register_parser.add_argument("--username", required=True)

    login_parser = subparsers.add_parser("login", help="Verify a demo user")
    login_parser.add_argument("--username", required=True)

    args = parser.parse_args()
    store = UserStore(args.db)
    password = getpass("Password: ")

    try:
        if args.command == "register":
            store.register(args.username, password)
            print("Account created successfully.")
        elif store.authenticate(args.username, password):
            print("Authentication successful.")
        else:
            print("Invalid username or password.")
    except ValueError as error:
        print(f"Registration failed: {error}")


if __name__ == "__main__":
    main()
