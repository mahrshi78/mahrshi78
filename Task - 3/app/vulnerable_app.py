"""Intentionally vulnerable training example. Never use with real accounts or data."""
import sqlite3


def initialize_database(connection):
    connection.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    connection.commit()


def register_user(connection, username, password):
    # INTENTIONAL FLAW: SQL is built from untrusted input; passwords are plaintext.
    query = (
        f"INSERT INTO users (username, password) "
        f"VALUES ('{username}', '{password}')"
    )
    connection.execute(query)
    connection.commit()


def authenticate_user(connection, username, password):
    # INTENTIONAL FLAW: string interpolation permits SQL injection.
    query = (
        "SELECT id, username FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    return connection.execute(query).fetchone()


if __name__ == "__main__":
    print("INTENTIONALLY VULNERABLE TRAINING SAMPLE — use dummy data only.")
    db = sqlite3.connect(":memory:")
    initialize_database(db)
    register_user(db, "demo_user", "DemoPassword123")
    print("Created one in-memory demo account. No network service is started.")
    db.close()
