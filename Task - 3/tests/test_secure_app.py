import sqlite3

import pytest
from app.secure_app import UserStore


@pytest.fixture
def store(tmp_path):
    return UserStore(tmp_path / "test_users.db")


def test_register_and_authenticate(store):
    store.register("alice_01", "Correct-Horse-42!")
    assert store.authenticate("alice_01", "Correct-Horse-42!")


def test_wrong_password_is_rejected(store):
    store.register("alice_01", "Correct-Horse-42!")
    assert not store.authenticate("alice_01", "Wrong-Password-42!")


def test_password_is_not_stored_in_plaintext(store):
    password = "Correct-Horse-42!"
    store.register("alice_01", password)

    with sqlite3.connect(store.database_path) as connection:
        saved_hash = connection.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            ("alice_01",),
        ).fetchone()[0]

    assert saved_hash != password
    assert saved_hash.startswith("scrypt:")


def test_duplicate_username_is_rejected(store):
    store.register("alice_01", "Correct-Horse-42!")
    with pytest.raises(ValueError, match="already registered"):
        store.register("alice_01", "Another-Password-43!")


def test_invalid_username_is_rejected(store):
    with pytest.raises(ValueError, match="Username must"):
        store.register("bad user", "Correct-Horse-42!")


def test_short_password_is_rejected(store):
    with pytest.raises(ValueError, match="Password must"):
        store.register("alice_01", "short")


def test_sql_injection_string_is_treated_as_data(store):
    store.register("alice_01", "Correct-Horse-42!")
    assert not store.authenticate(
        "' OR '1'='1",
        "anything",
    )
