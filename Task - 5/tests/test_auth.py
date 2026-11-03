def register(client, username="alice", password="Correct-Horse-42!"):
    return client.post("/register", data={"username": username, "password": password})


def test_registration_creates_standard_user(client, app):
    response = register(client)
    assert response.status_code == 302
    with app.app_context():
        from app.db import get_db
        row = get_db().execute(
            "SELECT username, password_hash, role FROM users WHERE username = ?",
            ("alice",),
        ).fetchone()
    assert row["role"] == "user"
    assert row["password_hash"] != "Correct-Horse-42!"


def test_registration_rejects_short_password(client):
    response = register(client, password="short")
    assert response.status_code == 200
    assert b"Password must be 12-128 characters" in response.data


def test_login_rejects_wrong_password(client):
    register(client)
    client.post("/logout")
    response = client.post("/login", data={
        "username": "alice", "password": "Wrong-Password-99!",
    })
    assert b"Invalid username or password" in response.data


def test_registration_cannot_select_admin_role(client, app):
    register(client)
    with app.app_context():
        from app.db import get_db
        row = get_db().execute(
            "SELECT role FROM users WHERE username = ?", ("alice",)
        ).fetchone()
    assert row["role"] == "user"
