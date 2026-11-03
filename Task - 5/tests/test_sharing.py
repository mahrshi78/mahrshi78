import io

from app.db import get_db


def signup(client, username):
    client.post("/register", data={
        "username": username, "password": "Correct-Horse-42!",
    })


def upload_one(client):
    client.post(
        "/upload",
        data={"file": (io.BytesIO(b"shared data"), "shared.txt")},
        content_type="multipart/form-data",
    )


def test_owner_can_share_read_access_and_revoke_it(client, app):
    signup(client, "alice")
    upload_one(client)
    with app.app_context():
        file_id = get_db().execute("SELECT id FROM files").fetchone()["id"]
    signup(client, "bob")
    with app.app_context():
        bob_id = get_db().execute(
            "SELECT id FROM users WHERE username = ?", ("bob",)
        ).fetchone()["id"]
    client.post("/logout")
    # Sign back in as the owner to grant access.
    client.post("/login", data={"username": "alice", "password": "Correct-Horse-42!"})
    result = client.post(f"/{file_id}/share", data={"username": "bob"})
    assert result.status_code == 302
    client.post("/logout")
    client.post("/login", data={"username": "bob", "password": "Correct-Horse-42!"})
    assert client.get(f"/{file_id}/download").data == b"shared data"
    client.post("/logout")
    client.post("/login", data={"username": "alice", "password": "Correct-Horse-42!"})
    client.post(f"/{file_id}/revoke/{bob_id}")
    client.post("/logout")
    client.post("/login", data={"username": "bob", "password": "Correct-Horse-42!"})
    assert client.get(f"/{file_id}/download").status_code == 404
