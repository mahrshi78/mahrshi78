import io
import sqlite3

from app.db import get_db


def signup(client, username, password="Correct-Horse-42!"):
    client.post("/register", data={"username": username, "password": password})


def test_upload_is_encrypted_at_rest_and_owner_can_download(client, app, tmp_path):
    signup(client, "alice")
    payload = b"confidential file contents"
    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(payload), "notes.txt")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 302

    with app.app_context():
        row = get_db().execute("SELECT * FROM files").fetchone()
        stored = (tmp_path / "encrypted" / row["stored_name"]).read_bytes()
        assert payload not in stored
        assert stored != payload

    download = client.get(f"/{row['id']}/download")
    assert download.status_code == 200
    assert download.data == payload
    assert download.headers["Content-Disposition"].startswith("attachment;")


def test_other_user_cannot_download_private_file(client, app):
    signup(client, "alice")
    client.post(
        "/upload",
        data={"file": (io.BytesIO(b"secret"), "private.txt")},
        content_type="multipart/form-data",
    )
    with app.app_context():
        file_id = get_db().execute("SELECT id FROM files").fetchone()["id"]

    client.post("/logout")
    signup(client, "bob")
    response = client.get(f"/{file_id}/download")
    assert response.status_code == 404


def test_upload_rejects_disallowed_extension(client, app):
    signup(client, "alice")
    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(b"not executable"), "tool.exe")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert b"file type is not allowed" in response.data.lower()
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) AS n FROM files").fetchone()["n"] == 0
