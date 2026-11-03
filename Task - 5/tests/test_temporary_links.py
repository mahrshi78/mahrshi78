import io
import re
import time

from app.db import get_db


def signup_and_upload(client):
    client.post("/register", data={
        "username": "alice", "password": "Correct-Horse-42!",
    })
    client.post(
        "/upload",
        data={"file": (io.BytesIO(b"temporary secret"), "temp.txt")},
        content_type="multipart/form-data",
    )


def create_temp_link(client, app):
    with app.app_context():
        file_id = get_db().execute("SELECT id FROM files").fetchone()["id"]
    response = client.post(
        f"/{file_id}/temporary-link",
        data={"minutes": "5"},
        follow_redirects=True,
    )
    match = re.search(rb"/temporary/([A-Za-z0-9_-]+)", response.data)
    assert match is not None
    return file_id, match.group(1).decode("ascii")


def test_temporary_link_downloads_before_expiry(client, app):
    signup_and_upload(client)
    file_id, token = create_temp_link(client, app)
    with app.app_context():
        row = get_db().execute(
            "SELECT token_hash, expires_at FROM download_links WHERE file_id = ?",
            (file_id,),
        ).fetchone()
        assert len(row["token_hash"]) == 64
        assert token not in row["token_hash"]
        assert row["expires_at"] > int(time.time())
    response = client.get(f"/temporary/{token}")
    assert response.status_code == 200
    assert response.data == b"temporary secret"


def test_expired_temporary_link_is_rejected(client, app):
    signup_and_upload(client)
    file_id, token = create_temp_link(client, app)
    with app.app_context():
        db = get_db()
        db.execute(
            "UPDATE download_links SET expires_at = 1 WHERE file_id = ?",
            (file_id,),
        )
        db.commit()
    response = client.get(f"/temporary/{token}")
    assert response.status_code == 404


def test_temporary_link_rejects_invalid_expiry(client, app):
    signup_and_upload(client)
    with app.app_context():
        file_id = get_db().execute("SELECT id FROM files").fetchone()["id"]
    response = client.post(
        f"/{file_id}/temporary-link",
        data={"minutes": "99999"},
        follow_redirects=True,
    )
    assert b"Link expiry must be between 1 and 1440 minutes" in response.data
    with app.app_context():
        count = get_db().execute("SELECT COUNT(*) AS n FROM download_links").fetchone()["n"]
    assert count == 0
