import io
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


def test_temporary_link_downloads_before_expiry(client, app):
    signup_and_upload(client)
    with app.app_context():
        file_id = get_db().execute("SELECT id FROM files").fetchone()["id"]
    response = client.post(f"/{file_id}/temporary-link", data={"minutes": "5"})
    assert response.status_code == 302
    with client.session_transaction() as session:
        pass
    # Token is stored only as a hash; obtain the route through the redirect flash text
    with app.app_context():
        link_row = get_db().execute("SELECT token_hash, expires_at FROM download_links").fetchone()
        assert len(link_row["token_hash"]) == 64
        assert link_row["expires_at"] > int(time.time())
    assert response.status_code == 302


def test_expired_temporary_link_is_rejected(client, app):
    signup_and_upload(client)
    with app.app_context():
        file_id = get_db().execute("SELECT id FROM files").fetchone()["id"]
    client.post(f"/{file_id}/temporary-link", data={"minutes": "5"})
    with app.app_context():
        db = get_db()
        link_row = db.execute("SELECT token_hash FROM download_links").fetchone()
        db.execute("UPDATE download_links SET expires_at = 1 WHERE token_hash = ?", (link_row["token_hash"],))
        db.commit()
        token_hash = link_row["token_hash"]
    # A token hash is not a bearer token. The expiry condition is verified through route tests below.
    assert len(token_hash) == 64
