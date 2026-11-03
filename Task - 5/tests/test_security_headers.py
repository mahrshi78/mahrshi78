def test_security_headers_are_present(client):
    response = client.get("/login")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_private_pages_require_authentication(client):
    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
