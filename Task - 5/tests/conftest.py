import pytest
from cryptography.fernet import Fernet

from app import create_app
from app.db import init_db


@pytest.fixture
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key-do-not-use-in-production",
        "FERNET_KEY": Fernet.generate_key(),
        "DATABASE": str(tmp_path / "test.sqlite"),
        "STORAGE_DIR": str(tmp_path / "encrypted"),
        "WTF_CSRF_ENABLED": False,
    })
    with app.app_context():
        init_db()
    yield app


@pytest.fixture
def client(app):
    return app.test_client()
