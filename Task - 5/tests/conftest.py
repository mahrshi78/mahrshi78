"""Pytest fixtures and import-path setup for Task 5."""
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

TASK_ROOT = Path(__file__).resolve().parents[1]
if str(TASK_ROOT) not in sys.path:
    sys.path.insert(0, str(TASK_ROOT))

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
