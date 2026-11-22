"""Test bootstrap: isolated data directory and a single FastAPI test client."""
from __future__ import annotations

import os
import tempfile

# Environment must be set before the application modules import config.
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="promptshield-test-")
os.environ["SEED_DEMO_SCANS"] = "0"
os.environ["SEED_DEMO_USERS"] = "1"
os.environ["PROMPTSHIELD_SECRET"] = "test-signing-key-not-for-production"
os.environ["RATE_LIMIT_SCAN_PER_MINUTE"] = "500"
os.environ["ALLOW_PRIVATE_URL_FETCH"] = "0"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import config  # noqa: E402
from app.main import app  # noqa: E402

ADMIN = {"email": config.SEED_ADMIN_EMAIL, "password": config.SEED_ADMIN_PASSWORD}
ANALYST = {"email": "analyst@promptshield.ai", "password": config.SEED_DEMO_PASSWORD}
VIEWER = {"email": "viewer@promptshield.ai", "password": config.SEED_DEMO_PASSWORD}


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as test_client:
        yield test_client


def _login(client: TestClient, creds: dict) -> str:
    response = client.post("/api/auth/login", json=creds)
    assert response.status_code == 200, response.text
    return response.json()["token"]


@pytest.fixture(scope="session")
def admin_token(client) -> str:
    return _login(client, ADMIN)


@pytest.fixture(scope="session")
def analyst_token(client) -> str:
    return _login(client, ANALYST)


@pytest.fixture(scope="session")
def viewer_token(client) -> str:
    return _login(client, VIEWER)


@pytest.fixture()
def admin_headers(admin_token) -> dict:
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture()
def analyst_headers(analyst_token) -> dict:
    return {"Authorization": f"Bearer {analyst_token}"}


@pytest.fixture()
def viewer_headers(viewer_token) -> dict:
    return {"Authorization": f"Bearer {viewer_token}"}
