"""API tests with the network and database disabled."""
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import core
import index
from detectors import netsafe


@pytest.fixture
def client():
    core._hits.clear()
    return TestClient(index.app)


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["model_loaded"] is True


def test_guest_check(client):
    r = client.post("/api/check-url", json={"url": "http://paypa1.com/login"})
    assert r.status_code == 200
    body = r.json()
    assert body["risk_level"] in ("high", "critical")
    assert body["signals"] and body["signals"][0]["title"]


def test_invalid_url_is_400_with_clear_message(client):
    r = client.post("/api/check-url", json={"url": "ftp://example.com"})
    assert r.status_code == 400
    assert "http" in r.json()["detail"]


def test_missing_url_is_422(client):
    r = client.post("/api/check-url", json={})
    assert r.status_code == 422


def test_guest_rate_limit(client):
    with mock.patch.object(core, "GUEST_PER_MINUTE", 3):
        codes = [client.post("/api/check-url", json={"url": "example.com"}).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200]
    assert codes[3] == 429


def test_signup_unavailable_without_db(client):
    r = client.post("/api/auth/signup", json={"email": "a@example.com"})
    assert r.status_code == 503


def test_signup_does_not_leak_existing_key(client):
    fake = mock.MagicMock()
    fake.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value.data = [{"id": 1}]
    with mock.patch.object(core, "supabase", return_value=fake):
        r = client.post("/api/auth/signup", json={"email": "victim@example.com"})
    assert r.status_code == 409
    assert "pg_" not in r.text


def test_bad_api_key_rejected_without_db_call(client):
    r = client.post("/api/check-url", json={"url": "example.com"}, headers={"X-API-Key": "nope"})
    assert r.status_code == 401


def test_internal_errors_are_not_leaked(client):
    with mock.patch("detectors.scorer.analyze", side_effect=RuntimeError("secret db password=hunter2")):
        r = client.post("/api/check-url", json={"url": "example.com"})
    assert r.status_code == 500
    assert "hunter2" not in r.text


@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.169.254", "10.0.0.5", "[::1]"])
def test_ssrf_guard_blocks_internal_addresses(host):
    res = netsafe.follow_redirects(f"http://{host}/latest/meta-data/")
    assert res.status is None and res.error


def test_ssrf_guard_blocks_hostname_resolving_private():
    with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("10.1.2.3", 0))]):
        res = netsafe.follow_redirects("http://internal.example/")
    assert res.status is None and "non-public" in (res.error or "")
