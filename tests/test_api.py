import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(model_path, monkeypatch, tmp_path):
    monkeypatch.setenv("SCAMCHECK_MODEL", str(model_path))
    from scamcheck import api
    api.RATE_LIMIT = 30
    with TestClient(api.app) as c:
        yield c


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.json()["metrics"]["uci_test"]["precision"] > 0.9


def test_check_scam(client):
    r = client.post("/api/check", json={"message": "Royal Mail: pay £1.45 at royalmail-redelivery-uk.com today"})
    body = r.json()
    assert r.status_code == 200 and body["verdict"] == "scam"
    assert any(s["id"] == "fake_link" for s in body["signals"])


def test_check_genuine(client):
    r = client.post("/api/check", json={"message": "See you at the park at 2?"})
    assert r.json()["verdict"] == "no_signs"


@pytest.mark.parametrize("payload", [{}, {"message": ""}, {"message": "x" * 2001}, {"message": 123}])
def test_bad_input_rejected(client, payload):
    assert client.post("/api/check", json=payload).status_code == 422


def test_whitespace_only_gives_friendly_error(client):
    r = client.post("/api/check", json={"message": "   "})
    assert r.status_code == 422 and "paste a message" in r.json()["detail"]


def test_security_headers(client):
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


def test_rate_limit(client):
    client.app.state.limiter.per_minute = 3
    codes = [client.post("/api/check", json={"message": "hello"}).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]


def test_messages_are_not_logged(client, caplog):
    secret = "my card number is 4111111111111111"
    client.post("/api/check", json={"message": secret})
    assert secret not in caplog.text
