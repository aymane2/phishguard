import pytest
from fastapi.testclient import TestClient

from api.main import app


@pytest.fixture(scope="module")
def client():
    # "with" déclenche le chargement du modèle (lifespan)
    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_predict_returns_expected_fields(client):
    r = client.post("/predict", json={"url": "https://www.google.com"})
    assert r.status_code == 200
    data = r.json()
    for key in ["prediction", "confidence", "phishing_probability",
                "threshold", "features", "model_version"]:
        assert key in data
    assert data["prediction"] in ("phishing", "legitimate")
    assert 0.0 <= data["phishing_probability"] <= 1.0


def test_suspicious_url_scores_higher_than_known_site(client):
    legit = client.post("/predict", json={"url": "https://www.google.com"}).json()
    phish = client.post(
        "/predict",
        json={"url": "http://paypal-secure-login.verify-account.xyz/signin"},
    ).json()
    assert phish["phishing_probability"] > legit["phishing_probability"]


def test_invalid_url_returns_422(client):
    r = client.post("/predict", json={"url": "pas une url"})
    assert r.status_code == 422


def test_missing_url_returns_422(client):
    r = client.post("/predict", json={})
    assert r.status_code == 422
