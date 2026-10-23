"""API REST PhishGuard : /predict et /health (F-06, F-08, F-10, F-11)."""
import os
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
from fastapi import FastAPI, Query
from pydantic import BaseModel, Field, field_validator
import tldextract

from src.brands import check_brand
from src.db import history, init_db, save_scan
from src.features import extract_features, normalize_url
from src.risk import risk_level
from src.ssl_check import check_certificate
from src.allowlist import is_allowed

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "model.joblib"
state: dict = {}
extract_domain = tldextract.TLDExtract(suffix_list_urls=())


@asynccontextmanager
async def lifespan(app: FastAPI):
    state["artifact"] = joblib.load(MODEL_PATH)
    init_db()
    yield
    state.clear()


app = FastAPI(title="PhishGuard API", version="1.0.0", lifespan=lifespan)


class PredictRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)

    @field_validator("url")
    @classmethod
    def check_url(cls, v: str) -> str:
        v = v.strip()
        host = urlparse(normalize_url(v)).hostname
        if not host or "." not in host or " " in v:
            raise ValueError("URL invalide")
        return v


class PredictResponse(BaseModel):
    prediction: str
    confidence: float
    phishing_probability: float
    threshold: float
    features: dict
    model_version: str
    brand_alert: dict | None = None
    risk_level: str = "low"
    ssl_info: dict | None = None


def _ssl_info(url: str) -> dict | None:
    if os.getenv("PHISHGUARD_SSL_CHECK", "1") == "0":
        return None
    return check_certificate(url, timeout=3.0)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    art = state["artifact"]
    feats = extract_features(req.url)

    # Extraction du domaine enregistré pour la liste blanche
    ext = extract_domain(req.url)
    domain_name = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else ""

    X = pd.DataFrame([feats])[art["features"]]
    p_phish = float(art["model"].predict_proba(X)[0, 1])

    brand = check_brand(req.url)
    cert = _ssl_info(req.url)

    # Vérification de la liste blanche (si le site est de confiance avec un SSL valide)
    if is_allowed(domain_name) and (not cert or cert.get("status") == "valid"):
        p_phish = 0.01  # Probabilité quasi nulle
        is_phish = False
    else:
        is_phish = p_phish >= art["threshold"]

    level = risk_level(p_phish, art["threshold"], brand, cert)

    save_scan(req.url, p_phish, "phishing" if is_phish else "legitimate",
              art["version"], feats, level)

    return PredictResponse(
        prediction="phishing" if is_phish else "legitimate",
        confidence=round(p_phish if is_phish else 1 - p_phish, 4),
        phishing_probability=round(p_phish, 4),
        threshold=art["threshold"],
        features=feats,
        model_version=art["version"],
        brand_alert=brand,
        risk_level=level,
        ssl_info=cert,
    )


@app.get("/history")
def get_history(
    limit: int = Query(50, ge=1, le=500),
    suspicious_only: bool = False,
):
    return history(limit=limit, suspicious_only=suspicious_only)