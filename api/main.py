"""API REST PhishGuard : /predict et /health (F-06, F-08, F-10, F-11)."""
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator

from src.features import extract_features, normalize_url

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "model.joblib"
state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Le modèle est chargé une seule fois, au démarrage
    state["artifact"] = joblib.load(MODEL_PATH)
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


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    art = state["artifact"]
    feats = extract_features(req.url)
    X = pd.DataFrame([feats])[art["features"]]
    p_phish = float(art["model"].predict_proba(X)[0, 1])
    is_phish = p_phish >= art["threshold"]
    return PredictResponse(
        prediction="phishing" if is_phish else "legitimate",
        confidence=round(p_phish if is_phish else 1 - p_phish, 4),
        phishing_probability=round(p_phish, 4),
        threshold=art["threshold"],
        features=feats,
        model_version=art["version"],
    )
