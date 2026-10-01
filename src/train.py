"""Entraîne la baseline et le Random Forest, évalue, sauvegarde le modèle."""
import json

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupKFold, GroupShuffleSplit, cross_val_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from src.features import extract_features

SEED = 42
THRESHOLD = 0.5
MODEL_VERSION = "1.0.0"

# --- 1. Données et features ---
df = pd.read_csv("data/dataset.csv")
X = pd.DataFrame([extract_features(u) for u in df["url"]])
y = df["label"]
groups = df["domain"]
FEATURES = list(X.columns)
print(f"{len(df)} URLs, {len(FEATURES)} features")

# --- 2. Split par domaine (aucun domaine dans train ET test) ---
splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
train_idx, test_idx = next(splitter.split(X, y, groups))
X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
g_train = groups.iloc[train_idx]

overlap = set(groups.iloc[train_idx]) & set(groups.iloc[test_idx])
assert not overlap, "Fuite de données : domaines communs train/test"
print(f"Train : {len(X_train)} | Test : {len(X_test)} | domaines communs : 0")


def evaluate(name, model):
    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= THRESHOLD).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()
    metrics = {
        "precision": precision_score(y_test, pred),
        "recall": recall_score(y_test, pred),
        "f1": f1_score(y_test, pred),
        "fpr": fp / (fp + tn),
        "fnr": fn / (fn + tp),
        "auc": roc_auc_score(y_test, proba),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }
    print(f"\n=== {name} ===")
    for k, v in metrics.items():
        print(f"{k:10s} {v:.4f}" if isinstance(v, float) else f"{k:10s} {v}")
    return metrics


# --- 3. Baseline : régression logistique ---
baseline = make_pipeline(
    StandardScaler(), LogisticRegression(max_iter=1000, random_state=SEED)
)
baseline.fit(X_train, y_train)
m_base = evaluate("Baseline (régression logistique)", baseline)

# --- 4. Random Forest ---
rf = RandomForestClassifier(
    n_estimators=300, max_depth=None, min_samples_split=4,
    class_weight="balanced", random_state=SEED, n_jobs=-1,
)

# Validation croisée par groupes de domaines (sur le train uniquement)
cv_scores = cross_val_score(
    rf, X_train, y_train, groups=g_train,
    cv=GroupKFold(n_splits=5), scoring="f1",
)
print(f"\nValidation croisée F1 (5 plis) : {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

rf.fit(X_train, y_train)
m_rf = evaluate("Random Forest", rf)

# --- 5. Importance des features ---
importances = pd.Series(rf.feature_importances_, index=FEATURES).sort_values(ascending=False)
print("\nTop 10 features :")
print(importances.head(10).round(4))

# --- 6. Sauvegarde ---
joblib.dump(
    {"model": rf, "features": FEATURES, "version": MODEL_VERSION, "threshold": THRESHOLD},
    "models/model.joblib",
)
with open("models/metrics.json", "w") as f:
    json.dump({"baseline": m_base, "random_forest": m_rf,
               "cv_f1_mean": float(cv_scores.mean())}, f, indent=2)
print("\nModèle sauvegardé dans models/model.joblib")
