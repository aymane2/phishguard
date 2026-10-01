"""Choisit le seuil de décision par validation croisée, puis évalue sur le test."""
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import GroupKFold, GroupShuffleSplit, cross_val_predict

from src.features import extract_features

SEED = 42
MAX_FPR = 0.05  # tolérance aux faux positifs choisie pour le projet

df = pd.read_csv("data/dataset.csv")
X = pd.DataFrame([extract_features(u) for u in df["url"]])
y, groups = df["label"], df["domain"]

# Même split que train.py (même graine)
tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED).split(X, y, groups))
art = joblib.load("models/model.joblib")

rf_cv = RandomForestClassifier(
    n_estimators=300, min_samples_split=4, class_weight="balanced",
    random_state=SEED, n_jobs=-1,
)
proba_val = cross_val_predict(
    rf_cv, X.iloc[tr], y.iloc[tr], groups=groups.iloc[tr],
    cv=GroupKFold(n_splits=5), method="predict_proba",
)[:, 1]


def rates(y_true, proba, t):
    pred = (proba >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return fp / (fp + tn), tp / (tp + fn), tp / max(tp + fp, 1)


best = 0.5
for t in np.arange(0.05, 0.96, 0.05):
    fpr, rec, _ = rates(y.iloc[tr], proba_val, t)
    if fpr <= MAX_FPR:
        best = round(float(t), 2)
        break
print(f"Seuil choisi (validation, FPR <= {MAX_FPR}) : {best}")

proba_test = art["model"].predict_proba(X.iloc[te])[:, 1]
print("\nseuil   FPR    rappel  précision   (jeu de test)")
for t in [0.3, 0.35, 0.4, 0.45, 0.5, 0.6, best]:
    fpr, rec, prec = rates(y.iloc[te], proba_test, t)
    mark = "  <-- choisi" if t == best else ""
    print(f"{t:<7} {fpr:.3f}  {rec:.3f}   {prec:.3f}{mark}")

art["threshold"] = best
joblib.dump(art, "models/model.joblib")
print(f"\nSeuil {best} enregistré dans models/model.joblib")
