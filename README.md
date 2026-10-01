# PhishGuard

![CI](https://github.com/aymane2/phishguard/actions/workflows/ci.yml/badge.svg)

Détecteur de phishing par analyse d'URL (sans ouvrir la page) : Random Forest, API REST FastAPI, interface Streamlit, Docker, CI GitHub Actions. Projet de validation M1.

## Architecture

- **Phase 1, entraînement (hors-ligne)** : données, features, Random Forest, `models/model.joblib`.
- **Phase 2, service (en ligne)** : l'API FastAPI charge le modèle au démarrage ; Streamlit appelle l'API et n'a aucun code de ML.

Chaîne complète :

    data/ -> src/prepare_data.py -> src/train.py -> src/threshold.py -> models/model.joblib
                                                                              |
                                               api/main.py (FastAPI)  <-------+
                                                      ^
                                          app/streamlit_app.py (interface)

## Installation

    git clone https://github.com/aymane2/phishguard.git
    cd phishguard
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements-dev.txt
    pip install streamlit requests

## Lancer l'API

    uvicorn api.main:app --reload

Documentation interactive : http://127.0.0.1:8000/docs

Test rapide :

    curl -X POST http://127.0.0.1:8000/predict \
      -H "Content-Type: application/json" \
      -d '{"url": "http://paypal-secure-login.verify-account.xyz/signin"}'

## Lancer l'interface

Dans un second terminal, avec l'API déjà lancée :

    streamlit run app/streamlit_app.py

## Avec Docker (API)

    docker build -t phishguard-api .
    docker run -d --name phishguard -p 8001:8000 phishguard-api
    curl http://127.0.0.1:8001/health

## Reproduire l'entraînement

Le dossier `data/` n'est pas versionné. Pour le reconstituer :

    mkdir -p data && cd data
    curl -L -o tranco.zip https://tranco-list.eu/top-1m.csv.zip && unzip tranco.zip
    curl -L -A "phishtank/votre-projet" -o phishtank.csv http://data.phishtank.com/data/online-valid.csv
    cd ..
    python src/prepare_data.py
    python -m src.train
    python -m src.threshold

Les sources étant mises à jour en continu, les résultats varieront légèrement d'une exécution à l'autre.

## Tests et qualité

    python -m pytest -v
    python -m ruff check .

La même chaîne s'exécute automatiquement à chaque push (GitHub Actions).

## Résultats (jeu de test, seuil de décision 0,45)

| Métrique | Résultat | Minimal visé |
|---|---|---|
| Précision | 0,966 | 0,90 |
| Rappel | 0,901 | 0,90 |
| Taux de faux positifs | 0,043 | 0,07 |
| AUC-ROC | 0,972 | 0,95 |

Le split est fait par domaine (aucun domaine commun entre entraînement et test) ; le seuil est choisi par validation croisée sur l'entraînement uniquement.

## Limites connues

- **Dataset partiellement synthétique** : les URLs légitimes viennent de Tranco (domaines seuls), complétées par des sous-domaines et chemins générés aléatoirement. Le modèle peut apprendre des habitudes de ce générateur : les scores réels seraient probablement plus bas.
- **Faux positifs sur des URLs légitimes longues** (ex. liens Amazon avec identifiants).
- **Features lexicales uniquement** : pas de WHOIS/DNS, pas d'analyse du contenu de la page.
- **Rappel proche du minimum** : à 0,45, le rappel est de 0,901 pour un minimum de 0,90.
- La feature « HTTPS » est volontairement exclue : toutes les URLs légitimes du jeu de données sont en HTTPS, ce qui créerait un biais.

## Structure

- `api/` : API FastAPI (`/predict`, `/health`)
- `app/` : interface Streamlit
- `src/` : extraction de features, préparation des données, entraînement, seuil
- `models/` : modèle sérialisé (.joblib) et métriques
- `tests/` : tests pytest
- `Dockerfile` : image de l'API
