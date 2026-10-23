# PhishGuard

![CI](https://github.com/aymane2/phishguard/actions/workflows/ci.yml/badge.svg)

Détecteur de phishing par analyse d'URL (sans ouvrir la page) : Random Forest (300 arbres), API REST FastAPI, interface Streamlit (en français), Docker, CI GitHub Actions. Projet de validation M1.

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

La même chaîne s'exécute automatiquement à chaque push (GitHub Actions) — **55 tests unitaires validés**.

## Résultats (jeu de test)

| Métrique | Résultat | Minimal visé |
|---|---|---|
| Précision | 0,959 | 0,90 |
| Rappel | 0,901 | 0,90 |
| Taux de faux positifs | 0,051 | 0,07 |
| AUC-ROC | 0,968 | 0,95 |

Le split est fait par domaine (aucun domaine commun entre entraînement et test) ; le seuil est choisi par validation croisée sur l'entraînement uniquement.

## Limites connues & Améliorations récentes

- **Domaines nus et faux positifs** : Intégration d'une proportion de domaines nus intacts dans la préparation des données et d'une **liste blanche (`src/allowlist.py`)** combinée à un certificat SSL valide pour éliminer les faux positifs sur les grands sites légitimes (ex. `fundingpips.com`).
- **Features lexicales uniquement** : pas de WHOIS/DNS, pas d'analyse du contenu de la page (prévu dans les évolutions futures).
- La feature « HTTPS » est volontairement exclue : toutes les URLs légitimes du jeu de données étant en HTTPS, cela créerait un biais d'apprentissage.

## Structure

- `api/` : API FastAPI (`/predict`, `/health`)
- `app/` : interface Streamlit (entièrement traduite en français avec explicabilité des 19 features)
- `src/` : extraction de features, préparation des données, liste blanche (`allowlist.py`), calcul du risque (`risk.py`), entraînement, seuil
- `models/` : modèle sérialisé (.joblib) et métriques
- `tests/` : tests pytest (55 tests)
- `Dockerfile` : image de l'API

## Tout lancer d'une commande (API + interface)

    docker compose up --build

Interface : http://localhost:8501, API : http://localhost:8000/docs

## Fonctionnalités Avancées

- **Historique** : chaque analyse est enregistrée dans une base SQLite (`data/phishguard.db`). Page « Historique » dans l'interface et route `GET /history`.
- **Usurpation de marque** : une alerte apparaît si un domaine contient ou imite une marque connue (`src/brands.py`).
- **Verdict en 3 niveaux (Sécurité & Risque)** :
  - 🟢 **Vert (Légitime)** : score faible ou site présent dans la liste blanche avec SSL valide.
  - 🟠 **Orange (À vérifier)** : probabilité comprise entre 0,35 et 0,65, alerte de marque ou certificat SSL invalide.
  - 🔴 **Rouge (Phishing)** : probabilité supérieure à 0,65 ou dépassant le seuil strict.
- **Certificat SSL** : l'API valide le certificat du site en arrière-plan (`src/ssl_check.py`) avec protection contre le SSRF.