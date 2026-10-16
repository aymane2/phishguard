"""Interface de démonstration PhishGuard. Aucun ML ici : tout passe par l'API."""
import os

import pandas as pd
import requests
import streamlit as st

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")

st.set_page_config(page_title="PhishGuard", page_icon="🛡️")
st.title("🛡️ PhishGuard")
st.caption("Détection de phishing par analyse d'URL (sans ouvrir la page)")

page = st.sidebar.radio("Navigation", ["Analyser", "Historique"])


def show_analysis():
    url = st.text_input("URL à analyser", placeholder="https://exemple.com/login")

    if st.button("Analyser", type="primary"):
        if not url.strip():
            st.warning("Saisis une URL.")
            return
        try:
            r = requests.post(f"{API_URL}/predict", json={"url": url}, timeout=10)
        except requests.exceptions.RequestException:
            st.error("L'API ne répond pas. Vérifie qu'elle est lancée (uvicorn api.main:app).")
            return
        if r.status_code == 422:
            st.error("URL invalide. Exemple : https://exemple.com/page")
            return
        if r.status_code != 200:
            st.error(f"Erreur de l'API (code {r.status_code}).")
            return

        data = r.json()
        p = data["phishing_probability"]

        if data["prediction"] == "phishing":
            st.error(f"⚠️ PHISHING détecté (confiance {data['confidence']:.0%})")
        else:
            st.success(f"✅ URL légitime (confiance {data['confidence']:.0%})")

        st.write(f"Probabilité de phishing : **{p:.0%}** (seuil de décision : {data['threshold']})")
        st.progress(min(max(p, 0.0), 1.0))

        st.subheader("Caractéristiques extraites")
        feats = pd.DataFrame(
            {"caractéristique": list(data["features"].keys()),
             "valeur": list(data["features"].values())}
        )
        st.dataframe(feats, width="stretch", hide_index=True)
        st.caption(f"Version du modèle : {data['model_version']}")


def show_history():
    st.subheader("Historique des analyses")
    only_suspicious = st.checkbox("Seulement les sites suspects", value=True)
    limit = st.slider("Nombre d'analyses affichées", 5, 200, 50)
    try:
        r = requests.get(
            f"{API_URL}/history",
            params={"limit": limit, "suspicious_only": only_suspicious},
            timeout=10,
        )
    except requests.exceptions.RequestException:
        st.error("L'API ne répond pas. Vérifie qu'elle est lancée (uvicorn api.main:app).")
        return
    if r.status_code != 200:
        st.error(f"Erreur de l'API (code {r.status_code}).")
        return
    rows = r.json()
    if not rows:
        st.info("Aucune analyse enregistrée pour l'instant.")
        return
    df = pd.DataFrame(rows)
    df["probability"] = (df["probability"] * 100).round(1).astype(str) + " %"
    st.caption(f"{len(df)} analyse(s) affichée(s)")
    st.dataframe(df, width="stretch", hide_index=True)


if page == "Analyser":
    show_analysis()
else:
    show_history()
