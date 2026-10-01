"""Interface de démonstration PhishGuard (F-12 à F-16). Aucun ML ici : tout passe par l'API."""
import os

import pandas as pd
import requests
import streamlit as st

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")

st.set_page_config(page_title="PhishGuard", page_icon="🛡️")
st.title("🛡️ PhishGuard")
st.caption("Détection de phishing par analyse d'URL (sans ouvrir la page)")

url = st.text_input("URL à analyser", placeholder="https://exemple.com/login")

if st.button("Analyser", type="primary"):
    if not url.strip():
        st.warning("Saisis une URL.")
    else:
        try:
            r = requests.post(f"{API_URL}/predict", json={"url": url}, timeout=10)
        except requests.exceptions.RequestException:
            st.error("L'API ne répond pas. Vérifie qu'elle est lancée (uvicorn api.main:app).")
        else:
            if r.status_code == 422:
                st.error("URL invalide. Exemple : https://exemple.com/page")
            elif r.status_code != 200:
                st.error(f"Erreur de l'API (code {r.status_code}).")
            else:
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
                st.dataframe(feats, use_container_width=True, hide_index=True)
                st.caption(f"Version du modèle : {data['model_version']}")
