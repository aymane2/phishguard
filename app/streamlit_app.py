"""Interface de démonstration PhishGuard. Aucun ML ici : tout passe par l'API."""
import os

import pandas as pd
import requests
import streamlit as st

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")

st.set_page_config(page_title="PhishGuard", page_icon="🛡️", layout="wide")
st.title("🛡️ PhishGuard")
st.caption("Détection de phishing par analyse d'URL (sans ouvrir la page)")

page = st.sidebar.radio("Navigation", ["Analyser", "Historique", "Certificat SSL"])


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

        level = data.get("risk_level", "low")
        if level == "high":
            st.error(f"⚠️ PHISHING détecté (confiance {data['confidence']:.0%})")
        elif level == "medium":
            st.warning("🟠 À vérifier : le modèle hésite ou un indice suspect a été relevé.")
        else:
            st.success(f"✅ URL légitime (confiance {data['confidence']:.0%})")

        st.write(f"Probabilité de phishing : **{p:.0%}** (seuil de décision : {data['threshold']})")
        st.progress(min(max(p, 0.0), 1.0))

        alert = data.get("brand_alert")
        if alert:
            st.warning(f"🎭 Usurpation de marque possible : {alert['message']}")

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
    df = df.rename(columns={
        "id": "N°", "url": "URL", "domain": "Domaine", "prediction": "Verdict",
        "probability": "Probabilité", "status": "Statut", "created_at": "Date (UTC)",
    })
    labels = {"high": "⚠️ phishing", "medium": "🟠 à vérifier", "low": "✅ légitime"}
    fallback = df["Verdict"].replace(
        {"phishing": "⚠️ phishing", "legitimate": "✅ légitime"})
    df["Verdict"] = df["risk_level"].map(labels).fillna(fallback)
    df = df.drop(columns=["risk_level"])
    df["Statut"] = df["Statut"].replace({"predicted": "prédit"})
    st.dataframe(df, width="stretch", hide_index=True)


def show_ssl():
    st.subheader("Certificat SSL d'un site")
    st.caption("Indice complémentaire : un certificat valide ne prouve pas "
               "qu'un site est honnête, les faux sites en obtiennent aussi.")
    url = st.text_input("Site à vérifier", placeholder="https://exemple.com")
    if not st.button("Vérifier le certificat", type="primary"):
        return
    if not url.strip():
        st.warning("Saisis une URL.")
        return
    try:
        r = requests.post(f"{API_URL}/ssl-check", json={"url": url}, timeout=20)
    except requests.exceptions.RequestException:
        st.error("L'API ne répond pas. Vérifie qu'elle est lancée (uvicorn api.main:app).")
        return
    if r.status_code == 422:
        st.error("URL invalide. Exemple : https://exemple.com")
        return
    if r.status_code != 200:
        st.error(f"Erreur de l'API (code {r.status_code}).")
        return

    res = r.json()
    status = res["status"]
    if status == "valid":
        if res["warnings"]:
            st.warning("🟠 Certificat valide, mais à surveiller : " + " ".join(res["warnings"]))
        else:
            st.success("✅ Certificat valide")
        rows = [
            ("Nom de domaine", res["hostname"]),
            ("Émetteur", res["issuer"]),
            ("Émis le", res["not_before"]),
            ("Expire le", res["not_after"]),
            ("Âge du certificat (jours)", res["age_days"]),
            ("Jours restants", res["days_left"]),
            ("Durée de validité (jours)", res["validity_days"]),
            ("Version TLS", res["tls_version"]),
        ]
        df = pd.DataFrame(rows, columns=["Information", "Valeur"]).astype(str)
        st.dataframe(df, width="stretch", hide_index=True)
    elif status == "invalid":
        st.error(f"❌ Certificat invalide : {res['reason']}.")
    elif status == "blocked":
        st.info(f"🔒 {res['reason']}")
    else:
        st.warning(f"⚠️ Vérification impossible : {res['reason']}")


if page == "Analyser":
    show_analysis()
elif page == "Historique":
    show_history()
else:
    show_ssl()
