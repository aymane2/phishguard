"""Interface de démonstration PhishGuard. Traduction des caractéristiques en français."""
import os

import pandas as pd
import requests
import streamlit as st

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")

st.set_page_config(page_title="PhishGuard", page_icon="🛡️", layout="wide")
st.title("🛡️ PhishGuard")
st.caption("Détection de phishing par analyse d'URL (sans ouvrir la page)")

page = st.sidebar.radio("Navigation", ["Analyser", "Historique"])

# Dictionnaire de traduction des 19 caractéristiques
FEATURE_LABELS = {
    "url_length": "Longueur totale de l'URL",
    "domain_length": "Longueur du domaine",
    "path_length": "Longueur du chemin (path)",
    "num_dots": "Nombre de points (.)",
    "num_hyphens": "Nombre de tirets (-)",
    "num_at": "Présence d'arobase (@)",
    "num_percent": "Nombre de pourcentages (%)",
    "num_question": "Nombre de points d'interrogation (?)",
    "num_equal": "Nombre de signes égal (=)",
    "num_ampersand": "Nombre de perluètes (&)",
    "num_underscore": "Nombre de tirets bas (_)",
    "num_digits": "Nombre de chiffres",
    "digit_ratio": "Ratio de chiffres",
    "entropy": "Complexité / Aléa du texte (Entropie)",
    "has_ip": "Utilise une adresse IP directe",
    "num_subdomains": "Nombre de sous-domaines",
    "risky_tld": "Extension de domaine à risque (.xyz, .top...)",
    "is_shortener": "Utilise un raccourcisseur de lien",
    "num_suspicious_words": "Mots-clés suspects détectés"
}


def show_cert(cert):
    status = cert.get("status")
    if status == "valid":
        st.info(f"🔒 Certificat SSL valide : émetteur {cert['issuer']}, "
                f"émis il y a {cert['age_days']} jour(s), expire le {cert['not_after']}.")
        for warning in cert.get("warnings", []):
            st.caption("ℹ️ " + warning)
    elif status == "invalid":
        st.warning(f"❌ Certificat SSL invalide : {cert['reason']}.")
    elif status == "unreachable":
        st.caption("Certificat SSL non vérifié : " + cert["reason"])


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

        cert = data.get("ssl_info")
        if cert:
            show_cert(cert)

        st.subheader("Caractéristiques extraites (Explicabilité)")

        # Application des libellés en français
        translated_features = {
            FEATURE_LABELS.get(k, k): v
            for k, v in data["features"].items()
        }

        feats = pd.DataFrame(
            {"Caractéristique": list(translated_features.keys()),
             "Valeur": list(translated_features.values())}
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


if page == "Analyser":
    show_analysis()
else:
    show_history()