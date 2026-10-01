"""Construit data/dataset.csv (url, label, domain) à partir de PhishTank et Tranco."""
import random

import pandas as pd
import tldextract

SEED = 42
N_PER_CLASS = 5000
random.seed(SEED)

# Extracteur de domaine hors-ligne (pas de téléchargement)
extract = tldextract.TLDExtract(suffix_list_urls=())


def registered_domain(url: str) -> str:
    return extract(url).registered_domain


# --- 1. Phishing (label = 1) ---
phish = pd.read_csv("data/phishtank.csv", usecols=["url"])
phish = phish.dropna().drop_duplicates()
phish = phish.sample(n=min(N_PER_CLASS, len(phish)), random_state=SEED)
phish["label"] = 1

# --- 2. Légitime (label = 0) ---
tranco = pd.read_csv("data/top-1m.csv", names=["rank", "domain"])
tranco = tranco.head(100_000).sample(n=N_PER_CLASS, random_state=SEED)

# Les domaines Tranco sont "nus" ; on construit des URLs réalistes,
# sinon le modèle apprendrait "pas de chemin = légitime".
PATHS = ["", "", "login", "account", "signin", "about", "products",
         "help", "contact", "en/home", "search?q=test", "news/2026/article"]


def build_url(domain: str) -> str:
    path = random.choice(PATHS)
    return f"https://{domain}/{path}" if path else f"https://{domain}"


legit = pd.DataFrame({"url": [build_url(d) for d in tranco["domain"]]})
legit["label"] = 0

# --- 3. Fusion, nettoyage ---
df = pd.concat([phish, legit], ignore_index=True)
df["url"] = df["url"].str.strip()
df = df[df["url"].str.len() > 0].drop_duplicates(subset="url")
df["domain"] = df["url"].apply(registered_domain)
df = df[df["domain"] != ""]

# Un domaine présent dans les deux classes serait ambigu : on l'écarte
both = set(df[df.label == 0]["domain"]) & set(df[df.label == 1]["domain"])
df = df[~df["domain"].isin(both)]

df = df.sample(frac=1, random_state=SEED).reset_index(drop=True)
df.to_csv("data/dataset.csv", index=False)

print(df["label"].value_counts())
print(df.head(10))
print(f"Domaines uniques : {df['domain'].nunique()}")
