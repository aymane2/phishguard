"""Construit data/dataset.csv (url, label, domain) à partir de PhishTank et Tranco."""
import random
import string

import pandas as pd
import tldextract

SEED = 42
N_PER_CLASS = 5000
random.seed(SEED)

extract = tldextract.TLDExtract(suffix_list_urls=())


def registered_domain(url: str) -> str:
    return extract(url).top_domain_under_public_suffix


# --- 1. Phishing (label = 1) ---
phish = pd.read_csv("data/phishtank.csv", usecols=["url"])
phish = phish.dropna().drop_duplicates()
phish = phish.sample(n=min(N_PER_CLASS, len(phish)), random_state=SEED)
phish["label"] = 1

# --- 2. Légitime (label = 0) ---
tranco = pd.read_csv("data/top-1m.csv", names=["rank", "domain"])
tranco = tranco.head(100_000).sample(n=N_PER_CLASS, random_state=SEED)

SUBDOMAINS = (
    [""] * 30 + ["www."] * 35
    + ["mail.", "blog.", "support.", "docs.", "app.", "shop.", "fr.", "en.",
       "m.", "accounts.", "help.", "news.", "login.", "secure.", "api.",
       "store.", "my.", "portal.", "www2.", "dev.docs."]
)
STATIC_PATHS = ["", "login", "account", "signin", "about", "products", "help",
                "contact", "en/home", "search", "news", "wiki/Main_Page",
                "fr/accueil", "user/profile", "settings/security"]


def rand_token(n):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def random_path() -> str:
    kind = random.random()
    if kind < 0.35:
        return random.choice(STATIC_PATHS)
    if kind < 0.65:
        return f"{random.choice(['article', 'product', 'item', 'post', 'dp'])}/{rand_token(random.randint(6, 12))}"
    if kind < 0.85:
        return f"{random.choice(STATIC_PATHS)}?id={random.randint(1, 99999)}&ref={rand_token(5)}"
    depth = random.randint(2, 4)
    return "/".join(rand_token(random.randint(3, 9)) for _ in range(depth))


def build_url(domain: str) -> str:
    sub = random.choice(SUBDOMAINS)
    path = random_path()
    return f"https://{sub}{domain}/{path}" if path else f"https://{sub}{domain}"


legit = pd.DataFrame({"url": [build_url(d) for d in tranco["domain"]]})
legit["label"] = 0

# --- 3. Fusion, nettoyage ---
df = pd.concat([phish, legit], ignore_index=True)
df["url"] = df["url"].str.strip()
df = df[df["url"].str.len() > 0].drop_duplicates(subset="url")
df["domain"] = df["url"].apply(registered_domain)
df = df[df["domain"] != ""]

both = set(df[df.label == 0]["domain"]) & set(df[df.label == 1]["domain"])
df = df[~df["domain"].isin(both)]

df = df.sample(frac=1, random_state=SEED).reset_index(drop=True)
df.to_csv("data/dataset.csv", index=False)

print(df["label"].value_counts())
print(df.sample(10, random_state=1))
print(f"Domaines uniques : {df['domain'].nunique()}")
