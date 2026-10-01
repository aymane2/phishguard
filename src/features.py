"""Extraction de caractéristiques lexicales à partir d'une URL (F-01, F-03, F-04)."""
import math
import re
from collections import Counter
from urllib.parse import urlparse

import tldextract

# Extracteur hors-ligne (aucun appel réseau)
_extract = tldextract.TLDExtract(suffix_list_urls=())

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "confirm", "password", "wallet", "support", "billing",
]
RISKY_TLDS = {
    "xyz", "top", "icu", "lol", "click", "work", "tk", "ml", "ga", "cf",
    "gq", "buzz", "online", "site", "live", "shop", "cfd", "sbs",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "l.ead.me", "q-r.to", "cutt.ly", "rb.gy",
}
IP_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def normalize_url(url: str) -> str:
    """Nettoie l'URL : espaces, schéma manquant, minuscules, sans fragment."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    url = url.split("#", 1)[0]
    return url.lower()


def shannon_entropy(text: str) -> float:
    """Mesure du « désordre » des caractères."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def extract_features(url: str) -> dict:
    """Transforme une URL en dictionnaire de caractéristiques numériques."""
    url = normalize_url(url)
    parsed = urlparse(url)
    host = parsed.hostname or ""
    parts = _extract(url)

    subdomain = parts.subdomain
    num_subdomains = len(subdomain.split(".")) if subdomain else 0
    digits = sum(ch.isdigit() for ch in url)

    return {
        "url_length": len(url),
        "domain_length": len(host),
        "path_length": len(parsed.path),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at": url.count("@"),
        "num_percent": url.count("%"),
        "num_question": url.count("?"),
        "num_equal": url.count("="),
        "num_ampersand": url.count("&"),
        "num_underscore": url.count("_"),
        "num_digits": digits,
        "digit_ratio": digits / len(url),
        "has_ip": int(bool(IP_REGEX.match(host))),
        "entropy": round(shannon_entropy(url), 4),
        "num_suspicious_words": sum(w in url for w in SUSPICIOUS_WORDS),
        "num_subdomains": num_subdomains,
        "risky_tld": int(parts.suffix in RISKY_TLDS),
        "is_shortener": int(host in SHORTENERS),
    }
