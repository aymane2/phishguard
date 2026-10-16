"""Détection d'usurpation de marque : un domaine qui imite une marque connue."""
import re
from urllib.parse import urlparse

import tldextract

from src.features import normalize_url

_extract = tldextract.TLDExtract(suffix_list_urls=())

# marque -> domaines officiels (domaine enregistré, sans sous-domaine)
BRANDS = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "google": {"google.com", "google.fr", "googleusercontent.com",
               "googleapis.com", "gstatic.com", "youtube.com", "gmail.com"},
    "amazon": {"amazon.com", "amazon.fr", "amazon.de", "amazon.es", "amazon.it",
               "amazon.co.uk", "amazon.ca", "amazonaws.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com",
                  "office.com", "outlook.com", "windows.com", "azure.com"},
    "apple": {"apple.com", "icloud.com"},
    "facebook": {"facebook.com", "fb.com", "messenger.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "dropbox": {"dropbox.com"},
    "github": {"github.com", "github.io", "githubusercontent.com"},
    "spotify": {"spotify.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "ebay": {"ebay.com", "ebay.fr"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "colissimo": {"colissimo.fr", "laposte.fr"},
    "chronopost": {"chronopost.fr"},
    "laposte": {"laposte.fr"},
    "ameli": {"ameli.fr"},
    "bnpparibas": {"bnpparibas.com", "bnpparibas.fr", "bnpparibas.net"},
    "creditagricole": {"credit-agricole.fr", "credit-agricole.com"},
    "societegenerale": {"societegenerale.fr", "societegenerale.com"},
    "labanquepostale": {"labanquepostale.fr"},
    "boursorama": {"boursorama.com", "boursobank.com"},
    "revolut": {"revolut.com"},
}

# Caractères souvent substitués pour imiter une lettre (0 -> o, 3 -> e...)
_LOOKALIKE = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "$": "s"})


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[-_.]", text) if t]


def _variants(token: str) -> set[str]:
    t = token.translate(_LOOKALIKE)
    variants = {t, t.replace("rn", "m"), t.replace("vv", "w")}
    if "1" in t:
        variants |= {t.replace("1", "l"), t.replace("1", "i")}
    return variants


def _distance(a: str, b: str) -> int:
    """Distance de Levenshtein : nombre minimal de modifications d'une lettre."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _contains_brand(tokens: list[str], brand: str) -> bool:
    for tok in tokens:
        if tok == brand:
            return True
        # marques longues : "paypalsecure" ou "securepaypal" comptent aussi
        if len(brand) >= 6 and (tok.startswith(brand) or tok.endswith(brand)):
            return True
    return False


def _lookalike(tokens: list[str], brand: str) -> str | None:
    for tok in tokens:
        if len(tok) < 4 or tok == brand:
            continue
        if brand in _variants(tok):
            return tok
        if len(brand) >= 6 and _distance(tok, brand) == 1:
            return tok
    return None


def check_brand(url: str) -> dict | None:
    """Renvoie une alerte si l'URL semble usurper une marque, sinon None."""
    host = urlparse(normalize_url(url)).hostname or ""
    parts = _extract(host)
    registered = parts.top_domain_under_public_suffix
    # adresse IP, ou site officiel d'une marque : aucune alerte
    if not registered or any(registered in o for o in BRANDS.values()):
        return None

    domain_tokens = _tokens(parts.domain)
    sub_tokens = _tokens(parts.subdomain)
    for brand, official in BRANDS.items():
        if _contains_brand(domain_tokens, brand):
            kind = "brand_in_domain"
            msg = (f"Le domaine « {registered} » contient « {brand} » "
                   f"mais n'est pas un domaine officiel de {brand}.")
        elif _contains_brand(sub_tokens, brand):
            kind = "brand_in_subdomain"
            msg = (f"« {brand} » apparaît dans le sous-domaine, mais le vrai "
                   f"domaine du site est « {registered} ».")
        else:
            tok = _lookalike(domain_tokens, brand)
            if tok is None:
                continue
            kind = "typosquatting"
            msg = (f"« {tok} » ressemble à « {brand} » "
                   "(faute ou caractère remplacé volontairement).")
        return {
            "brand": brand,
            "kind": kind,
            "domain": registered,
            "official": sorted(official)[:3],
            "message": msg,
        }
    return None
