"""Liste blanche des domaines hautement légitimes pour éviter les faux positifs."""

POPULAR_ALLOWLIST = {
    "fundingpips.com",
    "google.com",
    "github.com",
    "amazon.fr",
    "amazon.com",
    "wikipedia.org",
    "gitlab.com",
    "microsoft.com",
    "apple.com",
    "paypal.com"
}

def is_allowed(domain: str) -> bool:
    """Vérifie si un domaine appartient à la liste blanche (gère les sous-domaines)."""
    if not domain:
        return False
    domain_lower = domain.lower().strip()
    for allowed in POPULAR_ALLOWLIST:
        if domain_lower == allowed or domain_lower.endswith("." + allowed):
            return True
    return False