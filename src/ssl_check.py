"""Vérification du certificat SSL/TLS d'un site, avec protection contre les adresses internes."""
import ipaddress
import re
import socket
import ssl
from datetime import UTC, datetime
from urllib.parse import urlparse

TIMEOUT = 5.0
YOUNG_DAYS = 14      # certificat émis depuis moins de 14 jours : indice à signaler
EXPIRING_DAYS = 7    # expire dans moins de 7 jours : à signaler

_VERIFY_MESSAGES = {
    10: "le certificat est expiré",
    18: "le certificat est auto-signé",
    19: "le certificat est auto-signé (chaîne non reconnue)",
    20: "l'émetteur du certificat est inconnu",
    21: "l'émetteur du certificat est inconnu",
    62: "le certificat ne correspond pas au nom de domaine",
}


class BlockedHost(Exception):
    """Adresse non publique : on refuse de s'y connecter (protection SSRF)."""


def _target(url: str) -> tuple[str, int]:
    """Nom d'hôte et port TLS d'une URL (443 par défaut)."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    parsed = urlparse(url)
    port = parsed.port if parsed.scheme == "https" and parsed.port else 443
    return (parsed.hostname or "").lower(), port


def public_addresses(host: str, port: int = 443) -> list[str]:
    """Adresses IP de l'hôte, seulement si TOUTES sont publiques."""
    if not host or host == "localhost":
        raise BlockedHost(host)
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = []
    for info in infos:
        ip = info[4][0].split("%")[0]
        if not ipaddress.ip_address(ip).is_global:
            raise BlockedHost(ip)
        ips.append(ip)
    return ips


def _context() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def _ts(value: str) -> datetime:
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), UTC)


def parse_cert(cert: dict, now: datetime | None = None) -> dict:
    """Résume un certificat (format de ssl.getpeercert) et relève les indices."""
    now = now or datetime.now(UTC)
    not_before, not_after = _ts(cert["notBefore"]), _ts(cert["notAfter"])
    issuer = {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}
    age_days = (now - not_before).days
    days_left = (not_after - now).days
    warnings = []
    if age_days < YOUNG_DAYS:
        warnings.append(f"Certificat émis il y a seulement {max(age_days, 0)} jour(s).")
    if days_left < EXPIRING_DAYS:
        warnings.append(f"Le certificat expire dans {max(days_left, 0)} jour(s).")
    return {
        "issuer": issuer.get("organizationName") or issuer.get("commonName") or "inconnu",
        "not_before": not_before.date().isoformat(),
        "not_after": not_after.date().isoformat(),
        "age_days": age_days,
        "days_left": days_left,
        "validity_days": (not_after - not_before).days,
        "warnings": warnings,
    }


def check_certificate(url: str, timeout: float = TIMEOUT) -> dict:
    """Se connecte au site en HTTPS et analyse son certificat."""
    try:
        host, port = _target(url)
    except ValueError:
        return {"status": "error", "hostname": "", "reason": "URL invalide."}
    if not host:
        return {"status": "error", "hostname": "", "reason": "URL invalide."}
    try:
        ips = public_addresses(host, port)
    except BlockedHost:
        return {"status": "blocked", "hostname": host,
                "reason": "Adresse non publique : vérification refusée par sécurité."}
    except (OSError, UnicodeError):
        return {"status": "unreachable", "hostname": host,
                "reason": "Nom de domaine introuvable."}
    try:
        # on se connecte à l'IP déjà contrôlée (pas de seconde résolution DNS)
        with (
            socket.create_connection((ips[0], port), timeout=timeout) as sock,
            _context().wrap_socket(sock, server_hostname=host) as tls,
        ):
            cert = tls.getpeercert()
            version = tls.version()
    except ssl.SSLCertVerificationError as exc:
        reason = _VERIFY_MESSAGES.get(exc.verify_code, exc.verify_message or "certificat invalide")
        return {"status": "invalid", "hostname": host, "reason": reason}
    except (OSError, ssl.SSLError):
        return {"status": "unreachable", "hostname": host,
                "reason": "Connexion HTTPS impossible (délai dépassé ou pas de HTTPS)."}
    return {"status": "valid", "hostname": host, "tls_version": version, **parse_cert(cert)}
