"""Niveau de risque en 3 niveaux, calculé à partir de la probabilité du modèle."""

MARGIN = 0.15  # zone « à vérifier » : de (seuil - 0,15) jusqu'au seuil


def risk_level(probability: float, threshold: float, brand_alert=None,
               ssl_info=None) -> str:
    """Renvoie "high" (phishing), "medium" (à vérifier) ou "low" (légitime).

    Règles : au-dessus du seuil, c'est "high". Un certificat SSL invalide
    (expiré, auto-signé, mauvais domaine) ou une alerte de marque fait passer
    au moins à "medium". Un certificat valide ne baisse jamais le risque :
    les faux sites en obtiennent aussi.
    """
    if probability >= threshold:
        return "high"
    invalid_cert = bool(ssl_info) and ssl_info.get("status") == "invalid"
    if probability >= threshold - MARGIN or brand_alert or invalid_cert:
        return "medium"
    return "low"
