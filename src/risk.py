"""Niveau de risque en 3 niveaux, calculé à partir de la probabilité du modèle."""

def risk_level(probability: float, threshold: float, brand_alert=None,
               ssl_info=None) -> str:
    """Renvoie "high" (phishing), "medium" (à vérifier) ou "low" (légitime).

    Règles ajustées :
    - Au-delà de 0.65 ou du seuil strict -> "high"
    - Entre 0.35 et 0.65 (ou alerte de marque / certificat invalide) -> "medium"
    - En dessous -> "low"
    """
    invalid_cert = bool(ssl_info) and ssl_info.get("status") == "invalid"

    if probability > 0.65 or probability >= threshold:
        return "high"
    elif 0.35 <= probability <= 0.65 or brand_alert or invalid_cert:
        return "medium"
    return "low"