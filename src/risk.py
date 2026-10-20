"""Niveau de risque en 3 niveaux, calculé à partir de la probabilité du modèle."""

MARGIN = 0.15  # zone « à vérifier » : de (seuil - 0,15) jusqu'au seuil


def risk_level(probability: float, threshold: float, brand_alert=None) -> str:
    """Renvoie "high" (phishing), "medium" (à vérifier) ou "low" (légitime)."""
    if probability >= threshold:
        return "high"
    if probability >= threshold - MARGIN or brand_alert:
        return "medium"
    return "low"
