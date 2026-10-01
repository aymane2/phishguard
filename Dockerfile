FROM python:3.12-slim

WORKDIR /app

# Dépendances d'abord (meilleur cache Docker)
COPY requirements-api.txt .
RUN pip install --no-cache-dir -r requirements-api.txt

# Seulement ce dont l'API a besoin : le code et le modèle sérialisé
COPY src/ src/
COPY api/ api/
COPY models/model.joblib models/model.joblib

# Utilisateur non-root
RUN useradd --create-home appuser
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
