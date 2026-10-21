import os
import tempfile

# Base temporaire pour les tests (définie avant l'import de l'API)
os.environ.setdefault(
    "PHISHGUARD_DB", os.path.join(tempfile.mkdtemp(), "test.db")
)
os.environ.setdefault("PHISHGUARD_SSL_CHECK", "0")
