"""Synthetic clean fixture: no real secrets. Every value is a decoy that a
naive scanner might false-positive on. There should be ZERO findings here."""
import os
import hashlib

# Secrets loaded from the environment, never hardcoded
DATABASE_PASSWORD = os.environ["DATABASE_PASSWORD"]
API_KEY = os.environ.get("API_KEY")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")

# Placeholders, not real values
SECRET_KEY = "REPLACE_WITH_YOUR_SECRET_KEY"
DEFAULT_PASSWORD = "changeme"

# A SHA-256 hash (high entropy, but not a secret)
CHECKSUM = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# A UUID (high entropy, not a secret)
REQUEST_ID = "550e8400-e29b-41d4-a716-446655440000"


def connect():
    return {"password": DATABASE_PASSWORD, "key": API_KEY}
