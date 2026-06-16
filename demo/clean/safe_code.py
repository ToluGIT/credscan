"""
This file should produce ZERO credential findings.
All secrets are loaded from environment variables or external secret managers.
"""
import os
from typing import Optional


def get_db_connection():
    """Database credentials loaded from environment — safe pattern."""
    return {
        "host": os.environ["DB_HOST"],
        "password": os.environ["DB_PASSWORD"],      # safe: env var reference
        "username": os.environ.get("DB_USER", "app"),
    }


def get_aws_client():
    """AWS credentials from environment / instance profile — never hardcoded."""
    import boto3
    # boto3 reads AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY from env automatically
    return boto3.client("s3")


class Config:
    # Placeholder strings — should NOT be flagged
    SECRET_KEY: str = "REPLACE_WITH_ENV_VAR"
    DATABASE_URL: str = "postgresql://user:CHANGE_ME@localhost/db"
    API_KEY: Optional[str] = None

    @classmethod
    def from_env(cls):
        cfg = cls()
        cfg.SECRET_KEY = os.environ["SECRET_KEY"]
        cfg.DATABASE_URL = os.environ["DATABASE_URL"]
        cfg.API_KEY = os.environ.get("API_KEY")
        return cfg
