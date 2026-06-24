"""Synthetic fixture: hardcoded AWS credentials in application code.

All values here are fabricated for benchmark purposes. They are not live keys.
"""
import boto3

# TRUE POSITIVE: AWS access key id (AKIA prefix, 20 chars)
AWS_ACCESS_KEY_ID = "AKIAZ7Q2MNP4RVTW6XYL"
# TRUE POSITIVE: AWS secret access key (40-char base64 in assignment context)
AWS_SECRET_ACCESS_KEY = "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"

# Decoy: an environment-variable reference, not a literal secret (true negative)
REGION = "us-east-1"
SESSION_NAME = "ci-deploy-session"

client = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=REGION,
)
