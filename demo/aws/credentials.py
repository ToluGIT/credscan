# AWS credentials accidentally hardcoded in Python
import boto3

# Long-term IAM credentials
AWS_ACCESS_KEY_ID = "AKIAY2K7MNQ4RST6UVWX"
AWS_SECRET_ACCESS_KEY = "xK8mPn3R7vZ2qL5wJ9hE4yF1cB+tA0sD/NG6pQr"

# Temporary STS session credentials
STS_ACCESS_KEY = "ASIAY2K7MNQ4RST6UVWX12"
STS_SECRET     = "J9hE4yF1cBtA0sDNG6pQrxK8mPn3R7vZ2qL5wJbn"
STS_SESSION_TOKEN = "FQoGZXIvYXdzEJr//////////wEaDH9MbI9nNzVCj1"

# MWS Key
MWS_KEY = "amzn.mws.4ea38b7b-f563-7709-4bae-1a5f821f83cc"

client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
)
