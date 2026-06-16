# High-entropy strings that should be caught by entropy analysis
# These may not match a known pattern but are suspicious due to randomness

# 40-char base64-encoded secret (AWS-secret-key-length)
secret_key = "xK8mPn3R7vZ2qL5wJ9hE4yF1cB+tA0sD/NG6pQrb"

# JWT token
jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Long random hex string
api_secret = "a3f8e2b1c4d7f0a9e6b3c2d1f4e7a0b9c6d3e2f1a4b7c0d3"

# Random base64
random_b64 = "dGhpcyBpcyBhIHNlY3JldCBrZXkgdGhhdCBzaG91bGQgYmUgZGV0ZWN0ZWQ="

# OpenAI-format key
openai_key = "sk-proj-Ry7mKx2pQn4vZ8wBfCgHjLnMt9RsTuVwXy3Zp6QKx2pQn4"

# Hugging Face token
hf_token = "hf_Ry7mKx2pQn4vZ8wBfCgHjLnMt9RsTuV"
