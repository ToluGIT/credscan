"""Synthetic clean fixture: high-entropy strings that are NOT secrets.
The classic false-positive bait. There should be ZERO findings here."""

# Git commit SHA (40 hex chars, high entropy, not a secret)
COMMIT = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"

# SHA-256 content hash
INTEGRITY = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="

# MD5 of an asset
ASSET_HASH = "d41d8cd98f00b204e9800998ecf8427e"

# A UUIDv4 request id
TRACE_ID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"

# A base64-encoded public, non-sensitive config blob
ENCODED_CONFIG = "eyJ0aGVtZSI6ImRhcmsiLCJsYW5nIjoiZW4ifQ=="

# A semantic version and a long URL (no secret)
VERSION = "v2.14.3-rc.1+build.20240115"
DOCS_URL = "https://docs.example.com/api/v2/reference/authentication/overview"
