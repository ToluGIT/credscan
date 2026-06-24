# CredScan container image.
# Runs as a non-root user; mount the code to scan at /scan.
FROM python:3.12-slim

# Install into a venv-free system location, then drop privileges.
WORKDIR /opt/credscan

# Copy only what's needed to install the package first (better layer caching).
COPY setup.py setup.cfg pyproject.toml MANIFEST.in README.md ./
COPY src/ ./src/
COPY config/ ./config/

RUN pip install --no-cache-dir . \
    && rm -rf /root/.cache

# The config/ directory is not part of the importable package, so point the
# resolver at its copied location for this (non-editable) install.
ENV CREDSCAN_CONFIG_DIR=/opt/credscan/config

# Create and switch to a non-root user. A scanner should never need root, and
# running as root in CI is a finding in its own right.
RUN useradd --create-home --uid 10001 scanner
USER scanner

# The directory a caller mounts their code into.
WORKDIR /scan

ENTRYPOINT ["credscan"]
CMD ["--help"]
