"""
Docker parser — detects credentials in:
  1. Dockerfiles (ENV/ARG with hardcoded values)
  2. Docker image tarballs (.tar from `docker save`)
"""

import io
import json
import logging
import os
import re
import tarfile
from typing import Any, Dict, List

from credscan.core.parser_base import BaseParser

logger = logging.getLogger(__name__)

_DOCKERFILE_NAMES = {
    "dockerfile",
    "dockerfile.dev",
    "dockerfile.prod",
    "dockerfile.test",
}

# Dockerfile ENV / ARG with a hardcoded value
_ENV_PATTERN = re.compile(
    r"^(?:ENV|ARG)\s+(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*[= ]\s*(?P<value>[^\s\\][^\n]{4,})",
    re.MULTILINE,
)

# Credentials that appear to be real (not placeholder-like)
_PLACEHOLDER = re.compile(
    r"^(?:your[_-]|<|{|\$|example|placeholder|changeme|todo|xxx|none|null|true|false)",
    re.IGNORECASE,
)

# Credential-sounding key names
_CRED_KEYS = re.compile(
    r"(?i)(?:secret|key|token|password|passwd|pwd|api|auth|credential|cert|private)",
)

# Maximum bytes to read from a single layer file (prevent OOM on huge images)
_MAX_FILE_BYTES = 512 * 1024  # 512 KB per file inside the image


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.match(value.strip()))


def _is_credential_key(key: str) -> bool:
    return bool(_CRED_KEYS.search(key))


class DockerParser(BaseParser):
    """Parser for Dockerfiles and Docker image tarballs."""

    def can_parse(self, filepath: str) -> bool:
        basename = os.path.basename(filepath).lower()
        if basename in _DOCKERFILE_NAMES:
            return True
        # Docker image tarballs — but not every .tar, only ones whose name hints at docker
        if basename.endswith(".tar") and any(
            hint in basename for hint in ("image", "docker", "container", "layer")
        ):
            return True
        return False

    def parse(self, filepath: str) -> Dict[str, Any]:
        basename = os.path.basename(filepath).lower()
        if basename in _DOCKERFILE_NAMES:
            return self._parse_dockerfile(filepath)
        return self._parse_image_tarball(filepath)

    # ── Dockerfile ────────────────────────────────────────────────────────────

    def _parse_dockerfile(self, filepath: str) -> Dict[str, Any]:
        content = self.read_file(filepath)
        if not content:
            return {}

        entries = []
        for match in _ENV_PATTERN.finditer(content):
            key = match.group("key")
            value = match.group("value").strip().strip("\"'")

            if _is_placeholder(value):
                continue
            if not _is_credential_key(key):
                continue

            line_num = content[: match.start()].count("\n") + 1
            entries.append(
                {
                    "key": key,
                    "value": value,
                    "line": line_num,
                    "rule_name": "Dockerfile Hardcoded Credential",
                    "severity": "critical",
                    "category": "docker",
                    "path": filepath,
                    "description": f"Hardcoded credential '{key}' in Dockerfile instruction",
                }
            )

        return {"filepath": filepath, "file_type": "dockerfile", "entries": entries}

    # ── Docker image tarball ──────────────────────────────────────────────────

    def _parse_image_tarball(self, filepath: str) -> Dict[str, Any]:
        entries = []
        try:
            if not tarfile.is_tarfile(filepath):
                return {}

            with tarfile.open(filepath, "r:*") as outer:
                # Scan manifest.json for env vars baked in during build
                entries.extend(self._scan_manifest(outer, filepath))
                # Scan each layer tarball for credential files
                entries.extend(self._scan_layers(outer, filepath))

        except Exception as e:
            logger.warning(f"Could not read Docker image tarball {filepath}: {e}")

        return {"filepath": filepath, "file_type": "docker_image", "entries": entries}

    def _scan_manifest(
        self, outer: tarfile.TarFile, filepath: str
    ) -> List[Dict[str, Any]]:
        """Extract ENV vars from the image config (baked-in environment)."""
        entries = []
        try:
            manifest_member = outer.getmember("manifest.json")
            manifest_data = json.loads(outer.extractfile(manifest_member).read())
            config_path = manifest_data[0].get("Config", "")
            if not config_path:
                return entries

            config_member = outer.getmember(config_path)
            config_data = json.loads(outer.extractfile(config_member).read())
            env_vars = config_data.get("config", {}).get("Env", [])

            for env_entry in env_vars:
                if "=" not in env_entry:
                    continue
                key, _, value = env_entry.partition("=")
                if (
                    _is_credential_key(key)
                    and not _is_placeholder(value)
                    and len(value) >= 6
                ):
                    entries.append(
                        {
                            "key": key,
                            "value": value,
                            "line": 0,
                            "rule_name": "Docker Image Baked-In Credential",
                            "severity": "critical",
                            "category": "docker",
                            "path": filepath,
                            "description": f"Credential '{key}' baked into Docker image ENV layer",
                        }
                    )
        except (KeyError, json.JSONDecodeError, Exception) as e:
            logger.debug(f"Could not parse Docker manifest from {filepath}: {e}")
        return entries

    def _scan_layers(
        self, outer: tarfile.TarFile, filepath: str
    ) -> List[Dict[str, Any]]:
        """Scan layer tarballs inside the image for credential files."""
        entries = []
        # Only scan files that are likely to contain credentials
        _INTERESTING = re.compile(
            r"(?:\.env|\.aws/credentials|\.aws/config|"
            r"\.ssh/|id_rsa|id_dsa|id_ecdsa|id_ed25519|"
            r"credentials?|secrets?|config|settings|\.pem|\.key)$",
            re.IGNORECASE,
        )
        _CRED_LINE = re.compile(
            r"(?i)(?:password|passwd|secret|api_?key|access_?key|token)\s*[=:]\s*(\S{6,})",
        )

        for member in outer.getmembers():
            if not member.name.endswith("/layer.tar"):
                continue
            try:
                layer_buf = outer.extractfile(member).read()
                with tarfile.open(fileobj=io.BytesIO(layer_buf)) as layer:
                    for file_member in layer.getmembers():
                        if not file_member.isfile():
                            continue
                        if not _INTERESTING.search(file_member.name):
                            continue
                        try:
                            raw = layer.extractfile(file_member).read(_MAX_FILE_BYTES)
                            text = raw.decode("utf-8", errors="ignore")
                            for line_num, line in enumerate(text.splitlines(), 1):
                                for m in _CRED_LINE.finditer(line):
                                    value = m.group(1).strip().strip("\"'")
                                    if not _is_placeholder(value):
                                        entries.append(
                                            {
                                                "key": file_member.name,
                                                "value": value,
                                                "line": line_num,
                                                "rule_name": "Docker Layer Credential File",
                                                "severity": "critical",
                                                "category": "docker",
                                                "path": f"{filepath}::{file_member.name}",
                                                "description": (
                                                    f"Credential found in Docker layer file: {file_member.name}"
                                                ),
                                            }
                                        )
                        except Exception:
                            pass
            except Exception as e:
                logger.debug(f"Could not read layer {member.name}: {e}")

        return entries
