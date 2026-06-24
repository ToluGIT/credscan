"""
CI/CD pipeline parser for detecting credentials in GitHub Actions, GitLab CI,
Jenkins, and CircleCI configuration files.
"""

import logging
import os
import re
from typing import Any, Dict, List

from credscan.core.parser_base import BaseParser

logger = logging.getLogger(__name__)

# File matchers
_GITHUB_ACTIONS_DIR = os.path.join(".github", "workflows")
_GITLAB_CI = ".gitlab-ci.yml"
_CIRCLE_CI = os.path.join(".circleci", "config.yml")
_JENKINSFILE_NAMES = {"jenkinsfile", "jenkinsfile.groovy"}

# Detects hardcoded secrets in env: blocks — value must not be a variable reference
_ENV_BLOCK_PATTERN = re.compile(
    r"(?i)(?:^|\s)(?P<key>[A-Z_]*(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|API_KEY|ACCESS_KEY)[A-Z_]*)\s*:\s*(?P<value>[^\s${\n][^\n]{7,})",
    re.MULTILINE,
)

# Detects `echo $SECRET` style leakage in run steps
_ECHO_SECRET_PATTERN = re.compile(
    r'(?i)(?:echo|print|printf|console\.log)\s+["\']?\$\{?(?P<varname>[A-Z_]*(?:TOKEN|SECRET|KEY|PASSWORD)[A-Z_]*)\}?',
    re.MULTILINE,
)

# Detects hardcoded values passed directly to -e / --env / -v flags
_DOCKER_RUN_SECRET = re.compile(
    r'(?i)docker\s+run[^\n]*(?:-e|--env)\s+(?P<key>[A-Z_]+(?:TOKEN|SECRET|KEY|PASSWORD)[A-Z_]*)=(?P<value>[^\s$"\']{8,})',
    re.MULTILINE,
)

# Detects OIDC/JWT token being exposed via curl or similar
_TOKEN_CURL_EXPOSURE = re.compile(
    r'(?i)curl[^\n]*(?:-H|--header)\s+["\']?Authorization:\s*Bearer\s+(?P<token>[A-Za-z0-9._\-]{20,})["\']?',
    re.MULTILINE,
)

# Values that look like variable references — not real secrets
_VARIABLE_REF = re.compile(
    r"^\$\{?\{?[A-Z_]+\}?\}?$|^\$\(\(|^secrets\.|^vars\.|^env\.",
    re.IGNORECASE,
)


def _is_variable_ref(value: str) -> bool:
    return bool(_VARIABLE_REF.match(value.strip()))


class CICDParser(BaseParser):
    """Parser for CI/CD pipeline configuration files."""

    def can_parse(self, filepath: str) -> bool:
        basename = os.path.basename(filepath).lower()
        norm = filepath.replace("\\", "/")

        if _GITHUB_ACTIONS_DIR.replace("\\", "/") in norm and basename.endswith(
            (".yml", ".yaml")
        ):
            return True
        if basename in (_GITLAB_CI, os.path.basename(_GITLAB_CI)):
            return True
        if _CIRCLE_CI.replace("\\", "/") in norm:
            return True
        if basename in _JENKINSFILE_NAMES:
            return True

        return False

    def parse(self, filepath: str) -> Dict[str, Any]:
        content = self.read_file(filepath)
        if not content:
            return {}

        entries = []
        platform = self._detect_platform(filepath, content)

        entries.extend(self._find_hardcoded_env(content, filepath))
        entries.extend(self._find_echo_leaks(content, filepath))
        entries.extend(self._find_docker_secrets(content, filepath))
        entries.extend(self._find_token_curl_exposure(content, filepath))

        return {
            "filepath": filepath,
            "file_type": f"cicd_{platform}",
            "entries": entries,
        }

    _GH_ACTIONS_CONTENT = re.compile(r"^\s*(?:on|jobs)\s*:", re.MULTILINE)
    _GITLAB_CI_CONTENT = re.compile(r"(?:stages|include|extends)\s*:", re.MULTILINE)

    def _detect_platform(self, filepath: str, content: str = "") -> str:
        norm = filepath.replace("\\", "/")
        basename = os.path.basename(filepath).lower()
        if _GITHUB_ACTIONS_DIR.replace("\\", "/") in norm:
            return "github_actions"
        if basename == os.path.basename(_GITLAB_CI):
            return "gitlab_ci"
        if _CIRCLE_CI.replace("\\", "/") in norm:
            return "circleci"
        if basename in _JENKINSFILE_NAMES:
            return "jenkins"
        # Content-based heuristic for workflow files not in expected directories
        if (
            content
            and self._GH_ACTIONS_CONTENT.search(content)
            and "runs-on" in content
        ):
            return "github_actions"
        return "unknown"

    def _find_hardcoded_env(self, content: str, filepath: str) -> List[Dict[str, Any]]:
        entries = []
        for match in _ENV_BLOCK_PATTERN.finditer(content):
            value = match.group("value").strip().strip("\"'")
            if _is_variable_ref(value):
                continue
            line_num = content[: match.start()].count("\n") + 1
            entries.append(
                {
                    "key": match.group("key"),
                    "value": value,
                    "line": line_num,
                    "rule_name": "CI/CD Hardcoded Secret in env block",
                    "severity": "critical",
                    "category": "cicd",
                    "path": filepath,
                    "description": f"Hardcoded secret '{match.group('key')}' in CI/CD pipeline env block",
                }
            )
        return entries

    def _find_echo_leaks(self, content: str, filepath: str) -> List[Dict[str, Any]]:
        entries = []
        for match in _ECHO_SECRET_PATTERN.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            entries.append(
                {
                    "key": match.group("varname"),
                    "value": match.group("varname"),
                    "line": line_num,
                    "rule_name": "CI/CD Secret Printed to Log",
                    "severity": "high",
                    "category": "cicd",
                    "path": filepath,
                    "description": f"Secret variable '{match.group('varname')}' echoed to CI/CD log output",
                }
            )
        return entries

    def _find_docker_secrets(self, content: str, filepath: str) -> List[Dict[str, Any]]:
        entries = []
        for match in _DOCKER_RUN_SECRET.finditer(content):
            value = match.group("value")
            if _is_variable_ref(value):
                continue
            line_num = content[: match.start()].count("\n") + 1
            entries.append(
                {
                    "key": match.group("key"),
                    "value": value,
                    "line": line_num,
                    "rule_name": "CI/CD Hardcoded Secret in docker run",
                    "severity": "critical",
                    "category": "cicd",
                    "path": filepath,
                    "description": f"Hardcoded secret passed to docker run --env in CI/CD pipeline",
                }
            )
        return entries

    def _find_token_curl_exposure(
        self, content: str, filepath: str
    ) -> List[Dict[str, Any]]:
        entries = []
        for match in _TOKEN_CURL_EXPOSURE.finditer(content):
            token = match.group("token")
            if _is_variable_ref(token):
                continue
            line_num = content[: match.start()].count("\n") + 1
            entries.append(
                {
                    "key": "Authorization",
                    "value": token,
                    "line": line_num,
                    "rule_name": "CI/CD Hardcoded Bearer Token in curl",
                    "severity": "critical",
                    "category": "cicd",
                    "path": filepath,
                    "description": "Hardcoded Bearer token in curl command within CI/CD pipeline",
                }
            )
        return entries
