"""
Compliance control mapping for findings.

Maps each finding to the security controls it implicates. Hard-coded
credentials map cleanly onto a small, well-defined set of controls; the value
here is emitting them concretely (in a report a compliance reviewer can use),
not name-dropping standards in prose.

Controls referenced:
  - CWE-798 / CWE-259 / CWE-321  (weakness taxonomy)
  - NIST SP 800-53 IA-5           (Authenticator Management)
  - PCI-DSS v4.0 8.3.x / 6.3.x    (no hard-coded credentials; secure development)
  - OWASP ASVS V2 / V6            (authentication / stored secrets)
"""
from typing import Any, Dict, List

from credscan.remediation import _key_for_finding  # reuse the same classifier

# Controls that apply to every hard-coded credential finding.
_BASE_CONTROLS = [
    "NIST 800-53 IA-5(7)",   # no embedded unencrypted static authenticators
    "PCI-DSS 8.3.1",          # strong auth / no hard-coded credentials
    "OWASP ASVS V2.10",       # service authentication secrets not in source
]

# CWE per finding family (mirrors the SARIF CWE mapping).
_CWE_BY_KEY = {
    "private_keys": "CWE-321",   # hard-coded cryptographic key
    "database": "CWE-259",       # hard-coded password (often)
    "aws": "CWE-798", "gcp": "CWE-798", "github": "CWE-798",
    "slack": "CWE-798", "stripe": "CWE-798", "jwt": "CWE-798",
    "generic": "CWE-798",
}


def controls_for(finding: Dict[str, Any]) -> List[str]:
    """Return the list of control IDs a finding implicates."""
    key = _key_for_finding(finding)
    cwe = _CWE_BY_KEY.get(key, "CWE-798")
    # Password-specific findings are CWE-259 even outside the database family.
    haystack = " ".join(str(finding.get(k, "")) for k in
                        ("rule_name", "type", "description")).lower()
    if "password" in haystack and cwe == "CWE-798":
        cwe = "CWE-259"
    controls = [cwe] + list(_BASE_CONTROLS)
    if key in ("aws", "gcp", "github", "slack", "stripe"):
        # Secrets in CI/CD or cloud config also implicate secure-development.
        controls.append("PCI-DSS 6.3.1")
    return controls
