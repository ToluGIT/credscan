"""
Compliance control mapping for findings.

Maps each finding to the security controls it implicates. Hard-coded
credentials map cleanly onto a small, well-defined set of controls; the value
here is emitting them concretely (in a report a compliance reviewer can use),
not name-dropping standards in prose.

Controls referenced:
  - CWE-798 / CWE-259 / CWE-321  (weakness taxonomy)
  - NIST SP 800-53 IA-5(7)        (no embedded unencrypted static authenticators)
  - PCI-DSS v4.0 8.6.2 / 6.3.1    (no hard-coded account credentials; secure dev)
  - OWASP ASVS V2.10              (service authentication secrets not in source)
"""

from typing import Any, Dict, List

from credscan.remediation import _key_for_finding  # reuse the same classifier

# Controls that apply to every hard-coded credential finding.
_BASE_CONTROLS = [
    "NIST 800-53 IA-5(7)",  # no embedded unencrypted static authenticators
    "PCI-DSS 8.6.2",  # do not hard-code passwords/passphrases for accounts
    "OWASP ASVS V2.10",  # service authentication secrets not in source
]

# CWE per finding family (mirrors the SARIF CWE mapping).
_CWE_BY_KEY = {
    "private_keys": "CWE-321",  # hard-coded cryptographic key
    "database": "CWE-259",  # hard-coded password (often)
    "aws": "CWE-798",
    "gcp": "CWE-798",
    "github": "CWE-798",
    "slack": "CWE-798",
    "stripe": "CWE-798",
    "jwt": "CWE-798",
    "generic": "CWE-798",
}


def _cwe_for_finding(finding: Dict[str, Any]) -> str:
    """The most specific CWE for a finding (798 generic, 259 password, 321 key)."""
    key = _key_for_finding(finding)
    cwe = _CWE_BY_KEY.get(key, "CWE-798")
    haystack = " ".join(
        str(finding.get(k, "")) for k in ("rule_name", "type", "description")
    ).lower()
    if "password" in haystack and cwe == "CWE-798":
        cwe = "CWE-259"
    return cwe


def controls_for(finding: Dict[str, Any]) -> List[str]:
    """Return the flat list of control IDs a finding implicates (legacy shape)."""
    key = _key_for_finding(finding)
    controls = [_cwe_for_finding(finding)] + list(_BASE_CONTROLS)
    if key in ("aws", "gcp", "github", "slack", "stripe"):
        controls.append("PCI-DSS 6.3.1")
    return controls


# Each control, grouped by the framework an auditor filters on, with a short
# requirement title so the export is readable without a standards reference open.
_CONTROL_TITLES = {
    "CWE-798": "Use of hard-coded credentials",
    "CWE-259": "Use of hard-coded password",
    "CWE-321": "Use of hard-coded cryptographic key",
    "NIST 800-53 IA-5(7)": "No embedded unencrypted static authenticators",
    "PCI-DSS 8.6.2": "Do not hard-code passwords/passphrases for accounts",
    "PCI-DSS 6.3.1": "Remove development credentials before release",
    "OWASP ASVS V2.10": "Service authentication secrets not stored in source",
    "SOC 2 CC6.1": "Logical access controls protect credentials",
    "ISO 27001 A.8.24": "Use of cryptography / key management",
}

_FRAMEWORK_OF = {
    "CWE-798": "CWE",
    "CWE-259": "CWE",
    "CWE-321": "CWE",
    "NIST 800-53 IA-5(7)": "NIST 800-53",
    "PCI-DSS 8.6.2": "PCI-DSS v4.0",
    "PCI-DSS 6.3.1": "PCI-DSS v4.0",
    "OWASP ASVS V2.10": "OWASP ASVS",
    "SOC 2 CC6.1": "SOC 2",
    "ISO 27001 A.8.24": "ISO 27001",
}


def control_rows_for(finding: Dict[str, Any]) -> List[Dict[str, str]]:
    """Return one row per implicated control: framework, id, requirement title.

    Unlike controls_for (a flat joined string), this expands to one record per
    control so an auditor can filter/pivot a compliance export by framework.
    """
    ids = list(controls_for(finding))
    # Every hard-coded credential also maps to SOC 2 access control; crypto
    # material additionally implicates ISO 27001 key management.
    ids.append("SOC 2 CC6.1")
    if _cwe_for_finding(finding) == "CWE-321":
        ids.append("ISO 27001 A.8.24")
    seen = set()
    rows = []
    for cid in ids:
        if cid in seen:
            continue
        seen.add(cid)
        rows.append(
            {
                "framework": _FRAMEWORK_OF.get(cid, "Other"),
                "control": cid,
                "requirement": _CONTROL_TITLES.get(cid, ""),
            }
        )
    return rows
