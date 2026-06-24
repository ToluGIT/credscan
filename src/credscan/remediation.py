"""
Remediation guidance for findings.

A finding without a next step is half a tool. Each finding type maps to a short,
actionable remediation: what to do right now (rotate/revoke), the root-cause fix
(move to a managed secret store), and how to prevent recurrence. Guidance is
keyed by a normalized category derived from the finding's rule/category fields,
with a safe generic default.
"""
from typing import Any, Dict

# provider/category -> remediation guidance
_REMEDIATION: Dict[str, Dict[str, str]] = {
    "aws": {
        "action": "Deactivate and delete the key in IAM (Security credentials), "
                  "then issue a new one.",
        "revoke": "https://console.aws.amazon.com/iam/home#/security_credentials",
        "root_cause": "Use IAM roles / instance profiles or AWS Secrets Manager; "
                      "never embed long-term keys.",
    },
    "gcp": {
        "action": "Revoke the key/token in the Google Cloud console and rotate "
                  "the service account key.",
        "revoke": "https://console.cloud.google.com/apis/credentials",
        "root_cause": "Use Workload Identity or GCP Secret Manager instead of "
                      "embedded keys.",
    },
    "github": {
        "action": "Revoke the token in GitHub Developer settings and generate a "
                  "new fine-grained token.",
        "revoke": "https://github.com/settings/tokens",
        "root_cause": "Use GitHub Actions OIDC or encrypted Actions secrets, not "
                      "hard-coded PATs.",
    },
    "slack": {
        "action": "Revoke the token in the Slack app's OAuth settings and reinstall.",
        "revoke": "https://api.slack.com/apps",
        "root_cause": "Store Slack tokens in a secret manager and inject at runtime.",
    },
    "stripe": {
        "action": "Roll the key in the Stripe dashboard API keys page immediately.",
        "revoke": "https://dashboard.stripe.com/apikeys",
        "root_cause": "Use restricted keys and load secret keys from a secret store.",
    },
    "private_keys": {
        "action": "Treat the key as compromised: rotate the key pair and revoke "
                  "any certificates issued from it.",
        "revoke": "",
        "root_cause": "Store private keys in a KMS/HSM or secret manager; never "
                      "commit key material.",
    },
    "database": {
        "action": "Rotate the database password and update the connection secret.",
        "revoke": "",
        "root_cause": "Inject DB credentials from a secret manager; use IAM auth "
                      "where supported.",
    },
    "jwt": {
        "action": "Rotate the signing secret/key; existing tokens signed with it "
                  "are compromised.",
        "revoke": "",
        "root_cause": "Keep signing secrets in a secret manager and rotate on a "
                      "schedule.",
    },
}

_GENERIC = {
    "action": "Rotate or revoke the credential at its provider, then invalidate "
              "the exposed value.",
    "revoke": "",
    "root_cause": "Move the secret into a managed secret store (Vault, AWS/GCP "
                  "Secrets Manager, SOPS) and reference it at runtime.",
}

_PREVENTION = ("Add CredScan as a pre-commit hook and a CI gate so the secret "
               "cannot be reintroduced.")

# How a category in a finding maps onto a remediation key.
_CATEGORY_ALIASES = {
    "aws": "aws", "gcp": "gcp", "azure": "generic",
    "github": "github", "github___gitlab___bitbucket": "github",
    "slack": "slack", "messaging___chat": "slack",
    "stripe": "stripe", "payments___banking": "stripe",
    "private_keys": "private_keys", "ssh___ssl___certs": "private_keys",
    "structural_high_value": "generic",
    "database": "database", "database_credentials": "database",
    "jwt": "jwt",
}


def _key_for_finding(finding: Dict[str, Any]) -> str:
    haystack = " ".join(str(finding.get(k, "")) for k in
                        ("pattern_category", "category", "rule_name", "type")).lower()
    # The rule name carries the most specific signal; check it before falling
    # back to a broad category alias (e.g. structural_high_value -> generic).
    if "private key" in haystack or "rsa" in haystack or "pem" in haystack:
        return "private_keys"
    # Direct category alias next, but skip the catch-all 'structural_high_value'
    # which is too broad -- let the rule-name haystack below disambiguate it
    # (a structural AWS/GitHub/Stripe pattern should get specific guidance).
    cat = str(finding.get("pattern_category", "")).lower()
    if cat in _CATEGORY_ALIASES and cat != "structural_high_value":
        return _CATEGORY_ALIASES[cat]
    # Otherwise infer from the haystack.
    for token, key in (("aws", "aws"), ("gcp", "gcp"), ("google", "gcp"),
                       ("github", "github"), ("slack", "slack"),
                       ("stripe", "stripe"), ("jwt", "jwt"),
                       ("postgres", "database"), ("mysql", "database"),
                       ("mongo", "database"), ("database", "database")):
        if token in haystack:
            return key
    return "generic"


def remediation_for(finding: Dict[str, Any]) -> Dict[str, str]:
    """Return remediation guidance for a finding (always populated)."""
    base = _REMEDIATION.get(_key_for_finding(finding), _GENERIC)
    out = dict(base)
    out["prevention"] = _PREVENTION
    return out


def remediation_text(finding: Dict[str, Any]) -> str:
    """One-line-per-step remediation string for console/help output."""
    r = remediation_for(finding)
    parts = [f"Action: {r['action']}"]
    if r.get("revoke"):
        parts.append(f"Revoke: {r['revoke']}")
    parts.append(f"Fix: {r['root_cause']}")
    parts.append(f"Prevent: {r['prevention']}")
    return " | ".join(parts)
