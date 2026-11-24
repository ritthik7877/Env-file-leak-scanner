"""Regular-expression definitions for detecting potentially leaked secrets."""

from typing import Literal, TypedDict


class PatternDefinition(TypedDict):
    """A detector definition and its user-facing remediation."""

    name: str
    regex: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    fix: str


PATTERNS: list[PatternDefinition] = [
    {
        "name": "AWS Access Key",
        "regex": r"\b(AKIA[0-9A-Z]{16})\b",
        "severity": "CRITICAL",
        "fix": "Revoke and rotate the AWS access key, then move credentials to a secrets manager.",
    },
    {
        "name": "AWS Secret Key",
        "regex": r"(?i)\bAWS_SECRET_ACCESS_KEY\s*[:=]\s*[\"']?([^\s\"'#;,]+)",
        "severity": "CRITICAL",
        "fix": "Rotate the AWS secret access key immediately and store it outside source control.",
    },
    {
        "name": "GitHub Token",
        "regex": r"\b((?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{12,})\b",
        "severity": "CRITICAL",
        "fix": "Revoke the GitHub token, create a least-privilege replacement, and store it in a secrets manager.",
    },
    {
        "name": "Stripe Secret Key",
        "regex": r"\b(sk_live_[A-Za-z0-9]{12,})\b",
        "severity": "CRITICAL",
        "fix": "Roll the live Stripe secret key in the Stripe dashboard and remove it from source control.",
    },
    {
        "name": "Stripe Publishable Key",
        "regex": r"\b(pk_live_[A-Za-z0-9]{12,})\b",
        "severity": "LOW",
        "fix": "Confirm this publishable key is intended to be public; use a restricted key where possible.",
    },
    {
        "name": "Google API Key",
        "regex": r"\b(AIza[0-9A-Za-z_-]{30,})\b",
        "severity": "HIGH",
        "fix": "Restrict the Google API key by API and application, then rotate it if it was exposed.",
    },
    {
        "name": "Slack Token",
        "regex": r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b",
        "severity": "HIGH",
        "fix": "Revoke and replace the Slack token, then store the replacement in a secrets manager.",
    },
    {
        "name": "JWT",
        "regex": r"\b(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})\b",
        "severity": "HIGH",
        "fix": "Invalidate exposed tokens and rotate the signing secret if the JWT is still usable.",
    },
    {
        "name": "Private Key",
        "regex": r"(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)",
        "severity": "CRITICAL",
        "fix": "Revoke or replace the key pair and remove the private key from source control.",
    },
    {
        "name": "Database URL",
        "regex": (
            r"((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"
            r"[^:@/\s]+:[^@/\s]+@[^/\s\"'<>]+)"
        ),
        "severity": "CRITICAL",
        "fix": "Rotate the database password and move the connection URL into a secrets manager.",
    },
    {
        "name": "Generic Secret",
        "regex": (
            r"(?i)(?:\"|')?[A-Z0-9_]*(?:PASSWORD|SECRET|API_KEY|TOKEN)[A-Z0-9_]*(?:\"|')?"
            r"\s*[:=]\s*[\"']?([^\s\"'#;,]+)"
        ),
        "severity": "MEDIUM",
        "fix": "Rotate this value, load it from an untracked .env file, and add .env to .gitignore.",
    },
]
