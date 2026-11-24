"""Secret scanning and report generation."""

import re
from collections.abc import Iterable

from app.patterns import PATTERNS
from app.schemas import Finding, ScanSummary

SEVERITY_WEIGHTS = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
PLACEHOLDER_VALUES = {
    "your_key_here",
    "your-token-here",
    "changeme",
    "change_me",
    "example",
    "xxx",
    "xxxx",
    "xxxxx",
    "<token>",
    "<your_token>",
}


def _is_placeholder(value: str) -> bool:
    """Return whether a value is an obvious sample or template placeholder."""
    normalized = value.strip().strip("\"'").lower()
    if normalized in PLACEHOLDER_VALUES:
        return True
    return bool(
        re.fullmatch(r"x{4,}", normalized)
        or re.fullmatch(r"<[^>]+>", normalized)
        or re.fullmatch(r"your[_-].*[_-]here", normalized)
        or "example" in normalized
    )


def mask_secret(value: str) -> str:
    """Expose at most four leading and two trailing characters."""
    if len(value) <= 6:
        return "****"
    return f"{value[:4]}{'*' * max(4, len(value) - 6)}{value[-2:]}"


def scan_sources(sources: Iterable[tuple[str, str]]) -> ScanSummary:
    """Scan named source strings and return findings containing masked previews only."""
    findings_with_position: list[tuple[int, int, Finding]] = []
    seen_spans: set[tuple[str, int, int, int]] = set()
    files_scanned = 0

    for filename, content in sources:
        files_scanned += 1
        for line_number, line in enumerate(content.splitlines(), start=1):
            for pattern in PATTERNS:
                for match in re.finditer(pattern["regex"], line):
                    secret = match.group(1) if match.lastindex else match.group(0)
                    if not secret or _is_placeholder(secret):
                        continue

                    start = match.start(1) if match.lastindex else match.start()
                    end = match.end(1) if match.lastindex else match.end()
                    span = (filename, line_number, start, end)
                    if span in seen_spans:
                        continue
                    seen_spans.add(span)

                    finding = Finding(
                        filename=filename,
                        line_number=line_number,
                        secret_type=pattern["name"],
                        severity=pattern["severity"],
                        masked_preview=mask_secret(secret),
                        fix=pattern["fix"],
                    )
                    findings_with_position.append((line_number, start, finding))

    findings_with_position.sort(key=lambda item: (item[0], item[1]))
    findings = [item[2] for item in findings_with_position]
    counts = {severity: 0 for severity in SEVERITY_WEIGHTS}
    for finding in findings:
        counts[finding.severity] += 1
    risk_score = min(
        100,
        sum(SEVERITY_WEIGHTS[finding.severity] for finding in findings),
    )
    return ScanSummary(
        risk_score=risk_score,
        summary=counts,
        findings=findings,
        files_scanned=files_scanned,
    )


def scan_text(content: str, filename: str = "pasted.txt") -> ScanSummary:
    """Scan one text document."""
    return scan_sources([(filename, content)])
