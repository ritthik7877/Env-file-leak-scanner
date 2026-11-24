"""Focused tests for LeakLens secret detection and safe output."""

import pytest

from app.github_fetcher import is_valid_github_repo_url
from app.scanner import scan_text
from app.schemas import RepoScanRequest


def test_detects_aws_access_key():
    report = scan_text("AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF", ".env")
    assert len(report.findings) == 1
    assert report.findings[0].secret_type == "AWS Access Key"
    assert report.findings[0].severity == "CRITICAL"


def test_detects_github_token():
    report = scan_text("token=ghp_abcdefghijklmnopqrstuvwxyz123456", "settings.py")
    assert any(item.secret_type == "GitHub Token" for item in report.findings)


def test_ignores_placeholder_values():
    report = scan_text("API_KEY=your_key_here\nPASSWORD=xxxx\nTOKEN=<token>")
    assert report.findings == []
    assert report.risk_score == 0


def test_masks_preview_and_never_returns_full_secret():
    secret = "AKIA1234567890ABCDEF"
    report = scan_text(f"key={secret}")
    serialized = report.model_dump_json()
    finding = report.findings[0]
    assert finding.masked_preview == f"{secret[:4]}{'*' * (len(secret) - 6)}{secret[-2:]}"
    assert secret not in serialized


def test_reports_line_number_and_generic_secret():
    report = scan_text("# sample\n\nDATABASE_PASSWORD=not-a-real-password-value")
    assert report.findings[0].line_number == 3
    assert report.findings[0].secret_type == "Generic Secret"


def test_risk_score_and_severity_counts():
    report = scan_text(
        "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n"
        "API_KEY=not-a-real-api-key\n"
        "pk_live_123456789012345678"
    )
    assert report.summary == {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 1, "LOW": 1}
    assert report.risk_score == 45


def test_rejects_non_github_or_malformed_repo_url():
    assert not is_valid_github_repo_url("https://example.com/owner/repo")
    assert not is_valid_github_repo_url("https://github.com/owner/repo/extra")
    assert not is_valid_github_repo_url("https://user:pass@github.com/owner/repo")
    with pytest.raises(ValueError):
        RepoScanRequest(repo_url="https://example.com/owner/repo")


def test_scans_more_than_one_source_and_counts_files():
    report = scan_text("gho_abcdefghijklmnopqrstuvwxyz123456", "first.env")
    from app.scanner import scan_sources

    multiple = scan_sources([("first.env", "API_KEY=first_secret_value"), ("config.yml", "xoxb-123456789012")])
    assert report.files_scanned == 1
    assert multiple.files_scanned == 2
    assert len(multiple.findings) == 2
