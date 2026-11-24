"""Pydantic request and response models for LeakLens."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator

MAX_CONTENT_LENGTH = 1_000_000


class TextScanRequest(BaseModel):
    """Text and optional filename submitted for scanning."""

    content: str = Field(max_length=MAX_CONTENT_LENGTH)
    filename: str = Field(default="pasted.txt", min_length=1, max_length=255)


class RepoScanRequest(BaseModel):
    """Public GitHub repository URL submitted for scanning."""

    repo_url: str = Field(min_length=1, max_length=500)

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, value: str) -> str:
        """Reject URLs that are not public GitHub repository URLs."""
        from app.github_fetcher import is_valid_github_repo_url

        if not is_valid_github_repo_url(value):
            raise ValueError("Provide a public repository URL like https://github.com/owner/repo.")
        return value


class Finding(BaseModel):
    """A sanitized secret finding; the original matched value is never returned."""

    filename: str
    line_number: int
    secret_type: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    masked_preview: str
    fix: str


class ScanSummary(BaseModel):
    """Counts and risk score for one scan."""

    risk_score: int = Field(ge=0, le=100)
    summary: dict[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"], int]
    findings: list[Finding]
    files_scanned: int = Field(ge=0)


class HealthResponse(BaseModel):
    """Health-check response."""

    status: Literal["ok"]
