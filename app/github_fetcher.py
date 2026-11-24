"""Fetch a limited set of common configuration files from public GitHub repos."""

import base64
import re
from urllib.parse import quote, urlparse

import httpx

from app.schemas import MAX_CONTENT_LENGTH

GITHUB_API = "https://api.github.com"
MAX_REPO_FILES = 20
COMMON_FILENAMES = re.compile(
    r"(^|/)(?:\.env(?:\.[^/]*)?|config\.[^/]+|settings\.[^/]+|docker-compose\.yml)$",
    re.IGNORECASE,
)


class GitHubFetchError(Exception):
    """A safe, user-facing error while querying the GitHub API."""


def is_valid_github_repo_url(value: str) -> bool:
    """Validate an HTTPS GitHub URL containing exactly owner and repository."""
    try:
        parsed = urlparse(value.strip())
        port = parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return False
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    return (
        len(parts) == 2
        and bool(re.fullmatch(r"[A-Za-z0-9_.-]+", parts[0]))
        and bool(re.fullmatch(r"[A-Za-z0-9_.-]+", parts[1].removesuffix(".git")))
    )


def _repository_parts(repo_url: str) -> tuple[str, str]:
    """Return owner and repository after validation."""
    if not is_valid_github_repo_url(repo_url):
        raise ValueError("Provide a public repository URL like https://github.com/owner/repo.")
    parts = urlparse(repo_url.strip()).path.strip("/").split("/")
    return parts[0], parts[1].removesuffix(".git")


async def fetch_common_files(repo_url: str) -> list[tuple[str, str]]:
    """Fetch at most 20 matching files using GitHub's public REST API."""
    owner, repo = _repository_parts(repo_url)
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "LeakLens",
    }
    timeout = httpx.Timeout(15.0)
    try:
        async with httpx.AsyncClient(
            headers=headers, timeout=timeout, follow_redirects=False
        ) as client:
            repository_response = await client.get(
                f"{GITHUB_API}/repos/{owner}/{repo}"
            )
            if repository_response.status_code in (403, 429):
                raise GitHubFetchError("GitHub API rate limit reached. Try again later.")
            if repository_response.status_code == 404:
                raise GitHubFetchError("Repository not found or not publicly accessible.")
            repository_response.raise_for_status()
            default_branch = repository_response.json()["default_branch"]

            tree_response = await client.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/"
                f"{quote(default_branch, safe='')}?recursive=1"
            )
            if tree_response.status_code in (403, 429):
                raise GitHubFetchError("GitHub API rate limit reached. Try again later.")
            tree_response.raise_for_status()
            tree = tree_response.json().get("tree", [])
            matches = [
                entry
                for entry in tree
                if entry.get("type") == "blob"
                and COMMON_FILENAMES.search(entry.get("path", ""))
                and entry.get("size", MAX_CONTENT_LENGTH + 1) <= MAX_CONTENT_LENGTH
            ][:MAX_REPO_FILES]

            sources: list[tuple[str, str]] = []
            for entry in matches:
                path = entry["path"]
                response = await client.get(
                    f"{GITHUB_API}/repos/{owner}/{repo}/contents/{quote(path, safe='/')}",
                    params={"ref": default_branch},
                )
                if response.status_code in (403, 429):
                    raise GitHubFetchError("GitHub API rate limit reached. Try again later.")
                response.raise_for_status()
                payload = response.json()
                if payload.get("encoding") != "base64" or not payload.get("content"):
                    continue
                decoded = base64.b64decode(payload["content"])
                if len(decoded) > MAX_CONTENT_LENGTH:
                    continue
                try:
                    content = decoded.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                sources.append((path, content))
            return sources
    except GitHubFetchError:
        raise
    except (httpx.HTTPError, KeyError, ValueError) as error:
        raise GitHubFetchError("Could not fetch repository files from GitHub.") from error
