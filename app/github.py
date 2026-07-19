"""Fetch dependency manifests straight from GitHub — no local checkout needed."""

import logging
import re

import httpx

from app import config
from app.parsers import MANIFEST_PARSERS, SKIP_DIRS, ParsedDep

logger = logging.getLogger(__name__)

_GITHUB_URL_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$"
)


class GitHubError(Exception):
    pass


def parse_github_url(url: str) -> tuple[str, str] | None:
    """Return (owner, repo) for a GitHub repo URL, else None."""
    match = _GITHUB_URL_RE.match(url.strip())
    return (match.group(1), match.group(2)) if match else None


def is_manifest_path(path: str) -> bool:
    parts = path.split("/")
    return parts[-1] in MANIFEST_PARSERS and not any(p in SKIP_DIRS for p in parts)


def _client(token: str | None = None) -> httpx.Client:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "patch-scanner"}
    token = token or config.GITHUB_TOKEN
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(
        base_url="https://api.github.com", headers=headers, timeout=30
    )


def _check(resp: httpx.Response, context: str) -> httpx.Response:
    if resp.status_code == 404:
        raise GitHubError(f"{context}: not found (private repo? set GITHUB_TOKEN)")
    if resp.status_code == 403 and resp.headers.get("x-ratelimit-remaining") == "0":
        raise GitHubError(
            "GitHub API rate limit exceeded — set GITHUB_TOKEN for a higher limit"
        )
    if resp.status_code >= 400:
        raise GitHubError(f"{context}: GitHub returned {resp.status_code}")
    return resp


def collect_deps_github(url: str, token: str | None = None) -> set[ParsedDep]:
    parsed = parse_github_url(url)
    if parsed is None:
        raise GitHubError(f"Not a GitHub repo URL: {url}")
    owner, name = parsed

    with _client(token) as client:
        repo_info = _check(
            client.get(f"/repos/{owner}/{name}"), f"{owner}/{name}"
        ).json()
        branch = repo_info["default_branch"]

        tree = _check(
            client.get(
                f"/repos/{owner}/{name}/git/trees/{branch}", params={"recursive": "1"}
            ),
            f"{owner}/{name} tree",
        ).json()
        manifest_paths = [
            entry["path"]
            for entry in tree.get("tree", [])
            if entry.get("type") == "blob" and is_manifest_path(entry["path"])
        ]

        deps: set[ParsedDep] = set()
        for path in manifest_paths:
            resp = _check(
                client.get(
                    f"/repos/{owner}/{name}/contents/{path}",
                    params={"ref": branch},
                    headers={"Accept": "application/vnd.github.raw+json"},
                ),
                f"{owner}/{name}/{path}",
            )
            deps.update(MANIFEST_PARSERS[path.split("/")[-1]](resp.text))

    logger.info(
        "Fetched %d manifests from github.com/%s/%s", len(manifest_paths), owner, name
    )
    return deps
