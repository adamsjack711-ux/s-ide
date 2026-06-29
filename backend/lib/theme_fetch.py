"""Theme fetching — git-tag resolution (SwiftPM-style) + raw-URL fallback.

A theme source is either a git repo (versions = semver tags) or a direct raw
URL to a .side file. Network/disk side effects only; integrity (hash/lock/
cache) lives in theme_store.py.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

import httpx

_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
_GIT_TIMEOUT = 60


class ThemeFetchError(Exception):
    pass


def _is_raw_side(url: str) -> bool:
    return url.lower().split("?", 1)[0].endswith(".side")


def _run_git(args: list[str], cwd: str | None = None) -> tuple[int, str, str]:
    p = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=_GIT_TIMEOUT,
    )
    return p.returncode, p.stdout, p.stderr


def parse_semver(tag: str) -> tuple[int, int, int] | None:
    m = _SEMVER.match(tag.strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def ls_remote_tags(url: str) -> list[str]:
    rc, out, err = _run_git(["ls-remote", "--tags", "--refs", url])
    if rc != 0:
        raise ThemeFetchError(f"git ls-remote failed: {err.strip() or rc}")
    tags: list[str] = []
    for line in out.splitlines():
        parts = line.split("\trefs/tags/")
        if len(parts) == 2:
            tags.append(parts[1].strip())
    return tags


def resolve_version(url: str, requested: str | None) -> str:
    """Map a requested version (or None=latest) onto a concrete git tag."""
    if _is_raw_side(url):
        return requested or "raw"
    tags = ls_remote_tags(url)
    semver_tags = [(t, parse_semver(t)) for t in tags]
    semver_tags = [(t, v) for t, v in semver_tags if v is not None]
    if not semver_tags:
        raise ThemeFetchError("source has no semver tags")
    if requested:
        want = parse_semver(requested)
        for t, v in semver_tags:
            if v == want or t == requested:
                return t
        raise ThemeFetchError(f"version {requested} not found")
    # Latest = highest semver.
    return max(semver_tags, key=lambda tv: tv[1])[0]


def _read_side_from_dir(root: Path) -> bytes:
    candidate = root / "theme.side"
    if candidate.is_file():
        return candidate.read_bytes()
    sides = sorted(root.glob("*.side"))
    if not sides:
        sides = sorted(root.rglob("*.side"))
    if not sides:
        raise ThemeFetchError("no .side file found in source")
    return sides[0].read_bytes()


def fetch_side(url: str, tag: str) -> bytes:
    """Fetch the .side file bytes for a resolved version."""
    if _is_raw_side(url):
        try:
            r = httpx.get(url, follow_redirects=True, timeout=30)
            r.raise_for_status()
            return r.content
        except httpx.HTTPError as e:
            raise ThemeFetchError(f"raw fetch failed: {e}") from e

    with tempfile.TemporaryDirectory(prefix="side-fetch-") as tmp:
        rc, _out, err = _run_git(
            ["clone", "--depth", "1", "--branch", tag, "--single-branch", url, tmp + "/repo"]
        )
        if rc != 0:
            raise ThemeFetchError(f"git clone failed: {err.strip() or rc}")
        return _read_side_from_dir(Path(tmp) / "repo")
