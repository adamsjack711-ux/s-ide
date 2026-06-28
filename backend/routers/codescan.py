"""Codebase Scan — local regex-based SAST.

REST  POST /codescan   body { "path": "<absolute local dir>", "max_files": 4000 }

Walks a LOCAL source directory and runs language-agnostic regex SAST patterns
against text source files, surfacing findings as the design's "SAST" source.

Returns:
  {
    "root": "<abs path>",
    "scanned_files": N,
    "findings": [
      { "severity": "critical|high|medium|low",
        "title": "...", "type": "...",
        "file": "<relative path>", "line": <int>,
        "snippet": "...", "source": "SAST" }
      ...
    ]   # sorted by severity (critical first)
  }

Pure stdlib (os, re, pathlib). NO code execution — pattern matching only.
Reads are confined to `path`; binary/minified/oversized files are skipped.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from lib.auth import require_local_auth

router = APIRouter(tags=["codescan"], dependencies=[Depends(require_local_auth)])

# ── Limits / skip rules ──────────────────────────────────────────────────────
_DEFAULT_MAX_FILES = 4000
_MAX_FILES_CAP = 20000
_MAX_FILE_BYTES = 1_000_000  # 1 MB
_MAX_LINE_LEN = 1000  # treat very long lines as minified; skip the file

_SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "dist", "build",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", ".idea",
    ".gradle", "target", "vendor", ".next", "coverage",
}

# Common source / text extensions we are willing to read.
_TEXT_EXTS = {
    ".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue",
    ".svelte", ".java", ".kt", ".kts", ".go", ".rb", ".php", ".phtml",
    ".c", ".h", ".cpp", ".cc", ".hpp", ".cs", ".rs", ".scala", ".swift",
    ".sh", ".bash", ".zsh", ".pl", ".pm", ".lua", ".r", ".sql", ".html",
    ".htm", ".xml", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".conf", ".env", ".properties", ".gradle", ".tf", ".tfvars", ".dockerfile",
    ".groovy", ".dart", ".ex", ".exs", ".erl", ".clj", ".m", ".mm",
}
# Files (by exact name) that are source even without a listed extension.
_TEXT_NAMES = {"Dockerfile", "Makefile", ".env", ".npmrc", "Jenkinsfile"}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ── Pattern rules ────────────────────────────────────────────────────────────
# Each rule: (compiled_regex, severity, type, title)
def _rule(pattern: str, severity: str, type_: str, title: str, flags=re.IGNORECASE):
    return (re.compile(pattern, flags), severity, type_, title)


_RULES = [
    # ── Hardcoded secrets ────────────────────────────────────────────────────
    _rule(r"AKIA[0-9A-Z]{16}", "critical", "Hardcoded Secret",
          "Hardcoded AWS access key (CWE-798)", flags=0),
    _rule(r"-----BEGIN[A-Z ]*PRIVATE KEY-----", "critical", "Hardcoded Secret",
          "Embedded private key (CWE-798)", flags=0),
    _rule(r"\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token)\b\s*[:=]\s*[\"'][^\"']{6,}[\"']",
          "high", "Hardcoded Secret",
          "Hardcoded credential / secret (CWE-798)"),

    # ── SQL injection ────────────────────────────────────────────────────────
    # f-string SQL: f"... SELECT ... {var} ..."
    _rule(r"f[\"'][^\"']*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^\"']*\{",
          "high", "SQL Injection",
          "Tainted SQL via f-string interpolation (CWE-89)"),
    # concatenation / .format() into a SQL string
    _rule(r"[\"'][^\"']*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^\"']*[\"']\s*(?:\+|%|\.format\s*\()",
          "high", "SQL Injection",
          "Tainted SQL via string concatenation/format (CWE-89)"),

    # ── Command injection ────────────────────────────────────────────────────
    _rule(r"\bos\.system\s*\(.*[\+%]|\bos\.system\s*\(\s*f[\"']",
          "high", "Command Injection",
          "os.system with interpolated input (CWE-78)"),
    _rule(r"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True",
          "high", "Command Injection",
          "subprocess with shell=True (CWE-78)"),
    _rule(r"child_process\.exec\s*\(\s*[`\"']?[^)]*(?:\$\{|\+)",
          "high", "Command Injection",
          "child_process.exec with interpolated input (CWE-78)"),
    _rule(r"\beval\s*\(\s*[^)\"'`]*[A-Za-z_]\w*",
          "high", "Command Injection",
          "Dynamic eval() of a variable (CWE-95)"),
    _rule(r"\bexec\s*\(\s*[^)\"'`]*[A-Za-z_]\w*",
          "high", "Command Injection",
          "Dynamic exec() of a variable (CWE-95)"),

    # ── XSS sinks ────────────────────────────────────────────────────────────
    _rule(r"\.innerHTML\s*=", "medium", "XSS",
          "Assignment to innerHTML (CWE-79)"),
    _rule(r"dangerouslySetInnerHTML", "medium", "XSS",
          "React dangerouslySetInnerHTML sink (CWE-79)"),
    _rule(r"document\.write\s*\(", "medium", "XSS",
          "document.write() sink (CWE-79)"),
    _rule(r"v-html\b", "medium", "XSS",
          "Vue v-html sink (CWE-79)"),

    # ── Insecure deserialization ─────────────────────────────────────────────
    _rule(r"pickle\.loads?\s*\(", "high", "Insecure Deserialization",
          "Unsafe pickle deserialization (CWE-502)"),
    _rule(r"yaml\.load\((?!.*Loader)", "high", "Insecure Deserialization",
          "yaml.load without a safe Loader (CWE-502)"),
    _rule(r"marshal\.loads?\s*\(", "high", "Insecure Deserialization",
          "Unsafe marshal deserialization (CWE-502)"),

    # ── Weak crypto ──────────────────────────────────────────────────────────
    _rule(r"\bmd5\b", "low", "Weak Crypto",
          "Weak hash algorithm MD5 (CWE-327)"),
    _rule(r"\bsha1\b", "low", "Weak Crypto",
          "Weak hash algorithm SHA-1 (CWE-327)"),
    _rule(r"\bDES\b", "medium", "Weak Crypto",
          "Weak cipher DES (CWE-327)", flags=0),
    _rule(r"\bECB\b", "medium", "Weak Crypto",
          "Insecure ECB cipher mode (CWE-327)", flags=0),

    # ── Path traversal ───────────────────────────────────────────────────────
    _rule(r"\.\./", "medium", "Path Traversal",
          "Relative path traversal sequence (CWE-22)", flags=0),
    _rule(r"\bopen\s*\([^)]*\+", "medium", "Path Traversal",
          "open() with concatenated path (CWE-22)"),
]


class _ScanRequest(BaseModel):
    path: str
    max_files: int = _DEFAULT_MAX_FILES


def _is_text_file(p: Path) -> bool:
    if p.name in _TEXT_NAMES:
        return True
    return p.suffix.lower() in _TEXT_EXTS


def _scan_file(abs_path: Path, rel_path: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        with abs_path.open("r", encoding="utf-8", errors="strict") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeDecodeError, ValueError):
        return findings  # unreadable / binary — skip silently

    # Minified heuristic: any absurdly long line → skip the whole file.
    for ln in lines:
        if len(ln) > _MAX_LINE_LEN:
            return findings

    for i, line in enumerate(lines, start=1):
        for regex, severity, type_, title in _RULES:
            if regex.search(line):
                findings.append({
                    "severity": severity,
                    "title": title,
                    "type": type_,
                    "file": rel_path,
                    "line": i,
                    "snippet": line.strip()[:300],
                    "source": "SAST",
                })
    return findings


@router.post("/codescan")
def codescan(req: _ScanRequest) -> dict[str, Any]:
    raw = (req.path or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="path is required")

    try:
        root = Path(raw).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        raise HTTPException(status_code=400, detail="path does not exist")

    if not root.is_dir():
        raise HTTPException(status_code=400, detail="path is not a directory")

    max_files = max(1, min(int(req.max_files or _DEFAULT_MAX_FILES), _MAX_FILES_CAP))

    scanned = 0
    findings: list[dict[str, Any]] = []

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in-place so os.walk doesn't descend into them.
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

        for name in filenames:
            if scanned >= max_files:
                break
            abs_path = Path(dirpath) / name

            if abs_path.is_symlink():
                continue
            if not _is_text_file(abs_path):
                continue

            try:
                # Confine to root (defence in depth against symlink/.. escapes).
                resolved = abs_path.resolve(strict=True)
                resolved.relative_to(root)
                if resolved.stat().st_size > _MAX_FILE_BYTES:
                    continue
            except (OSError, ValueError):
                continue

            rel = os.path.relpath(abs_path, root)
            scanned += 1
            findings.extend(_scan_file(abs_path, rel))

        if scanned >= max_files:
            break

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 9), f["file"], f["line"]))

    return {
        "root": str(root),
        "scanned_files": scanned,
        "findings": findings,
    }
