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
    # build outputs / packaged artifacts — scanning these is just noise
    "dist-electron", "out", ".cache", "DerivedData", "Pods", ".turbo",
    ".parcel-cache", ".svelte-kit", "site-packages",
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
    # NOTE: a bare "../" is NOT flagged — it matches every relative import and
    # buries the report in false positives. We flag the genuinely suspicious
    # forms instead: URL-encoded traversal payloads, and path-building from
    # concatenated/interpolated input.
    _rule(r"%2e%2e(?:%2f|%5c|/|\\)|\.\.(?:%2f|%5c)", "medium", "Path Traversal",
          "Encoded path traversal sequence (CWE-22)"),
    _rule(r"\bopen\s*\([^)]*\+", "medium", "Path Traversal",
          "open() with concatenated path (CWE-22)"),
]


# ── Application-asset inventory ───────────────────────────────────────────────
# The Graph view's "scan" wants an inventory of the application itself, not just
# SAST findings. We derive it from the same single walk: languages by extension,
# entry points, config/secret files, and (parsed from manifests) frameworks +
# dependencies, plus best-effort route/endpoint extraction.

_LANG_BY_EXT = {
    ".py": "Python", ".pyw": "Python", ".js": "JavaScript", ".mjs": "JavaScript",
    ".cjs": "JavaScript", ".jsx": "JavaScript (JSX)", ".ts": "TypeScript",
    ".tsx": "TypeScript (TSX)", ".vue": "Vue", ".svelte": "Svelte", ".java": "Java",
    ".kt": "Kotlin", ".kts": "Kotlin", ".go": "Go", ".rb": "Ruby", ".php": "PHP",
    ".phtml": "PHP", ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
    ".cs": "C#", ".rs": "Rust", ".scala": "Scala", ".swift": "Swift", ".sh": "Shell",
    ".bash": "Shell", ".zsh": "Shell", ".pl": "Perl", ".pm": "Perl", ".lua": "Lua",
    ".r": "R", ".sql": "SQL", ".html": "HTML", ".htm": "HTML", ".dart": "Dart",
    ".ex": "Elixir", ".exs": "Elixir", ".clj": "Clojure", ".groovy": "Groovy",
}

# Files (by exact name) that are application entry points worth surfacing.
_ENTRY_NAMES = {
    "main.py", "app.py", "manage.py", "wsgi.py", "asgi.py", "__main__.py",
    "server.js", "server.ts", "index.js", "index.ts", "main.js", "main.ts",
    "main.tsx", "index.tsx", "Dockerfile", "docker-compose.yml",
    "docker-compose.yaml", "Makefile", "package.json",
}

# Config / secret-bearing files.
_CONFIG_SUFFIXES = {".env", ".ini", ".toml", ".cfg", ".conf", ".properties", ".yaml", ".yml"}
_CONFIG_NAMES = {".env", ".npmrc"}

# package.json dependency → friendly framework name.
_JS_FRAMEWORKS = {
    "react": "React", "react-dom": "React", "next": "Next.js", "vue": "Vue",
    "svelte": "Svelte", "@angular/core": "Angular", "vite": "Vite",
    "electron": "Electron", "express": "Express", "fastify": "Fastify",
    "@nestjs/core": "NestJS", "tailwindcss": "Tailwind", "webpack": "Webpack",
    "typescript": "TypeScript",
}
# python dependency (lowercased prefix) → friendly framework name.
_PY_FRAMEWORKS = {
    "fastapi": "FastAPI", "flask": "Flask", "django": "Django", "uvicorn": "Uvicorn",
    "gunicorn": "Gunicorn", "sqlalchemy": "SQLAlchemy", "pydantic": "Pydantic",
    "starlette": "Starlette", "tornado": "Tornado", "celery": "Celery",
}

# Route / endpoint extraction (method, path) — FastAPI/Flask/Express style.
_ROUTE_METHOD_PATH = re.compile(
    r'@(?:app|router|api)\.(get|post|put|delete|patch|websocket)\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_ROUTE_FLASK = re.compile(r'@(?:app|bp|blueprint)\.route\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
_ROUTE_EXPRESS = re.compile(
    r'\b(?:app|router)\.(get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']'
)


class _ScanRequest(BaseModel):
    path: str
    max_files: int = _DEFAULT_MAX_FILES


def _is_text_file(p: Path) -> bool:
    if p.name in _TEXT_NAMES:
        return True
    return p.suffix.lower() in _TEXT_EXTS


def _scan_file(abs_path: Path, rel_path: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (findings, routes) for one source file from a single read."""
    findings: list[dict[str, Any]] = []
    routes: list[dict[str, Any]] = []
    try:
        with abs_path.open("r", encoding="utf-8", errors="strict") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeDecodeError, ValueError):
        return findings, routes  # unreadable / binary — skip silently

    # Minified heuristic: any absurdly long line → skip the whole file.
    for ln in lines:
        if len(ln) > _MAX_LINE_LEN:
            return findings, routes

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
        # Route extraction (cheap, on the same line buffer).
        m = _ROUTE_METHOD_PATH.search(line) or _ROUTE_EXPRESS.search(line)
        if m:
            routes.append({"method": m.group(1).upper(), "path": m.group(2),
                           "file": rel_path, "line": i})
        else:
            mf = _ROUTE_FLASK.search(line)
            if mf:
                routes.append({"method": "ANY", "path": mf.group(1),
                               "file": rel_path, "line": i})
    return findings, routes


def _parse_dependencies(root: Path) -> tuple[list[dict[str, str]], set[str]]:
    """Parse common manifests → (dependencies, framework-names).

    Best-effort + stdlib-only. Missing/unparseable manifests are skipped.
    """
    deps: list[dict[str, str]] = []
    frameworks: set[str] = set()

    # package.json
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            import json
            data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
            for sect in ("dependencies", "devDependencies"):
                for name, ver in (data.get(sect) or {}).items():
                    deps.append({"name": name, "version": str(ver), "source": "package.json"})
                    if name in _JS_FRAMEWORKS:
                        frameworks.add(_JS_FRAMEWORKS[name])
        except Exception:
            pass

    # requirements.txt
    req = root / "requirements.txt"
    if req.is_file():
        try:
            for raw in req.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                name = re.split(r"[=<>!~ \[]", line, 1)[0].strip()
                if name:
                    deps.append({"name": name, "version": line[len(name):].strip(),
                                 "source": "requirements.txt"})
                    if name.lower() in _PY_FRAMEWORKS:
                        frameworks.add(_PY_FRAMEWORKS[name.lower()])
        except Exception:
            pass

    # pyproject.toml — light regex (avoid a TOML dep)
    pyproj = root / "pyproject.toml"
    if pyproj.is_file():
        try:
            txt = pyproj.read_text(encoding="utf-8", errors="ignore")
            for dep in re.findall(r'["\']([A-Za-z0-9_.\-]+)\s*(?:[<>=!~].*?)?["\']', txt):
                low = dep.lower()
                if low in _PY_FRAMEWORKS:
                    frameworks.add(_PY_FRAMEWORKS[low])
        except Exception:
            pass

    # Presence-based frameworks
    if (root / "go.mod").is_file():
        frameworks.add("Go modules")
    if (root / "Cargo.toml").is_file():
        frameworks.add("Cargo / Rust")
    if (root / "Dockerfile").is_file():
        frameworks.add("Docker")
    if any((root / n).is_file() for n in ("docker-compose.yml", "docker-compose.yaml")):
        frameworks.add("Docker Compose")

    return deps, frameworks


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

    # Asset-inventory accumulators (built from the same walk).
    from collections import Counter
    lang_counts: Counter[str] = Counter()
    entry_files: list[str] = []
    config_files: list[str] = []
    routes: list[dict[str, Any]] = []

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

            # ── Asset tallies ──
            suf = abs_path.suffix.lower()
            if suf in _LANG_BY_EXT:
                lang_counts[_LANG_BY_EXT[suf]] += 1
            if name in _ENTRY_NAMES:
                entry_files.append(rel)
            if name in _CONFIG_NAMES or suf in _CONFIG_SUFFIXES:
                config_files.append(rel)

            f, r = _scan_file(abs_path, rel)
            findings.extend(f)
            routes.extend(r)

        if scanned >= max_files:
            break

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 9), f["file"], f["line"]))

    # ── Assemble the application-asset inventory ──
    deps, frameworks = _parse_dependencies(root)
    # Findings grouped by type → an asset category too (links graph ↔ review).
    finding_types: Counter[str] = Counter(f["type"] for f in findings)

    def _cat(cat_id: str, label: str, items: list[dict[str, Any]]) -> dict[str, Any]:
        return {"id": cat_id, "label": label, "count": len(items), "items": items}

    assets = [
        _cat("languages", "Languages",
             [{"name": lang, "detail": f"{n} file{'' if n == 1 else 's'}"}
              for lang, n in lang_counts.most_common()]),
        _cat("frameworks", "Frameworks & Tech",
             [{"name": fw} for fw in sorted(frameworks)]),
        _cat("entrypoints", "Entry Points",
             [{"name": p, "file": p} for p in sorted(set(entry_files))][:60]),
        _cat("routes", "Routes / Endpoints",
             [{"name": f"{rt['method']} {rt['path']}", "detail": f"{rt['file']}:{rt['line']}",
               "file": rt["file"], "line": rt["line"]} for rt in routes][:200]),
        _cat("dependencies", "Dependencies",
             [{"name": d["name"], "detail": d.get("version", ""), "source": d.get("source", "")}
              for d in deps][:200]),
        _cat("configs", "Config & Secrets",
             [{"name": p, "file": p} for p in sorted(set(config_files))][:80]),
        _cat("findings", "Code Findings",
             [{"name": t, "detail": f"{n} finding{'' if n == 1 else 's'}"}
              for t, n in finding_types.most_common()]),
    ]

    return {
        "root": str(root),
        "scanned_files": scanned,
        "findings": findings,
        "assets": assets,
    }
