"""CMS / web-stack fingerprinter — Wappalyzer-lite.

REST  GET /cms/fingerprint?url=https://target.example.com&confirm=true

Fetches the URL once (GET, follow up to 3 redirects), inspects:
  * response headers (server, x-powered-by, set-cookie, etc.)
  * HTML body (generator meta, script src patterns, inline script names)
  * cookies (well-known names by CMS)
  * favicon hash (planned — not in v1)

Returns detected technologies grouped by category, with confidence (low/med/high)
and best-effort version extraction.
"""
from __future__ import annotations

import asyncio
import logging
import re
import ssl
import time
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Query, Request

from lib import hids_notify, scope
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode
from lib.target_policy import check_target
from lib.validators import validate_url

logger = logging.getLogger(__name__)

router = APIRouter(tags=["cms"])


# (name, category, [
#   ("header", header_name, value_regex_or_None, version_group_or_None),
#   ("html",   pattern,                          version_group),
#   ("cookie", cookie_name,                      None),
# ])
SIGNATURES: list[tuple[str, str, list[tuple]]] = [
    ("WordPress", "CMS", [
        ("html", r"<meta name=\"generator\" content=\"WordPress ?([\d.]*)", 1),
        ("html", r"/wp-content/", None),
        ("html", r"/wp-includes/", None),
        ("cookie", "wordpress_logged_in", None),
    ]),
    ("Drupal", "CMS", [
        ("html", r"<meta name=\"Generator\" content=\"Drupal ?([\d.]*)", 1),
        ("header", "x-generator", r"Drupal ?([\d.]+)", 1),
        ("html", r"sites/all/(modules|themes)/", None),
    ]),
    ("Joomla", "CMS", [
        ("html", r"<meta name=\"generator\" content=\"Joomla! ?([\d.]*)", 1),
        ("html", r"/media/jui/js/", None),
    ]),
    ("Ghost", "CMS", [
        ("html", r"<meta name=\"generator\" content=\"Ghost ?([\d.]*)", 1),
        ("header", "x-ghost-cache-status", None, None),
    ]),
    ("Shopify", "Ecommerce", [
        ("header", "x-shopify-stage", None, None),
        ("html", r"cdn\.shopify\.com", None),
        ("cookie", "_shopify_y", None),
    ]),
    ("Magento", "Ecommerce", [
        ("html", r"Magento_PageBuilder", None),
        ("cookie", "frontend", None),
    ]),
    ("WooCommerce", "Ecommerce", [
        ("html", r"woocommerce-", None),
        ("html", r"/wp-content/plugins/woocommerce/", None),
    ]),

    # Frontend frameworks
    ("React", "JS framework", [
        ("html", r"data-reactroot=", None),
        ("html", r"_react(Listening|Container)", None),
        ("html", r"react(?:\.production)?\.min\.js", None),
        ("html", r"<div\s+[^>]*id=[\"']root[\"'][^>]*>", None),
        ("html", r"__REACT_DEVTOOLS_GLOBAL_HOOK__", None),
        ("html", r"/[^\"'\s]*react[-.][^\"'\s]*\.js", None),
    ]),
    ("Vue.js", "JS framework", [
        ("html", r"data-v-[a-f0-9]{8}", None),
        ("html", r"vue(?:\.runtime)?(?:\.min)?\.js", None),
        ("html", r"<div\s+[^>]*id=[\"']app[\"'][^>]*>", None),
        ("html", r"__VUE_HMR_RUNTIME__", None),
    ]),
    ("Angular", "JS framework", [
        # ng-version attribute is canonical — high-confidence on its own.
        ("html", r"ng-version=\"([\d.]+)\"", 1),
        ("html", r"<app-root[\s>]", None),
        ("html", r"ng-app=|ng-controller=", None),
        ("html", r"@angular/", None),
        # CLI default bundle filenames (runtime/polyfills/main with hashes).
        ("html", r"runtime[.\-][a-f0-9]{8,}\.js", None),
        ("html", r"polyfills[.\-][a-f0-9]{8,}\.js", None),
    ]),
    ("Next.js", "Framework", [
        ("html", r"/_next/static/", None),
        ("html", r"<script[^>]+id=[\"']__NEXT_DATA__[\"']", None),
        ("html", r"__NEXT_DATA__", None),
        ("header", "x-powered-by", r"Next\.js ?([\d.]+)?", 1),
    ]),
    ("Node.js", "Backend", [
        ("header", "x-powered-by", r"Express", None),
    ]),
    ("Nuxt.js", "Framework", [
        ("html", r"window\.__NUXT__", None),
        ("html", r"/_nuxt/", None),
    ]),
    ("Svelte/SvelteKit", "Framework", [
        ("html", r"data-sveltekit-", None),
        ("html", r"_app/immutable/", None),
    ]),
    ("Gatsby", "Framework", [
        ("html", r"id=\"___gatsby\"", None),
        ("html", r"window\.___gatsby", None),
    ]),

    # Servers
    ("nginx", "Web server", [
        ("header", "server", r"nginx/?([\d.]*)?", 1),
    ]),
    ("Apache", "Web server", [
        ("header", "server", r"Apache/?([\d.]*)?", 1),
    ]),
    ("Caddy", "Web server", [
        ("header", "server", r"Caddy", None),
    ]),
    ("Cloudflare", "CDN", [
        ("header", "server", r"^cloudflare$", None),
        ("header", "cf-ray", None, None),
    ]),
    ("Fastly", "CDN", [
        ("header", "x-fastly-request-id", None, None),
        ("header", "x-served-by", r"cache-.*-FAS", None),
    ]),
    ("Akamai", "CDN", [
        ("header", "x-akamai-transformed", None, None),
    ]),
    ("Vercel", "Hosting/Edge", [
        ("header", "x-vercel-id", None, None),
        ("header", "server", r"Vercel", None),
    ]),
    ("Netlify", "Hosting/Edge", [
        ("header", "server", r"Netlify", None),
    ]),
    ("GitHub Pages", "Hosting", [
        ("header", "x-github-request-id", None, None),
    ]),
    ("AWS CloudFront", "CDN", [
        ("header", "via", r"CloudFront", None),
        ("header", "x-amz-cf-id", None, None),
    ]),

    # Backend frameworks
    ("Express.js", "Backend", [
        ("header", "x-powered-by", r"Express", None),
    ]),
    ("PHP", "Backend", [
        ("header", "x-powered-by", r"PHP/([\d.]+)", 1),
        ("header", "server", r"PHP/([\d.]+)", 1),
    ]),
    ("ASP.NET", "Backend", [
        ("header", "x-powered-by", r"ASP\.NET", None),
        ("header", "x-aspnet-version", r"([\d.]+)", 1),
    ]),
    ("Ruby on Rails", "Backend", [
        ("header", "x-powered-by", r"Phusion Passenger", None),
        ("cookie", "_rails_session", None),
        ("html", r"name=\"csrf-token\"", None),
    ]),
    ("Django", "Backend", [
        ("cookie", "csrftoken", None),
        ("cookie", "sessionid", None),  # weak — many things use this
    ]),
    ("FastAPI", "Backend", [
        ("html", r"<title>FastAPI</title>", None),
        ("html", r"swagger-ui-bundle", None),
    ]),

    # Analytics / tags
    ("Google Analytics", "Analytics", [
        ("html", r"google-analytics\.com/(?:ga|analytics)\.js", None),
        ("html", r"gtag/js\?id=G-", None),
    ]),
    ("Google Tag Manager", "Tag manager", [
        ("html", r"googletagmanager\.com/gtm\.js", None),
    ]),

    # CDNs/libraries (low confidence — just signals)
    ("jQuery", "JS library", [
        ("html", r"jquery(?:-)?([\d.]+)?(?:\.min)?\.js", 1),
    ]),
    ("Bootstrap", "UI", [
        ("html", r"bootstrap(?:-)?([\d.]+)?(?:\.min)?\.css", 1),
    ]),
    ("Tailwind CSS", "UI", [
        ("html", r"tailwindcss/(\d+\.\d+\.\d+)", 1),
        ("html", r"tw-(bg|text|flex|grid)-", None),
    ]),
]


def _fetch(url: str, timeout: float = 10.0) -> tuple[int, dict[str, str], str, str, str]:
    """GET the URL, following up to 5 redirects and aggregating signals across hops.

    Returns (final_status, merged_headers_lower, merged_body_text, final_url,
    merged_set_cookie). Signals from intermediate redirect responses (server
    header, set-cookie, X-Powered-By, etc.) are preserved so apps that redirect
    `/` → `/login` still fingerprint their stack from the redirect hop.
    """
    import http.client
    seen: set[str] = set()
    cur = url
    merged_headers: dict[str, str] = {}
    merged_cookies: list[str] = []
    bodies: list[str] = []
    last_status = 0
    final_url = cur
    MAX_HOPS = 6  # original + up to 5 redirects
    for _ in range(MAX_HOPS):
        if cur in seen:
            break
        seen.add(cur)
        u = urlparse(cur if "://" in cur else "https://" + cur)
        scheme = (u.scheme or "https").lower()
        host = u.hostname or ""
        port = u.port or (443 if scheme == "https" else 80)
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        try:
            if scheme == "https":
                conn = http.client.HTTPSConnection(
                    host, port, timeout=timeout,
                    context=ssl._create_unverified_context(),
                )
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request("GET", path, headers={
                "Host": host,
                "User-Agent": "Mozilla/5.0 (compatible; network-tools/0.1)",
                "Accept": "text/html,application/xhtml+xml,*/*",
                "Accept-Language": "en-US,en;q=0.7",
                "Connection": "close",
            })
            resp = conn.getresponse()
            hop_headers = {k.lower(): v for k, v in resp.getheaders()}
            # Aggregate every fingerprint-bearing header across hops (do not
            # let a bland 200 page overwrite signals from the redirect hop).
            for hk, hv in hop_headers.items():
                if hk == "set-cookie":
                    merged_cookies.append(hv)
                elif hk not in merged_headers or not merged_headers[hk]:
                    merged_headers[hk] = hv
            last_status = resp.status
            final_url = cur
            if resp.status in (301, 302, 303, 307, 308) and hop_headers.get("location"):
                loc = hop_headers["location"]
                if not loc.startswith("http"):
                    loc = f"{scheme}://{host}{loc if loc.startswith('/') else '/' + loc}"
                # Read (and keep) any body the redirect hop served — sometimes
                # the HTML includes <meta refresh> or framework markers.
                try:
                    hop_body = resp.read(64 * 1024).decode("utf-8", errors="replace")
                    if hop_body.strip():
                        bodies.append(hop_body)
                except Exception:
                    pass
                cur = loc
                conn.close()
                continue
            body = resp.read(200 * 1024).decode("utf-8", errors="replace")
            bodies.append(body)
            conn.close()
            merged_cookie_str = "\n".join(merged_cookies)
            if "set-cookie" not in merged_headers and merged_cookie_str:
                merged_headers["set-cookie"] = merged_cookie_str
            return last_status, merged_headers, "\n".join(bodies), final_url, merged_cookie_str
        except Exception as exc:
            # Only return a hard failure if we have not yet collected ANY
            # successful response. Otherwise return what we managed to gather.
            if not merged_headers and not bodies:
                return 0, {}, str(exc), cur, ""
            break
    merged_cookie_str = "\n".join(merged_cookies)
    if "set-cookie" not in merged_headers and merged_cookie_str:
        merged_headers["set-cookie"] = merged_cookie_str
    if not merged_headers and not bodies:
        return 0, {}, "(too many redirects)", cur, ""
    return last_status or 0, merged_headers, "\n".join(bodies), final_url, merged_cookie_str


def _match_signatures(
    headers: dict[str, str], body: str, set_cookie: str,
) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def add(name: str, cat: str, version: str, signals: list[str]) -> None:
        # Merge multiple signals for the same name
        for existing in found:
            if existing["name"] == name:
                if version and not existing["version"]:
                    existing["version"] = version
                for s in signals:
                    if s not in existing["signals"]:
                        existing["signals"].append(s)
                if len(existing["signals"]) >= 2:
                    existing["confidence"] = "high"
                return
        found.append({
            "name": name, "category": cat,
            "version": version or "",
            "signals": signals,
            "confidence": "med" if len(signals) >= 2 else "low",
        })

    for name, category, sigs in SIGNATURES:
        for sig in sigs:
            kind = sig[0]
            try:
                if kind == "header":
                    _, hdr, pattern, vg = sig
                    val = headers.get(hdr, "")
                    if not val:
                        continue
                    if pattern is None:
                        add(name, category, "", [f"header {hdr}"])
                    else:
                        m = re.search(pattern, val, re.I)
                        if m:
                            version = m.group(vg) if vg and m.lastindex and vg <= m.lastindex else ""
                            add(name, category, version or "", [f"header {hdr}: {val[:50]}"])
                elif kind == "html":
                    _, pattern, vg = sig
                    m = re.search(pattern, body, re.I)
                    if m:
                        version = ""
                        if vg and m.lastindex and vg <= m.lastindex:
                            version = m.group(vg) or ""
                        add(name, category, version, [f"html /{pattern[:40]}/"])
                elif kind == "cookie":
                    _, cookie_name, _ = sig
                    if cookie_name in set_cookie:
                        add(name, category, "", [f"cookie {cookie_name}"])
            except re.error:
                continue
            except IndexError:
                continue

    # Confidence: 2+ signals = high; otherwise med (if version) or low.
    # Special case: Angular ng-version is canonical — promote to high even
    # on a single signal.
    for f in found:
        if len(f["signals"]) >= 2:
            f["confidence"] = "high"
        elif f["version"]:
            f["confidence"] = "med"
        if f["name"] == "Angular" and any("ng-version" in s for s in f["signals"]):
            f["confidence"] = "high"

    return found


@router.get("/cms/fingerprint")
async def cms_fingerprint(request: Request,
                          url: str = Query(...),
                          confirm: bool = Query(default=False)) -> dict[str, Any]:
    raw = url.strip()
    if raw and "://" not in raw:
        raw = "https://" + raw
    url = validate_url(raw, field="url")
    u = urlparse(url)
    host = u.hostname or ""
    if not host:
        raise MhpError("could not parse host", code=ErrorCode.INVALID_URL)

    verdict, reason, _ = scope.enforce_rest(
        host, get_engagement_id(request), get_mode(request), confirm=confirm,
    )

    t0 = time.monotonic()
    status, headers, body, final_url, set_cookie = await asyncio.to_thread(_fetch, url)
    if status == 0:
        logger.info("cms fingerprint fetch failed host=%s", host)
        raise MhpError(
            f"fetch failed for {host}",
            code=ErrorCode.UPSTREAM_FAILED,
            status_code=502,
            extra={"target": host},
        )

    matches = _match_signatures(headers, body, set_cookie)

    by_cat: dict[str, list[dict[str, Any]]] = {}
    for m in matches:
        by_cat.setdefault(m["category"], []).append(m)

    findings: list[dict[str, Any]] = []
    if not matches:
        findings.append({"severity": "info", "label": "No stack signatures matched",
                         "detail": "Either obscured / SPA / behind CDN with no leaks"})
    # Helpful info-level finding: surface version-disclosing servers
    for m in matches:
        if m["version"] and m["category"] in ("Web server", "Backend"):
            findings.append({
                "severity": "info",
                "label": f"{m['name']} version disclosed",
                "detail": f"version {m['version']} surfaced — consider hiding in prod",
            })

    elapsed = round(time.monotonic() - t0, 2)
    await hids_notify.notify(
        "info", "cms",
        f"CMS fingerprint — {host}: {len(matches)} technologies",
        {"host": host, "url": url, "tech_count": len(matches),
         "elapsed_seconds": elapsed},
    )

    return {
        "url": url,
        "final_url": final_url,
        "host": host,
        "status_code": status,
        "elapsed_seconds": elapsed,
        "technologies": matches,
        "by_category": by_cat,
        "interesting_headers": {
            k: headers.get(k, "")
            for k in ("server", "x-powered-by", "x-generator", "via",
                      "cf-ray", "x-vercel-id", "x-shopify-stage")
            if headers.get(k)
        },
        "findings": findings,
        "policy": {"verdict": verdict, "reason": reason},
    }
