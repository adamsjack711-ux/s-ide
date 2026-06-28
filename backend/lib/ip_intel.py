"""Blue-team IP intelligence helpers.

Pure Python — no GUI, no globals — so the same module can be imported from
the FastAPI backend, future CLIs, and tests.
"""
from __future__ import annotations

import subprocess
import threading

# Substring matches in an ASN/org name that signal a datacenter or cloud
# provider rather than residential/enterprise space.
HOSTING_KEYWORDS: tuple[str, ...] = (
    "amazon", "aws", "google", "microsoft", "azure", "ovh", "digitalocean",
    "linode", "hetzner", "vultr", "cloudflare", "fastly", "akamai", "rackspace",
    "alibaba", "tencent", "scaleway", "leaseweb", "choopa", "datacamp", "m247",
    "hostwinds", "contabo", "psychz", "hivelocity", "oracle cloud", "ibm cloud",
)

# DNS-based blocklists. Lookup form: <reversed-ip>.<zone>. A successful A
# record (typically 127.0.0.X) means the IP is listed.
DNSBLS: tuple[tuple[str, str], ...] = (
    ("Spamhaus ZEN",   "zen.spamhaus.org"),
    ("SpamCop",        "bl.spamcop.net"),
    ("Barracuda",      "b.barracudacentral.org"),
    ("SORBS",          "dnsbl.sorbs.net"),
    ("CBL/Abuseat",    "cbl.abuseat.org"),
)


def reverse_ip(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def dnsbl_check_one(ip: str, zone: str, timeout: float = 2.0) -> str:
    """Query a single DNSBL.

    Returns 'Clean', 'Listed (...)', 'Timeout', or 'Error: ...'.
    Uses `dig` so we get a real per-query timeout (socket.gethostbyname doesn't).
    """
    query = f"{reverse_ip(ip)}.{zone}"
    try:
        r = subprocess.run(
            ["dig", "+short", f"+time={int(timeout)}", "+tries=1", query, "A"],
            capture_output=True, text=True, timeout=timeout + 1.0,
        )
    except subprocess.TimeoutExpired:
        return "Timeout"
    except Exception as exc:
        return f"Error: {exc}"
    out = r.stdout.strip()
    if not out:
        return "Clean"
    first = out.splitlines()[0]
    if first.startswith("127."):
        return f"Listed ({first})"
    return f"Unusual: {first}"


def dnsbl_check_all(ip: str) -> list[tuple[str, str]]:
    """Run all DNSBL queries in parallel. Returns [(name, status), ...] in stable order."""
    statuses: dict[str, str] = {}
    lock = threading.Lock()

    def check(name: str, zone: str) -> None:
        result = dnsbl_check_one(ip, zone)
        with lock:
            statuses[name] = result

    threads = [threading.Thread(target=check, args=(n, z), daemon=True)
               for n, z in DNSBLS]
    for t in threads: t.start()
    for t in threads: t.join(timeout=4.0)
    return [(n, statuses.get(n, "Timeout")) for n, _ in DNSBLS]


def classify_hosting(org: str) -> str:
    """Return a short hosting-type label based on the org string, or '' if unknown."""
    if not org:
        return ""
    lo = org.lower()
    for kw in HOSTING_KEYWORDS:
        if kw in lo:
            return "Datacenter / Cloud hosting"
    return ""


def whois_abuse_lines(whois_text: str) -> list[str]:
    """Extract just the abuse-contact lines from a whois dump."""
    keep: list[str] = []
    for ln in whois_text.splitlines():
        ls = ln.strip()
        if not ls or ls.startswith("%") or ls.startswith("#"):
            continue
        if "abuse" in ls.lower() and ":" in ls:
            keep.append(ls)
    seen: set[str] = set()
    out: list[str] = []
    for ln in keep:
        if ln not in seen:
            seen.add(ln)
            out.append(ln)
    return out
