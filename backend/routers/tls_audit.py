"""TLS / SSL Auditor.

REST  GET /tls/audit/{host}?port=443

Returns:
  - host / port / ip
  - cert: { subject, issuer, sans, not_before, not_after, days_until_expiry,
            sha256, key_type, key_bits, signature_algorithm,
            self_signed, hostname_matches }
  - chain: [ { subject, issuer } ... ]   trust chain depth
  - protocols: { "TLSv1.0": "supported"|"unsupported"|"not_tested",
                 "TLSv1.1": ...,
                 "TLSv1.2": ...,
                 "TLSv1.3": ... }
  - negotiated_cipher: { name, bits, kex }
  - hsts: { present, max_age, include_subdomains, preload }
  - http_redirect_to_https: bool | null
  - findings: list of {severity, label, detail}
  - policy: { verdict, reason }

Pure-Python via `ssl` + `cryptography`. Legacy protocol probing shells out to
`openssl s_client` if available (Python's bundled ssl module won't enable
TLS 1.0/1.1 in modern OpenSSL builds).
"""
from __future__ import annotations

import logging
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from fastapi import APIRouter, Depends, Request

from lib import hids_notify, scope
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode
from lib.target_policy import check_target
from lib.validators import validate_hostname, validate_port

logger = logging.getLogger(__name__)

router = APIRouter(tags=["tls"], dependencies=[Depends(require_local_auth)])

import shutil as _shutil
# Prefer whatever's on PATH (catches Linux distros + non-default Homebrew
# prefixes). Fall back to canonical Mac/Linux paths so the tuple iteration
# below still has a chance even if nothing's on PATH.
OPENSSL = _shutil.which("openssl") or "/opt/homebrew/bin/openssl"


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def _connect_get_cert(host: str, port: int, timeout: float = 5.0) -> tuple[bytes | None, dict | None, str | None]:
    """Modern TLS connection. Returns (DER cert, getpeercert dict, negotiated cipher name)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want to inspect even bad certs
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                # Some servers send no cert if anonymous suite; that's rare.
                cipher = ssock.cipher()  # (name, version, bits)
                cipher_dict = {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]} if cipher else None
                # We can't easily decode the chain via getpeercert() in non-validating mode.
                # Parse the leaf cert below; chain enumeration would require WolfSSL/openssl.
                return der, cipher_dict, None
    except (socket.timeout, OSError, ssl.SSLError) as exc:
        return None, None, str(exc)


def _check_protocol(host: str, port: int, version: str, timeout: float = 4.0) -> str:
    """Return 'supported' | 'unsupported' | 'not_tested'.

    Uses python ssl for TLSv1.2/1.3 (always available) and openssl s_client
    for the legacy versions (which python ssl in OpenSSL 3+ refuses to enable).
    """
    if version in ("TLSv1.2", "TLSv1.3"):
        py_ver = {"TLSv1.2": ssl.TLSVersion.TLSv1_2,
                  "TLSv1.3": ssl.TLSVersion.TLSv1_3}[version]
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = py_ver
            ctx.maximum_version = py_ver
        except (ValueError, OSError):
            return "not_tested"
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return "supported"
        except (socket.timeout, OSError, ssl.SSLError):
            return "unsupported"

    # Legacy via openssl CLI
    flag = {"SSLv3": "-ssl3", "TLSv1.0": "-tls1",
            "TLSv1.1": "-tls1_1"}.get(version)
    if not flag:
        return "not_tested"
    for openssl in (OPENSSL, "/usr/bin/openssl"):
        try:
            r = subprocess.run(
                [openssl, "s_client", "-connect", f"{host}:{port}", flag, "-servername", host],
                input="", capture_output=True, text=True, timeout=timeout,
            )
            out = (r.stdout or "") + (r.stderr or "")
            if "-----BEGIN CERTIFICATE-----" in out and "no peer certificate available" not in out.lower():
                return "supported"
            if "unsupported protocol" in out.lower() or "no protocols available" in out.lower():
                return "unsupported"
            if "ssl handshake failure" in out.lower() or "handshake failure" in out.lower():
                return "unsupported"
            return "unsupported"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return "not_tested"


def _parse_cert(der: bytes, hostname: str) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)

    def _name_to_str(n: x509.Name) -> str:
        return ", ".join(f"{a.rfc4514_string()}" for a in n.rdns) or n.rfc4514_string()

    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for entry in ext.value:
            sans.append(str(entry.value))
    except x509.ExtensionNotFound:
        pass

    sha256 = hashes.Hash(hashes.SHA256()); sha256.update(der); sha = sha256.finalize().hex()

    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        key_type = "RSA"; key_bits = pk.key_size
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        key_type = f"EC ({pk.curve.name})"; key_bits = pk.curve.key_size
    elif isinstance(pk, ed25519.Ed25519PublicKey):
        key_type = "Ed25519"; key_bits = 256
    else:
        key_type = type(pk).__name__; key_bits = 0

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    days_left = (not_after - datetime.now(timezone.utc)).days

    issuer_str = _name_to_str(cert.issuer)
    subject_str = _name_to_str(cert.subject)
    self_signed = issuer_str == subject_str

    # Hostname match (CN + SANs, with naive wildcard support)
    host = hostname.lower().rstrip(".")
    cn = ""
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cn_attrs:
            cn = cn_attrs[0].value
    except Exception:
        pass

    candidates = [c.lower().rstrip(".") for c in [cn, *sans] if c]
    hostname_matches = False
    for c in candidates:
        if c == host:
            hostname_matches = True; break
        if c.startswith("*.") and host.endswith(c[1:]) and host.count(".") == c.count("."):
            hostname_matches = True; break

    return {
        "subject":          subject_str,
        "issuer":           issuer_str,
        "sans":             sans,
        "not_before":       not_before.isoformat(),
        "not_after":        not_after.isoformat(),
        "days_until_expiry": days_left,
        "sha256":           sha,
        "key_type":         key_type,
        "key_bits":         key_bits,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "self_signed":      self_signed,
        "hostname_matches": hostname_matches,
    }


def _check_hsts_and_redirect(host: str, port: int, timeout: float = 5.0) -> tuple[dict, bool | None]:
    """Fetch / over HTTPS and check Strict-Transport-Security. Also probe whether
    plain HTTP redirects to HTTPS."""
    hsts = {"present": False, "max_age": 0, "include_subdomains": False, "preload": False}
    try:
        import http.client
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl._create_unverified_context())
        conn.request("HEAD", "/", headers={"Host": host, "User-Agent": "network-tools"})
        resp = conn.getresponse()
        hsts_header = resp.getheader("Strict-Transport-Security", "")
        conn.close()
        if hsts_header:
            hsts["present"] = True
            parts = [p.strip().lower() for p in hsts_header.split(";")]
            for p in parts:
                if p.startswith("max-age="):
                    try: hsts["max_age"] = int(p.split("=", 1)[1])
                    except ValueError: pass
                elif p == "includesubdomains":
                    hsts["include_subdomains"] = True
                elif p == "preload":
                    hsts["preload"] = True
    except Exception:
        pass

    http_to_https: bool | None = None
    try:
        import http.client as _hc
        conn = _hc.HTTPConnection(host, 80, timeout=4.0)
        conn.request("HEAD", "/", headers={"Host": host, "User-Agent": "network-tools"})
        resp = conn.getresponse()
        loc = (resp.getheader("Location") or "").lower()
        http_to_https = resp.status in (301, 302, 307, 308) and loc.startswith("https://")
        conn.close()
    except Exception:
        http_to_https = None

    return hsts, http_to_https


@router.get("/tls/audit/{host}")
async def tls_audit(host: str, request: Request, port: int = 443) -> dict[str, Any]:
    # Accept "host:port" shape in the path param for consistency with
    # /fingerprint/bulk and friends. The hostname validator rejects colons,
    # so we split *before* validating. IPv6 has colons of its own — we keep
    # this simple by only splitting when exactly one ':' is present (which
    # excludes both bracket-form "[::1]:443" and bare "::1"). Users wanting
    # IPv6 + non-default port should pass the `?port=` query string instead.
    raw = host.strip()
    if raw.count(":") == 1:
        h_part, _, port_str = raw.rpartition(":")
        if h_part and port_str:
            host = h_part
            try:
                port = int(port_str)
            except ValueError:
                raise MhpError(
                    "port must be a number",
                    code=ErrorCode.INVALID_PORT,
                    extra={"target": raw},
                ) from None

    host = validate_hostname(host, field="host")
    port = validate_port(port, field="port")

    # Passive tool — warn is informational only, doesn't block.
    verdict, reason, _ = scope.enforce_rest(
        host, get_engagement_id(request), get_mode(request), deny_only=True,
    )

    ip = _resolve(host)
    if not ip:
        raise MhpError(
            f"cannot resolve {host!r}",
            code=ErrorCode.RESOLVE_FAILED,
            status_code=404,
            extra={"target": host},
        )

    der, cipher, conn_err = _connect_get_cert(host, port)
    cert: dict[str, Any] = {}
    if der:
        cert = _parse_cert(der, host)
    else:
        return {
            "host": host, "port": port, "ip": ip,
            "cert": {}, "chain": [],
            "protocols": {},
            "negotiated_cipher": None,
            "hsts": {"present": False, "max_age": 0, "include_subdomains": False, "preload": False},
            "http_redirect_to_https": None,
            "findings": [{"severity": "high", "label": "TLS handshake failed",
                          "detail": conn_err or "connection refused"}],
            "policy": {"verdict": verdict, "reason": reason},
        }

    # Protocol probe — concurrent would be nicer but four probes is fine sequential
    protocols: dict[str, str] = {}
    for v in ("SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
        protocols[v] = _check_protocol(host, port, v)

    hsts, http_to_https = _check_hsts_and_redirect(host, port)

    # ── Findings ─────────────────────────────────────────────────────────────
    findings: list[dict[str, Any]] = []

    if cert.get("days_until_expiry", 999) < 0:
        findings.append({"severity": "high", "label": "Cert expired",
                         "detail": f"{-cert['days_until_expiry']} day(s) ago"})
    elif cert.get("days_until_expiry", 999) < 14:
        findings.append({"severity": "high", "label": "Cert expires soon",
                         "detail": f"{cert['days_until_expiry']} day(s)"})
    elif cert.get("days_until_expiry", 999) < 30:
        findings.append({"severity": "warn", "label": "Cert expiring within 30d",
                         "detail": f"{cert['days_until_expiry']} day(s)"})

    if cert.get("self_signed"):
        findings.append({"severity": "warn", "label": "Self-signed cert",
                         "detail": "issuer == subject"})

    if not cert.get("hostname_matches", True):
        findings.append({"severity": "high", "label": "Hostname mismatch",
                         "detail": f"{host} not in CN/SAN"})

    if cert.get("key_type") == "RSA" and cert.get("key_bits", 0) < 2048:
        findings.append({"severity": "high", "label": "Weak RSA key",
                         "detail": f"{cert['key_bits']} bits"})

    for v in ("SSLv3", "TLSv1.0", "TLSv1.1"):
        if protocols.get(v) == "supported":
            findings.append({"severity": "high", "label": f"Legacy {v} enabled",
                             "detail": "should be disabled"})

    if protocols.get("TLSv1.3") != "supported":
        findings.append({"severity": "info", "label": "TLS 1.3 not offered",
                         "detail": "modern clients still work, but consider enabling"})

    if port == 443 and not hsts["present"]:
        findings.append({"severity": "warn", "label": "No HSTS header",
                         "detail": "Strict-Transport-Security missing"})
    elif hsts["present"] and hsts["max_age"] < 15552000:  # 6 months
        findings.append({"severity": "info", "label": "HSTS max-age short",
                         "detail": f"{hsts['max_age']}s (<6mo)"})

    if port == 443 and http_to_https is False:
        findings.append({"severity": "warn", "label": "HTTP→HTTPS not enforced",
                         "detail": "plain :80 does not redirect"})

    # ── HIDS emit ────────────────────────────────────────────────────────────
    sev_for_hids = "warning" if any(f["severity"] == "high" for f in findings) else "info"
    await hids_notify.notify(
        sev_for_hids, "tls",
        f"TLS audit — {host}:{port} ({len([f for f in findings if f['severity']=='high'])} high)",
        {"host": host, "port": port, "days_left": cert.get("days_until_expiry"),
         "hostname_matches": cert.get("hostname_matches"),
         "high_findings": len([f for f in findings if f["severity"]=="high"])},
    )

    return {
        "host": host, "port": port, "ip": ip,
        "cert": cert,
        "chain": [],   # leaf only for now; chain enumeration via openssl s_client is a future addition
        "protocols": protocols,
        "negotiated_cipher": cipher,
        "hsts": hsts,
        "http_redirect_to_https": http_to_https,
        "findings": findings,
        "policy": {"verdict": verdict, "reason": reason},
    }
