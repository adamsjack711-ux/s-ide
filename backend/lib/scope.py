"""Engagement-scope enforcement.

Layered on top of `lib/target_policy.py`, which does the OS-level
IP-class check (loopback / private / Tailscale / external). This module
adds the *engagement-relative* check: "is this target inside the active
engagement's scope list, and not on its exclusions list?"

The two layers compose. A typical target-accepting endpoint calls both::

    from lib import scope, target_policy

    pol_verdict, pol_reason = target_policy.check_target(target)
    sc_verdict, sc_reason   = scope.check(target, engagement_id)

    # Most-restrictive wins. Order: deny > warn > allow.
    verdict, reason = scope.combine(
        (pol_verdict, pol_reason), (sc_verdict, sc_reason),
    )

Scope syntax (each entry is a string in `engagement.scope` /
`engagement.exclusions`):

    1.2.3.4                    exact IP
    1.2.3.0/24                 CIDR
    example.com                exact hostname OR any of its subdomains
    *.example.com              subdomains only (NOT the bare apex)
    https://example.com/path   URL — host extracted, path ignored
    sub.example.com            exact-or-subdomain match

Exclusion matches always deny, regardless of whether scope matches.
Empty scope means "no restriction" — the engagement is permissive
unless the user explicitly scopes it. This is the standard pentest
contract pattern: scope is opt-in.

The Lab/Engagement mode flag (see `lib/mode.py`) drives the top-level
gate:

  * ``mode="lab"`` — scope check is skipped entirely, returns
    ``("allow", "lab mode")``. The target-policy layer (loopback /
    private / Tailscale / external IP-class) still runs above this.
  * ``mode="engagement"`` and no engagement_id — denied: engagement
    mode requires an active engagement.
  * ``mode="engagement"`` and engagement_id — full per-engagement
    scope+exclusions check.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Literal
from urllib.parse import urlparse

from lib import engagements
from lib.errors import ErrorCode, MhpError, ws_error
from lib.mode import Mode

logger = logging.getLogger(__name__)

Verdict = Literal["allow", "warn", "deny"]
_RANK: dict[Verdict, int] = {"allow": 0, "warn": 1, "deny": 2}


def combine(
    a: tuple[Verdict, str], b: tuple[Verdict, str],
) -> tuple[Verdict, str]:
    """Return whichever of `a`/`b` is more restrictive (deny > warn > allow).

    Tie-breaks on `a` so policy-layer reasons surface first when both are
    "warn" — keeps the UI from flip-flopping between equally-bad reasons.
    """
    if _RANK[a[0]] >= _RANK[b[0]]:
        return a
    return b


def _host_from_target(target: str) -> str:
    """Strip URL scheme/path so we match on host only."""
    t = (target or "").strip()
    if "://" in t:
        try:
            t = urlparse(t).hostname or t
        except ValueError:
            pass
    # Strip optional port `host:1234`. Don't strip from IPv6 — those have
    # multiple colons and live in brackets when porty.
    if t.count(":") == 1 and not t.startswith("["):
        t = t.split(":", 1)[0]
    return t.lower().strip(".")


def _entry_matches(target_host: str, target_ip: ipaddress._BaseAddress | None,
                   entry: str) -> bool:
    """One scope/exclusion entry vs one (host, optional IP)."""
    e = (entry or "").strip().lower()
    if not e:
        return False
    # URL in scope entry — extract host, ignore path.
    e_host = _host_from_target(e)
    if not e_host:
        return False
    # CIDR / IP entry
    try:
        net = ipaddress.ip_network(e_host, strict=False)
        if target_ip is not None and target_ip in net:
            return True
        # If the target is itself an IP-shaped string, check that too.
        try:
            t_ip = ipaddress.ip_address(target_host)
            if t_ip in net:
                return True
        except ValueError:
            pass
        return False
    except ValueError:
        pass
    # Hostname entry
    if e_host.startswith("*."):
        suffix = e_host[2:]
        return target_host.endswith("." + suffix)
    # Bare host: match exact OR any subdomain (standard scope contract).
    return target_host == e_host or target_host.endswith("." + e_host)


def _resolve_optional(target_host: str) -> ipaddress._BaseAddress | None:
    """Cheap resolve — returns one IP or None. We use the policy layer's
    resolver via lazy import to avoid circular deps; on failure return
    None and let the host string still match by name."""
    try:
        return ipaddress.ip_address(target_host)
    except ValueError:
        pass
    try:
        from lib.target_policy import _resolve  # internal, but stable
        ips = _resolve(target_host)
        return ips[0] if ips else None
    except Exception:
        return None


def check_against(
    target: str, *, scope_list: list[str], exclusions: list[str],
) -> tuple[Verdict, str]:
    """Match `target` against an arbitrary scope + exclusions pair.

    Useful for previewing scope decisions without committing to an
    engagement record (e.g. the "scope editor" UI).
    """
    host = _host_from_target(target)
    if not host:
        return "deny", "empty target"
    ip = _resolve_optional(host)

    for entry in exclusions or []:
        if _entry_matches(host, ip, entry):
            return "deny", f"matched exclusion: {entry}"

    scope = [e for e in (scope_list or []) if e.strip()]
    if not scope:
        # Permissive default — no scope means no scope-imposed restriction.
        return "allow", "no scope set"

    for entry in scope:
        if _entry_matches(host, ip, entry):
            return "allow", f"matched scope: {entry}"

    return "deny", "target not in engagement scope"


def check(
    target: str,
    engagement_id: str | None,
    mode: Mode = "lab",
) -> tuple[Verdict, str]:
    """Engagement-scope check honoring the Lab/Engagement mode.

    Verdict matrix:
      * ``mode="lab"`` → allow, regardless of engagement_id (Lab mode
        is the "freely experiment" mode; scope is not enforced).
      * ``mode="engagement"`` and missing engagement_id → deny.
      * ``mode="engagement"`` with an engagement_id that doesn't exist
        → deny (stale frontend IDs shouldn't silently bypass scope).
      * ``mode="engagement"`` with a valid engagement → match against
        its scope and exclusions.
    """
    if mode == "lab":
        return "allow", "lab mode"
    # mode == "engagement" from here on.
    if not engagement_id:
        return "deny", "engagement mode requires an active engagement"
    try:
        eng = engagements.get_engagement(engagement_id)
    except Exception:
        logger.exception("scope: failed to load engagement %s", engagement_id)
        return "deny", "could not load engagement record"
    if not eng:
        return "deny", f"engagement {engagement_id} not found"
    return check_against(
        target,
        scope_list=eng.get("scope") or [],
        exclusions=eng.get("exclusions") or [],
    )


def check_combined(
    target: str,
    engagement_id: str | None,
    mode: Mode = "lab",
) -> tuple[Verdict, str, dict[str, str]]:
    """Full check: target_policy + engagement scope, honoring mode.

    Returns `(verdict, reason, layers)` where `layers` is a dict mapping
    layer name to reason so the UI can show which layer triggered which
    verdict.
    """
    from lib import target_policy  # lazy import keeps this file's footprint minimal
    # target_policy.check_target() resolves the *host* and classifies the IP
    # class (loopback / private / Tailscale / external). It doesn't strip URL
    # scheme/path, so passing a full URL like "http://127.0.0.1:8081" yields a
    # spurious "could not resolve" warn even though the underlying host is
    # loopback. Normalize to a bare host before handing it down.
    pol_target = _host_from_target(target) or target
    # target_policy raises through to the IDNA encoder for pathological
    # inputs like "..../etc/passwd" — we treat any unhandled crash from
    # the policy layer as a deny rather than letting it 500.
    try:
        pol_v, pol_r = target_policy.check_target(pol_target)
    except Exception as e:
        pol_v, pol_r = "deny", f"target failed validation: {type(e).__name__}"
    sc_v,  sc_r  = check(target, engagement_id, mode)
    verdict, _ = combine((pol_v, pol_r), (sc_v, sc_r))
    # Reason on the combined verdict prefers the layer that triggered it.
    if _RANK[pol_v] >= _RANK[sc_v]:
        reason = f"policy: {pol_r}"
    else:
        reason = f"scope: {sc_r}"
    return verdict, reason, {"policy": f"{pol_v}: {pol_r}",
                             "scope":  f"{sc_v}: {sc_r}"}


# ── Enforcement helpers ──────────────────────────────────────────────────────
#
# Two thin wrappers around `check_combined` that fold in the side-effects
# every router does identically (emit a `scope` event, return an error frame
# / raise `MhpError` on deny|warn, close the WS). Routers call these in one
# line instead of repeating the 25-line check + dispatch block.


async def enforce_ws(
    ws,
    target: str,
    engagement_id: str | None,
    mode: Mode,
    *,
    confirm: bool = False,
    deny_only: bool = False,
    active: bool = False,
    action: str | None = None,
) -> bool:
    """WS scope check + side-effects. Returns True if the scan may proceed.

    On allow: sends a `{"type":"scope",...}` event so the UI can show the
    verdict, returns True.

    On deny or unconfirmed warn: sends the scope event, then a TARGET_DENIED
    or NEED_CONFIRM error frame, closes the WS, returns False. The caller
    typically does `if not await enforce_ws(...): return`.

    `deny_only=True` is for passive tools (TLS audit, WHOIS, CT logs) where
    `warn` doesn't block — the verdict is still surfaced in the response
    but execution proceeds without a confirm round-trip.

    `active=True` marks this as an ACTIVE run that reaches the target. After
    the scope verdict passes, the safety layer's hard gate runs: a non-lab
    target requires a covering authorization attestation (else 403), and the
    allowed action is recorded into the append-only audit ledger. Passive
    tools leave `active` False and are unaffected. `action` labels the audit
    record (defaults to the tool name the caller would otherwise use).
    """
    verdict, reason, layers = check_combined(target, engagement_id, mode)
    await ws.send_json({
        "type": "scope", "target": target, "mode": mode,
        "verdict": verdict, "reason": reason, "layers": layers,
    })
    if verdict == "deny":
        await ws.send_json(ws_error(
            ErrorCode.TARGET_DENIED,
            f"scope check failed: {reason}",
            target=target,
        ))
        await ws.close()
        return False
    if verdict == "warn" and not confirm and not deny_only:
        await ws.send_json(ws_error(
            ErrorCode.NEED_CONFIRM,
            reason, target=target, need_confirm=True,
        ))
        await ws.close()
        return False
    if active and not await _enforce_active_ws(ws, target, engagement_id, action):
        return False
    return True


async def _enforce_active_ws(
    ws, target: str, engagement_id: str | None, action: str | None,
) -> bool:
    """Run the safety hard gate for an active WS run.

    Lab-class targets pass freely. External targets require a covering
    attestation; on miss, send a TARGET_DENIED frame + close + return False.
    On allow, append an audit record (provenance + attestation id) and return
    True.
    """
    from lib import safety

    prov = safety.provenance(target)
    try:
        attestation_id = safety.require_active_allowed(target, engagement_id)
    except Exception as exc:
        # HTTPException(403) from the gate, or any failure → refuse the run.
        detail = getattr(exc, "detail", None) or str(exc)
        await ws.send_json(ws_error(
            ErrorCode.TARGET_DENIED,
            str(detail),
            target=target,
        ))
        await ws.close()
        return False
    safety.audit_active(
        action=action or "active_run",
        target=target,
        provenance=prov,
        params={"engagement_id": engagement_id},
        attestation_id=attestation_id,
    )
    return True


def enforce_engagement_present(
    engagement_id: str | None,
    mode: Mode,
) -> None:
    """For tools where the "target" isn't a network endpoint (local
    listeners, IMDS provider names, SSID detectors, etc.) but actions still
    need to be tied to an engagement under Engagement mode.

    Raises `MhpError(NEED_CONFIRM)` style only when mode=engagement and no
    engagement is active; otherwise silently allows. Skips target matching
    entirely — there's nothing to scope against.
    """
    if mode != "engagement":
        return
    if not engagement_id:
        raise MhpError(
            "engagement mode requires an active engagement",
            code=ErrorCode.TARGET_DENIED,
            status_code=403,
            extra={"reason": "engagement mode requires an active engagement"},
        )
    try:
        eng = engagements.get_engagement(engagement_id)
    except Exception:
        logger.exception("scope: failed to load engagement %s", engagement_id)
        raise MhpError(
            "could not load engagement record",
            code=ErrorCode.TARGET_DENIED,
            status_code=403,
        ) from None
    if not eng:
        raise MhpError(
            f"engagement {engagement_id} not found",
            code=ErrorCode.TARGET_DENIED,
            status_code=403,
        )


async def enforce_engagement_present_ws(
    ws,
    engagement_id: str | None,
    mode: Mode,
) -> bool:
    """WS equivalent of `enforce_engagement_present`. Sends an error frame
    + closes the WS on failure, returns False; returns True on allow."""
    try:
        enforce_engagement_present(engagement_id, mode)
    except MhpError as exc:
        await ws.send_json(ws_error(
            ErrorCode.TARGET_DENIED, exc.message,
        ))
        await ws.close()
        return False
    return True


def enforce_rest(
    target: str,
    engagement_id: str | None,
    mode: Mode,
    *,
    confirm: bool = False,
    deny_only: bool = False,
    active: bool = False,
    action: str | None = None,
) -> tuple[Verdict, str, dict[str, str]]:
    """REST scope check. Raises MhpError on deny or unconfirmed warn.

    Returns `(verdict, reason, layers)` for the allow / passive-warn case
    so callers can include the verdict in their response payload (existing
    `policy: {verdict, reason}` fields keep working).

    `deny_only=True`: passive tools — `warn` proceeds without confirm.

    `active=True`: this is an ACTIVE run. After the scope verdict passes, the
    safety hard gate runs — a non-lab target requires a covering attestation
    (raises HTTPException(403) otherwise), and the allowed run is appended to
    the audit ledger. `action` labels the audit record.
    """
    verdict, reason, layers = check_combined(target, engagement_id, mode)
    if verdict == "deny":
        raise MhpError(
            f"scope check failed: {reason}",
            code=ErrorCode.TARGET_DENIED,
            status_code=403,
            extra={"target": target, "layers": layers},
        )
    if verdict == "warn" and not confirm and not deny_only:
        raise MhpError(
            reason,
            code=ErrorCode.NEED_CONFIRM,
            status_code=409,
            extra={"need_confirm": True, "target": target, "layers": layers},
        )
    if active:
        from lib import safety

        prov = safety.provenance(target)
        # require_active_allowed raises HTTPException(403) on a missing
        # attestation for a non-lab target — let it propagate (FastAPI turns
        # it into the 403 response the acceptance test expects).
        attestation_id = safety.require_active_allowed(target, engagement_id)
        safety.audit_active(
            action=action or "active_run",
            target=target,
            provenance=prov,
            params={"engagement_id": engagement_id},
            attestation_id=attestation_id,
        )
    return verdict, reason, layers
