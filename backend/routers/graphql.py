"""GraphQL introspection probe.

REST  GET /graphql/introspect?url=...&confirm=true

POSTs the standard introspection query to the URL. If introspection is
enabled (common dev/staging misconfig in prod), we get the full schema back —
types, queries, mutations, deprecated fields, suggested attack surface.
"""
from __future__ import annotations

import asyncio
import json
import logging
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

router = APIRouter(tags=["graphql"])


INTROSPECTION_QUERY = """\
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind } }
      }
      enumValues(includeDeprecated: true) { name isDeprecated }
    }
  }
}
"""


def _post(url: str, body: bytes, timeout: float = 10.0) -> tuple[int, dict[str, str], bytes, str]:
    import http.client
    u = urlparse(url if "://" in url else "https://" + url)
    scheme = (u.scheme or "https").lower()
    host = u.hostname or ""
    port = u.port or (443 if scheme == "https" else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                           context=ssl._create_unverified_context())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("POST", path, body=body, headers={
            "Host": host,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "network-tools/0.1 (+graphql)",
            "Content-Length": str(len(body)),
            "Connection": "close",
        })
        resp = conn.getresponse()
        data = resp.read()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers, data, host
    finally:
        try: conn.close()
        except Exception: pass


def _type_name(t: dict[str, Any] | None) -> str:
    """Unwrap a GraphQL type ref like NON_NULL → LIST → name."""
    if not t:
        return ""
    name = t.get("name") or ""
    if name:
        return name
    inner = t.get("ofType")
    return _type_name(inner)


@router.get("/graphql/introspect")
async def graphql_introspect(
    request: Request,
    url: str = Query(...),
    confirm: bool = Query(default=False),
) -> dict[str, Any]:
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

    body = json.dumps({"query": INTROSPECTION_QUERY}).encode("utf-8")
    t0 = time.monotonic()
    try:
        status, headers, data, host_used = await asyncio.to_thread(_post, url, body)
    except Exception:
        logger.exception("graphql introspect fetch failed host=%s", host)
        raise MhpError(
            "GraphQL endpoint fetch failed",
            code=ErrorCode.UPSTREAM_FAILED,
            status_code=502,
            extra={"target": host},
        )

    elapsed = round(time.monotonic() - t0, 2)
    content_type = (headers.get("content-type") or "").lower().strip()
    ct_main = content_type.split(";", 1)[0].strip()
    valid_ct = ct_main in ("application/json", "application/graphql-response+json")

    # Gate 1: HTTP status must be exactly 200.
    if status != 200:
        return {
            "url": url, "host": host_used, "status_code": status,
            "introspection_enabled": False,
            "elapsed_seconds": elapsed,
            "raw_preview": data[:600].decode("utf-8", errors="replace"),
            "findings": [{"severity": "info",
                          "label": "Not a GraphQL introspection response",
                          "detail": f"Response was status={status}, content-type={ct_main or 'unknown'} — not a GraphQL endpoint"}],
            "policy": {"verdict": verdict, "reason": reason},
        }

    # Gate 2: Content-Type must be application/json or application/graphql-response+json.
    if not valid_ct:
        return {
            "url": url, "host": host_used, "status_code": status,
            "introspection_enabled": False,
            "elapsed_seconds": elapsed,
            "raw_preview": data[:600].decode("utf-8", errors="replace"),
            "findings": [{"severity": "info",
                          "label": "Not a GraphQL introspection response",
                          "detail": f"Response was status={status}, content-type={ct_main or 'unknown'} — not a GraphQL endpoint"}],
            "policy": {"verdict": verdict, "reason": reason},
        }

    # Gate 3: Body must parse as JSON.
    try:
        resp = json.loads(data)
    except Exception:
        return {
            "url": url, "host": host_used, "status_code": status,
            "introspection_enabled": False,
            "elapsed_seconds": elapsed,
            "raw_preview": data[:600].decode("utf-8", errors="replace"),
            "findings": [{"severity": "info",
                          "label": "Response is not JSON",
                          "detail": f"Response was status={status}, content-type={ct_main} but body did not parse as JSON"}],
            "policy": {"verdict": verdict, "reason": reason},
        }

    if not isinstance(resp, dict):
        return {
            "url": url, "host": host_used, "status_code": status,
            "introspection_enabled": False,
            "elapsed_seconds": elapsed,
            "findings": [{"severity": "info",
                          "label": "Unexpected JSON shape",
                          "detail": "Top-level JSON was not an object — not a GraphQL response"}],
            "policy": {"verdict": verdict, "reason": reason},
        }

    if "errors" in resp and "data" not in resp:
        return {
            "url": url, "host": host_used, "status_code": status,
            "introspection_enabled": False,
            "elapsed_seconds": elapsed,
            "errors": resp.get("errors", []),
            "findings": [{"severity": "info",
                          "label": "Introspection rejected",
                          "detail": "Endpoint exists but introspection is disabled"}],
            "policy": {"verdict": verdict, "reason": reason},
        }

    # Gate 4: Parsed JSON must have a data.__schema object.
    data_obj = resp.get("data")
    schema_obj = (data_obj or {}).get("__schema") if isinstance(data_obj, dict) else None
    if not isinstance(schema_obj, dict):
        return {
            "url": url, "host": host_used, "status_code": status,
            "introspection_enabled": False,
            "elapsed_seconds": elapsed,
            "findings": [{"severity": "info",
                          "label": "No introspection schema in response",
                          "detail": "Response parsed as JSON but did not contain data.__schema — endpoint may not be GraphQL or introspection is disabled"}],
            "policy": {"verdict": verdict, "reason": reason},
        }

    schema = schema_obj
    types_raw = schema.get("types") or []

    query_type = (schema.get("queryType") or {}).get("name") or ""
    mutation_type = (schema.get("mutationType") or {}).get("name") or ""
    subscription_type = (schema.get("subscriptionType") or {}).get("name") or ""

    types: list[dict[str, Any]] = []
    queries: list[dict[str, Any]] = []
    mutations: list[dict[str, Any]] = []
    deprecated: list[dict[str, Any]] = []

    for t in types_raw:
        kind = t.get("kind") or ""
        name = t.get("name") or ""
        if not name or name.startswith("__"):
            continue
        types.append({"name": name, "kind": kind,
                      "description": t.get("description") or ""})
        for f in t.get("fields") or []:
            field = {
                "field": f.get("name") or "",
                "type": _type_name(f.get("type")),
                "args": [
                    {"name": a.get("name"), "type": _type_name(a.get("type"))}
                    for a in (f.get("args") or [])
                ],
                "description": f.get("description") or "",
            }
            if name == query_type:
                queries.append(field)
            elif name == mutation_type:
                mutations.append(field)
            if f.get("isDeprecated"):
                deprecated.append({**field, "parent": name,
                                   "reason": f.get("deprecationReason") or ""})

    findings: list[dict[str, Any]] = [{
        "severity": "warn",
        "label": "GraphQL introspection enabled",
        "detail": "Public schema dump is possible — disable in production",
    }]
    if mutations:
        findings.append({
            "severity": "info",
            "label": f"{len(mutations)} mutations exposed",
            "detail": "Each is a write surface — review auth on each",
        })
    if deprecated:
        findings.append({
            "severity": "info",
            "label": f"{len(deprecated)} deprecated fields",
            "detail": "Often left lying around; sometimes lack updated auth checks",
        })

    await hids_notify.notify(
        "warning", "graphql",
        f"GraphQL introspection enabled — {host_used}: {len(queries)} queries / {len(mutations)} mutations",
        {"host": host_used, "queries": len(queries),
         "mutations": len(mutations), "types": len(types)},
    )

    return {
        "url": url, "host": host_used, "status_code": status,
        "introspection_enabled": True,
        "elapsed_seconds": elapsed,
        "query_type": query_type,
        "mutation_type": mutation_type,
        "subscription_type": subscription_type,
        "type_count": len(types),
        "types": types[:200],   # cap to keep response sane
        "queries": queries,
        "mutations": mutations,
        "deprecated": deprecated,
        "findings": findings,
        "policy": {"verdict": verdict, "reason": reason},
    }
