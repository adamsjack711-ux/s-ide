"""Azure Recon — read-only audit via the DefaultAzureCredential chain.

Credentials come from whatever `az login` / env vars / managed-identity provide.
We never accept credentials over the UI — the user sets up `az login` outside
the app once.

The Azure mgmt SDKs are per-service; we import lazily so a missing one doesn't
break the rest of the app. Each `_check_*` returns its own findings + a small
summary, and errors per-service so a permission failure on Storage doesn't
prevent Network from running.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Request

from lib import scope
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/azure", tags=["azure-recon"])


def _import_az():
    try:
        from azure.identity import DefaultAzureCredential
        from azure.core.exceptions import (
            ClientAuthenticationError, HttpResponseError,
        )
        return DefaultAzureCredential, ClientAuthenticationError, HttpResponseError
    except ImportError as e:
        raise MhpError(
            "azure-identity not available. pip install azure-identity "
            "azure-mgmt-resource azure-mgmt-storage azure-mgmt-compute "
            "azure-mgmt-network azure-mgmt-keyvault",
            code=ErrorCode.TOOL_MISSING,
            status_code=503,
            extra={"import_error": str(e)},
        )


@router.get("/status")
def status() -> dict[str, Any]:
    DefaultAzureCredential, AuthErr, HttpErr = _import_az()
    try:
        from azure.mgmt.resource.subscriptions import SubscriptionClient
    except ImportError as e:
        raise MhpError(
            "azure-mgmt-resource-subscriptions missing",
            code=ErrorCode.TOOL_MISSING,
            status_code=503,
            extra={"import_error": str(e)},
        )
    cred = DefaultAzureCredential()
    try:
        client = SubscriptionClient(cred)
        subs = [{"id": s.subscription_id, "name": s.display_name,
                 "state": s.state}
                for s in client.subscriptions.list()]
        return {"ok": True, "subscriptions": subs}
    except (AuthErr, HttpErr) as e:
        logger.info("azure status auth/http error: %s", type(e).__name__)
        return {"ok": False, "error": f"{type(e).__name__}", "code": type(e).__name__}
    except Exception as e:
        logger.exception("azure status: unexpected error")
        return {"ok": False, "error": f"{type(e).__name__}"}


def _add(out: list[dict[str, Any]], severity: str, service: str,
         title: str, detail: str, evidence: Any = None) -> None:
    out.append({"severity": severity, "service": service, "title": title,
                "detail": detail, "evidence": evidence})


def _check_storage(cred, sub_id: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    try:
        from azure.mgmt.storage import StorageManagementClient
        client = StorageManagementClient(cred, sub_id)
    except ImportError as e:
        return {"error": f"azure-mgmt-storage missing: {e}", "findings": findings}
    try:
        accounts = []
        for acc in client.storage_accounts.list():
            entry = {
                "name": acc.name, "kind": acc.kind,
                "allow_blob_public_access": getattr(acc, "allow_blob_public_access", None),
                "https_only": getattr(acc, "enable_https_traffic_only", None),
                "location": acc.location,
            }
            if entry["allow_blob_public_access"] is True:
                _add(findings, "high", "Storage",
                     f"Storage account {acc.name}: allows public blob access",
                     f"Storage account {acc.name!r} has allow_blob_public_access=True. "
                     "Individual containers may still be public.",
                     evidence=entry)
            if entry["https_only"] is False:
                _add(findings, "medium", "Storage",
                     f"Storage account {acc.name}: HTTP allowed",
                     f"Account {acc.name!r} does not enforce HTTPS-only.",
                     evidence=entry)
            accounts.append(entry)
        return {"findings": findings, "summary": {"accounts": len(accounts)},
                "accounts": accounts[:100]}
    except Exception as e:
        logger.info("azure check failed: %s", type(e).__name__)
        return {"error": f"{type(e).__name__}", "code": type(e).__name__, "findings": findings}


def _check_compute(cred, sub_id: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    try:
        from azure.mgmt.compute import ComputeManagementClient
        client = ComputeManagementClient(cred, sub_id)
    except ImportError as e:
        return {"error": f"azure-mgmt-compute missing: {e}", "findings": findings}
    try:
        vms = []
        for vm in client.virtual_machines.list_all():
            entry = {
                "name": vm.name,
                "location": vm.location,
                "os_type": getattr(vm.storage_profile.os_disk, "os_type", None),
            }
            vms.append(entry)
        return {"findings": findings, "summary": {"vms": len(vms)},
                "vms": vms[:100]}
    except Exception as e:
        logger.info("azure check failed: %s", type(e).__name__)
        return {"error": f"{type(e).__name__}", "code": type(e).__name__, "findings": findings}


def _check_network(cred, sub_id: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    try:
        from azure.mgmt.network import NetworkManagementClient
        client = NetworkManagementClient(cred, sub_id)
    except ImportError as e:
        return {"error": f"azure-mgmt-network missing: {e}", "findings": findings}
    try:
        nsgs = []
        for nsg in client.network_security_groups.list_all():
            open_rules = []
            for rule in (nsg.security_rules or []):
                src = rule.source_address_prefix or ""
                if rule.direction == "Inbound" and rule.access == "Allow" and src in ("*", "0.0.0.0/0", "Internet"):
                    open_rules.append({
                        "name": rule.name,
                        "proto": rule.protocol,
                        "ports": rule.destination_port_range,
                    })
            if open_rules:
                _add(findings, "high", "Network",
                     f"NSG {nsg.name}: open ingress from Internet",
                     f"NSG {nsg.name!r} has {len(open_rules)} rule(s) allowing inbound "
                     "traffic from *, 0.0.0.0/0, or Internet.",
                     evidence={"nsg": nsg.name, "rules": open_rules})
            nsgs.append({"name": nsg.name, "location": nsg.location,
                         "open_rules": open_rules})
        return {"findings": findings, "summary": {"nsgs": len(nsgs)},
                "nsgs": nsgs[:100]}
    except Exception as e:
        logger.info("azure check failed: %s", type(e).__name__)
        return {"error": f"{type(e).__name__}", "code": type(e).__name__, "findings": findings}


def _check_keyvault(cred, sub_id: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    try:
        from azure.mgmt.keyvault import KeyVaultManagementClient
        client = KeyVaultManagementClient(cred, sub_id)
    except ImportError as e:
        return {"error": f"azure-mgmt-keyvault missing: {e}", "findings": findings}
    try:
        vaults = []
        for v in client.vaults.list():
            net_acl = getattr(v.properties, "network_acls", None) if v.properties else None
            default_action = getattr(net_acl, "default_action", "Allow") if net_acl else "Allow"
            entry = {
                "name": v.name, "location": v.location,
                "default_network_action": default_action,
            }
            if default_action == "Allow":
                _add(findings, "medium", "KeyVault",
                     f"Key Vault {v.name}: default-allow network ACL",
                     f"Vault {v.name!r} has network default_action=Allow — accessible "
                     "from any network.",
                     evidence=entry)
            vaults.append(entry)
        return {"findings": findings, "summary": {"vaults": len(vaults)},
                "vaults": vaults[:100]}
    except Exception as e:
        logger.info("azure check failed: %s", type(e).__name__)
        return {"error": f"{type(e).__name__}", "code": type(e).__name__, "findings": findings}


@router.get("/recon")
def recon(request: Request, subscription_id: str | None = None,
          services: str = "storage,compute,network,keyvault") -> dict[str, Any]:
    # Subscription id (if provided) is matched as scope target so a
    # specific tenant can be locked in for the engagement.
    sc_target = (subscription_id or "azure").strip() or "azure"
    scope.enforce_rest(
        sc_target, get_engagement_id(request), get_mode(request), deny_only=True,
    )
    DefaultAzureCredential, _, _ = _import_az()
    cred = DefaultAzureCredential()

    # Pick subscription
    try:
        from azure.mgmt.resource.subscriptions import SubscriptionClient
        sub_client = SubscriptionClient(cred)
        subs = [{"id": s.subscription_id, "name": s.display_name}
                for s in sub_client.subscriptions.list()]
    except Exception:
        logger.exception("azure recon: could not list subscriptions")
        raise MhpError(
            "Could not list Azure subscriptions (run `az login` first)",
            code=ErrorCode.UNAUTHORIZED,
            status_code=401,
        )
    if not subs:
        raise MhpError(
            "no subscriptions visible — run `az login` first",
            code=ErrorCode.UNAUTHORIZED,
            status_code=401,
        )
    sub_id = subscription_id or subs[0]["id"]
    sub_name = next((s["name"] for s in subs if s["id"] == sub_id), sub_id)

    picked = {s.strip() for s in services.split(",") if s.strip()}
    out: dict[str, Any] = {
        "subscription": {"id": sub_id, "name": sub_name},
        "all_subscriptions": subs,
        "services": {},
        "findings": [],
    }
    runners = {
        "storage":  lambda: _check_storage(cred, sub_id),
        "compute":  lambda: _check_compute(cred, sub_id),
        "network":  lambda: _check_network(cred, sub_id),
        "keyvault": lambda: _check_keyvault(cred, sub_id),
    }
    for name, fn in runners.items():
        if name not in picked:
            continue
        res = fn()
        out["services"][name] = res
        out["findings"].extend(res.get("findings", []))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out["findings"].sort(key=lambda f: order.get(f["severity"], 99))
    return out
