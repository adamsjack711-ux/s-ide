"""GCP Recon — read-only audit via Application Default Credentials.

Credentials come from `gcloud auth application-default login` or a
GOOGLE_APPLICATION_CREDENTIALS service-account file. Like the AWS/Azure
routers, this is best-effort: a missing dep or a permission failure on one
service won't take down the rest.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter

from lib.errors import ErrorCode, MhpError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/gcp", tags=["gcp-recon"])


def _has_adc() -> bool:
    """Cheap check for any plausible Application Default Credentials source.

    Without this, google.auth.default() falls through to a GCE metadata probe
    that hangs for ~15s inside containers that aren't on GCE.
    """
    if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        return True
    return (Path.home() / ".config" / "gcloud"
            / "application_default_credentials.json").exists()


def _import_gcp():
    try:
        from google.auth import default as gauth_default
        from google.auth.exceptions import DefaultCredentialsError
        return gauth_default, DefaultCredentialsError
    except ImportError as e:
        raise MhpError(
            "google-auth not available. pip install google-cloud-resource-manager "
            "google-cloud-storage google-cloud-compute",
            code=ErrorCode.TOOL_MISSING,
            status_code=503,
            extra={"import_error": str(e)},
        )


@router.get("/status")
def status() -> dict[str, Any]:
    gauth_default, DefaultCredentialsError = _import_gcp()
    if not _has_adc():
        return {"ok": False, "error":
                "no GCP credentials (set GOOGLE_APPLICATION_CREDENTIALS or "
                "run `gcloud auth application-default login`)"}
    try:
        cred, project_id = gauth_default()
        return {"ok": True, "default_project": project_id,
                "principal": getattr(cred, "service_account_email", None)
                              or getattr(cred, "_service_account_email", None)
                              or "user-credentials"}
    except DefaultCredentialsError as e:
        logger.info("gcp status creds error: %s", type(e).__name__)
        return {"ok": False, "error": f"{type(e).__name__}", "code": "DefaultCredentialsError"}
    except Exception as e:
        logger.exception("gcp status: unexpected error")
        return {"ok": False, "error": f"{type(e).__name__}"}


def _add(out: list[dict[str, Any]], severity: str, service: str,
         title: str, detail: str, evidence: Any = None) -> None:
    out.append({"severity": severity, "service": service, "title": title,
                "detail": detail, "evidence": evidence})


def _list_projects(cred) -> list[dict[str, Any]]:
    from google.cloud import resourcemanager_v3
    client = resourcemanager_v3.ProjectsClient(credentials=cred)
    out: list[dict[str, Any]] = []
    # search_projects returns projects the caller can see
    for p in client.search_projects():
        out.append({"id": p.project_id, "name": p.display_name,
                    "state": p.state.name})
    return out


def _check_storage(cred, project_id: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    try:
        from google.cloud import storage
    except ImportError as e:
        return {"error": f"google-cloud-storage missing: {e}", "findings": findings}
    try:
        client = storage.Client(credentials=cred, project=project_id)
        buckets: list[dict[str, Any]] = []
        for b in client.list_buckets():
            entry = {"name": b.name, "location": b.location, "public": False}
            # IAM policy
            try:
                policy = b.get_iam_policy(requested_policy_version=3)
                for binding in policy.bindings:
                    members = binding.get("members", [])
                    role = binding.get("role", "")
                    if "allUsers" in members:
                        entry["public"] = True
                        _add(findings, "critical", "Storage",
                             f"Bucket {b.name}: allUsers has {role}",
                             f"Bucket {b.name!r} grants {role} to allUsers — "
                             "publicly accessible.",
                             evidence={"bucket": b.name, "role": role,
                                       "members": list(members)})
                    elif "allAuthenticatedUsers" in members:
                        _add(findings, "high", "Storage",
                             f"Bucket {b.name}: allAuthenticatedUsers has {role}",
                             f"Bucket {b.name!r} grants {role} to any "
                             "Google-authenticated user.",
                             evidence={"bucket": b.name, "role": role,
                                       "members": list(members)})
            except Exception as e:
                entry["iam_error"] = str(e)[:200]
            buckets.append(entry)
        return {"findings": findings, "summary": {"buckets": len(buckets)},
                "buckets": buckets[:100]}
    except Exception as e:
        logger.info("gcp check failed: %s", type(e).__name__)
        return {"error": f"{type(e).__name__}", "code": type(e).__name__, "findings": findings}


def _check_compute(cred, project_id: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    try:
        from google.cloud import compute_v1
    except ImportError as e:
        return {"error": f"google-cloud-compute missing: {e}", "findings": findings}
    try:
        instances_client = compute_v1.InstancesClient(credentials=cred)
        firewalls_client = compute_v1.FirewallsClient(credentials=cred)

        # AggregatedList returns instances across all zones in one call
        instances: list[dict[str, Any]] = []
        for zone, scoped in instances_client.aggregated_list(project=project_id):
            if not scoped.instances:
                continue
            for inst in scoped.instances:
                public_ip = None
                for nic in inst.network_interfaces:
                    for ac in nic.access_configs:
                        if ac.nat_i_p:
                            public_ip = ac.nat_i_p
                            break
                # Default service account warning
                using_default = any(
                    sa.email and sa.email.endswith("-compute@developer.gserviceaccount.com")
                    for sa in inst.service_accounts
                )
                entry = {
                    "name": inst.name,
                    "zone": zone.split("/")[-1],
                    "public_ip": public_ip,
                    "machine_type": (inst.machine_type or "").split("/")[-1],
                    "using_default_sa": using_default,
                }
                if public_ip:
                    _add(findings, "medium", "Compute",
                         f"VM {inst.name}: public IP",
                         f"Instance {inst.name!r} ({entry['zone']}) has public IP "
                         f"{public_ip}.",
                         evidence=entry)
                if using_default:
                    _add(findings, "medium", "Compute",
                         f"VM {inst.name}: default service account",
                         f"Instance {inst.name!r} uses the default Compute Engine SA. "
                         "Prefer a dedicated SA with least privilege.",
                         evidence=entry)
                instances.append(entry)

        # Firewall rules — flag 0.0.0.0/0 allow
        fws: list[dict[str, Any]] = []
        for fw in firewalls_client.list(project=project_id):
            if fw.direction != "INGRESS":
                continue
            sources = list(fw.source_ranges)
            if "0.0.0.0/0" not in sources:
                continue
            allowed = [{"proto": a.I_p_protocol,
                        "ports": list(a.ports)} for a in fw.allowed]
            if not allowed:
                continue
            _add(findings, "high", "Compute",
                 f"Firewall {fw.name}: 0.0.0.0/0 ingress",
                 f"Firewall rule {fw.name!r} allows ingress from 0.0.0.0/0 "
                 f"({len(allowed)} rule(s)).",
                 evidence={"firewall": fw.name, "allowed": allowed,
                           "target_tags": list(fw.target_tags)})
            fws.append({"name": fw.name, "allowed": allowed})

        return {"findings": findings,
                "summary": {"instances": len(instances), "open_firewalls": len(fws)},
                "instances": instances[:100], "open_firewalls": fws[:50]}
    except Exception as e:
        logger.info("gcp check failed: %s", type(e).__name__)
        return {"error": f"{type(e).__name__}", "code": type(e).__name__, "findings": findings}


def _check_iam(cred, project_id: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    try:
        from google.cloud import resourcemanager_v3
        client = resourcemanager_v3.ProjectsClient(credentials=cred)
    except ImportError as e:
        return {"error": f"google-cloud-resource-manager missing: {e}", "findings": findings}
    try:
        resource = f"projects/{project_id}"
        policy = client.get_iam_policy(resource=resource)
        bindings: list[dict[str, Any]] = []
        for b in policy.bindings:
            members = list(b.members)
            role = b.role
            bindings.append({"role": role, "members": members})
            if "allUsers" in members:
                _add(findings, "critical", "IAM",
                     f"Project IAM: allUsers has {role}",
                     f"Project-level IAM grants {role} to allUsers.",
                     evidence={"role": role, "members": members})
            elif "allAuthenticatedUsers" in members:
                _add(findings, "high", "IAM",
                     f"Project IAM: allAuthenticatedUsers has {role}",
                     f"Project-level IAM grants {role} to any Google-authenticated user.",
                     evidence={"role": role, "members": members})
            if role in ("roles/owner", "roles/editor"):
                # Owner / Editor are very broad — flag if granted to user accounts
                user_members = [m for m in members if m.startswith("user:")]
                if user_members:
                    _add(findings, "medium", "IAM",
                         f"Project IAM: {len(user_members)} user(s) with {role}",
                         f"Users {', '.join(user_members[:3])} have {role} — broad permissions.",
                         evidence={"role": role, "members": user_members})
        return {"findings": findings,
                "summary": {"bindings": len(bindings)},
                "bindings": bindings[:50]}
    except Exception as e:
        logger.info("gcp check failed: %s", type(e).__name__)
        return {"error": f"{type(e).__name__}", "code": type(e).__name__, "findings": findings}


@router.get("/recon")
def recon(project: str | None = None,
          services: str = "iam,storage,compute") -> dict[str, Any]:
    gauth_default, DefaultCredentialsError = _import_gcp()
    try:
        cred, default_project = gauth_default()
    except DefaultCredentialsError as e:
        logger.info("gcp recon: no credentials: %s", e)
        raise MhpError(
            "No GCP credentials (run `gcloud auth application-default login`)",
            code=ErrorCode.UNAUTHORIZED,
            status_code=401,
        )

    target_project = project or default_project
    if not target_project:
        try:
            projs = _list_projects(cred)
        except Exception:
            logger.exception("gcp recon: could not list projects")
            raise MhpError(
                "No default project; could not list projects either",
                code=ErrorCode.UNAUTHORIZED,
                status_code=401,
            )
        if not projs:
            raise MhpError(
                "No projects visible to this credential",
                code=ErrorCode.UNAUTHORIZED,
                status_code=401,
            )
        target_project = projs[0]["id"]
    else:
        try:
            projs = _list_projects(cred)
        except Exception:
            projs = []

    picked = {s.strip() for s in services.split(",") if s.strip()}
    out: dict[str, Any] = {
        "project": target_project,
        "available_projects": projs,
        "services": {},
        "findings": [],
    }
    runners = {
        "iam":     lambda: _check_iam(cred, target_project),
        "storage": lambda: _check_storage(cred, target_project),
        "compute": lambda: _check_compute(cred, target_project),
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
