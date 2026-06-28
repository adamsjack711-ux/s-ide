"""Lateral Movement Planner — BloodHound JSON parser + path solver.

Takes a BloodHound ZIP (the kind the Ingestor produces) or individual JSON
files, builds an in-memory graph, and computes shortest attack paths via BFS.

We don't bundle Neo4j or BloodHound's UI — this is a focused "given the same
data, find the obvious wins" tool. Categories of edges we currently model:

  - MemberOf            (transitive group membership)
  - AdminTo             (user/group has admin on a computer)
  - HasSession          (user has an active session on a computer)
  - CanRDP, CanPSRemote (logon types)
  - ForceChangePassword, GenericAll, WriteOwner, GenericWrite, WriteDacl,
    AllExtendedRights, Owns (ACL paths)
  - DCSync hints from GetChangesAll / GetChanges combo

For each query:
  - shortest path to Domain Admins from a starting principal
  - reachability of N targets within K hops

Plus a static technique reference rendered on the page (e.g. ForceChangePassword
→ how to actually use it once you spot it).
"""
from __future__ import annotations

import io
import json
import logging
import zipfile
from collections import defaultdict, deque
from typing import Any

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from lib import audit_log, scope
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/lateral", tags=["lateral"])

# Cap upload size at 200 MB — large BloodHound dumps are still well below this.
MAX_UPLOAD_BYTES = 200 * 1024 * 1024
MAX_NAME_LEN = 512


# In-memory graph state — one "loaded dataset" per process.
class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}    # objectid -> {name, kind, props}
        self.edges: dict[str, list[tuple[str, str]]] = defaultdict(list)  # src -> [(dst, kind)]
        self.name_index: dict[str, str] = {}          # uppercased name -> objectid

    def add_node(self, oid: str, name: str, kind: str, props: dict[str, Any]) -> None:
        if not oid:
            return
        self.nodes[oid] = {"name": name, "kind": kind, "props": props}
        if name:
            self.name_index[name.upper()] = oid

    def add_edge(self, src: str, dst: str, kind: str) -> None:
        if src and dst and src != dst:
            self.edges[src].append((dst, kind))

    def stats(self) -> dict[str, Any]:
        by_kind: dict[str, int] = defaultdict(int)
        for n in self.nodes.values():
            by_kind[n["kind"]] += 1
        edge_count = sum(len(v) for v in self.edges.values())
        return {
            "nodes": len(self.nodes), "edges": edge_count,
            "by_kind": dict(by_kind),
        }


_graph = Graph()


# ── BloodHound JSON parsers ────────────────────────────────────────────────

ACL_EDGES = {
    "ForceChangePassword", "GenericAll", "WriteOwner",
    "GenericWrite", "WriteDacl", "AllExtendedRights",
    "Owns", "AddMember", "AddSelf", "ReadLAPSPassword",
    "ReadGMSAPassword", "GetChanges", "GetChangesAll",
}


def _ingest_users(g: Graph, data: dict[str, Any]) -> None:
    for u in data.get("data", []):
        props = u.get("Properties", {}) or {}
        oid = u.get("ObjectIdentifier") or props.get("objectid") or ""
        name = props.get("name", "")
        g.add_node(oid, name, "User", props)
        for grp in u.get("PrimaryGroupSid") or []:
            g.add_edge(oid, grp, "MemberOf")
        # Aces
        for ace in u.get("Aces", []) or []:
            kind = ace.get("RightName") or ""
            principal = ace.get("PrincipalSID") or ""
            if principal and kind in ACL_EDGES:
                g.add_edge(principal, oid, kind)


def _ingest_groups(g: Graph, data: dict[str, Any]) -> None:
    for grp in data.get("data", []):
        props = grp.get("Properties", {}) or {}
        oid = grp.get("ObjectIdentifier") or props.get("objectid") or ""
        name = props.get("name", "")
        g.add_node(oid, name, "Group", props)
        for m in grp.get("Members") or []:
            mid = m.get("ObjectIdentifier") or m.get("MemberId") or ""
            if mid:
                g.add_edge(mid, oid, "MemberOf")
        for ace in grp.get("Aces", []) or []:
            kind = ace.get("RightName") or ""
            principal = ace.get("PrincipalSID") or ""
            if principal and kind in ACL_EDGES:
                g.add_edge(principal, oid, kind)


def _ingest_computers(g: Graph, data: dict[str, Any]) -> None:
    for c in data.get("data", []):
        props = c.get("Properties", {}) or {}
        oid = c.get("ObjectIdentifier") or props.get("objectid") or ""
        name = props.get("name", "")
        g.add_node(oid, name, "Computer", props)
        # AdminTo
        for entry in (c.get("LocalAdmins") or {}).get("Results", []) or []:
            principal = entry.get("ObjectIdentifier") or ""
            g.add_edge(principal, oid, "AdminTo")
        # Sessions
        for s in (c.get("Sessions") or {}).get("Results", []) or []:
            user = s.get("UserSID") or ""
            if user:
                g.add_edge(user, oid, "HasSession")
        # CanRDP
        for entry in (c.get("RemoteDesktopUsers") or {}).get("Results", []) or []:
            principal = entry.get("ObjectIdentifier") or ""
            g.add_edge(principal, oid, "CanRDP")
        for entry in (c.get("PSRemoteUsers") or {}).get("Results", []) or []:
            principal = entry.get("ObjectIdentifier") or ""
            g.add_edge(principal, oid, "CanPSRemote")
        # Aces
        for ace in c.get("Aces", []) or []:
            kind = ace.get("RightName") or ""
            principal = ace.get("PrincipalSID") or ""
            if principal and kind in ACL_EDGES:
                g.add_edge(principal, oid, kind)


def _ingest_domains(g: Graph, data: dict[str, Any]) -> None:
    for d in data.get("data", []):
        props = d.get("Properties", {}) or {}
        oid = d.get("ObjectIdentifier") or props.get("objectid") or ""
        name = props.get("name", "")
        g.add_node(oid, name, "Domain", props)
        for ace in d.get("Aces", []) or []:
            kind = ace.get("RightName") or ""
            principal = ace.get("PrincipalSID") or ""
            if principal and kind in ACL_EDGES:
                g.add_edge(principal, oid, kind)


_INGESTORS = {
    "users":     _ingest_users,
    "groups":    _ingest_groups,
    "computers": _ingest_computers,
    "domains":   _ingest_domains,
}


def _classify_file(name: str) -> str | None:
    """Map a BloodHound filename → category. SharpHound writes
    `<timestamp>_<domain>_users.json`."""
    low = name.lower()
    for k in _INGESTORS:
        if low.endswith(f"_{k}.json") or low == f"{k}.json":
            return k
    return None


# ── Upload + load ──────────────────────────────────────────────────────────

@router.post("/load")
async def load_zip(
    request: Request,
    file: UploadFile = File(...),
    confirm_auth: bool = Form(False),
) -> dict[str, Any]:
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    if not confirm_auth:
        raise HTTPException(
            403,
            "Confirm you have authorization to analyze this AD environment.",
        )
    global _graph
    data = await file.read()
    if not data:
        raise HTTPException(400, "empty upload")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "file too large (max 200 MB)")

    # Audit the ingest: loading a BloodHound dump pulls a domain's directory
    # data into the engagement's analysis surface, so it belongs in the
    # append-only action log alongside the network tools. Started here (after
    # auth + size checks); finalized completed/error below.
    audit_id = ""
    try:
        audit_id = audit_log.start(
            tool="lateral",
            target=file.filename or "bloodhound-upload",
            argv=["load", f"bytes={len(data)}"],
            engagement_id=get_engagement_id(request),
            mode=get_mode(request),
        )
    except Exception:
        logger.exception("audit_log.start failed (load continues)")

    new_graph = Graph()
    loaded: dict[str, int] = {}
    try:
        if file.filename and file.filename.lower().endswith(".json"):
            try:
                obj = json.loads(data)
            except Exception:
                logger.info("lateral load: invalid JSON upload filename=%r", file.filename)
                raise HTTPException(400, "upload is not valid JSON")
            kind = _classify_file(file.filename)
            if not kind:
                raise HTTPException(400,
                    "Could not classify JSON — filename should be like *_users.json / *_groups.json / *_computers.json / *_domains.json")
            _INGESTORS[kind](new_graph, obj)
            loaded[kind] = len(obj.get("data", []))
        else:
            # Treat as ZIP
            try:
                zf = zipfile.ZipFile(io.BytesIO(data))
            except Exception:
                logger.info("lateral load: not a valid ZIP or JSON filename=%r", file.filename)
                raise HTTPException(400, "upload is not a valid ZIP or JSON")
            for member in zf.namelist():
                if not member.endswith(".json"):
                    continue
                kind = _classify_file(member)
                if not kind:
                    continue
                try:
                    obj = json.loads(zf.read(member))
                except Exception:
                    continue
                _INGESTORS[kind](new_graph, obj)
                loaded[kind] = loaded.get(kind, 0) + len(obj.get("data", []))

        if not loaded:
            raise HTTPException(400, "no recognized BloodHound JSON files in upload")
    except Exception as e:
        if audit_id:
            detail = getattr(e, "detail", None) or f"{type(e).__name__}: {e}"
            try:
                audit_log.error(audit_id, str(detail))
            except Exception:
                logger.exception("audit_log.error failed")
        raise

    _graph = new_graph
    if audit_id:
        try:
            stats = _graph.stats()
            files_summary = ", ".join(f"{k}={v}" for k, v in loaded.items())
            audit_log.complete(
                audit_id,
                summary=f"loaded {files_summary}; {stats['nodes']} nodes, {stats['edges']} edges",
            )
        except Exception:
            logger.exception("audit_log.complete failed")
    return {"loaded_files": loaded, "stats": _graph.stats()}


@router.get("/status")
def status() -> dict[str, Any]:
    return {"loaded": len(_graph.nodes) > 0, "stats": _graph.stats()}


@router.post("/clear")
def clear(request: Request) -> dict[str, bool]:
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    global _graph
    _graph = Graph()
    return {"cleared": True}


# ── Path queries ──────────────────────────────────────────────────────────

class PathBody(BaseModel):
    # principal name (e.g. "ALICE@CORP.LOCAL") or objectid; cap stops a
    # giant input string from being hashed through name_index.
    source: str = Field(..., min_length=1, max_length=MAX_NAME_LEN)
    target: str = Field("", max_length=MAX_NAME_LEN)  # empty = "any Domain Admin"
    max_hops: int = Field(6, ge=1, le=20)
    confirm_auth: bool = False


def _resolve(g: Graph, key: str) -> str | None:
    """Look up a principal by name or objectid."""
    if key in g.nodes:
        return key
    up = key.upper()
    return g.name_index.get(up)


def _bfs(g: Graph, src: str, targets: set[str], max_hops: int) -> list[list[tuple[str, str]]]:
    """Return all shortest paths from `src` to any node in `targets`.
    Each path is a list of (node, edge_kind_that_led_to_node) — edge_kind
    is "" for the starting node."""
    if src in targets:
        return [[(src, "")]]
    # BFS by depth, recording parents
    parents: dict[str, list[tuple[str, str]]] = {src: []}
    depth = {src: 0}
    frontier = deque([src])
    found_at_depth: int | None = None
    while frontier:
        cur = frontier.popleft()
        d = depth[cur]
        if d >= max_hops:
            continue
        if found_at_depth is not None and d >= found_at_depth:
            continue
        for (dst, kind) in g.edges.get(cur, []):
            if dst in depth:
                # Same-depth alternative? Add as additional parent
                if depth[dst] == d + 1:
                    parents.setdefault(dst, []).append((cur, kind))
                continue
            depth[dst] = d + 1
            parents.setdefault(dst, []).append((cur, kind))
            if dst in targets:
                found_at_depth = d + 1
            else:
                frontier.append(dst)

    # Reconstruct one shortest path per reachable target. Walk target → src;
    # for each node, look up its first recorded parent to find both the next
    # node AND the kind of the edge that LED INTO this node.
    results: list[list[tuple[str, str]]] = []
    for t in targets:
        if t not in depth or depth[t] > max_hops:
            continue
        chain: list[str] = []
        edge_into: list[str] = []
        cur = t
        while True:
            ps = parents.get(cur, [])
            chain.append(cur)
            edge_into.append(ps[0][1] if ps else "")
            if cur == src or not ps:
                break
            cur = ps[0][0]
        if chain[-1] != src:
            continue  # broken backtrack — skip this target
        chain.reverse()
        edge_into.reverse()
        edge_into[0] = ""  # src has no incoming edge in this path
        results.append(list(zip(chain, edge_into)))
    return results


@router.post("/path")
def path(body: PathBody, request: Request) -> dict[str, Any]:
    if not body.confirm_auth:
        raise HTTPException(
            403,
            "Confirm you have authorization to analyze this AD environment.",
        )
    if not _graph.nodes:
        raise HTTPException(400, "no graph loaded — upload a BloodHound ZIP first")

    src_id = _resolve(_graph, body.source.strip())
    if not src_id:
        raise HTTPException(404, f"source not found: {body.source!r}")

    if body.target.strip():
        tgt_id = _resolve(_graph, body.target.strip())
        if not tgt_id:
            raise HTTPException(404, f"target not found: {body.target!r}")
        targets = {tgt_id}
    else:
        # Default: any Domain Admins / Enterprise Admins / Schema Admins group
        targets = set()
        for oid, n in _graph.nodes.items():
            if n["kind"] == "Group" and n["name"].upper() in (
                "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS",
            ):
                targets.add(oid)
            # Also accept fully qualified
            up = n["name"].upper()
            if "@" in up and up.split("@")[0] in (
                "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS",
            ):
                targets.add(oid)

    if not targets:
        raise HTTPException(404, "no targets found (no Domain Admins-like groups in graph)")

    # Audit the path query — once source + targets resolve, this is a real
    # analysis action against the loaded directory data. Started here (after
    # resolution so unresolved-source/target 404s stay out of the log) and
    # finalized either side of the BFS.
    src_name = _graph.nodes[src_id].get("name") or src_id
    audit_id = ""
    try:
        audit_id = audit_log.start(
            tool="lateral",
            target=src_name,
            argv=["path", f"source={src_name}",
                  f"target={body.target.strip() or 'domain-admins'}",
                  f"max_hops={body.max_hops}"],
            engagement_id=get_engagement_id(request),
            mode=get_mode(request),
        )
    except Exception:
        logger.exception("audit_log.start failed (path continues)")

    try:
        paths = _bfs(_graph, src_id, targets, body.max_hops)
    except Exception as e:
        if audit_id:
            try:
                audit_log.error(audit_id, f"{type(e).__name__}: {e}")
            except Exception:
                logger.exception("audit_log.error failed")
        raise

    if audit_id:
        try:
            audit_log.complete(
                audit_id,
                summary=f"{len(paths)} path(s) to {len(targets)} target(s)",
            )
        except Exception:
            logger.exception("audit_log.complete failed")

    return {
        "source": {"id": src_id, **_graph.nodes[src_id]},
        "targets": [{"id": t, **_graph.nodes[t]} for t in targets],
        "paths": [
            [{"id": node, **_graph.nodes.get(node, {"name": "?", "kind": "?"}),
              "edge": edge}
             for node, edge in p]
            for p in paths
        ],
    }


# ── Technique reference ───────────────────────────────────────────────────

@router.get("/techniques")
def techniques() -> dict[str, Any]:
    """Static reference of how to actually exploit each edge type once you find it."""
    return {"techniques": _TECHNIQUES}


_TECHNIQUES = [
    {"edge": "MemberOf",
     "name": "Transitive group membership",
     "summary": "If A is in group B and B is in group C, A inherits C's permissions."},
    {"edge": "AdminTo",
     "name": "Local admin on a computer",
     "summary": "Use psexec/wmiexec/atexec/smbexec to land a shell as SYSTEM.",
     "cmd": "psexec.py corp.local/{user}:{pass}@{host}"},
    {"edge": "HasSession",
     "name": "User has a session on a host",
     "summary": "Compromise that host → dump LSASS → steal the user's TGT or hash.",
     "cmd": "mimikatz: sekurlsa::logonpasswords"},
    {"edge": "ForceChangePassword",
     "name": "Can reset the target's password",
     "summary": "Reset the password, log in as them. Disruptive — owner will notice.",
     "cmd": 'net rpc password "<user>" "<NewPass!>" -U domain/me%mypass -S DC'},
    {"edge": "GenericAll",
     "name": "Full control",
     "summary": "Equivalent to owning the object. Can change password, add SPN, modify attributes."},
    {"edge": "GenericWrite",
     "name": "Can modify most attributes",
     "summary": "Set a fake SPN → Kerberoast; or add the principal to a privileged group."},
    {"edge": "WriteDacl",
     "name": "Can modify the object's DACL",
     "summary": "Grant yourself GenericAll, then proceed as above."},
    {"edge": "WriteOwner",
     "name": "Can take ownership",
     "summary": "Take ownership → grant yourself rights → exploit GenericAll."},
    {"edge": "AddMember",
     "name": "Can add members to the target group",
     "summary": "Add yourself (or a controlled account) to Domain Admins.",
     "cmd": "net group \"Domain Admins\" attacker /add /domain"},
    {"edge": "AddSelf",
     "name": "Can add SELF to the target group",
     "summary": "Same as AddMember but limited to the principal that owns the edge."},
    {"edge": "ReadLAPSPassword",
     "name": "Can read the local admin password (LAPS)",
     "summary": "Query ms-Mcs-AdmPwd via LDAP; log in as local admin on the target."},
    {"edge": "ReadGMSAPassword",
     "name": "Can read gMSA password",
     "summary": "Use gMSAdumper / Get-ADServiceAccount to recover the password from MSDS-ManagedPassword."},
    {"edge": "GetChanges",
     "name": "DCSync partial (with GetChangesAll = full)",
     "summary": "Combined with GetChangesAll: replicate every secret from the DC.",
     "cmd": "secretsdump.py -just-dc corp.local/me@DC"},
    {"edge": "GetChangesAll",
     "name": "DCSync — pull every secret from the DC",
     "summary": "Full domain compromise. With GetChanges granted on the domain object you can DCSync.",
     "cmd": "secretsdump.py -just-dc corp.local/me@DC"},
    {"edge": "CanRDP",
     "name": "Can RDP into the computer",
     "summary": "xfreerdp / mstsc with the user's creds → land on the desktop, escalate from there."},
    {"edge": "CanPSRemote",
     "name": "Can PSRemote (WinRM) into the computer",
     "summary": "Enter-PSSession or evil-winrm — gets a powershell on the target."},
]
