"""Capability enablement API — the control surface for the server-side gate.

`GET /capabilities` reports every gated group and whether it's on; `POST
/capabilities/{group}` flips one (audit-logged). The intrusive/privileged
routers refuse calls until their group is enabled here — see `lib.capability`.

Gated by the same loopback + token guards as every other privileged route
(applied in `main.py`), so only the local app can change enablement.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from lib import audit_log, capability

router = APIRouter(prefix="/capabilities", tags=["capabilities"])


class CapabilityState(BaseModel):
    group: str
    enabled: bool
    routers: list[str]


class ToggleBody(BaseModel):
    enabled: bool


def _state(group: str) -> CapabilityState:
    return CapabilityState(
        group=group,
        enabled=capability.is_enabled(group),
        routers=list(capability.GROUP_ROUTERS[group]),
    )


@router.get("", response_model=list[CapabilityState])
def list_capabilities() -> list[CapabilityState]:
    return [_state(g) for g in capability.ALL_GROUPS]


@router.post("/{group}", response_model=CapabilityState)
def set_capability(group: str, body: ToggleBody, request: Request) -> CapabilityState:
    if group not in capability.GROUP_ROUTERS:
        raise HTTPException(status_code=404, detail=f"unknown capability group '{group}'")
    with audit_log.action(
        tool="capability",
        target=group,
        argv=["capability", "enable" if body.enabled else "disable", group],
    ) as act:
        capability.set_enabled(group, body.enabled)
        act.summary = f"{group} {'enabled' if body.enabled else 'disabled'}"
    return _state(group)
