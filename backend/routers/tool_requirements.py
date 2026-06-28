"""HTTP surface for the tool-requirements registry."""

from fastapi import APIRouter, Depends

from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError
from lib.tool_requirements import (
    check_readiness,
    get_requirement,
    list_requirements,
)

router = APIRouter(tags=["tool-requirements"],
                   dependencies=[Depends(require_local_auth)])


@router.get("/tools/requirements")
def get_all() -> dict[str, object]:
    return {"tools": list_requirements()}


@router.get("/tools/requirements/{tool_id}")
def get_one(tool_id: str) -> dict[str, object]:
    req = get_requirement(tool_id)
    if req is None:
        raise MhpError(f"no requirement entry for tool {tool_id!r}",
                       code=ErrorCode.NOT_FOUND, status_code=404)
    return req.model_dump()


@router.get("/tools/requirements/{tool_id}/check")
def get_check(tool_id: str) -> dict[str, object]:
    req = get_requirement(tool_id)
    if req is None:
        raise MhpError(f"no requirement entry for tool {tool_id!r}",
                       code=ErrorCode.NOT_FOUND, status_code=404)
    return check_readiness(req)
