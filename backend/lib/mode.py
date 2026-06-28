"""Lab vs Engagement mode.

Mode is derived from whether the request carries an engagement_id, NOT
from a caller-controlled header. The legacy `X-MHP-Mode` header and
`?mode=` query param are ignored — they were trivially spoofable, which
let any caller send `mode=lab` to short-circuit `scope.check_combined`
and run off-scope scans against arbitrary targets.

The mapping is:

  * engagement_id supplied → mode = "engagement", scope is enforced
    against that engagement's allow/deny lists
  * engagement_id absent   → mode = "lab", scope check short-circuits

To run an exploratory off-scope call, the operator must explicitly
clear their active engagement in the renderer (which makes the
frontend stop sending `X-MHP-Engagement-Id`). Switching mode by
flipping a header is no longer possible.

`scope.check_combined` accepts the resolved mode and uses it to decide
whether to enforce engagement scope or short-circuit. See
`backend/lib/scope.py` for the resulting verdict matrix.
"""
from __future__ import annotations

from typing import Literal

from starlette.requests import HTTPConnection

Mode = Literal["lab", "engagement"]


def get_engagement_id(conn: HTTPConnection) -> str | None:
    """Resolve the active engagement id for one request/WS.

    Precedence:
      1. ``X-MHP-Engagement-Id`` header
      2. ``?engagement_id=`` query param
      3. ``None``

    Used by REST endpoints to avoid threading `engagement_id` through every
    request body. WS endpoints generally read it from the handshake init
    message instead, since that's already where per-scan options live.
    """
    raw = (
        conn.headers.get("X-MHP-Engagement-Id")
        or conn.query_params.get("engagement_id")
        or ""
    ).strip()
    return raw or None


def get_mode(conn: HTTPConnection) -> Mode:
    """Resolve the mode for one request/WS.

    Engagement mode iff an engagement_id is supplied. Lab otherwise.
    """
    return "engagement" if get_engagement_id(conn) else "lab"
