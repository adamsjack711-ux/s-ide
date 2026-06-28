"""Active Directory authentication helpers shared by every AD router.

Auth surface area we support:

  - **Anonymous LDAP bind** — useful against poorly-secured domains (rare in
    modern AD).
  - **Simple LDAP bind** — username/password.
  - **NTLM LDAP bind** — DOMAIN\\username + password (most common AD path).
  - **Pass-the-Hash** for SMB and Kerberos — supply LM:NT hash instead of
    password. NT-only is also accepted (LM is set to the empty hash).

Every endpoint receives a `CredsModel` Pydantic object; helpers in this
module turn it into a working ldap3.Connection or impacket SMBConnection.

We deliberately don't accept Kerberos tickets (`.ccache`) at the moment —
adding it is feasible (impacket's `gssapi` flow) but the AD tools are useful
without it.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

BindMethod = Literal["simple", "ntlm", "anonymous"]


class CredsModel(BaseModel):
    """Authentication bundle accepted by every AD endpoint."""
    dc_host:  str  = Field(..., description="DC hostname or IP")
    domain:   str  = Field("", description="DNS domain (e.g. corp.local). "
                                            "Required for NTLM, optional for simple.")
    username: str  = Field("", description="sAMAccountName (no domain prefix). "
                                            "Empty = anonymous.")
    password: str  = Field("", description="Password OR empty (use nt_hash).")
    nt_hash:  str  = Field("", description="NT hash (32 hex chars) — for pass-the-hash. "
                                            "If set, password is ignored.")
    bind:     BindMethod = Field("ntlm")
    use_ssl:  bool = Field(False, description="LDAPS (port 636) instead of LDAP (389).")
    use_tls:  bool = Field(False, description="StartTLS on the LDAP connection.")


def _ldap_user_string(c: CredsModel) -> str:
    """Format the `user` string ldap3 expects, based on bind type."""
    if c.bind == "ntlm":
        # ldap3 NTLM wants `DOMAIN\user`
        dom = c.domain.split(".")[0] if c.domain else ""
        return f"{dom}\\{c.username}" if dom else c.username
    if c.bind == "simple":
        # Bind DN; we let the caller pass a UPN if they want, otherwise build one
        if c.username and "@" not in c.username and c.domain:
            return f"{c.username}@{c.domain}"
        return c.username
    return ""  # anonymous


def open_ldap(c: CredsModel):
    """Open and bind an ldap3.Connection. Raises on failure.

    Returns the bound Connection — the caller is responsible for `.unbind()`.
    """
    from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, ANONYMOUS

    server = Server(
        c.dc_host,
        use_ssl=c.use_ssl,
        get_info=ALL,
    )

    if c.bind == "anonymous":
        conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)
        return conn

    auth = NTLM if c.bind == "ntlm" else SIMPLE
    user = _ldap_user_string(c)
    password = c.password
    if c.nt_hash and c.bind == "ntlm":
        # ldap3 supports `aad3b435b51404eeaad3b435b51404ee:<NThash>` for PtH
        lm_blank = "aad3b435b51404eeaad3b435b51404ee"
        password = f"{lm_blank}:{c.nt_hash.lower()}"

    conn = Connection(
        server, user=user, password=password,
        authentication=auth, auto_bind=False,
    )
    if c.use_tls and not c.use_ssl:
        conn.start_tls()
    conn.bind()
    if not conn.bound:
        raise RuntimeError(
            f"LDAP bind failed: {conn.result.get('description')}: "
            f"{conn.result.get('message', '')}"
        )
    return conn


def open_smb(c: CredsModel, target: str = ""):
    """Open an impacket SMBConnection (SMB2/3) bound to `c`.

    `target` defaults to `c.dc_host` but can be overridden for non-DC hosts.
    Caller is responsible for `.close()`.
    """
    from impacket.smbconnection import SMBConnection

    host = target or c.dc_host
    conn = SMBConnection(host, host)
    if c.username:
        lm = ""
        nt = ""
        if c.nt_hash:
            nt = c.nt_hash.lower()
        conn.login(
            c.username, c.password if not c.nt_hash else "",
            c.domain, lm, nt,
        )
    else:
        # Null session
        conn.login("", "")
    return conn


def domain_to_base_dn(domain: str) -> str:
    """corp.local -> DC=corp,DC=local"""
    if not domain:
        return ""
    return ",".join(f"DC={p}" for p in domain.split("."))


# UAC bit constants we care about for findings
UAC_SCRIPT                 = 0x0001
UAC_ACCOUNTDISABLE         = 0x0002
UAC_PASSWD_NOTREQD         = 0x0020
UAC_PASSWD_CANT_CHANGE     = 0x0040
UAC_NORMAL_ACCOUNT         = 0x0200
UAC_DONT_EXPIRE_PASSWORD   = 0x10000
UAC_DONT_REQUIRE_PREAUTH   = 0x400000
UAC_TRUSTED_FOR_DELEGATION = 0x80000


def decode_uac(uac: int) -> list[str]:
    flags: list[dict[int, str]] = [
        {UAC_ACCOUNTDISABLE: "DISABLED"},
        {UAC_PASSWD_NOTREQD: "PASSWD_NOTREQD"},
        {UAC_DONT_EXPIRE_PASSWORD: "DONT_EXPIRE_PASSWORD"},
        {UAC_DONT_REQUIRE_PREAUTH: "DONT_REQUIRE_PREAUTH"},
        {UAC_TRUSTED_FOR_DELEGATION: "TRUSTED_FOR_DELEGATION"},
    ]
    out = []
    for d in flags:
        for bit, name in d.items():
            if uac & bit:
                out.append(name)
    return out
