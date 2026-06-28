"""AWS Recon — read-only audit using the default boto3 credential chain.

Credential discovery (in order): env vars, `~/.aws/credentials`, EC2 IMDS role.
The user does normal `aws configure` setup outside the app — we never ask
for keys in-UI. boto3's docs are at https://boto3.amazonaws.com/v1/documentation/.

Each check is best-effort: a permission failure on one service shouldn't block
the rest. We catch boto3's ClientError per call and report it as a per-service
error string.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Request

from lib import scope
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/aws", tags=["aws-recon"])

# Severity buckets follow the engagement model
SEV_INFO = "info"
SEV_LOW = "low"
SEV_MEDIUM = "medium"
SEV_HIGH = "high"
SEV_CRITICAL = "critical"


def _import_boto():
    """Lazy-import so the app boots even when boto3 isn't available."""
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError
        return boto3, ClientError, NoCredentialsError, BotoCoreError
    except ImportError as e:
        raise MhpError(
            "boto3 is not available in this build. "
            "Run `pip install boto3` if developing locally.",
            code=ErrorCode.TOOL_MISSING,
            status_code=503,
            extra={"import_error": str(e)},
        )


@router.get("/status")
def status() -> dict[str, Any]:
    """Quick health check + caller-identity probe — useful before kicking off
    a full recon so the user can see which account they're about to audit."""
    boto3, ClientError, NoCredentialsError, _ = _import_boto()
    try:
        sts = boto3.client("sts")
        ident = sts.get_caller_identity()
        return {
            "ok": True,
            "account": ident.get("Account"),
            "user_arn": ident.get("Arn"),
            "user_id": ident.get("UserId"),
        }
    except NoCredentialsError:
        return {"ok": False, "error": "no credentials found (try `aws configure`)"}
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "ClientError")
        logger.info("aws status check failed: %s", e)
        return {"ok": False, "error": f"AWS API {code}", "code": code}


def _add_finding(out: list[dict[str, Any]], severity: str, service: str,
                 title: str, detail: str, evidence: Any = None) -> None:
    out.append({
        "severity": severity, "service": service,
        "title": title, "detail": detail,
        "evidence": evidence,
    })


def _check_iam(boto3, ClientError) -> dict[str, Any]:
    import datetime
    iam = boto3.client("iam")
    findings: list[dict[str, Any]] = []
    summary: dict[str, Any] = {"users": 0, "roles": 0, "policies": 0}
    try:
        paginator = iam.get_paginator("list_users")
        users: list[dict[str, Any]] = []
        for page in paginator.paginate():
            for u in page["Users"]:
                # Last activity (PasswordLastUsed)
                pwd_last = u.get("PasswordLastUsed")
                age_days = None
                if pwd_last:
                    age_days = (datetime.datetime.now(datetime.timezone.utc) - pwd_last).days
                # Access keys
                ak = iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]
                keys = []
                for k in ak:
                    k_age = (datetime.datetime.now(datetime.timezone.utc) - k["CreateDate"]).days
                    keys.append({
                        "id": k["AccessKeyId"], "status": k["Status"],
                        "age_days": k_age,
                    })
                    if k["Status"] == "Active" and k_age > 90:
                        _add_finding(findings, SEV_MEDIUM, "IAM",
                                     f"Active access key {k_age}d old",
                                     f"User {u['UserName']!r} has active access key "
                                     f"{k['AccessKeyId']} created {k_age} days ago "
                                     "(AWS guidance: rotate every 90 days).",
                                     evidence=k)
                # MFA
                mfa = iam.list_mfa_devices(UserName=u["UserName"])["MFADevices"]
                if pwd_last and not mfa:
                    _add_finding(findings, SEV_MEDIUM, "IAM",
                                 "Console user without MFA",
                                 f"User {u['UserName']!r} has console access "
                                 "but no MFA device.",
                                 evidence={"user": u["UserName"]})
                users.append({
                    "name": u["UserName"], "arn": u["Arn"],
                    "password_age_days": age_days, "keys": keys, "mfa": len(mfa) > 0,
                })
        summary["users"] = len(users)
        # Roles with admin policies
        roles_with_admin: list[str] = []
        for page in iam.get_paginator("list_roles").paginate():
            for r in page["Roles"]:
                summary["roles"] += 1
                attached = iam.list_attached_role_policies(RoleName=r["RoleName"])
                for p in attached["AttachedPolicies"]:
                    if "Administrator" in p["PolicyName"] or p["PolicyArn"].endswith("/AdministratorAccess"):
                        roles_with_admin.append(r["RoleName"])
                        _add_finding(findings, SEV_HIGH, "IAM",
                                     f"Role with AdministratorAccess: {r['RoleName']}",
                                     f"Role {r['RoleName']!r} has policy "
                                     f"{p['PolicyName']!r} attached.",
                                     evidence={"role": r["RoleName"], "policy": p})
        return {"findings": findings, "summary": summary, "users_sample": users[:50]}
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "ClientError")
        logger.info("aws check failed: %s", e)
        return {"error": f"AWS API {code}", "code": code, "findings": findings}


def _check_s3(boto3, ClientError) -> dict[str, Any]:
    s3 = boto3.client("s3")
    findings: list[dict[str, Any]] = []
    try:
        resp = s3.list_buckets()
        buckets: list[dict[str, Any]] = []
        for b in resp.get("Buckets", []):
            name = b["Name"]
            entry: dict[str, Any] = {"name": name, "public": False, "errors": []}
            # PublicAccessBlock
            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                entry["public_access_block"] = pab
                # All four flags should be True for safety
                if not all(pab.values()):
                    _add_finding(findings, SEV_HIGH, "S3",
                                 f"Bucket {name}: incomplete public-access block",
                                 f"Bucket {name!r} has at least one PublicAccessBlock "
                                 "flag disabled — public exposure possible.",
                                 evidence={"bucket": name, "pab": pab})
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code == "NoSuchPublicAccessBlockConfiguration":
                    _add_finding(findings, SEV_HIGH, "S3",
                                 f"Bucket {name}: no PublicAccessBlock configured",
                                 f"Bucket {name!r} has no PublicAccessBlock — "
                                 "ACLs/policies alone gate access.",
                                 evidence={"bucket": name})
                else:
                    entry["errors"].append(f"PAB: {code}")
            # ACL grants
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")
                    if "AllUsers" in uri:
                        entry["public"] = True
                        _add_finding(findings, SEV_CRITICAL, "S3",
                                     f"Bucket {name}: ACL grants AllUsers",
                                     f"Bucket {name!r} has an ACL grant to AllUsers "
                                     f"({grant['Permission']}) — public.",
                                     evidence={"bucket": name, "grant": grant})
                    elif "AuthenticatedUsers" in uri:
                        _add_finding(findings, SEV_HIGH, "S3",
                                     f"Bucket {name}: ACL grants AuthenticatedUsers",
                                     f"Bucket {name!r} grants {grant['Permission']} "
                                     "to any AWS-authenticated user.",
                                     evidence={"bucket": name, "grant": grant})
            except ClientError as e:
                entry["errors"].append(f"ACL: {e.response.get('Error', {}).get('Code', '')}")
            buckets.append(entry)
        return {"findings": findings, "summary": {"buckets": len(buckets)},
                "buckets": buckets}
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "ClientError")
        logger.info("aws check failed: %s", e)
        return {"error": f"AWS API {code}", "code": code, "findings": findings}


def _check_ec2(boto3, ClientError) -> dict[str, Any]:
    ec2 = boto3.client("ec2")
    findings: list[dict[str, Any]] = []
    try:
        instances: list[dict[str, Any]] = []
        for page in ec2.get_paginator("describe_instances").paginate():
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    if inst["State"]["Name"] != "running":
                        continue
                    entry = {
                        "id": inst["InstanceId"],
                        "type": inst["InstanceType"],
                        "public_ip": inst.get("PublicIpAddress"),
                        "private_ip": inst.get("PrivateIpAddress"),
                        "az": inst.get("Placement", {}).get("AvailabilityZone"),
                    }
                    if entry["public_ip"]:
                        _add_finding(findings, SEV_MEDIUM, "EC2",
                                     f"EC2 with public IP: {inst['InstanceId']}",
                                     f"Instance {inst['InstanceId']!r} has public IP "
                                     f"{entry['public_ip']} — confirm intent.",
                                     evidence=entry)
                    instances.append(entry)
        # Security groups with open ingress
        sgs = []
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page["SecurityGroups"]:
                open_rules = []
                for rule in sg.get("IpPermissions", []):
                    for ip in rule.get("IpRanges", []):
                        if ip.get("CidrIp") == "0.0.0.0/0":
                            open_rules.append({
                                "proto": rule.get("IpProtocol"),
                                "from_port": rule.get("FromPort"),
                                "to_port": rule.get("ToPort"),
                            })
                if open_rules:
                    _add_finding(findings, SEV_HIGH, "EC2",
                                 f"SG {sg['GroupName']}: open 0.0.0.0/0 ingress",
                                 f"Security group {sg['GroupName']!r} "
                                 f"({sg['GroupId']}) has {len(open_rules)} open ingress "
                                 "rule(s).",
                                 evidence={"sg_id": sg["GroupId"],
                                           "name": sg["GroupName"],
                                           "rules": open_rules})
                sgs.append({"id": sg["GroupId"], "name": sg["GroupName"],
                            "open_rules": open_rules})
        return {"findings": findings,
                "summary": {"instances_running": len(instances), "sgs": len(sgs)},
                "instances": instances[:100], "sgs": sgs[:100]}
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "ClientError")
        logger.info("aws check failed: %s", e)
        return {"error": f"AWS API {code}", "code": code, "findings": findings}


def _check_lambda(boto3, ClientError) -> dict[str, Any]:
    lam = boto3.client("lambda")
    findings: list[dict[str, Any]] = []
    SECRET_HINTS = ("PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL", "PRIVATE")
    try:
        funcs: list[dict[str, Any]] = []
        for page in lam.get_paginator("list_functions").paginate():
            for f in page["Functions"]:
                env = (f.get("Environment") or {}).get("Variables", {})
                suspicious = []
                for k in env:
                    if any(h in k.upper() for h in SECRET_HINTS):
                        suspicious.append(k)
                if suspicious:
                    _add_finding(findings, SEV_HIGH, "Lambda",
                                 f"Lambda {f['FunctionName']}: secrets in env vars",
                                 f"Function {f['FunctionName']!r} has env keys that look "
                                 "like secrets: " + ", ".join(suspicious),
                                 evidence={"function": f["FunctionName"], "keys": suspicious})
                funcs.append({"name": f["FunctionName"], "runtime": f["Runtime"],
                              "env_keys": list(env.keys())})
        return {"findings": findings, "summary": {"functions": len(funcs)},
                "functions": funcs[:100]}
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "ClientError")
        logger.info("aws check failed: %s", e)
        return {"error": f"AWS API {code}", "code": code, "findings": findings}


def _check_rds(boto3, ClientError) -> dict[str, Any]:
    rds = boto3.client("rds")
    findings: list[dict[str, Any]] = []
    try:
        dbs: list[dict[str, Any]] = []
        for page in rds.get_paginator("describe_db_instances").paginate():
            for db in page["DBInstances"]:
                entry = {
                    "id": db["DBInstanceIdentifier"],
                    "engine": db.get("Engine"),
                    "public": db.get("PubliclyAccessible", False),
                    "endpoint": (db.get("Endpoint") or {}).get("Address"),
                }
                if entry["public"]:
                    _add_finding(findings, SEV_HIGH, "RDS",
                                 f"RDS {db['DBInstanceIdentifier']}: publicly accessible",
                                 f"DB instance {db['DBInstanceIdentifier']!r} "
                                 f"({db.get('Engine')}) has PubliclyAccessible=true.",
                                 evidence=entry)
                dbs.append(entry)
        return {"findings": findings, "summary": {"dbs": len(dbs)}, "dbs": dbs[:50]}
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "ClientError")
        logger.info("aws check failed: %s", e)
        return {"error": f"AWS API {code}", "code": code, "findings": findings}


@router.get("/recon")
def recon(request: Request, services: str = "iam,s3,ec2,lambda,rds") -> dict[str, Any]:
    # Cloud recon's "target" is the AWS account fetched via STS mid-handler.
    # Require an active engagement under Engagement mode so the action ties
    # to a record; per-account scope matching would need a follow-up edit
    # after STS returns the account id.
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    boto3, ClientError, NoCredentialsError, BotoCoreError = _import_boto()
    # Confirm we have credentials before issuing the per-service calls
    try:
        ident = boto3.client("sts").get_caller_identity()
    except (NoCredentialsError, ClientError, BotoCoreError) as e:
        logger.info("aws recon credentials unusable: %s", e)
        raise MhpError(
            "AWS credentials not usable (run `aws configure` or check env vars)",
            code=ErrorCode.UNAUTHORIZED,
            status_code=401,
        )

    picked = {s.strip() for s in services.split(",") if s.strip()}
    out: dict[str, Any] = {
        "account": ident.get("Account"),
        "user_arn": ident.get("Arn"),
        "services": {},
        "findings": [],
    }
    runners = {
        "iam":    lambda: _check_iam(boto3, ClientError),
        "s3":     lambda: _check_s3(boto3, ClientError),
        "ec2":    lambda: _check_ec2(boto3, ClientError),
        "lambda": lambda: _check_lambda(boto3, ClientError),
        "rds":    lambda: _check_rds(boto3, ClientError),
    }
    for name, fn in runners.items():
        if name not in picked:
            continue
        res = fn()
        out["services"][name] = res
        out["findings"].extend(res.get("findings", []))
    # Sort by severity
    order = {SEV_CRITICAL: 0, SEV_HIGH: 1, SEV_MEDIUM: 2, SEV_LOW: 3, SEV_INFO: 4}
    out["findings"].sort(key=lambda f: order.get(f["severity"], 99))
    return out
