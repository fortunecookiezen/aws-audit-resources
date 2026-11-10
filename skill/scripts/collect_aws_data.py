#!/usr/bin/env python3
"""
collect_aws_data.py — gather AWS account configuration data for the aws-audit skill.

Collects data for the six core audit areas (IAM, MFA, S3, CloudTrail/logging,
Security Groups/VPC, root account), plus detection and monitoring services
(GuardDuty, Security Hub, Inspector, IAM Access Analyzer, AWS Config,
CloudWatch Logs), databases (RDS, DynamoDB, ElastiCache), encryption and
secrets (KMS, Secrets Manager, EBS, SNS topic policies) and ECR, via boto3,
and writes a single JSON snapshot that scripts/run_checks.py can evaluate
against a chosen compliance framework. Regional services are collected from
the same regions as EC2/VPC (--regions or --all-regions).

Usage:
    # From the skill/ directory, in a virtual environment (never the system Python):
    python3 -m venv .venv && source .venv/bin/activate
    # Python >= 3.10. On macOS, /usr/bin/python3 is 3.9: use /opt/homebrew/bin/python3 -m venv .venv
    pip install -r requirements.txt

    # Using credentials already in the environment / a named profile:
    python3 collect_aws_data.py --all-regions -o snapshot.json
    python3 collect_aws_data.py --profile my-profile --regions us-east-1,us-west-2 -o snapshot.json

    # Having this script assume a cross-account role itself, instead of
    # pre-exporting AWS_ACCESS_KEY_ID/SECRET/SESSION_TOKEN into the shell
    # (see the repo's cloudformation/security-audit-role.yml /
    # terraform/security-audit-role/ for how that role is deployed):
    python3 collect_aws_data.py --all-regions \\
        --role-arn arn:aws:iam::123456789012:role/opspath-CrossAccountSecurityAuditRole \\
        --role-session-name jdoe-20261013 \\
        -o snapshot.json

Output schema (top level):
    {
      "collected_at": "<ISO8601 UTC timestamp>",
      "tool_version": "<git describe of the tool checkout, e.g. v0.1.0>",
      "account_id": "<12-digit account id, from sts:GetCallerIdentity>",
      "caller_arn": "<arn of the identity that ran the collection>",
      "regions": ["us-east-1", ...],
      "iam": { ... },
      "s3": { ... },
      "cloudtrail": { ... },
      "ec2": { ... },
      "account_contacts": { ... },
      "organization": { ... },
      "guardduty": {"regions": [{"region", "detectors": [{"detector_id", "status"}]}]},
      "securityhub": {"regions": [{"region", "enabled", "standards": [...]}]},
      "inspector": {"regions": [{"region", "account_status", "ec2", "ecr", "lambda"}]},
      "access_analyzer": {"regions": [{"region", "analyzers": [{"name", "type", "status"}]}]},
      "config": {"regions": [{"region", "recorders": [{"name", "all_supported", "recording", ...}]}]},
      "logs": {"log_groups": [{"region", "name", "retention_in_days", "kms_key_id"}]},
      "rds": {"instances": [...], "clusters": [...], "snapshots": [...]},
      "kms": {"keys": [{"region", "key_id", "aliases", "rotation_supported", "rotation_enabled", "public_policy", ...}]},
      "secretsmanager": {"secrets": [{"region", "name", "rotation_enabled", "public_policy", ...}]},
      "dynamodb": {"tables": [{"region", "name", "pitr_status"}]},
      "elasticache": {"replication_groups": [...], "clusters": [...]},
      "ebs": {"regions": [{"region", "encryption_by_default", "public_snapshot_ids", ...}], "volumes": [...]},
      "ecr": {"registries": [{"region", "scan_type", "rules"}], "repositories": [...]},
      "sns": {"topics": [{"region", "name", "kms_master_key_id", "public_policy"}]},
      "collection_errors": [
        {"section": "ec2", "call": "describe_vpcs(us-east-1)",
         "operation": "describe_vpcs", "region": "us-east-1",
         "error_code": "UnauthorizedOperation", "message": "..."}, ...
      ]
    }

Any section can be missing or partial (e.g. if the caller lacks a permission,
or a user hand-builds a subset of this schema from exported files) — run_checks.py
marks checks that need missing data as "skipped" rather than failing them.

A call that fails during collection leaves an empty value in its place (an
empty VPC list, no bucket logging), which looks the same as an account with
nothing there. collection_errors records every such failure, so run_checks.py
can mark the checks that depend on it as incomplete and diff_findings.py won't
count their missing resources as fixed. An empty list means every call
succeeded; a snapshot without the key predates this and can't say either way.
Error codes that mean "not configured" (no password policy, no bucket policy,
no public access block, no security contact) are the answer, not a failure,
and aren't recorded. A per-resource value that couldn't be read is stored as
unknown, not as a guess: a trail's s3_bucket_access_logging_enabled is null,
and a bucket lists the fields it couldn't read in "unreadable" (e.g.
["logging_enabled"]), so the checks leave that resource out instead of
failing or passing it.
"""

import argparse
import csv
import io
import json
import re
import sys
import time
from datetime import datetime, timezone

from tool_version import tool_version, version_problem

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:
    print("boto3 is required: activate a venv and run pip install -r requirements.txt (from the skill/ directory)", file=sys.stderr)
    sys.exit(1)


ADMIN_PORTS = [(22, 22), (3389, 3389)]


def utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


def get_session(args):
    """Build a boto3 Session, optionally assuming a cross-account role first."""
    base_kwargs = {}
    if args.profile:
        base_kwargs["profile_name"] = args.profile

    if not args.role_arn:
        return boto3.Session(**base_kwargs)

    base_session = boto3.Session(**base_kwargs)
    sts = base_session.client("sts")
    try:
        resp = sts.assume_role(
            RoleArn=args.role_arn,
            RoleSessionName=args.role_session_name,
        )
    except ClientError as e:
        print(f"Failed to assume role {args.role_arn}: {e}", file=sys.stderr)
        sys.exit(1)

    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def get_caller_identity(session):
    """Verify credentials and get account id up front (sts:GetCallerIdentity)."""
    sts = session.client("sts")
    try:
        ident = sts.get_caller_identity()
        return ident.get("Account"), ident.get("Arn")
    except ClientError as e:
        print(f"sts:GetCallerIdentity failed — check credentials/role: {e}", file=sys.stderr)
        sys.exit(1)


def get_regions(session, args):
    if args.regions:
        return [r.strip() for r in args.regions.split(",") if r.strip()]
    if args.all_regions:
        ec2 = session.client("ec2", region_name="us-east-1")
        resp = ec2.describe_regions(AllRegions=False)
        return sorted(r["RegionName"] for r in resp["Regions"])
    # default: caller's configured region, or us-east-1 if unset
    return [session.region_name or "us-east-1"]


# Every failed call, written to the snapshot as collection_errors, tagged
# with the snapshot section being collected when it failed.
COLLECTION_ERRORS = []
CURRENT_SECTION = None

# _try's default for `failed`: return `default` on a failed call too.
_SAME = object()

# Error codes that mean "this isn't configured," not "the call failed": the
# default value is the real answer, so they aren't collection errors.
NOT_CONFIGURED = {
    "get_account_password_policy": {"NoSuchEntity"},
    "get_public_access_block": {"NoSuchPublicAccessBlockConfiguration"},
    "get_bucket_policy": {"NoSuchBucketPolicy"},
    "get_alternate_contact": {"ResourceNotFoundException"},
    # Security Hub not enabled in the region.
    "describe_hub": {"InvalidAccessException"},
    "get_repository_policy": {"RepositoryPolicyNotFoundException"},
}

# Condition keys that tie a Principal:"*" statement to specific accounts,
# organizations, sources or networks. A statement carrying any of them isn't
# treated as public (CIS 2.21's "unrestricted access").
RESTRICTING_CONDITION_KEYS = {
    "aws:sourceaccount", "aws:sourcearn", "aws:sourceowner",
    "aws:principalorgid", "aws:principalorgpaths", "aws:principalaccount", "aws:principalarn",
    "aws:sourcevpc", "aws:sourcevpce", "aws:sourceip",
    "kms:calleraccount",
}


def _operation(label):
    """API operation name from a call label: "describe_vpcs(us-east-1)" ->
    "describe_vpcs", "s3control.get_public_access_block" ->
    "get_public_access_block"."""
    return re.split(r"[(\s]", label, maxsplit=1)[0].rsplit(".", 1)[-1]


def _record_error(label, code, message, region=None):
    COLLECTION_ERRORS.append({
        "section": CURRENT_SECTION,
        "call": label,
        "operation": _operation(label),
        "region": region,
        "error_code": code,
        "message": message,
    })
    print(f"  [warn] {label}: {code}", file=sys.stderr)


def _try(fn, default=None, label="", region=None, failed=_SAME):
    """fn() or, on error, `default`. A "not configured" error code returns
    `default` as the real answer; any other failure is recorded and returns
    `failed` - pass it when `default` would read as a real value (an empty
    logging config meaning "logging off")."""
    if failed is _SAME:
        failed = default
    try:
        return fn()
    except ClientError as e:
        error = e.response.get("Error", {})
        code = error.get("Code", "Unknown")
        if code in NOT_CONFIGURED.get(_operation(label), ()):
            return default
        _record_error(label, code, error.get("Message", str(e)), region)
        return failed
    except BotoCoreError as e:
        # Endpoint, connection and credential failures: before this, one
        # unreachable region ended the whole run.
        _record_error(label, type(e).__name__, str(e), region)
        return failed


def _paginate(client, operation, key, **kwargs):
    """All items under `key` across every page of a paginated API call. A
    single un-paginated call silently truncates (list_policies returns at
    most 100 items per page by default)."""
    items = []
    for page in client.get_paginator(operation).paginate(**kwargs):
        items.extend(page.get(key, []))
    return items


def _is_admin_wildcard(doc):
    """True if a policy document has an Allow statement with Action "*" and
    Resource "*" - full administrator access."""
    if not doc:
        return False
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions and "*" in resources:
            return True
    return False


def _policy_is_public(doc):
    """True if a resource policy has an Allow statement for any principal
    (Principal "*" or {"AWS": "*"}, or NotPrincipal) that no restricting
    condition key narrows. Documents aren't stored, only this answer."""
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except (json.JSONDecodeError, TypeError):
            return None
    if not doc:
        return False
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        if "NotPrincipal" in stmt:
            public = True
        elif principal == "*":
            public = True
        elif isinstance(principal, dict):
            aws = principal.get("AWS", [])
            public = "*" in (aws if isinstance(aws, list) else [aws])
        else:
            public = False
        if not public:
            continue
        cond_keys = {k.lower() for block in (stmt.get("Condition") or {}).values()
                     if isinstance(block, dict) for k in block}
        if cond_keys & RESTRICTING_CONDITION_KEYS:
            continue
        return True
    return False


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


def _inline_policies(iam, principal_type, name, arn, policy_names):
    """One entry per inline policy on a user/role/group, flagged for
    admin-wildcard. Documents aren't stored (they can be large); only whether
    each one grants Action:*/Resource:*. A document that can't be read is
    recorded with is_admin_wildcard None so the gap is visible, not assumed
    safe."""
    getter = {"user": ("get_user_policy", "UserName"),
              "role": ("get_role_policy", "RoleName"),
              "group": ("get_group_policy", "GroupName")}[principal_type]
    entries = []
    for policy_name in policy_names:
        doc = _try(
            lambda: getattr(iam, getter[0])(**{getter[1]: name, "PolicyName": policy_name})["PolicyDocument"],
            default=None, label=f"{getter[0]}({name}, {policy_name})",
        )
        entries.append({
            "principal_type": principal_type,
            "principal_name": name,
            "principal_arn": arn,
            "policy_name": policy_name,
            "is_admin_wildcard": _is_admin_wildcard(doc) if doc is not None else None,
        })
    return entries


def collect_iam(session):
    iam = session.client("iam")
    out = {}

    out["password_policy"] = _try(
        lambda: iam.get_account_password_policy()["PasswordPolicy"],
        default=None, label="get_account_password_policy",
    )

    account_summary = _try(
        lambda: iam.get_account_summary()["SummaryMap"],
        default={}, label="get_account_summary",
    )
    out["account_summary"] = account_summary
    out["root_mfa_enabled"] = bool(account_summary.get("AccountMFAEnabled"))
    out["root_access_keys_present"] = bool(account_summary.get("AccountAccessKeysPresent"))

    # root hardware vs. virtual MFA: a root account appearing in the virtual-MFA
    # list means its device is virtual, not hardware.
    out["root_has_virtual_mfa"] = False
    if out["root_mfa_enabled"]:
        virtual_devices = _try(
            lambda: iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")["VirtualMFADevices"],
            default=[], label="list_virtual_mfa_devices",
        )
        out["root_has_virtual_mfa"] = any(
            d.get("User", {}).get("Arn", "").endswith(":root") for d in virtual_devices
        )

    # Credential report: richest single source for users[] below. Generation is
    # async, so poll briefly for completion.
    credential_rows = []
    try:
        iam.generate_credential_report()
        for _ in range(10):
            try:
                report = iam.get_credential_report()
                break
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") == "ReportInProgress":
                    time.sleep(2)
                    continue
                raise
        else:
            report = None
            _record_error("get_credential_report", "ReportNotReady",
                          "credential report still in progress after 10 attempts")
        if report:
            # boto3 already base64-decodes IAM's blob-typed Content field for you
            # (botocore's protocol parser does this automatically) - it arrives as
            # raw CSV bytes, not a base64 string. That's different from the AWS CLI,
            # where `aws iam get-credential-report --query Content --output text`
            # prints the still-base64-encoded value and a manual `base64 --decode`
            # is required there. Calling base64.b64decode() here on boto3's output
            # fails with "Incorrect padding" because it's not valid base64 - it's
            # already decoded. (A try/except-based fallback that re-attempts base64
            # decoding when utf-8 decoding fails is NOT a safe way to handle both
            # shapes: a base64 string is itself valid utf-8/ASCII, so the utf-8
            # decode would silently succeed and hand back the base64 text as if it
            # were the CSV, rather than erroring - confirmed empirically rather than
            # assumed.)
            raw = report["Content"]
            content = raw.decode("utf-8") if isinstance(raw, bytes) else raw
            credential_rows = list(csv.DictReader(io.StringIO(content)))
    except ClientError as e:
        _record_error("get_credential_report", e.response.get("Error", {}).get("Code", "Unknown"),
                      e.response.get("Error", {}).get("Message", str(e)))

    out["credential_report"] = credential_rows

    # Per-user policy attachment detail (direct vs. group-only, admin-wildcard detection)
    users = []
    inline_policies = []
    iam_users = _try(lambda: _paginate(iam, "list_users", "Users"), default=[], label="list_users")
    for u in iam_users:
        name = u["UserName"]
        attached = _try(
            lambda: _paginate(iam, "list_attached_user_policies", "AttachedPolicies", UserName=name),
            default=[], label=f"list_attached_user_policies({name})",
        )
        inline = _try(
            lambda: _paginate(iam, "list_user_policies", "PolicyNames", UserName=name),
            default=[], label=f"list_user_policies({name})",
        )
        groups = _try(
            lambda: _paginate(iam, "list_groups_for_user", "Groups", UserName=name),
            default=[], label=f"list_groups_for_user({name})",
        )
        users.append({
            "user_name": name,
            "arn": u["Arn"],
            "create_date": u["CreateDate"].isoformat() if u.get("CreateDate") else None,
            "attached_managed_policies": [p["PolicyName"] for p in attached],
            "attached_managed_policy_arns": [p["PolicyArn"] for p in attached],
            "inline_policy_names": inline,
            "has_direct_attachment": bool(attached) or bool(inline),
            "group_names": [g["GroupName"] for g in groups],
        })
        inline_policies += _inline_policies(iam, "user", name, u["Arn"], inline)
    out["users"] = users

    # Inline policies on roles and groups. An inline Action:* / Resource:*
    # grant is as much full admin as an attached AdministratorAccess, but it
    # never shows up in list_policies, so it has to be read per principal.
    for r in _try(lambda: _paginate(iam, "list_roles", "Roles"), default=[], label="list_roles"):
        if r.get("Path", "").startswith("/aws-service-role/"):
            continue  # service-linked roles: AWS-managed, can't carry customer inline policies
        names = _try(
            lambda: _paginate(iam, "list_role_policies", "PolicyNames", RoleName=r["RoleName"]),
            default=[], label=f"list_role_policies({r['RoleName']})",
        )
        inline_policies += _inline_policies(iam, "role", r["RoleName"], r["Arn"], names)
    for g in _try(lambda: _paginate(iam, "list_groups", "Groups"), default=[], label="list_groups"):
        names = _try(
            lambda: _paginate(iam, "list_group_policies", "PolicyNames", GroupName=g["GroupName"]),
            default=[], label=f"list_group_policies({g['GroupName']})",
        )
        inline_policies += _inline_policies(iam, "group", g["GroupName"], g["Arn"], names)
    out["inline_policies"] = inline_policies

    # Policies currently attached anywhere, flagged for *:* admin-wildcard statements
    policies = []
    attached_policies = _try(
        lambda: _paginate(iam, "list_policies", "Policies", Scope="All", OnlyAttached=True),
        default=[], label="list_policies",
    )
    for p in attached_policies:
        arn = p["Arn"]
        is_admin_wildcard = False
        version_id = p.get("DefaultVersionId")
        if version_id:
            doc = _try(
                lambda: iam.get_policy_version(PolicyArn=arn, VersionId=version_id)["PolicyVersion"]["Document"],
                default=None, label=f"get_policy_version({arn})",
            )
            is_admin_wildcard = _is_admin_wildcard(doc)
        entry = {
            "policy_name": p["PolicyName"],
            "arn": arn,
            "is_aws_managed": arn.startswith("arn:aws:iam::aws:policy/"),
            "is_admin_wildcard": is_admin_wildcard,
        }
        # Only chase down *who* holds an admin-wildcard policy (extra API calls) -
        # non-admin policies don't need this for any check we run today.
        if is_admin_wildcard:
            roles = _try(
                lambda: _paginate(iam, "list_entities_for_policy", "PolicyRoles", PolicyArn=arn),
                default=[], label=f"list_entities_for_policy({arn}) roles",
            )
            users_ = _try(
                lambda: _paginate(iam, "list_entities_for_policy", "PolicyUsers", PolicyArn=arn),
                default=[], label=f"list_entities_for_policy({arn}) users",
            )
            groups_ = _try(
                lambda: _paginate(iam, "list_entities_for_policy", "PolicyGroups", PolicyArn=arn),
                default=[], label=f"list_entities_for_policy({arn}) groups",
            )
            entry["attached_role_names"] = [r["RoleName"] for r in roles]
            entry["attached_user_names"] = [u["UserName"] for u in users_]
            entry["attached_group_names"] = [g["GroupName"] for g in groups_]
        policies.append(entry)
    out["policies"] = policies

    # Support role: does any role have AWSSupportAccess attached?
    support_role_exists = False
    support_policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
    entities = _try(
        lambda: iam.list_entities_for_policy(PolicyArn=support_policy_arn, EntityFilter="Role")["PolicyRoles"],
        default=[], label="list_entities_for_policy(AWSSupportAccess)",
    )
    support_role_exists = bool(entities)
    out["support_role_exists"] = support_role_exists

    return out


def collect_s3(session, account_id):
    s3control = session.client("s3control")
    s3api = session.client("s3")
    out = {}

    out["account_public_access_block"] = _try(
        lambda: s3control.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"],
        default=None, label="s3control.get_public_access_block",
    )

    buckets_resp = _try(lambda: s3api.list_buckets()["Buckets"], default=[], label="list_buckets")
    buckets = []
    for b in buckets_resp:
        name = b["Name"]
        entry = {"name": name, "unreadable": []}
        failed = object()

        pab = _try(
            lambda: s3api.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"],
            default=None, label=f"get_public_access_block({name})", failed=failed,
        )
        if pab is failed:
            entry["unreadable"].append("public_access_block")
            pab = None
        entry["public_access_block"] = pab

        policy_text = _try(
            lambda: s3api.get_bucket_policy(Bucket=name)["Policy"],
            default=None, label=f"get_bucket_policy({name})", failed=failed,
        )
        if policy_text is failed:
            entry["unreadable"].append("has_https_only_deny")
            policy_text = None
        has_https_only_deny = False
        if policy_text:
            try:
                policy_doc = json.loads(policy_text)
                statements = policy_doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                for stmt in statements:
                    if stmt.get("Effect") != "Deny":
                        continue
                    cond = stmt.get("Condition", {})
                    if str(cond.get("Bool", {}).get("aws:SecureTransport", "")).lower() == "false":
                        has_https_only_deny = True
                        break
            except (json.JSONDecodeError, TypeError):
                pass
        entry["bucket_policy_present"] = policy_text is not None
        entry["has_https_only_deny"] = has_https_only_deny

        versioning = _try(
            lambda: s3api.get_bucket_versioning(Bucket=name),
            default={}, label=f"get_bucket_versioning({name})", failed=None,
        )
        if versioning is None:
            entry["unreadable"].append("mfa_delete")
            versioning = {}
        entry["versioning_status"] = versioning.get("Status")
        entry["mfa_delete"] = versioning.get("MFADelete")

        logging_conf = _try(
            lambda: s3api.get_bucket_logging(Bucket=name),
            default={}, label=f"get_bucket_logging({name})", failed=None,
        )
        if logging_conf is None:
            entry["unreadable"].append("logging_enabled")
        entry["logging_enabled"] = None if logging_conf is None else "LoggingEnabled" in logging_conf

        buckets.append(entry)

    out["buckets"] = buckets
    return out


def collect_cloudtrail(session):
    ct = session.client("cloudtrail")
    out = {}
    trails = _try(lambda: ct.describe_trails(includeShadowTrails=True)["trailList"], default=[], label="describe_trails")
    trail_entries = []
    for t in trails:
        name = t.get("Name")
        trail_arn = t.get("TrailARN")
        status = _try(
            lambda: ct.get_trail_status(Name=trail_arn or name),
            default={}, label=f"get_trail_status({name})",
        )
        event_selectors = _try(
            lambda: ct.get_event_selectors(TrailName=trail_arn or name),
            default={}, label=f"get_event_selectors({name})",
        )
        trail_entries.append({
            "name": name,
            "trail_arn": trail_arn,
            "is_multi_region_trail": t.get("IsMultiRegionTrail", False),
            "is_logging": status.get("IsLogging", False),
            "log_file_validation_enabled": t.get("LogFileValidationEnabled", False),
            "kms_key_id": t.get("KmsKeyId"),
            "s3_bucket_name": t.get("S3BucketName"),
            "s3_bucket_access_logging_enabled": None,  # filled in below once we know the bucket
            "event_selectors": event_selectors.get("EventSelectors", []),
            "advanced_event_selectors": event_selectors.get("AdvancedEventSelectors", []),
        })

    # Cross-reference each trail's S3 destination bucket for server access logging
    s3api = session.client("s3")
    for entry in trail_entries:
        bucket = entry.get("s3_bucket_name")
        if not bucket:
            continue
        # An organization trail's bucket is usually in another account (the
        # management or log archive account), where this call is denied
        # unless that bucket's policy allows it. Unknown stays None.
        logging_conf = _try(
            lambda: s3api.get_bucket_logging(Bucket=bucket),
            default={}, label=f"get_bucket_logging({bucket})", failed=None,
        )
        if logging_conf is not None:
            entry["s3_bucket_access_logging_enabled"] = "LoggingEnabled" in logging_conf

    out["trails"] = trail_entries
    return out


def collect_ec2(session, regions):
    out = {"vpcs": [], "flow_logs": [], "security_groups": [], "instances": []}

    for region in regions:
        ec2 = session.client("ec2", region_name=region)

        vpcs = _try(lambda: ec2.describe_vpcs()["Vpcs"], default=[], label=f"describe_vpcs({region})", region=region)
        for v in vpcs:
            out["vpcs"].append({"region": region, "vpc_id": v["VpcId"], "is_default": v.get("IsDefault", False)})

        flow_logs = _try(lambda: ec2.describe_flow_logs()["FlowLogs"], default=[], label=f"describe_flow_logs({region})", region=region)
        for fl in flow_logs:
            out["flow_logs"].append({
                "region": region,
                "resource_id": fl.get("ResourceId"),
                "traffic_type": fl.get("TrafficType"),
                "flow_log_status": fl.get("FlowLogStatus"),
            })

        sgs = _try(lambda: ec2.describe_security_groups()["SecurityGroups"], default=[], label=f"describe_security_groups({region})", region=region)
        for sg in sgs:
            out["security_groups"].append({
                "region": region,
                "group_id": sg["GroupId"],
                "group_name": sg.get("GroupName"),
                "vpc_id": sg.get("VpcId"),
                "ip_permissions": sg.get("IpPermissions", []),
                "ip_permissions_egress": sg.get("IpPermissionsEgress", []),
            })

        reservations = _try(lambda: ec2.describe_instances()["Reservations"], default=[], label=f"describe_instances({region})", region=region)
        for r in reservations:
            for i in r.get("Instances", []):
                out["instances"].append({
                    "region": region,
                    "instance_id": i["InstanceId"],
                    "state": i.get("State", {}).get("Name"),
                    "http_tokens": i.get("MetadataOptions", {}).get("HttpTokens"),
                })

    return out


def collect_account_contacts(session):
    account = session.client("account")
    out = {}
    out["primary_contact"] = _try(
        lambda: account.get_contact_information()["ContactInformation"],
        default=None, label="get_contact_information",
    )
    out["security_contact"] = _try(
        lambda: account.get_alternate_contact(AlternateContactType="SECURITY")["AlternateContact"],
        default=None, label="get_alternate_contact(SECURITY)",
    )
    return out


def collect_organization(session):
    """Best-effort AWS Organizations context, used by run_checks.py to avoid
    flagging a centrally-managed root user as a false positive.

    organizations:DescribeOrganization works from any member account and tells
    us whether this account is in an org at all. Whether centralized root
    access management (the feature that lets an org delete/disable member
    accounts' root credentials - see
    https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-enable-root-access.html)
    is actually turned on is a different question, and iam:ListOrganizationsFeatures
    - the only API that answers it - can only be called from the
    Organizations management account or an account delegated as IAM's trusted
    administrator (AccountNotManagementOrDelegatedAdministrator otherwise).
    Most audits run from inside the member account being audited, so that call
    is *expected* to fail here; root_credentials_management_enabled stays None
    in that case rather than guessing, and run_checks.py's root checks fall
    back to an explicit --exceptions attestation instead (see
    references/exceptions-and-exclusions.md).
    """
    out = {
        "in_organization": False,
        "organization_id": None,
        "management_account_id": None,
        "feature_set": None,
        "root_credentials_management_enabled": None,
        "root_credentials_management_queryable": False,
    }

    org = session.client("organizations")
    try:
        desc = org.describe_organization()["Organization"]
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code not in ("AWSOrganizationsNotInUseException", "AccessDeniedException"):
            _record_error("organizations.describe_organization", code, e.response.get("Error", {}).get("Message", str(e)))
        return out

    out["in_organization"] = True
    out["organization_id"] = desc.get("Id")
    out["management_account_id"] = desc.get("MasterAccountId")
    out["feature_set"] = desc.get("FeatureSet")

    iam = session.client("iam")
    try:
        feats = iam.list_organizations_features()
        out["root_credentials_management_enabled"] = "RootCredentialsManagement" in feats.get("EnabledFeatures", [])
        out["root_credentials_management_queryable"] = True
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "ServiceAccessNotEnabledException":
            # The organization hasn't enabled trusted access for IAM, so centralized
            # root credential management can't be on: an answer, not an error.
            out["root_credentials_management_enabled"] = False
            out["root_credentials_management_queryable"] = True
        elif code != "AccountNotManagementOrDelegatedAdministrator":
            _record_error("iam.list_organizations_features", code, e.response.get("Error", {}).get("Message", str(e)))
        # else: expected when running from a plain member account - not an error.

    return out


# ---------------------------------------------------------------------------
# Detection and monitoring services (one region entry per region whose calls
# succeeded; a region missing from "regions" failed and is in
# collection_errors, so its checks are marked incomplete rather than passed).
# ---------------------------------------------------------------------------

_FAILED = object()


def collect_guardduty(session, regions):
    out = {"regions": []}
    for region in regions:
        gd = session.client("guardduty", region_name=region)
        ids = _try(lambda: _paginate(gd, "list_detectors", "DetectorIds"),
                   default=None, label=f"list_detectors({region})", region=region)
        if ids is None:
            continue
        detectors = []
        for d in ids:
            info = _try(lambda: gd.get_detector(DetectorId=d), default=None,
                        label=f"get_detector({region}, {d})", region=region)
            detectors.append({"detector_id": d, "status": (info or {}).get("Status")})
        out["regions"].append({"region": region, "detectors": detectors})
    return out


def collect_securityhub(session, regions):
    out = {"regions": []}
    for region in regions:
        sh = session.client("securityhub", region_name=region)
        hub = _try(lambda: sh.describe_hub(), default=None, label=f"describe_hub({region})",
                   region=region, failed=_FAILED)
        if hub is _FAILED:
            continue
        entry = {"region": region, "enabled": hub is not None, "standards": []}
        if hub is not None:
            standards = _try(lambda: _paginate(sh, "get_enabled_standards", "StandardsSubscriptions"),
                             default=[], label=f"get_enabled_standards({region})", region=region)
            entry["standards"] = [{"arn": s.get("StandardsArn"), "status": s.get("StandardsStatus")}
                                  for s in standards]
        out["regions"].append(entry)
    return out


def collect_inspector(session, regions, account_id):
    out = {"regions": []}
    for region in regions:
        insp = session.client("inspector2", region_name=region)
        resp = _try(lambda: insp.batch_get_account_status(accountIds=[account_id]),
                    default=None, label=f"batch_get_account_status({region})", region=region)
        if resp is None:
            continue
        acct = next(iter(resp.get("accounts") or []), {})
        state = acct.get("resourceState") or {}
        out["regions"].append({
            "region": region,
            "account_status": (acct.get("state") or {}).get("status"),
            "ec2": (state.get("ec2") or {}).get("status"),
            "ecr": (state.get("ecr") or {}).get("status"),
            "lambda": (state.get("lambda") or {}).get("status"),
        })
    return out


def collect_access_analyzer(session, regions):
    out = {"regions": []}
    for region in regions:
        aa = session.client("accessanalyzer", region_name=region)
        analyzers = _try(lambda: _paginate(aa, "list_analyzers", "analyzers"),
                         default=None, label=f"list_analyzers({region})", region=region)
        if analyzers is None:
            continue
        out["regions"].append({"region": region, "analyzers": [
            {"name": a.get("name"), "type": a.get("type"), "status": a.get("status")} for a in analyzers]})
    return out


def collect_config(session, regions):
    out = {"regions": []}
    for region in regions:
        cfg = session.client("config", region_name=region)
        recorders = _try(lambda: cfg.describe_configuration_recorders()["ConfigurationRecorders"],
                         default=None, label=f"describe_configuration_recorders({region})", region=region)
        if recorders is None:
            continue
        statuses = _try(lambda: cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"],
                        default=None, label=f"describe_configuration_recorder_status({region})", region=region)
        if statuses is None:
            continue
        by_name = {s.get("name"): s for s in statuses}
        entries = []
        for r in recorders:
            group = r.get("recordingGroup") or {}
            strategy = (group.get("recordingStrategy") or {}).get("useOnly")
            status = by_name.get(r.get("name"), {})
            entries.append({
                "name": r.get("name"),
                "all_supported": bool(group.get("allSupported")) or strategy == "ALL_SUPPORTED_RESOURCE_TYPES",
                "include_global_resource_types": bool(group.get("includeGlobalResourceTypes")),
                "recording_strategy": strategy,
                "recording": bool(status.get("recording")),
                "last_status": status.get("lastStatus"),
            })
        out["regions"].append({"region": region, "recorders": entries})
    return out


def collect_logs(session, regions):
    out = {"log_groups": []}
    for region in regions:
        logs = session.client("logs", region_name=region)
        groups = _try(lambda: _paginate(logs, "describe_log_groups", "logGroups"),
                      default=[], label=f"describe_log_groups({region})", region=region)
        for g in groups:
            out["log_groups"].append({
                "region": region,
                "name": g.get("logGroupName"),
                "retention_in_days": g.get("retentionInDays"),
                "kms_key_id": g.get("kmsKeyId"),
            })
    return out


# ---------------------------------------------------------------------------
# Data stores, keys and secrets
# ---------------------------------------------------------------------------

def collect_rds(session, regions):
    out = {"instances": [], "clusters": [], "snapshots": []}
    for region in regions:
        rds = session.client("rds", region_name=region)
        for i in _try(lambda: _paginate(rds, "describe_db_instances", "DBInstances"),
                      default=[], label=f"describe_db_instances({region})", region=region):
            out["instances"].append({
                "region": region,
                "id": i.get("DBInstanceIdentifier"),
                "engine": i.get("Engine"),
                "cluster_id": i.get("DBClusterIdentifier"),
                "publicly_accessible": bool(i.get("PubliclyAccessible")),
                "storage_encrypted": bool(i.get("StorageEncrypted")),
                "backup_retention_period": i.get("BackupRetentionPeriod"),
                "deletion_protection": bool(i.get("DeletionProtection")),
                "multi_az": bool(i.get("MultiAZ")),
            })
        for c in _try(lambda: _paginate(rds, "describe_db_clusters", "DBClusters"),
                      default=[], label=f"describe_db_clusters({region})", region=region):
            out["clusters"].append({
                "region": region,
                "id": c.get("DBClusterIdentifier"),
                "engine": c.get("Engine"),
                "storage_encrypted": bool(c.get("StorageEncrypted")),
                "backup_retention_period": c.get("BackupRetentionPeriod"),
                "deletion_protection": bool(c.get("DeletionProtection")),
            })
        # Manual snapshots only: automated ones can't be shared. A snapshot is
        # public when its "restore" attribute includes "all".
        for kind, op, key, id_key, attr_op, attr_id, attr_key in (
            ("instance", "describe_db_snapshots", "DBSnapshots", "DBSnapshotIdentifier",
             "describe_db_snapshot_attributes", "DBSnapshotIdentifier", "DBSnapshotAttributesResult"),
            ("cluster", "describe_db_cluster_snapshots", "DBClusterSnapshots", "DBClusterSnapshotIdentifier",
             "describe_db_cluster_snapshot_attributes", "DBClusterSnapshotIdentifier", "DBClusterSnapshotAttributesResult"),
        ):
            snaps = _try(lambda: _paginate(rds, op, key, SnapshotType="manual"),
                         default=[], label=f"{op}({region})", region=region)
            for s in snaps:
                sid = s.get(id_key)
                entry = {"region": region, "id": sid, "kind": kind,
                         "encrypted": bool(s.get("Encrypted") if kind == "instance" else s.get("StorageEncrypted")),
                         "public": None, "unreadable": []}
                attrs = _try(lambda: getattr(rds, attr_op)(**{attr_id: sid})[attr_key],
                             default=None, label=f"{attr_op}({sid})", region=region)
                if attrs is None:
                    entry["unreadable"].append("public")
                else:
                    restore = next((a.get("AttributeValues", []) for a in attrs.get(
                        "DBSnapshotAttributes" if kind == "instance" else "DBClusterSnapshotAttributes", [])
                        if a.get("AttributeName") == "restore"), [])
                    entry["public"] = "all" in restore
                out["snapshots"].append(entry)
    return out


def collect_kms(session, regions):
    """Customer-managed, enabled keys only: AWS-managed keys rotate
    automatically and their policies aren't the customer's to change."""
    out = {"keys": []}
    for region in regions:
        kms = session.client("kms", region_name=region)
        keys = _try(lambda: _paginate(kms, "list_keys", "Keys"),
                    default=[], label=f"list_keys({region})", region=region)
        aliases = _try(lambda: _paginate(kms, "list_aliases", "Aliases"),
                       default=[], label=f"list_aliases({region})", region=region)
        alias_names = {}
        for a in aliases:
            if a.get("TargetKeyId"):
                alias_names.setdefault(a["TargetKeyId"], []).append(a.get("AliasName"))
        for k in keys:
            kid = k["KeyId"]
            meta = _try(lambda: kms.describe_key(KeyId=kid)["KeyMetadata"],
                        default=None, label=f"describe_key({kid})", region=region)
            if meta is None:
                out["keys"].append({"region": region, "key_id": kid, "aliases": alias_names.get(kid, []),
                                    "unreadable": ["metadata", "rotation_enabled", "public_policy"]})
                continue
            if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled":
                continue
            entry = {
                "region": region,
                "key_id": kid,
                "aliases": alias_names.get(kid, []),
                "key_spec": meta.get("KeySpec"),
                "origin": meta.get("Origin"),
                "multi_region": bool(meta.get("MultiRegion")),
                # Automatic rotation is only supported for symmetric keys with
                # AWS-generated key material outside a custom key store.
                "rotation_supported": meta.get("KeySpec") == "SYMMETRIC_DEFAULT" and meta.get("Origin") == "AWS_KMS",
                "rotation_enabled": None,
                "public_policy": None,
                "unreadable": [],
            }
            if entry["rotation_supported"]:
                rot = _try(lambda: kms.get_key_rotation_status(KeyId=kid),
                           default=None, label=f"get_key_rotation_status({kid})", region=region)
                if rot is None:
                    entry["unreadable"].append("rotation_enabled")
                else:
                    entry["rotation_enabled"] = bool(rot.get("KeyRotationEnabled"))
                    entry["rotation_period_days"] = rot.get("RotationPeriodInDays")
            policy = _try(lambda: kms.get_key_policy(KeyId=kid, PolicyName="default")["Policy"],
                          default=None, label=f"get_key_policy({kid})", region=region)
            if policy is None:
                entry["unreadable"].append("public_policy")
            else:
                entry["public_policy"] = _policy_is_public(policy)
            out["keys"].append(entry)
    return out


def collect_secretsmanager(session, regions):
    out = {"secrets": []}
    for region in regions:
        sm = session.client("secretsmanager", region_name=region)
        secrets = _try(lambda: _paginate(sm, "list_secrets", "SecretList"),
                       default=[], label=f"list_secrets({region})", region=region)
        for s in secrets:
            name = s.get("Name")
            entry = {
                "region": region,
                "name": name,
                "arn": s.get("ARN"),
                "owning_service": s.get("OwningService"),
                "rotation_enabled": bool(s.get("RotationEnabled")),
                "last_rotated": _iso(s.get("LastRotatedDate")),
                "last_changed": _iso(s.get("LastChangedDate")),
                "public_policy": None,
                "unreadable": [],
            }
            policy = _try(lambda: sm.get_resource_policy(SecretId=s["ARN"]),
                          default=None, label=f"get_resource_policy({name})", region=region)
            if policy is None:
                entry["unreadable"].append("public_policy")
            else:
                entry["public_policy"] = _policy_is_public(policy.get("ResourcePolicy"))
            out["secrets"].append(entry)
    return out


def collect_dynamodb(session, regions):
    out = {"tables": []}
    for region in regions:
        ddb = session.client("dynamodb", region_name=region)
        names = _try(lambda: _paginate(ddb, "list_tables", "TableNames"),
                     default=[], label=f"list_tables({region})", region=region)
        for name in names:
            entry = {"region": region, "name": name, "pitr_status": None, "unreadable": []}
            cb = _try(lambda: ddb.describe_continuous_backups(TableName=name)["ContinuousBackupsDescription"],
                      default=None, label=f"describe_continuous_backups({name})", region=region)
            if cb is None:
                entry["unreadable"].append("pitr_status")
            else:
                entry["pitr_status"] = (cb.get("PointInTimeRecoveryDescription") or {}).get("PointInTimeRecoveryStatus")
            out["tables"].append(entry)
    return out


def collect_elasticache(session, regions):
    """Replication groups (Redis/Valkey, clustered or not) plus standalone
    cache clusters that aren't members of one (Memcached, single-node Redis)."""
    out = {"replication_groups": [], "clusters": []}
    for region in regions:
        ec = session.client("elasticache", region_name=region)
        for g in _try(lambda: _paginate(ec, "describe_replication_groups", "ReplicationGroups"),
                      default=[], label=f"describe_replication_groups({region})", region=region):
            out["replication_groups"].append({
                "region": region,
                "id": g.get("ReplicationGroupId"),
                "engine": g.get("Engine"),
                "at_rest_encryption": bool(g.get("AtRestEncryptionEnabled")),
                "transit_encryption": bool(g.get("TransitEncryptionEnabled")),
                "transit_encryption_mode": g.get("TransitEncryptionMode"),
                "auth_token_enabled": bool(g.get("AuthTokenEnabled")),
            })
        for c in _try(lambda: _paginate(ec, "describe_cache_clusters", "CacheClusters"),
                      default=[], label=f"describe_cache_clusters({region})", region=region):
            if c.get("ReplicationGroupId"):
                continue
            out["clusters"].append({
                "region": region,
                "id": c.get("CacheClusterId"),
                "engine": c.get("Engine"),
                "at_rest_encryption": bool(c.get("AtRestEncryptionEnabled")),
                "transit_encryption": bool(c.get("TransitEncryptionEnabled")),
                "auth_token_enabled": bool(c.get("AuthTokenEnabled")),
            })
    return out


def collect_ebs(session, regions):
    out = {"regions": [], "volumes": []}
    for region in regions:
        ec2 = session.client("ec2", region_name=region)
        entry = {"region": region, "unreadable": []}
        default_enc = _try(lambda: ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"],
                           default=None, label=f"get_ebs_encryption_by_default({region})", region=region)
        if default_enc is None:
            entry["unreadable"].append("encryption_by_default")
        entry["encryption_by_default"] = default_enc
        entry["snapshot_block_public_access"] = _try(
            lambda: ec2.get_snapshot_block_public_access_state()["State"],
            default=None, label=f"get_snapshot_block_public_access_state({region})", region=region)
        # One call finds every snapshot this account owns that anyone can restore.
        public = _try(lambda: _paginate(ec2, "describe_snapshots", "Snapshots",
                                        OwnerIds=["self"], RestorableByUserIds=["all"]),
                      default=None, label=f"describe_snapshots({region})", region=region)
        if public is None:
            entry["unreadable"].append("public_snapshot_ids")
        entry["public_snapshot_ids"] = None if public is None else [s["SnapshotId"] for s in public]
        out["regions"].append(entry)
        for v in _try(lambda: _paginate(ec2, "describe_volumes", "Volumes"),
                      default=[], label=f"describe_volumes({region})", region=region):
            out["volumes"].append({
                "region": region,
                "volume_id": v["VolumeId"],
                "encrypted": bool(v.get("Encrypted")),
                "state": v.get("State"),
                "attached_to": [a.get("InstanceId") for a in v.get("Attachments", [])],
            })
    return out


def collect_ecr(session, regions):
    out = {"registries": [], "repositories": []}
    for region in regions:
        ecr = session.client("ecr", region_name=region)
        scanning = _try(lambda: ecr.get_registry_scanning_configuration()["scanningConfiguration"],
                        default=None, label=f"get_registry_scanning_configuration({region})", region=region)
        if scanning is not None:
            out["registries"].append({
                "region": region,
                "scan_type": scanning.get("scanType"),
                "rules": [{"scan_frequency": r.get("scanFrequency"),
                           "filters": [f.get("filter") for f in r.get("repositoryFilters", [])]}
                          for r in scanning.get("rules", [])],
            })
        for r in _try(lambda: _paginate(ecr, "describe_repositories", "repositories"),
                      default=[], label=f"describe_repositories({region})", region=region):
            name = r.get("repositoryName")
            entry = {
                "region": region,
                "name": name,
                "scan_on_push": bool((r.get("imageScanningConfiguration") or {}).get("scanOnPush")),
                "tag_mutability": r.get("imageTagMutability"),
                "public_policy": None,
                "unreadable": [],
            }
            policy = _try(lambda: ecr.get_repository_policy(repositoryName=name)["policyText"],
                          default=False, label=f"get_repository_policy({name})", region=region, failed=None)
            if policy is None:
                entry["unreadable"].append("public_policy")
            else:
                entry["public_policy"] = _policy_is_public(policy) if policy else False
            out["repositories"].append(entry)
    return out


def collect_sns(session, regions):
    out = {"topics": []}
    for region in regions:
        sns = session.client("sns", region_name=region)
        topics = _try(lambda: _paginate(sns, "list_topics", "Topics"),
                      default=[], label=f"list_topics({region})", region=region)
        for t in topics:
            arn = t["TopicArn"]
            name = arn.rsplit(":", 1)[-1]
            entry = {"region": region, "name": name, "kms_master_key_id": None,
                     "public_policy": None, "unreadable": []}
            attrs = _try(lambda: sns.get_topic_attributes(TopicArn=arn)["Attributes"],
                         default=None, label=f"get_topic_attributes({name})", region=region)
            if attrs is None:
                entry["unreadable"].append("public_policy")
            else:
                entry["kms_master_key_id"] = attrs.get("KmsMasterKeyId")
                entry["public_policy"] = _policy_is_public(attrs.get("Policy"))
            out["topics"].append(entry)
    return out


def main():
    global CURRENT_SECTION
    parser = argparse.ArgumentParser(description="Collect AWS account data for the aws-audit skill.")
    parser.add_argument("--profile", help="named AWS CLI profile to use")
    parser.add_argument("--role-arn", help="assume this role before collecting (alternative to pre-exported credentials)")
    parser.add_argument("--role-session-name", default="aws-audit-session",
                        help="role session name used with --role-arn; set it to <auditor>-<YYYYMMDD> so the "
                             "snapshot's caller_arn and the audited account's CloudTrail show who collected")
    parser.add_argument("--regions", help="comma-separated list of regions (default: caller's configured region)")
    parser.add_argument("--all-regions", action="store_true", help="collect regional data (EC2/VPC and every regional service) from every enabled region")
    parser.add_argument("-o", "--output", default="snapshot.json", help="output JSON file path")
    args = parser.parse_args()

    version = tool_version()
    print(f"Tool version: {version}", file=sys.stderr)
    problem = version_problem(version)
    if problem:
        print(f"WARNING: {problem}. Audit from a release checkout (git checkout vX.Y.Z).", file=sys.stderr)

    session = get_session(args)
    account_id, caller_arn = get_caller_identity(session)
    print(f"Collecting data for account {account_id} as {caller_arn}", file=sys.stderr)

    regions = get_regions(session, args)
    print(f"Regions: {', '.join(regions)}", file=sys.stderr)

    snapshot = {
        "collected_at": utcnow_iso(),
        "tool_version": version,
        "account_id": account_id,
        "caller_arn": caller_arn,
        "regions": regions,
    }

    print("Collecting IAM...", file=sys.stderr)
    CURRENT_SECTION = "iam"
    snapshot["iam"] = collect_iam(session)

    print("Collecting S3...", file=sys.stderr)
    CURRENT_SECTION = "s3"
    snapshot["s3"] = collect_s3(session, account_id)

    print("Collecting CloudTrail...", file=sys.stderr)
    CURRENT_SECTION = "cloudtrail"
    snapshot["cloudtrail"] = collect_cloudtrail(session)

    print("Collecting EC2/VPC...", file=sys.stderr)
    CURRENT_SECTION = "ec2"
    snapshot["ec2"] = collect_ec2(session, regions)

    print("Collecting account contacts...", file=sys.stderr)
    CURRENT_SECTION = "account_contacts"
    snapshot["account_contacts"] = collect_account_contacts(session)

    print("Collecting organization context...", file=sys.stderr)
    CURRENT_SECTION = "organization"
    snapshot["organization"] = collect_organization(session)

    # Regional services, collected from the same regions as EC2/VPC.
    for section, label, collect in (
        ("guardduty", "GuardDuty", lambda: collect_guardduty(session, regions)),
        ("securityhub", "Security Hub", lambda: collect_securityhub(session, regions)),
        ("inspector", "Inspector", lambda: collect_inspector(session, regions, account_id)),
        ("access_analyzer", "IAM Access Analyzer", lambda: collect_access_analyzer(session, regions)),
        ("config", "AWS Config", lambda: collect_config(session, regions)),
        ("logs", "CloudWatch Logs", lambda: collect_logs(session, regions)),
        ("rds", "RDS", lambda: collect_rds(session, regions)),
        ("kms", "KMS", lambda: collect_kms(session, regions)),
        ("secretsmanager", "Secrets Manager", lambda: collect_secretsmanager(session, regions)),
        ("dynamodb", "DynamoDB", lambda: collect_dynamodb(session, regions)),
        ("elasticache", "ElastiCache", lambda: collect_elasticache(session, regions)),
        ("ebs", "EBS", lambda: collect_ebs(session, regions)),
        ("ecr", "ECR", lambda: collect_ecr(session, regions)),
        ("sns", "SNS", lambda: collect_sns(session, regions)),
    ):
        print(f"Collecting {label}...", file=sys.stderr)
        CURRENT_SECTION = section
        snapshot[section] = collect()

    snapshot["collection_errors"] = COLLECTION_ERRORS

    with open(args.output, "w") as f:
        json.dump(snapshot, f, indent=2, default=str)

    print(f"Wrote {args.output}", file=sys.stderr)
    if COLLECTION_ERRORS:
        print(f"WARNING: {len(COLLECTION_ERRORS)} call(s) failed and were recorded as collection_errors; "
              "the checks that depend on them will be marked incomplete. Fix the cause (usually a "
              "permission or a region) and collect again before relying on those checks.", file=sys.stderr)


if __name__ == "__main__":
    main()
