#!/usr/bin/env python3
"""
collect_aws_data.py — gather AWS account configuration data for the aws-audit skill.

Collects data for the six core audit areas (IAM, MFA, S3, CloudTrail/logging,
Security Groups/VPC, root account) via boto3 and writes a single JSON snapshot
that scripts/run_checks.py can evaluate against a chosen compliance framework.

Usage:
    pip install boto3 --break-system-packages

    # Using credentials already in the environment / a named profile:
    python3 collect_aws_data.py --all-regions -o snapshot.json
    python3 collect_aws_data.py --profile my-profile --regions us-east-1,us-west-2 -o snapshot.json

    # Having this script assume a cross-account role itself, instead of
    # pre-exporting AWS_ACCESS_KEY_ID/SECRET/SESSION_TOKEN into the shell
    # (see the repo's cloudformation/security-audit-role.yml /
    # terraform/security-audit-role/ for how that role is deployed):
    python3 collect_aws_data.py --all-regions \\
        --role-arn arn:aws:iam::123456789012:role/opspath-CrossAccountSecurityAuditRole \\
        --role-session-name audit-session \\
        -o snapshot.json

Output schema (top level):
    {
      "collected_at": "<ISO8601 UTC timestamp>",
      "account_id": "<12-digit account id, from sts:GetCallerIdentity>",
      "caller_arn": "<arn of the identity that ran the collection>",
      "regions": ["us-east-1", ...],
      "iam": { ... },
      "s3": { ... },
      "cloudtrail": { ... },
      "ec2": { ... },
      "account_contacts": { ... }
    }

Any section can be missing or partial (e.g. if the caller lacks a permission,
or a user hand-builds a subset of this schema from exported files) — run_checks.py
marks checks that need missing data as "skipped" rather than failing them.
"""

import argparse
import csv
import io
import json
import sys
import time
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("boto3 is required: pip install boto3 --break-system-packages", file=sys.stderr)
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


def _try(fn, default=None, label=""):
    try:
        return fn()
    except ClientError as e:
        print(f"  [warn] {label or fn}: {e.response.get('Error', {}).get('Code', e)}", file=sys.stderr)
        return default


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
        print(f"  [warn] credential report: {e.response.get('Error', {}).get('Code', e)}", file=sys.stderr)

    out["credential_report"] = credential_rows

    # Per-user policy attachment detail (direct vs. group-only, admin-wildcard detection)
    users = []
    iam_users = _try(lambda: iam.list_users()["Users"], default=[], label="list_users")
    for u in iam_users:
        name = u["UserName"]
        attached = _try(
            lambda: iam.list_attached_user_policies(UserName=name)["AttachedPolicies"],
            default=[], label=f"list_attached_user_policies({name})",
        )
        inline = _try(
            lambda: iam.list_user_policies(UserName=name)["PolicyNames"],
            default=[], label=f"list_user_policies({name})",
        )
        groups = _try(
            lambda: iam.list_groups_for_user(UserName=name)["Groups"],
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
    out["users"] = users

    # Policies currently attached anywhere, flagged for *:* admin-wildcard statements
    policies = []
    attached_policies = _try(
        lambda: iam.list_policies(Scope="All", OnlyAttached=True)["Policies"],
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
            if doc:
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
                        is_admin_wildcard = True
                        break
        policies.append({
            "policy_name": p["PolicyName"],
            "arn": arn,
            "is_aws_managed": arn.startswith("arn:aws:iam::aws:policy/"),
            "is_admin_wildcard": is_admin_wildcard,
        })
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
        entry = {"name": name}

        entry["public_access_block"] = _try(
            lambda: s3api.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"],
            default=None, label=f"get_public_access_block({name})",
        )

        policy_text = _try(
            lambda: s3api.get_bucket_policy(Bucket=name)["Policy"],
            default=None, label=f"get_bucket_policy({name})",
        )
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
            default={}, label=f"get_bucket_versioning({name})",
        )
        entry["versioning_status"] = versioning.get("Status")
        entry["mfa_delete"] = versioning.get("MFADelete")

        logging_conf = _try(
            lambda: s3api.get_bucket_logging(Bucket=name),
            default={}, label=f"get_bucket_logging({name})",
        )
        entry["logging_enabled"] = "LoggingEnabled" in logging_conf

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
        logging_conf = _try(
            lambda: s3api.get_bucket_logging(Bucket=bucket),
            default={}, label=f"get_bucket_logging({bucket})",
        )
        entry["s3_bucket_access_logging_enabled"] = "LoggingEnabled" in logging_conf

    out["trails"] = trail_entries
    return out


def collect_ec2(session, regions):
    out = {"vpcs": [], "flow_logs": [], "security_groups": [], "instances": []}

    for region in regions:
        ec2 = session.client("ec2", region_name=region)

        vpcs = _try(lambda: ec2.describe_vpcs()["Vpcs"], default=[], label=f"describe_vpcs({region})")
        for v in vpcs:
            out["vpcs"].append({"region": region, "vpc_id": v["VpcId"], "is_default": v.get("IsDefault", False)})

        flow_logs = _try(lambda: ec2.describe_flow_logs()["FlowLogs"], default=[], label=f"describe_flow_logs({region})")
        for fl in flow_logs:
            out["flow_logs"].append({
                "region": region,
                "resource_id": fl.get("ResourceId"),
                "traffic_type": fl.get("TrafficType"),
                "flow_log_status": fl.get("FlowLogStatus"),
            })

        sgs = _try(lambda: ec2.describe_security_groups()["SecurityGroups"], default=[], label=f"describe_security_groups({region})")
        for sg in sgs:
            out["security_groups"].append({
                "region": region,
                "group_id": sg["GroupId"],
                "group_name": sg.get("GroupName"),
                "vpc_id": sg.get("VpcId"),
                "ip_permissions": sg.get("IpPermissions", []),
                "ip_permissions_egress": sg.get("IpPermissionsEgress", []),
            })

        reservations = _try(lambda: ec2.describe_instances()["Reservations"], default=[], label=f"describe_instances({region})")
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


def main():
    parser = argparse.ArgumentParser(description="Collect AWS account data for the aws-audit skill.")
    parser.add_argument("--profile", help="named AWS CLI profile to use")
    parser.add_argument("--role-arn", help="assume this role before collecting (alternative to pre-exported credentials)")
    parser.add_argument("--role-session-name", default="aws-audit-session", help="role session name used with --role-arn")
    parser.add_argument("--regions", help="comma-separated list of regions (default: caller's configured region)")
    parser.add_argument("--all-regions", action="store_true", help="collect EC2/VPC data from every enabled region")
    parser.add_argument("-o", "--output", default="snapshot.json", help="output JSON file path")
    args = parser.parse_args()

    session = get_session(args)
    account_id, caller_arn = get_caller_identity(session)
    print(f"Collecting data for account {account_id} as {caller_arn}", file=sys.stderr)

    regions = get_regions(session, args)
    print(f"Regions: {', '.join(regions)}", file=sys.stderr)

    snapshot = {
        "collected_at": utcnow_iso(),
        "account_id": account_id,
        "caller_arn": caller_arn,
        "regions": regions,
    }

    print("Collecting IAM...", file=sys.stderr)
    snapshot["iam"] = collect_iam(session)

    print("Collecting S3...", file=sys.stderr)
    snapshot["s3"] = collect_s3(session, account_id)

    print("Collecting CloudTrail...", file=sys.stderr)
    snapshot["cloudtrail"] = collect_cloudtrail(session)

    print("Collecting EC2/VPC...", file=sys.stderr)
    snapshot["ec2"] = collect_ec2(session, regions)

    print("Collecting account contacts...", file=sys.stderr)
    snapshot["account_contacts"] = collect_account_contacts(session)

    with open(args.output, "w") as f:
        json.dump(snapshot, f, indent=2, default=str)

    print(f"Wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
