#!/usr/bin/env python3
"""
run_checks.py — evaluate an aws-audit snapshot against a chosen compliance framework.

Usage:
    python3 run_checks.py snapshot.json --framework cis -o findings.json
    # --framework in {cis, well_architected, soc2, iso27001, all}

    # To correct known false positives (a root user with credentials
    # centrally removed via AWS Organizations, a named break-glass/admin
    # role that is intentionally AdministratorAccess, a longer root-reuse
    # review window) pass an exceptions file - see
    # references/exceptions-and-exclusions.md for the schema, and
    # references/accepting-findings-process.md for how to decide what
    # belongs in one:
    python3 run_checks.py snapshot.json --framework cis --exceptions exceptions.json -o findings.json

Reads the JSON produced by collect_aws_data.py (or an equivalent hand-built file
matching its schema) and runs the 27 checks documented in
references/check-catalog.md. Any check whose required snapshot data is missing
is marked "skipped" rather than guessed at or silently dropped.

One of those 27 (default_vpc_exists) is best-practice-only: no CIS AWS
Foundations Benchmark, SOC 2, or ISO 27001 control actually requires deleting
a region's default VPC, so its "refs" for those three frameworks are an
informational note rather than a control ID - see check-catalog.md's footnote
and references/remediation-and-retesting.md's "Findings outside the audited
framework's scope." It still runs and reports under every framework; it just
doesn't masquerade as satisfying a control that doesn't exist.

Findings carry one of three statuses: "pass", "fail", or "accepted" - the last
one only ever produced when an --exceptions file explicitly matches a finding
(a centrally-managed root user, or a named admin principal on the accepted
list). "accepted" findings are never silently dropped: they stay in the output
with the evidence and the exception's own justification note attached, so the
report can show them as deliberately risk-accepted rather than as open issues.

A "root credentials are centrally managed" claim (auto-detected or attested)
is never trusted on its own: root_mfa_enabled, root_hardware_mfa,
root_no_access_keys, root_not_used_routinely, and iam_credentials_unused_45d
(for the root row only) all corroborate it against the actual collected data
first - no login profile, no access keys, no MFA device - via
_root_has_no_usable_credentials(). If a claim and the data disagree, the
claim is not applied and the discrepancy itself is attached to that check's
evidence, loudly, rather than either silently passing or silently falling
back with no explanation.
"""

import argparse
import inspect
import json
import re
import sys
from datetime import datetime, timezone


ADMIN_PORTS = [(22, 22), (3389, 3389)]


# ---------------------------------------------------------------------------
# Check metadata: title, area, severity, remediation, and cross-framework
# control references. Keep this in lockstep with references/check-catalog.md.
# ---------------------------------------------------------------------------
CHECKS_META = {
    "root_mfa_enabled": {
        "title": "Root user has MFA enabled",
        "area": "Root Account",
        "severity": "Critical",
        "remediation": "Sign in as root and attach a virtual or hardware MFA device via IAM console > Security Credentials.",
        "refs": {"cis": "2.5", "well_architected": "SEC01-BP02", "soc2": "CC6.1, CC6.6", "iso27001": "A.8.5"},
    },
    "root_hardware_mfa": {
        "title": "Root user uses a hardware MFA device",
        "area": "Root Account",
        "severity": "Medium",
        "remediation": "Remove the virtual MFA device from root and register a hardware MFA token or FIDO security key instead.",
        "refs": {"cis": "2.6", "well_architected": "SEC01-BP02", "soc2": "CC6.1", "iso27001": "A.8.5"},
    },
    "root_no_access_keys": {
        "title": "Root user has no access keys",
        "area": "Root Account",
        "severity": "Critical",
        "remediation": "Sign in as root, go to My Security Credentials > Access keys, and delete every listed key.",
        "refs": {"cis": "2.4", "well_architected": "SEC01-BP02", "soc2": "CC6.1, CC6.3", "iso27001": "A.8.2"},
    },
    "root_not_used_routinely": {
        "title": "Root user is not used for routine tasks",
        "area": "Root Account",
        "severity": "High",
        "remediation": "Create named IAM users/roles with MFA for daily admin work; reserve root for the narrow set of root-only tasks.",
        "refs": {"cis": "2.7", "well_architected": "SEC01-BP02", "soc2": "CC6.3", "iso27001": "A.8.2"},
    },
    "account_security_contact_registered": {
        "title": "Security alternate contact is registered",
        "area": "Root Account",
        "severity": "Low",
        "remediation": "aws account put-alternate-contact --alternate-contact-type SECURITY --email-address <alias> --name <team> --phone-number <number> --title 'Security Team'",
        "refs": {"cis": "2.3", "well_architected": "SEC01-BP02", "soc2": "CC6.2", "iso27001": "A.5.18"},
    },
    "iam_password_policy_length": {
        "title": "IAM password policy requires minimum length of 14+",
        "area": "IAM",
        "severity": "Medium",
        "remediation": "aws iam update-account-password-policy --minimum-password-length 14 (combine with other password-policy flags in one call).",
        "refs": {"cis": "2.8", "well_architected": "SEC02-BP01", "soc2": "CC6.1", "iso27001": "A.5.17"},
    },
    "iam_password_policy_reuse": {
        "title": "IAM password policy prevents password reuse",
        "area": "IAM",
        "severity": "Medium",
        "remediation": "aws iam update-account-password-policy --password-reuse-prevention 24",
        "refs": {"cis": "2.9", "well_architected": "SEC02-BP01", "soc2": "CC6.1", "iso27001": "A.5.17"},
    },
    "iam_user_mfa_console_access": {
        "title": "IAM users with console access have MFA enabled",
        "area": "MFA",
        "severity": "Critical",
        "remediation": "Have the user (or an admin) register an MFA device via aws iam enable-mfa-device or the IAM console.",
        "refs": {"cis": "2.10", "well_architected": "SEC02-BP01", "soc2": "CC6.1, CC6.6", "iso27001": "A.8.5"},
    },
    "iam_credentials_unused_45d": {
        "title": "No credentials unused for 45+ days",
        "area": "IAM",
        "severity": "Medium",
        "remediation": "Deactivate unused access keys (iam:UpdateAccessKey) or delete the login profile (iam:DeleteLoginProfile); remove the user if no longer needed.",
        "refs": {"cis": "2.11", "well_architected": "SEC02-BP05", "soc2": "CC6.3", "iso27001": "A.5.18"},
    },
    "iam_access_key_rotation_90d": {
        "title": "Access keys rotated within 90 days",
        "area": "IAM",
        "severity": "Medium",
        "remediation": "Create a new access key, migrate usage to it, then delete/deactivate the old one.",
        "refs": {"cis": "2.12", "well_architected": "SEC02-BP05", "soc2": "CC6.1", "iso27001": "A.5.17"},
    },
    "iam_permissions_via_group_only": {
        "title": "IAM users receive permissions only through groups",
        "area": "IAM",
        "severity": "Low",
        "remediation": "Move directly-attached/inline policies to a group, add the user to the group, then remove the direct policy from the user.",
        "refs": {"cis": "2.13", "well_architected": "SEC02-BP06", "soc2": "CC6.3", "iso27001": "A.5.15"},
    },
    "iam_no_full_admin_policy": {
        "title": "No IAM policy grants full *:* admin privileges where attached",
        "area": "IAM",
        "severity": "High",
        "remediation": "Detach the overly-broad policy and replace it with a least-privilege customer-managed policy.",
        "refs": {"cis": "2.14", "well_architected": "SEC03-BP02", "soc2": "CC6.3", "iso27001": "A.5.15, A.8.2"},
    },
    "iam_support_role_exists": {
        "title": "A dedicated support role exists for AWS Support incidents",
        "area": "IAM",
        "severity": "Low",
        "remediation": "Create an IAM role with an appropriate trust policy and attach the AWSSupportAccess managed policy.",
        "refs": {"cis": "2.15", "well_architected": "SEC02-BP02", "soc2": "CC6.2", "iso27001": "A.8.2"},
    },
    "s3_block_public_access": {
        "title": "S3 Block Public Access is enabled (account and bucket level)",
        "area": "S3",
        "severity": "Critical",
        "remediation": "aws s3control put-public-access-block (account level) and aws s3api put-public-access-block (per bucket) with all four flags true.",
        "refs": {"cis": "3.1.4", "well_architected": "SEC03-BP07", "soc2": "CC6.1, CC6.6", "iso27001": "A.5.15"},
    },
    "s3_bucket_https_only": {
        "title": "S3 bucket policy denies non-HTTPS requests",
        "area": "S3",
        "severity": "Medium",
        "remediation": "Add a bucket policy Deny statement keyed on aws:SecureTransport=false for all principals/actions.",
        "refs": {"cis": "3.1.1", "well_architected": "SEC08-BP04", "soc2": "CC6.7", "iso27001": "A.8.24"},
    },
    "s3_bucket_mfa_delete": {
        "title": "S3 bucket has MFA Delete enabled",
        "area": "S3",
        "severity": "Low",
        "remediation": "Enable versioning and MFA Delete via the root user: aws s3api put-bucket-versioning --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa '<device-arn> <code>'.",
        "refs": {"cis": "3.1.2", "well_architected": "SEC08-BP04", "soc2": "CC6.7", "iso27001": "A.8.24"},
    },
    "s3_bucket_logging_enabled": {
        "title": "S3 bucket has access logging enabled",
        "area": "S3",
        "severity": "Medium",
        "remediation": "Enable S3 server access logging (or CloudTrail S3 data events) delivered to a dedicated, access-restricted bucket.",
        "refs": {"cis": "4.8, 4.9", "well_architected": "SEC04-BP01", "soc2": "CC7.1", "iso27001": "A.8.15"},
    },
    "cloudtrail_multi_region_enabled": {
        "title": "A multi-region CloudTrail trail is enabled and logging",
        "area": "CloudTrail / Logging",
        "severity": "Critical",
        "remediation": "aws cloudtrail create-trail --is-multi-region-trail, then aws cloudtrail start-logging.",
        "refs": {"cis": "4.1", "well_architected": "SEC04-BP01", "soc2": "CC7.1, CC7.2", "iso27001": "A.8.15"},
    },
    "cloudtrail_log_file_validation": {
        "title": "CloudTrail log file validation is enabled",
        "area": "CloudTrail / Logging",
        "severity": "Medium",
        "remediation": "aws cloudtrail update-trail --enable-log-file-validation",
        "refs": {"cis": "4.2", "well_architected": "SEC04-BP01", "soc2": "CC7.1", "iso27001": "A.5.28"},
    },
    "cloudtrail_bucket_access_logging": {
        "title": "The CloudTrail S3 bucket itself has access logging enabled",
        "area": "CloudTrail / Logging",
        "severity": "Medium",
        "remediation": "aws s3api put-bucket-logging on the CloudTrail destination bucket, targeting a separate log bucket.",
        "refs": {"cis": "4.4", "well_architected": "SEC04-BP02", "soc2": "CC6.1", "iso27001": "A.8.15"},
    },
    "cloudtrail_kms_encryption": {
        "title": "CloudTrail logs are encrypted at rest with a KMS CMK",
        "area": "CloudTrail / Logging",
        "severity": "Medium",
        "remediation": "aws cloudtrail update-trail --kms-key-id <key-arn> (grant CloudTrail the needed key-policy permissions).",
        "refs": {"cis": "4.5", "well_architected": "SEC04-BP01", "soc2": "CC6.1", "iso27001": "A.8.24"},
    },
    "vpc_flow_logs_enabled": {
        "title": "Every VPC has flow logging enabled",
        "area": "Security Groups / VPC",
        "severity": "Medium",
        "remediation": "aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL ...",
        "refs": {"cis": "4.7", "well_architected": "SEC04-BP01", "soc2": "CC7.2", "iso27001": "A.8.16"},
    },
    "sg_no_open_admin_ports_ipv4": {
        "title": "No security group allows 0.0.0.0/0 ingress to admin ports",
        "area": "Security Groups / VPC",
        "severity": "Critical",
        "remediation": "aws ec2 revoke-security-group-ingress to remove/narrow the rule; use a bastion or SSM Session Manager instead.",
        "refs": {"cis": "6.3", "well_architected": "SEC05-BP02", "soc2": "CC6.1, CC6.6", "iso27001": "A.8.20"},
    },
    "sg_no_open_admin_ports_ipv6": {
        "title": "No security group allows ::/0 ingress to admin ports",
        "area": "Security Groups / VPC",
        "severity": "Critical",
        "remediation": "Same as the IPv4 variant, via aws ec2 revoke-security-group-ingress targeting the IPv6 range entry.",
        "refs": {"cis": "6.4", "well_architected": "SEC05-BP02", "soc2": "CC6.1, CC6.6", "iso27001": "A.8.20"},
    },
    "sg_default_restricts_traffic": {
        "title": "The default security group of every VPC restricts all traffic",
        "area": "Security Groups / VPC",
        "severity": "Low",
        "remediation": "Move resources off the default security group, then strip all ingress/egress rules from it.",
        "refs": {"cis": "6.5", "well_architected": "SEC05-BP01", "soc2": "CC6.1", "iso27001": "A.8.20"},
    },
    "ec2_imdsv2_required": {
        "title": "EC2 instances require IMDSv2",
        "area": "Security Groups / VPC",
        "severity": "Medium",
        "remediation": "aws ec2 modify-instance-metadata-options --http-tokens required --http-endpoint enabled; set this as the default for new launches.",
        "refs": {"cis": "6.7", "well_architected": "SEC05-BP02", "soc2": "CC6.1", "iso27001": "A.8.20"},
    },
    "default_vpc_exists": {
        "title": "No unmanaged default VPC remains in this region",
        "area": "Security Groups / VPC",
        "severity": "Low",
        "remediation": "If this default VPC is not in active, documented use: terminate/detach anything still attached to it, delete its default subnets and internet gateway, then `aws ec2 delete-vpc --vpc-id <vpc-id>` (AWS requires the VPC to be empty first - work bottom-up: ENIs/instances, then the IGW, then the subnets, then the VPC). If it IS intentionally retained and in use, document that decision rather than leaving it as an unreviewed, auto-created default - see references/remediation-and-retesting.md.",
        # No CIS AWS Foundations Benchmark, SOC 2, or ISO 27001 control specifically
        # requires deleting the default VPC - it's an AWS best practice (every default
        # VPC ships with public subnets and an internet gateway pre-attached, which is
        # the opposite of intentional network layering), not a framework control. Track
        # it as informational for those three rather than fabricating a control ID; see
        # check-catalog.md's footnote and remediation-and-retesting.md's "Findings
        # outside the audited framework's scope."
        "refs": {
            "cis": "Not in CIS v7.0.0 scope (AWS best practice)",
            "well_architected": "SEC05-BP01",
            "soc2": "Not a TSC control (AWS best practice)",
            "iso27001": "Not a specific Annex A control (AWS best practice)",
        },
    },
}

FRAMEWORK_KEYS = {"cis", "well_architected", "soc2", "iso27001"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _covers_port(from_port, to_port, protocol, target_port):
    """Does this permission's port range (with its protocol) cover target_port?"""
    if protocol == "-1":
        return True
    if from_port is None or to_port is None:
        return False
    return from_port <= target_port <= to_port


def _rule_open_to(perm, cidr_key, wildcard_cidr):
    return any(r.get("CidrIp" if cidr_key == "ipv4" else "CidrIpv6") == wildcard_cidr
               for r in perm.get("IpRanges" if cidr_key == "ipv4" else "Ipv6Ranges", []))


def _sg_open_to_admin_ports(security_groups, cidr_key, wildcard_cidr):
    """Return list of (group_id, port) tuples where the SG is open to wildcard_cidr on an admin port."""
    findings = []
    for sg in security_groups:
        for perm in sg.get("ip_permissions", []):
            protocol = perm.get("IpProtocol", "-1")
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            if not _rule_open_to(perm, cidr_key, wildcard_cidr):
                continue
            for admin_from, admin_to in ADMIN_PORTS:
                if protocol == "-1" or (
                    from_port is not None and to_port is not None
                    and from_port <= admin_to and to_port >= admin_from
                ):
                    findings.append((sg["group_id"], admin_from))
    return findings


def _reference_now(snap):
    """Reference 'current time' for age calculations: the snapshot's own
    collected_at timestamp if present, otherwise wall-clock time. Anchoring to
    collected_at keeps age-based checks (45-day unused, 90-day rotation)
    deterministic for a given snapshot regardless of when run_checks.py is
    actually executed."""
    collected_at = snap.get("collected_at")
    if collected_at:
        try:
            return datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def load_exceptions(path):
    """Load an --exceptions file. See references/exceptions-and-exclusions.md
    for the schema. Returns {} if path is None."""
    if not path:
        return {}
    with open(path) as f:
        return json.load(f)


def _root_has_no_usable_credentials(snap):
    """Direct evidence from the collected data (never from the exceptions
    file) of whether root genuinely has no usable sign-in path: no console
    login profile (password), no access keys, no MFA device. Returns
    (ok: bool, detail: str). ok is True only when all three are absent -
    this is the actual substance behind a "root credentials are centrally
    managed" claim, not a substitute for it. A claim can be true in spirit
    (org-wide root management is configured) while being stale or
    incomplete for this specific account (e.g. management was enabled
    after this account already had a root access key), so the claim alone
    is never enough to flip these checks to "pass"."""
    iam = snap.get("iam", {})
    account_summary = iam.get("account_summary", {})
    rows = iam.get("credential_report") or []
    root_row = next((r for r in rows if r.get("user") == "<root_account>"), None)

    problems = []

    if root_row is not None and "password_enabled" in root_row:
        has_password = str(root_row["password_enabled"]).lower() == "true"
    else:
        has_password = bool(account_summary.get("AccountPasswordPresent"))
    if has_password:
        problems.append("root has a console login profile (password) set")

    if "root_access_keys_present" in iam:
        has_keys = bool(iam["root_access_keys_present"])
    else:
        has_keys = bool(account_summary.get("AccountAccessKeysPresent"))
    if has_keys:
        problems.append("root has at least one access key present")

    if "root_mfa_enabled" in iam:
        has_mfa = bool(iam["root_mfa_enabled"])
    else:
        has_mfa = bool(account_summary.get("AccountMFAEnabled"))
    if has_mfa:
        problems.append("root has an MFA device registered")

    if problems:
        return False, "; ".join(problems)
    return True, "no login profile, no access keys, no MFA device"


def _root_centrally_managed(snap, exceptions):
    """Is this account's root user credentials centrally managed via AWS
    Organizations (deleted/disabled org-wide, not just locally hardened)?
    Returns (is_managed: bool, evidence_note: str | None, contradiction: str | None).

    A claim of central management can come from two places:
      1. Auto-detected: collect_aws_data.py successfully called
         iam:ListOrganizationsFeatures (only possible when it ran from the
         Organizations management account or IAM's delegated administrator)
         and RootCredentialsManagement was in the enabled-features list.
      2. Attested: the person running the audit confirmed it out-of-band
         (e.g. by checking from the management account) and recorded that in
         --exceptions as root_credentials_centrally_managed.attested=true.
    Auto-detection is preferred when both are present, since it's not relying
    on an unverified human claim; attestation exists because most audits run
    from inside the member account being audited, where the API genuinely
    cannot be called (AccountNotManagementOrDelegatedAdministrator) and no
    amount of re-trying will produce a different answer.

    Neither source is trusted on its own. A claim only results in
    is_managed=True when it's corroborated by _root_has_no_usable_credentials:
    no login profile, no access keys, no MFA device. If a claim exists but
    the data disagrees with it, is_managed is False (the normal check logic
    runs, exactly as if no claim had been made) and `contradiction` carries
    an explanation to attach to that check's evidence - so a stale or
    incomplete attestation shows up as a loud, specific discrepancy instead
    of either silently passing or silently falling back with no explanation.
    """
    org = snap.get("organization") or {}
    claimed = False
    claim_note = None
    if org.get("root_credentials_management_queryable") and org.get("root_credentials_management_enabled") is True:
        claimed = True
        claim_note = (
            f"Auto-detected via iam:ListOrganizationsFeatures (org {org.get('organization_id')}): "
            "RootCredentialsManagement is enabled."
        )
    else:
        attestation = (exceptions or {}).get("root_credentials_centrally_managed") or {}
        if attestation.get("attested") is True:
            by = attestation.get("attested_by", "unspecified")
            when = attestation.get("attested_date", "unspecified date")
            note = attestation.get("note", "")
            claimed = True
            claim_note = f"Attested by {by} on {when} (not auto-verifiable from this account): {note}".rstrip(": ")

    if not claimed:
        return False, None, None

    evidence_ok, detail = _root_has_no_usable_credentials(snap)
    if evidence_ok:
        return True, claim_note, None

    contradiction = (
        f"{claim_note} However, collected data contradicts this: {detail}. "
        "Not applying the exception - treating as a real finding until this is resolved "
        "(either central management wasn't actually applied here or has drifted, or the "
        "exceptions file needs correcting)."
    )
    return False, None, contradiction


def _match_accepted_admin_principal(name, arn, exceptions):
    """Check `name` (a role/user name) and `arn` against the
    accepted_admin_principals list in --exceptions. Returns the matching
    exception entry dict (with its "note") or None."""
    for entry in (exceptions or {}).get("accepted_admin_principals", []):
        pattern = entry.get("pattern")
        if not pattern:
            continue
        match_field = name if entry.get("match", "name") == "name" else arn
        if match_field and re.search(pattern, match_field):
            return entry
    return None


# ---------------------------------------------------------------------------
# Check functions. Each returns a list of {resource, status, evidence} dicts.
# status is "pass", "fail", or "accepted" (only ever set when --exceptions
# explicitly matches - see _root_centrally_managed / _match_accepted_admin_principal).
# An empty list (with no exception) is valid when there's genuinely nothing to
# evaluate (e.g. no S3 buckets at all).
# ---------------------------------------------------------------------------

def check_root_mfa_enabled(snap, exceptions=None):
    iam = snap.get("iam", {})
    if "root_mfa_enabled" not in iam:
        return None
    managed, note, contradiction = _root_centrally_managed(snap, exceptions)
    if managed:
        return [{
            "resource": "root",
            "status": "pass",
            "evidence": f"AccountMFAEnabled={iam.get('account_summary', {}).get('AccountMFAEnabled')} - "
                        f"root credentials are centrally managed, not self-managed with MFA. {note}",
        }]
    enabled = iam["root_mfa_enabled"]
    evidence = f"AccountMFAEnabled={iam.get('account_summary', {}).get('AccountMFAEnabled')}"
    if contradiction:
        evidence += f" {contradiction}"
    return [{
        "resource": "root",
        "status": "pass" if enabled else "fail",
        "evidence": evidence,
    }]


def check_root_hardware_mfa(snap, exceptions=None):
    iam = snap.get("iam", {})
    if "root_mfa_enabled" not in iam:
        return None
    managed, note, contradiction = _root_centrally_managed(snap, exceptions)
    if managed:
        return [{
            "resource": "root",
            "status": "pass",
            "evidence": f"Root credentials are centrally managed; no locally-held MFA device to assess. {note}",
        }]
    if not iam["root_mfa_enabled"]:
        evidence = "Root has no MFA device at all."
        if contradiction:
            evidence += f" {contradiction}"
        return [{"resource": "root", "status": "fail", "evidence": evidence}]
    has_virtual = iam.get("root_has_virtual_mfa")
    if has_virtual is None:
        return None
    evidence = "Root MFA device is virtual." if has_virtual else "Root MFA device is not virtual (hardware/FIDO assumed)."
    if contradiction:
        evidence += f" {contradiction}"
    return [{
        "resource": "root",
        "status": "fail" if has_virtual else "pass",
        "evidence": evidence,
    }]


def check_root_no_access_keys(snap, exceptions=None):
    iam = snap.get("iam", {})
    if "root_access_keys_present" not in iam:
        return None
    present = iam["root_access_keys_present"]
    managed, note, contradiction = _root_centrally_managed(snap, exceptions)
    evidence = f"AccountAccessKeysPresent={iam.get('account_summary', {}).get('AccountAccessKeysPresent')}"
    if managed:
        evidence += f" - root credentials are centrally managed. {note}"
    elif contradiction:
        evidence += f" {contradiction}"
    return [{"resource": "root", "status": "fail" if present else "pass", "evidence": evidence}]


def check_root_not_used_routinely(snap, exceptions=None):
    iam = snap.get("iam", {})
    rows = iam.get("credential_report")
    if rows is None:
        return None
    root_row = next((r for r in rows if r.get("user") == "<root_account>"), None)
    if root_row is None:
        return None

    managed, note, contradiction = _root_centrally_managed(snap, exceptions)
    if managed:
        return [{
            "resource": "root",
            "status": "pass",
            "evidence": f"Root credentials are centrally managed; root cannot sign in to be used routinely. {note}",
        }]

    window_days = (exceptions or {}).get("root_routine_use_window_days", 365)
    last_used_fields = ["password_last_used", "access_key_1_last_used_date", "access_key_2_last_used_date"]
    now = _reference_now(snap)
    recent = []
    stale = []
    for field in last_used_fields:
        val = root_row.get(field)
        if not val or val in ("N/A", "no_information", "not_supported"):
            continue
        try:
            last_used = datetime.fromisoformat(val.replace("Z", "+00:00"))
            age_days = (now - last_used).days
        except ValueError:
            continue
        if age_days <= window_days:
            recent.append(f"{field}={val} ({age_days}d ago)")
        else:
            stale.append(f"{field}={val} ({age_days}d ago)")

    status = "fail" if recent else "pass"
    if recent:
        evidence = f"Used within the {window_days}-day review window: {', '.join(recent)}."
    elif stale:
        evidence = f"Only activity older than the {window_days}-day review window: {', '.join(stale)}. Not treated as routine use."
    else:
        evidence = "No root login or access-key activity recorded in the credential report."
    if contradiction:
        evidence += f" {contradiction}"
    return [{"resource": "root", "status": status, "evidence": evidence}]


def check_account_security_contact_registered(snap):
    contacts = snap.get("account_contacts")
    if contacts is None:
        return None
    sec = contacts.get("security_contact")
    return [{
        "resource": "account",
        "status": "pass" if sec else "fail",
        "evidence": "Security alternate contact is set." if sec else "No Security alternate contact registered.",
    }]


def check_iam_password_policy_length(snap):
    iam = snap.get("iam", {})
    if "password_policy" not in iam:
        return None
    policy = iam["password_policy"]
    if policy is None:
        return [{"resource": "account", "status": "fail", "evidence": "No account password policy is set."}]
    length = policy.get("MinimumPasswordLength", 0)
    return [{"resource": "account", "status": "pass" if length >= 14 else "fail", "evidence": f"MinimumPasswordLength={length}"}]


def check_iam_password_policy_reuse(snap):
    iam = snap.get("iam", {})
    if "password_policy" not in iam:
        return None
    policy = iam["password_policy"]
    if policy is None:
        return [{"resource": "account", "status": "fail", "evidence": "No account password policy is set."}]
    reuse = policy.get("PasswordReusePrevention", 0)
    return [{"resource": "account", "status": "pass" if reuse and reuse >= 24 else "fail", "evidence": f"PasswordReusePrevention={reuse}"}]


def check_iam_user_mfa_console_access(snap):
    iam = snap.get("iam", {})
    rows = iam.get("credential_report")
    if rows is None:
        return None
    results = []
    for row in rows:
        user = row.get("user")
        if user == "<root_account>":
            continue
        if str(row.get("password_enabled", "false")).lower() != "true":
            continue
        mfa_active = str(row.get("mfa_active", "false")).lower() == "true"
        results.append({
            "resource": user,
            "status": "pass" if mfa_active else "fail",
            "evidence": f"password_enabled=true, mfa_active={row.get('mfa_active')}",
        })
    return results


def check_iam_credentials_unused_45d(snap, exceptions=None):
    iam = snap.get("iam", {})
    rows = iam.get("credential_report")
    if rows is None:
        return None
    managed, note, contradiction = _root_centrally_managed(snap, exceptions)
    results = []
    now = _reference_now(snap)
    for row in rows:
        user = row.get("user")
        if user == "<root_account>" and managed:
            results.append({
                "resource": user,
                "status": "pass",
                "evidence": f"Root credentials are centrally managed; root cannot sign in to accrue activity. {note}",
            })
            continue
        stale_fields = []
        for field in ("password_last_used", "access_key_1_last_used_date", "access_key_2_last_used_date"):
            val = row.get(field)
            if not val or val in ("N/A", "no_information", "not_supported"):
                continue
            try:
                last_used = datetime.fromisoformat(val.replace("Z", "+00:00"))
                age_days = (now - last_used).days
                if age_days > 45:
                    stale_fields.append(f"{field}={val} ({age_days}d)")
            except ValueError:
                continue
        evidence = "; ".join(stale_fields) if stale_fields else "All active credentials used within 45 days."
        if user == "<root_account>" and contradiction:
            evidence += f" {contradiction}"
        results.append({
            "resource": user,
            "status": "fail" if stale_fields else "pass",
            "evidence": evidence,
        })
    return results


def check_iam_access_key_rotation_90d(snap):
    iam = snap.get("iam", {})
    rows = iam.get("credential_report")
    if rows is None:
        return None
    results = []
    now = _reference_now(snap)
    for row in rows:
        user = row.get("user")
        old_keys = []
        for num in ("1", "2"):
            active = str(row.get(f"access_key_{num}_active", "false")).lower() == "true"
            rotated = row.get(f"access_key_{num}_last_rotated")
            if not active or not rotated or rotated in ("N/A", "not_supported"):
                continue
            try:
                last_rotated = datetime.fromisoformat(rotated.replace("Z", "+00:00"))
                age_days = (now - last_rotated).days
                if age_days > 90:
                    old_keys.append(f"key{num} rotated {age_days}d ago")
            except ValueError:
                continue
        results.append({
            "resource": user,
            "status": "fail" if old_keys else "pass",
            "evidence": "; ".join(old_keys) if old_keys else "All active access keys rotated within 90 days.",
        })
    return results


def check_iam_permissions_via_group_only(snap):
    iam = snap.get("iam", {})
    users = iam.get("users")
    if users is None:
        return None
    return [{
        "resource": u["user_name"],
        "status": "fail" if u.get("has_direct_attachment") else "pass",
        "evidence": f"attached_managed_policies={u.get('attached_managed_policies')}, inline_policy_names={u.get('inline_policy_names')}",
    } for u in users]


def check_iam_no_full_admin_policy(snap, exceptions=None):
    """Flag every admin-wildcard (Action:* + Resource:*) policy attachment.

    A policy is the resource for any snapshot collected before
    collect_aws_data.py started recording who a policy is attached to
    (attached_role_names/attached_user_names/attached_group_names) - that's
    the pre-existing, conservative per-policy behavior, kept as a fallback so
    older snapshots still evaluate the same way they always did.

    Once attachment data is present, each attached role/user is its own
    finding (naming who actually holds the policy, not just that the policy
    exists), and is matched against --exceptions' accepted_admin_principals:
    a match downgrades "fail" to "accepted" - still enumerated with full
    evidence, never silently dropped - for principals like a named
    OrganizationAccountAccessRole or a documented break-glass role where
    full-admin access is a deliberate, reviewed decision rather than an
    oversight.
    """
    iam = snap.get("iam", {})
    policies = iam.get("policies")
    if policies is None:
        return None

    results = []
    for p in policies:
        if not p.get("is_admin_wildcard"):
            results.append({
                "resource": p["policy_name"],
                "status": "pass",
                "evidence": f"arn={p['arn']}, is_admin_wildcard=False",
            })
            continue

        has_attachment_data = any(
            k in p for k in ("attached_role_names", "attached_user_names", "attached_group_names")
        )
        if not has_attachment_data:
            # Pre-upgrade snapshot: no record of who holds this policy.
            results.append({
                "resource": p["policy_name"],
                "status": "fail",
                "evidence": f"arn={p['arn']}, is_admin_wildcard=True",
            })
            continue

        principals = (
            [("role", n) for n in p.get("attached_role_names", [])]
            + [("user", n) for n in p.get("attached_user_names", [])]
            + [("group", n) for n in p.get("attached_group_names", [])]
        )
        if not principals:
            # Admin-wildcard policy exists but is attached to nothing we could
            # enumerate (e.g. attached only to a group we didn't resolve, or
            # list_entities_for_policy failed) - still worth a finding on the
            # policy itself so it isn't silently dropped.
            results.append({
                "resource": p["policy_name"],
                "status": "fail",
                "evidence": f"arn={p['arn']}, is_admin_wildcard=True, no attached principals could be enumerated",
            })
            continue

        for kind, name in principals:
            accepted = _match_accepted_admin_principal(name, p["arn"], exceptions)
            resource = f"{p['policy_name']} → {kind}:{name}"
            if accepted:
                results.append({
                    "resource": resource,
                    "status": "accepted",
                    "evidence": f"arn={p['arn']}. Accepted: {accepted.get('note', 'matches an accepted_admin_principals rule')} "
                                f"(pattern: {accepted.get('pattern')}).",
                })
            else:
                results.append({
                    "resource": resource,
                    "status": "fail",
                    "evidence": f"arn={p['arn']}, is_admin_wildcard=True, attached directly to {kind} '{name}'.",
                })
    return results


def check_iam_support_role_exists(snap):
    iam = snap.get("iam", {})
    if "support_role_exists" not in iam:
        return None
    exists = iam["support_role_exists"]
    return [{"resource": "account", "status": "pass" if exists else "fail", "evidence": f"support_role_exists={exists}"}]


def check_s3_block_public_access(snap):
    s3 = snap.get("s3", {})
    results = []
    account_pab = s3.get("account_public_access_block")
    if account_pab is not None:
        all_true = all(account_pab.get(f) for f in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
        results.append({"resource": "account", "status": "pass" if all_true else "fail", "evidence": str(account_pab)})
    buckets = s3.get("buckets")
    if buckets is not None:
        for b in buckets:
            pab = b.get("public_access_block")
            if pab is None:
                results.append({"resource": b["name"], "status": "fail", "evidence": "No bucket-level Block Public Access configuration."})
                continue
            all_true = all(pab.get(f) for f in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
            results.append({"resource": b["name"], "status": "pass" if all_true else "fail", "evidence": str(pab)})
    return results or None


def check_s3_bucket_https_only(snap):
    buckets = snap.get("s3", {}).get("buckets")
    if buckets is None:
        return None
    return [{
        "resource": b["name"],
        "status": "pass" if b.get("has_https_only_deny") else "fail",
        "evidence": f"has_https_only_deny={b.get('has_https_only_deny')}",
    } for b in buckets]


def check_s3_bucket_mfa_delete(snap):
    buckets = snap.get("s3", {}).get("buckets")
    if buckets is None:
        return None
    return [{
        "resource": b["name"],
        "status": "pass" if b.get("mfa_delete") == "Enabled" else "fail",
        "evidence": f"versioning_status={b.get('versioning_status')}, mfa_delete={b.get('mfa_delete')}",
    } for b in buckets]


def check_s3_bucket_logging_enabled(snap):
    buckets = snap.get("s3", {}).get("buckets")
    if buckets is None:
        return None
    return [{
        "resource": b["name"],
        "status": "pass" if b.get("logging_enabled") else "fail",
        "evidence": f"logging_enabled={b.get('logging_enabled')}",
    } for b in buckets]


def check_cloudtrail_multi_region_enabled(snap):
    trails = snap.get("cloudtrail", {}).get("trails")
    if trails is None:
        return None
    matching = [t for t in trails if t.get("is_multi_region_trail") and t.get("is_logging")]
    status = "pass" if matching else "fail"
    evidence = f"{len(matching)} multi-region trail(s) actively logging out of {len(trails)} total trail(s)."
    return [{"resource": "account", "status": status, "evidence": evidence}]


def check_cloudtrail_log_file_validation(snap):
    trails = snap.get("cloudtrail", {}).get("trails")
    if trails is None:
        return None
    return [{
        "resource": t.get("name"),
        "status": "pass" if t.get("log_file_validation_enabled") else "fail",
        "evidence": f"log_file_validation_enabled={t.get('log_file_validation_enabled')}",
    } for t in trails]


def check_cloudtrail_bucket_access_logging(snap):
    trails = snap.get("cloudtrail", {}).get("trails")
    if trails is None:
        return None
    results = []
    for t in trails:
        val = t.get("s3_bucket_access_logging_enabled")
        if val is None:
            continue
        results.append({
            "resource": t.get("s3_bucket_name") or t.get("name"),
            "status": "pass" if val else "fail",
            "evidence": f"s3_bucket_access_logging_enabled={val}",
        })
    return results or None


def check_cloudtrail_kms_encryption(snap):
    trails = snap.get("cloudtrail", {}).get("trails")
    if trails is None:
        return None
    return [{
        "resource": t.get("name"),
        "status": "pass" if t.get("kms_key_id") else "fail",
        "evidence": f"kms_key_id={t.get('kms_key_id')}",
    } for t in trails]


def check_vpc_flow_logs_enabled(snap):
    ec2 = snap.get("ec2", {})
    vpcs = ec2.get("vpcs")
    flow_logs = ec2.get("flow_logs")
    if vpcs is None or flow_logs is None:
        return None
    logged_resource_ids = {fl.get("resource_id") for fl in flow_logs if fl.get("flow_log_status") == "ACTIVE"}
    return [{
        "resource": f"{v['vpc_id']} ({v['region']})",
        "status": "pass" if v["vpc_id"] in logged_resource_ids else "fail",
        "evidence": f"active_flow_log_present={v['vpc_id'] in logged_resource_ids}",
    } for v in vpcs]


def check_sg_no_open_admin_ports_ipv4(snap):
    sgs = snap.get("ec2", {}).get("security_groups")
    if sgs is None:
        return None
    flagged = _sg_open_to_admin_ports(sgs, "ipv4", "0.0.0.0/0")
    flagged_ids = {gid for gid, _ in flagged}
    return [{
        "resource": sg["group_id"],
        "status": "fail" if sg["group_id"] in flagged_ids else "pass",
        "evidence": "Open to 0.0.0.0/0 on an admin port (22/3389)." if sg["group_id"] in flagged_ids else "No 0.0.0.0/0 ingress on admin ports.",
    } for sg in sgs]


def check_sg_no_open_admin_ports_ipv6(snap):
    sgs = snap.get("ec2", {}).get("security_groups")
    if sgs is None:
        return None
    flagged = _sg_open_to_admin_ports(sgs, "ipv6", "::/0")
    flagged_ids = {gid for gid, _ in flagged}
    return [{
        "resource": sg["group_id"],
        "status": "fail" if sg["group_id"] in flagged_ids else "pass",
        "evidence": "Open to ::/0 on an admin port (22/3389)." if sg["group_id"] in flagged_ids else "No ::/0 ingress on admin ports.",
    } for sg in sgs]


def check_sg_default_restricts_traffic(snap):
    sgs = snap.get("ec2", {}).get("security_groups")
    if sgs is None:
        return None
    results = []
    for sg in sgs:
        if sg.get("group_name") != "default":
            continue
        restricted = not sg.get("ip_permissions") and not sg.get("ip_permissions_egress")
        results.append({
            "resource": f"{sg['group_id']} ({sg.get('vpc_id')})",
            "status": "pass" if restricted else "fail",
            "evidence": f"ingress_rules={len(sg.get('ip_permissions', []))}, egress_rules={len(sg.get('ip_permissions_egress', []))}",
        })
    return results or None


def check_ec2_imdsv2_required(snap):
    instances = snap.get("ec2", {}).get("instances")
    if instances is None:
        return None
    running = [i for i in instances if i.get("state") == "running"]
    return [{
        "resource": i["instance_id"],
        "status": "pass" if i.get("http_tokens") == "required" else "fail",
        "evidence": f"http_tokens={i.get('http_tokens')}",
    } for i in running]


def check_default_vpc_exists(snap):
    vpcs = snap.get("ec2", {}).get("vpcs")
    if vpcs is None:
        return None
    # Each entry here is a VPC that actually exists in the account today. A
    # region whose default VPC was already deleted simply has no entry for
    # it - that's the passing state, not something to report "skipped" or
    # synthesize a pass for; nothing to check means nothing to flag.
    return [{
        "resource": f"{v['vpc_id']} ({v['region']})",
        "status": "fail" if v.get("is_default") else "pass",
        "evidence": (
            f"is_default={v.get('is_default', False)}; "
            + ("this is the AWS auto-created default VPC for this region."
               if v.get("is_default")
               else "a custom (non-default) VPC.")
        ),
    } for v in vpcs]


CHECK_FUNCS = {
    "root_mfa_enabled": check_root_mfa_enabled,
    "root_hardware_mfa": check_root_hardware_mfa,
    "root_no_access_keys": check_root_no_access_keys,
    "root_not_used_routinely": check_root_not_used_routinely,
    "account_security_contact_registered": check_account_security_contact_registered,
    "iam_password_policy_length": check_iam_password_policy_length,
    "iam_password_policy_reuse": check_iam_password_policy_reuse,
    "iam_user_mfa_console_access": check_iam_user_mfa_console_access,
    "iam_credentials_unused_45d": check_iam_credentials_unused_45d,
    "iam_access_key_rotation_90d": check_iam_access_key_rotation_90d,
    "iam_permissions_via_group_only": check_iam_permissions_via_group_only,
    "iam_no_full_admin_policy": check_iam_no_full_admin_policy,
    "iam_support_role_exists": check_iam_support_role_exists,
    "s3_block_public_access": check_s3_block_public_access,
    "s3_bucket_https_only": check_s3_bucket_https_only,
    "s3_bucket_mfa_delete": check_s3_bucket_mfa_delete,
    "s3_bucket_logging_enabled": check_s3_bucket_logging_enabled,
    "cloudtrail_multi_region_enabled": check_cloudtrail_multi_region_enabled,
    "cloudtrail_log_file_validation": check_cloudtrail_log_file_validation,
    "cloudtrail_bucket_access_logging": check_cloudtrail_bucket_access_logging,
    "cloudtrail_kms_encryption": check_cloudtrail_kms_encryption,
    "vpc_flow_logs_enabled": check_vpc_flow_logs_enabled,
    "sg_no_open_admin_ports_ipv4": check_sg_no_open_admin_ports_ipv4,
    "sg_no_open_admin_ports_ipv6": check_sg_no_open_admin_ports_ipv6,
    "sg_default_restricts_traffic": check_sg_default_restricts_traffic,
    "ec2_imdsv2_required": check_ec2_imdsv2_required,
    "default_vpc_exists": check_default_vpc_exists,
}


def run(snapshot, framework, exceptions=None):
    exceptions = exceptions or {}
    findings = []
    checks_evaluated = []
    checks_skipped = []

    for check_id, meta in CHECKS_META.items():
        if framework != "all" and framework not in meta["refs"]:
            continue
        func = CHECK_FUNCS[check_id]
        # Only the handful of checks that actually use --exceptions declare
        # the parameter; everything else keeps its original one-arg signature.
        if "exceptions" in inspect.signature(func).parameters:
            results = func(snapshot, exceptions=exceptions)
        else:
            results = func(snapshot)
        if results is None:
            checks_skipped.append(check_id)
            continue
        checks_evaluated.append(check_id)
        for r in results:
            findings.append({
                "check_id": check_id,
                "title": meta["title"],
                "area": meta["area"],
                "severity": meta["severity"],
                "remediation": meta["remediation"],
                "refs": meta["refs"] if framework == "all" else {framework: meta["refs"].get(framework)},
                "resource": r["resource"],
                "status": r["status"],
                "evidence": r["evidence"],
            })

    failed = [f for f in findings if f["status"] == "fail"]
    passed = [f for f in findings if f["status"] == "pass"]
    accepted = [f for f in findings if f["status"] == "accepted"]
    by_severity = {}
    for f in failed:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    summary = {
        "account_id": snapshot.get("account_id"),
        "collected_at": snapshot.get("collected_at"),
        "framework": framework,
        "total_findings": len(findings),
        "failed": len(failed),
        "passed": len(passed),
        "accepted": len(accepted),
        "by_severity": by_severity,
        "checks_evaluated": checks_evaluated,
        "checks_skipped": checks_skipped,
        "exceptions_applied": bool(exceptions),
    }

    return {"summary": summary, "findings": findings}


def main():
    parser = argparse.ArgumentParser(description="Evaluate an aws-audit snapshot against a compliance framework.")
    parser.add_argument("snapshot", help="path to the snapshot JSON produced by collect_aws_data.py")
    parser.add_argument("--framework", choices=sorted(FRAMEWORK_KEYS | {"all"}), default="cis")
    parser.add_argument("--exceptions", help="path to an exceptions JSON file - see references/exceptions-and-exclusions.md")
    parser.add_argument("-o", "--output", default="findings.json")
    args = parser.parse_args()

    with open(args.snapshot) as f:
        snapshot = json.load(f)

    exceptions = load_exceptions(args.exceptions)

    result = run(snapshot, args.framework, exceptions)

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2, default=str)

    accepted_count = result["summary"]["accepted"]
    accepted_suffix = f" / {accepted_count} accepted" if accepted_count else ""
    print(
        f"{result['summary']['failed']} failed / {result['summary']['passed']} passed{accepted_suffix} "
        f"({len(result['summary']['checks_evaluated'])} checks evaluated, "
        f"{len(result['summary']['checks_skipped'])} skipped for missing data). "
        f"Wrote {args.output}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
