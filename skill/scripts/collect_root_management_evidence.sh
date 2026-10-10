#!/usr/bin/env bash
#
# collect_root_management_evidence.sh - record who confirmed AWS Organizations
# centralized root access management, from which account, and when.
#
# Run it in AWS CloudShell (or any shell with the AWS CLI and jq), signed in
# to the Organizations management account or IAM's delegated administrator
# account - iam:ListOrganizationsFeatures fails anywhere else. The audited
# member account can't run it.
#
# Usage:
#     bash collect_root_management_evidence.sh [output-dir]
#
# Writes one file, root-management-evidence-<UTC timestamp>.json, containing:
#   - collected_at:           when the commands ran (UTC, ISO 8601)
#   - caller_identity:        aws sts get-caller-identity
#   - organizations_features: aws iam list-organizations-features
# and prints its SHA-256. In CloudShell, download the file (Actions >
# Download file) and save it in the engagement's audit-runs/<account_id>-<YYYYMMDD>/evidence/
# directory. The auditor takes exceptions.json's attested_by from
# caller_identity and attested_date from collected_at - see
# references/exceptions-and-exclusions.md, "From the documentation request."

set -euo pipefail

out_dir="${1:-.}"

for cmd in aws jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: $cmd is required but not installed." >&2
    exit 1
  fi
done

collected_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
file_stamp="$(date -u -d "$collected_at" +%Y%m%dT%H%M%SZ 2>/dev/null || date -u -j -f %Y-%m-%dT%H:%M:%SZ "$collected_at" +%Y%m%dT%H%M%SZ)"

caller_identity="$(aws sts get-caller-identity --output json)"

err_file="$(mktemp)"
trap 'rm -f "$err_file"' EXIT
if ! features="$(aws iam list-organizations-features --output json 2>"$err_file")"; then
  echo "ERROR: aws iam list-organizations-features failed:" >&2
  cat "$err_file" >&2
  echo "Run this from the Organizations management account or IAM's delegated administrator account." >&2
  exit 1
fi

out_file="${out_dir%/}/root-management-evidence-${file_stamp}.json"
jq -n \
  --arg collected_at "$collected_at" \
  --argjson caller_identity "$caller_identity" \
  --argjson organizations_features "$features" \
  '{collected_at: $collected_at, caller_identity: $caller_identity, organizations_features: $organizations_features}' \
  > "$out_file"

echo "Wrote $out_file"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$out_file"
else
  shasum -a 256 "$out_file"
fi

if jq -e '.organizations_features.EnabledFeatures | index("RootCredentialsManagement")' "$out_file" >/dev/null; then
  echo "RootCredentialsManagement is enabled for $(jq -r '.organizations_features.OrganizationId' "$out_file")."
else
  echo "WARNING: RootCredentialsManagement is NOT enabled; this file does not support a centrally-managed claim." >&2
fi
