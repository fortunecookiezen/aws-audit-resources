#!/usr/bin/env bash
#
# collect_admin_role_evidence.sh - record evidence that the AWS-created admin
# roles in an AWS Organizations member account (OrganizationAccountAccessRole,
# service-managed StackSets "stacksets-exec-<hash>" execution roles) are what
# they claim to be: who can assume them, what they hold, and why they exist.
#
# Two halves, run in two places (AWS CloudShell, or any shell with the AWS CLI
# and jq):
#
#   member [role-name ...]
#       Run in the audited member account (the CrossAccountSecurityAuditRole's
#       SecurityAudit policy is enough). Records each role's trust policy,
#       CreateDate, RoleLastUsed, attached and inline policies. With no role
#       names, it records OrganizationAccountAccessRole plus every role whose
#       name starts with "stacksets-exec-".
#
#   management <member-account-id>
#       Run in the Organizations management account. Records how the member
#       account joined (JoinedMethod CREATED means Organizations created
#       OrganizationAccountAccessRole; INVITED means someone created it by
#       hand), whether StackSets trusted access is enabled, and which
#       service-managed StackSets have instances in the member account.
#       From a StackSets delegated administrator account instead, set
#       CALL_AS=DELEGATED_ADMIN.
#
# Usage:
#     bash collect_admin_role_evidence.sh member [role-name ...]
#     bash collect_admin_role_evidence.sh management 111122223333
#     OUT_DIR=/some/dir bash collect_admin_role_evidence.sh ...   (default: .)
#
# Each run writes one admin-role-evidence-<mode>-<account>-<UTC timestamp>.json
# with collected_at and caller_identity, and prints its SHA-256. Save both
# files in the engagement's audit-runs/<account_id>-<YYYYMMDD>/evidence/
# directory and cite them in the documentation request's section 3 Evidence
# column - see references/accepting-findings-process.md.

set -euo pipefail

usage() {
  sed -n '/^# Usage:/,/^#     OUT_DIR/p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

for cmd in aws jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: $cmd is required but not installed." >&2
    exit 1
  fi
done

mode="${1:-}"
[ -n "$mode" ] || usage
shift

out_dir="${OUT_DIR:-.}"
collected_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
file_stamp="$(date -u -d "$collected_at" +%Y%m%dT%H%M%SZ 2>/dev/null || date -u -j -f %Y-%m-%dT%H:%M:%SZ "$collected_at" +%Y%m%dT%H%M%SZ)"
caller_identity="$(aws sts get-caller-identity --output json)"
caller_account="$(jq -r .Account <<<"$caller_identity")"

err_file="$(mktemp)"
trap 'rm -f "$err_file"' EXIT

# aws_json <cli args...>: run an AWS CLI call, print its JSON; on failure print
# {"error": "<message>"} instead, so one missing role or denied call is
# recorded in the evidence rather than aborting the whole run.
aws_json() {
  local out
  if out="$(aws "$@" --output json 2>"$err_file")"; then
    if [ -n "$out" ]; then printf '%s' "$out"; else printf '{}'; fi
  else
    jq -n --arg e "$(tr '\n' ' ' <"$err_file")" '{error: $e}'
  fi
}

write_evidence() {
  local name="$1" body="$2" out_file
  out_file="${out_dir%/}/admin-role-evidence-${name}-${file_stamp}.json"
  jq -n \
    --arg collected_at "$collected_at" \
    --argjson caller_identity "$caller_identity" \
    --argjson body "$body" \
    '{collected_at: $collected_at, caller_identity: $caller_identity} + $body' \
    >"$out_file"
  echo "Wrote $out_file"
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$out_file"; else shasum -a 256 "$out_file"; fi
}

collect_member() {
  local roles=("$@") role get attached inline entries="[]"
  if [ "${#roles[@]}" -eq 0 ]; then
    roles=(OrganizationAccountAccessRole)
    while IFS= read -r role; do
      [ -n "$role" ] && roles+=("$role")
    done < <(aws iam list-roles --output json \
               --query "Roles[?starts_with(RoleName, 'stacksets-exec-')].RoleName" | jq -r '.[]')
  fi

  for role in "${roles[@]}"; do
    get="$(aws_json iam get-role --role-name "$role")"
    attached="$(aws_json iam list-attached-role-policies --role-name "$role")"
    inline="$(aws_json iam list-role-policies --role-name "$role")"
    entries="$(jq \
      --arg name "$role" --argjson get "$get" --argjson attached "$attached" --argjson inline "$inline" \
      '. + [{
         role_name: $name,
         role: ($get.Role // $get),
         attached_policies: ($attached.AttachedPolicies // $attached),
         inline_policy_names: ($inline.PolicyNames // $inline)
       }]' <<<"$entries")"
  done

  write_evidence "member-${caller_account}" "$(jq -n --argjson roles "$entries" '{mode: "member", roles: $roles}')"

  echo
  jq -r '.[] |
    if .role.error then "\(.role_name): NOT FOUND or not readable - \(.role.error)"
    else "\(.role_name): trusted by \([.role.AssumeRolePolicyDocument.Statement[]?.Principal | if type == "object" then (to_entries[].value | if type == "array" then .[] else . end) else . end] | join(", ")); policies: \([.attached_policies[]?.PolicyName] | join(", ")); created \(.role.CreateDate); last used \(.role.RoleLastUsed.LastUsedDate // "never/unknown")"
    end' <<<"$entries"
}

collect_management() {
  local member_account="${1:-}" call_as="${CALL_AS:-SELF}" account service_access stack_sets instances="[]" name inst
  [[ "$member_account" =~ ^[0-9]{12}$ ]] || { echo "ERROR: management mode needs the 12-digit member account ID." >&2; usage; }

  account="$(aws_json organizations describe-account --account-id "$member_account")"
  if jq -e .error >/dev/null <<<"$account"; then
    echo "ERROR: organizations describe-account failed: $(jq -r .error <<<"$account")" >&2
    echo "Run this from the Organizations management account." >&2
    exit 1
  fi
  service_access="$(aws_json organizations list-aws-service-access-for-organization)"
  stack_sets="$(aws_json cloudformation list-stack-sets --status ACTIVE --call-as "$call_as")"

  while IFS= read -r name; do
    [ -n "$name" ] || continue
    inst="$(aws_json cloudformation list-stack-instances --stack-set-name "$name" \
              --stack-instance-account "$member_account" --call-as "$call_as")"
    instances="$(jq --arg name "$name" --argjson inst "$inst" \
      '. + [{stack_set_name: $name, instances: ($inst.Summaries // $inst)}]' <<<"$instances")"
  done < <(jq -r '.Summaries[]? | select(.PermissionModel == "SERVICE_MANAGED") | .StackSetName' <<<"$stack_sets")

  write_evidence "management-${member_account}" "$(jq -n \
    --arg member "$member_account" --argjson account "$account" --argjson access "$service_access" \
    --argjson stack_sets "$stack_sets" --argjson instances "$instances" \
    '{mode: "management",
      member_account_id: $member,
      member_account: ($account.Account // $account),
      enabled_service_principals: ($access.EnabledServicePrincipals // $access),
      service_managed_stack_sets: [($stack_sets.Summaries // [])[] | select(.PermissionModel == "SERVICE_MANAGED")],
      stack_instances_in_member_account: [$instances[] | select((.instances | type) != "array" or (.instances | length) > 0)]}')"

  echo
  jq -r '"Account \(.Id) (\(.Name)) joined the organization by \(.JoinedMethod) on \(.JoinedTimestamp)."' <<<"$(jq '.Account // .' <<<"$account")"
  if [ "$(jq -r '.Account.JoinedMethod' <<<"$account")" = "INVITED" ]; then
    echo "WARNING: the account was invited, so OrganizationAccountAccessRole was created by hand, not by AWS Organizations; it needs the same evidence as any other admin role (who created it, ticket or IaC)." >&2
  fi
  if jq -e '[.EnabledServicePrincipals[]?.ServicePrincipal] | index("member.org.stacksets.cloudformation.amazonaws.com")' >/dev/null <<<"$service_access"; then
    echo "StackSets trusted access is enabled for the organization."
  else
    echo "WARNING: StackSets trusted access is not enabled (or not readable); service-managed stacksets-exec roles shouldn't exist." >&2
  fi
  jq -r 'if length == 0 then "No ACTIVE service-managed StackSet has instances in this account - a stacksets-exec role here may be left over."
         else .[] | "StackSet \(.stack_set_name) has instance(s) in this account." end' <<<"$instances"
}

case "$mode" in
  member) collect_member "$@" ;;
  management) collect_management "$@" ;;
  *) usage ;;
esac
