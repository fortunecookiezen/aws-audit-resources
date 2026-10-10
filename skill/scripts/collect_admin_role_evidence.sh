#!/usr/bin/env bash
#
# collect_admin_role_evidence.sh - record evidence that the admin roles AWS
# services create in an AWS Organizations member account are what they claim
# to be: who can assume them, what they hold, and why they exist. Covers
# OrganizationAccountAccessRole, service-managed StackSets
# "stacksets-exec-<hash>" execution roles, and IAM Identity Center
# "AWSReservedSSO_<permission set>_<hash>" roles.
#
# Two halves, run in two places (AWS CloudShell, or any shell with the AWS CLI
# and jq):
#
#   member [role-name ...]
#       Run in the audited member account (the CrossAccountSecurityAuditRole's
#       SecurityAudit policy is enough). Records each role's trust policy,
#       CreateDate, RoleLastUsed, attached policies, and inline policies
#       including their full documents. With no role names, it records
#       OrganizationAccountAccessRole, every role whose name starts with
#       "stacksets-exec-", every IAM Identity Center role (path
#       /aws-reserved/sso.amazonaws.com/), and every IAM role created by a
#       StackSet's stack in this account ("StackSet-*" stacks), so roles a
#       StackSet deploys - a deployment role, a vendor's role - are captured
#       and linked to the stack that created them. StackSet stacks are
#       regional: it searches the CLI's configured region, or the regions in
#       STACK_REGIONS (space-separated).
#
#   management <member-account-id>
#       Run in the Organizations management account. Records how the member
#       account joined (JoinedMethod CREATED means Organizations created
#       OrganizationAccountAccessRole; INVITED means someone created it by
#       hand), whether StackSets trusted access is enabled, and which
#       service-managed StackSets have instances in the member account. It
#       also records every IAM Identity Center permission set provisioned to
#       the member account: its managed and inline policies, and who is
#       assigned it - users by user name, groups by name with their members.
#       From a StackSets delegated administrator account instead, set
#       CALL_AS=DELEGATED_ADMIN; Identity Center calls also work from its
#       delegated administrator account.
#
# Usage:
#     bash collect_admin_role_evidence.sh member [role-name ...]
#     bash collect_admin_role_evidence.sh management 111122223333
#     STACK_REGIONS="us-east-1 us-west-2" bash collect_admin_role_evidence.sh member
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
    jq -n --arg e "$(tr '\n' ' ' <"$err_file" | sed 's/ *$//')" '{error: $e}'
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

# stackset_roles: JSON object {role-name: [{stack, region}]} for every IAM
# role created by a "StackSet-*" stack in STACK_REGIONS (default: the CLI's
# configured region). Lookups that fail are recorded under "_errors".
stackset_roles() {
  local regions region stacks stack res origin="{}"
  regions="${STACK_REGIONS:-$(aws configure get region 2>/dev/null || true)}"
  regions="${regions:-${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}}"
  for region in $regions; do
    stacks="$(aws_json cloudformation list-stacks --region "$region" \
      --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE UPDATE_ROLLBACK_COMPLETE IMPORT_COMPLETE \
      --query "StackSummaries[?starts_with(StackName, 'StackSet-')].StackName")"
    if jq -e 'type == "object" and .error' >/dev/null <<<"$stacks"; then
      origin="$(jq --arg r "$region" --argjson e "$stacks" '._errors += [{region: $r, error: $e.error}]' <<<"$origin")"
      continue
    fi
    while IFS= read -r stack; do
      [ -n "$stack" ] || continue
      res="$(aws_json cloudformation describe-stack-resources --region "$region" --stack-name "$stack" \
        --query "StackResources[?ResourceType=='AWS::IAM::Role'].PhysicalResourceId")"
      origin="$(jq --arg s "$stack" --arg r "$region" --argjson res "$res" '
        if ($res | type) == "array"
        then reduce $res[] as $role (.; .[$role] += [{stack: $s, region: $r}])
        else ._errors += [{region: $r, stack: $s, error: $res.error}] end' <<<"$origin")"
    done < <(jq -r '.[]' <<<"$stacks")
  done
  printf '%s' "$origin"
}

collect_member() {
  local roles=("$@") role get attached inline inline_docs pname doc entries="[]" origin="{}"
  if [ "${#roles[@]}" -eq 0 ]; then
    roles=(OrganizationAccountAccessRole)
    while IFS= read -r role; do
      [ -n "$role" ] && roles+=("$role")
    done < <(aws iam list-roles --output json \
               --query "Roles[?starts_with(RoleName, 'stacksets-exec-') || starts_with(Path, '/aws-reserved/sso.amazonaws.com/')].RoleName" | jq -r '.[]')
    origin="$(stackset_roles)"
    while IFS= read -r role; do
      [[ " ${roles[*]} " == *" $role "* ]] || roles+=("$role")
    done < <(jq -r 'del(._errors) | keys[]' <<<"$origin")
  fi

  for role in "${roles[@]}"; do
    get="$(aws_json iam get-role --role-name "$role")"
    attached="$(aws_json iam list-attached-role-policies --role-name "$role")"
    inline="$(aws_json iam list-role-policies --role-name "$role")"
    inline_docs="[]"
    while IFS= read -r pname; do
      [ -n "$pname" ] || continue
      doc="$(aws_json iam get-role-policy --role-name "$role" --policy-name "$pname")"
      inline_docs="$(jq --arg n "$pname" --argjson d "$doc" \
        '. + [{policy_name: $n, document: ($d.PolicyDocument // $d)}]' <<<"$inline_docs")"
    done < <(jq -r '.PolicyNames[]?' <<<"$inline")
    entries="$(jq \
      --arg name "$role" --argjson get "$get" --argjson attached "$attached" --argjson inline "$inline_docs" \
      --argjson origin "$origin" \
      '. + [{
         role_name: $name,
         created_by_stackset_stacks: ($origin[$name] // []),
         role: ($get.Role // $get),
         attached_policies: ($attached.AttachedPolicies // $attached),
         inline_policies: $inline
       }]' <<<"$entries")"
  done

  write_evidence "member-${caller_account}" "$(jq -n --argjson roles "$entries" --argjson origin "$origin" \
    '{mode: "member", roles: $roles} + (if $origin._errors then {stackset_lookup_errors: $origin._errors} else {} end)')"

  echo
  jq -r '.[] |
    if .role.error then "\(.role_name): NOT FOUND or not readable - \(.role.error)"
    else "\(.role_name)\(if (.created_by_stackset_stacks | length) > 0 then " [created by \(.created_by_stackset_stacks | map(.stack + " in " + .region) | join(", "))]" else "" end): trusted by \([.role.AssumeRolePolicyDocument.Statement[]?.Principal | if type == "object" then (to_entries[].value | if type == "array" then .[] else . end) else . end] | join(", ")); policies: \([.attached_policies[]?.PolicyName] + [.inline_policies[]? | "\(.policy_name) (inline\(if ([.document.Statement] | flatten | map(select(.Effect == "Allow" and ([.Action] | flatten | index("*")) and ([.Resource] | flatten | index("*")))) | length) > 0 then ", grants *:*" else "" end))"] | join(", ")); created \(.role.CreateDate); last used \(.role.RoleLastUsed.LastUsedDate // "never/unknown")"
    end' <<<"$entries"
  jq -r '._errors[]? | "WARNING: StackSet role lookup failed in \(.region)\(if .stack then " for \(.stack)" else "" end): \(.error)"' <<<"$origin" >&2
}

# collect_sso <member-account-id>: JSON describing every Identity Center
# permission set provisioned to the account and who is assigned it.
collect_sso() {
  local member_account="$1" instances instance_arn store_id ps_arns ps_arn ps managed inline assignments
  local principals ptype pid principal members member_ids mid result="[]"
  instances="$(aws_json sso-admin list-instances)"
  if jq -e '.error or ((.Instances // []) | length == 0)' >/dev/null <<<"$instances"; then
    jq -n --argjson i "$instances" '{error: ($i.error // "no IAM Identity Center instance found")}'
    return
  fi
  instance_arn="$(jq -r '.Instances[0].InstanceArn' <<<"$instances")"
  store_id="$(jq -r '.Instances[0].IdentityStoreId' <<<"$instances")"
  ps_arns="$(aws_json sso-admin list-permission-sets-provisioned-to-account --instance-arn "$instance_arn" --account-id "$member_account")"

  while IFS= read -r ps_arn; do
    [ -n "$ps_arn" ] || continue
    ps="$(aws_json sso-admin describe-permission-set --instance-arn "$instance_arn" --permission-set-arn "$ps_arn")"
    managed="$(aws_json sso-admin list-managed-policies-in-permission-set --instance-arn "$instance_arn" --permission-set-arn "$ps_arn")"
    inline="$(aws_json sso-admin get-inline-policy-for-permission-set --instance-arn "$instance_arn" --permission-set-arn "$ps_arn")"
    assignments="$(aws_json sso-admin list-account-assignments --instance-arn "$instance_arn" --account-id "$member_account" --permission-set-arn "$ps_arn")"

    principals="[]"
    while IFS=$'\t' read -r ptype pid; do
      [ -n "$pid" ] || continue
      if [ "$ptype" = "USER" ]; then
        principal="$(aws_json identitystore describe-user --identity-store-id "$store_id" --user-id "$pid")"
        principal="$(jq --arg t "$ptype" --arg id "$pid" '{type: $t, id: $id, user_name: (.UserName // null), display_name: (.DisplayName // null), error: (.error // null)}' <<<"$principal")"
      else
        principal="$(aws_json identitystore describe-group --identity-store-id "$store_id" --group-id "$pid")"
        member_ids="$(aws_json identitystore list-group-memberships --identity-store-id "$store_id" --group-id "$pid")"
        members="[]"
        while IFS= read -r mid; do
          [ -n "$mid" ] || continue
          members="$(jq --argjson u "$(aws_json identitystore describe-user --identity-store-id "$store_id" --user-id "$mid")" \
            '. + [$u.UserName // ("unresolved user " + ($u.error // "?"))]' <<<"$members")"
        done < <(jq -r '.GroupMemberships[]?.MemberId.UserId // empty' <<<"$member_ids")
        principal="$(jq --arg t "$ptype" --arg id "$pid" --argjson m "$members" '{type: $t, id: $id, group_name: (.DisplayName // null), members: $m, error: (.error // null)}' <<<"$principal")"
      fi
      principals="$(jq --argjson p "$principal" '. + [$p]' <<<"$principals")"
    done < <(jq -r '.AccountAssignments[]? | [.PrincipalType, .PrincipalId] | @tsv' <<<"$assignments")

    result="$(jq --argjson ps "$ps" --argjson managed "$managed" --argjson inline "$inline" --argjson principals "$principals" --arg arn "$ps_arn" \
      '. + [{
         permission_set_arn: $arn,
         name: ($ps.PermissionSet.Name // null),
         session_duration: ($ps.PermissionSet.SessionDuration // null),
         managed_policies: ($managed.AttachedManagedPolicies // $managed),
         inline_policy: (if ($inline.InlinePolicy // "") == "" then null else ($inline.InlinePolicy | fromjson? // $inline.InlinePolicy) end),
         assigned_to: $principals
       }]' <<<"$result")"
  done < <(jq -r '.PermissionSets[]?' <<<"$ps_arns")

  jq -n --arg instance "$instance_arn" --arg store "$store_id" --argjson sets "$result" --argjson raw "$ps_arns" \
    '{instance_arn: $instance, identity_store_id: $store, permission_sets: $sets} + (if $raw.error then {error: $raw.error} else {} end)'
}

collect_management() {
  local member_account="${1:-}" call_as="${CALL_AS:-SELF}" account service_access stack_sets instances="[]" name inst sso
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

  sso="$(collect_sso "$member_account")"

  write_evidence "management-${member_account}" "$(jq -n \
    --arg member "$member_account" --argjson account "$account" --argjson access "$service_access" \
    --argjson stack_sets "$stack_sets" --argjson instances "$instances" --argjson sso "$sso" \
    '{mode: "management",
      member_account_id: $member,
      member_account: ($account.Account // $account),
      enabled_service_principals: ($access.EnabledServicePrincipals // $access),
      service_managed_stack_sets: [($stack_sets.Summaries // [])[] | select(.PermissionModel == "SERVICE_MANAGED")],
      stack_instances_in_member_account: [$instances[] | select((.instances | type) != "array" or (.instances | length) > 0)],
      identity_center: $sso}')"

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
  jq -r 'if .error then "WARNING: Identity Center not recorded: \(.error)"
         else .permission_sets[] | "Permission set \(.name): policies \([.managed_policies[]?.Name] + (if .inline_policy then ["inline"] else [] end) | join(", ")); assigned to \([.assigned_to[] | if .type == "USER" then "user \(.user_name // .id)" else "group \(.group_name // .id) (\(.members | join(", ")))" end] | join("; "))"
         end' <<<"$sso"
}

case "$mode" in
  member) collect_member "$@" ;;
  management) collect_management "$@" ;;
  *) usage ;;
esac
