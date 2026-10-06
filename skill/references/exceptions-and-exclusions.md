# Exceptions: handling known false positives

A handful of the 27 automated checks can't tell the difference between "this
is genuinely wrong" and "this is exactly what a well-run account looks like,"
because the distinguishing fact isn't visible from the data `collect_aws_data.py`
can gather on its own. Three concrete cases:

1. **Root user has no MFA / no access keys / shows no recent activity, because
   AWS Organizations Root Access Management deleted its credentials
   entirely** — not because nobody bothered to set up MFA. `root_mfa_enabled`,
   `root_hardware_mfa`, `root_not_used_routinely`, and `iam_credentials_unused_45d`
   (for the root row only) can't tell these apart from raw
   `GetAccountSummary`/credential-report data; both cases produce identical
   values (`AccountMFAEnabled=0`, no password, no keys).
2. **`root_not_used_routinely` flags *any* recorded root activity, including a
   five-year-old initial account-setup login** — "used once at account
   creation, never since" and "used last week" look the same to a check that
   only asks "is there a non-empty `password_last_used` value," which is why
   this check now evaluates activity against a time window instead (default
   365 days) rather than ever/never.
3. **`iam_no_full_admin_policy` flags every attachment of an admin-wildcard
   policy identically**, whether it's a clearly-named `Administrator` or
   `OrganizationAccountAccessRole` that's supposed to hold `AdministratorAccess`,
   or a mystery role nobody can explain.

None of these are fixed by silently special-casing them in the check logic —
that would hide a real problem just as easily as a false one. Instead, `run_checks.py`
takes an optional `--exceptions <file>.json` that makes the auditor's judgment
call explicit, attributable, and visible in the output rather than invisible.

## What's auto-detected vs. what needs attestation

`collect_aws_data.py` tries to determine whether root credentials are
centrally managed by calling `iam:ListOrganizationsFeatures`. That call only
succeeds from the AWS Organizations **management account** or an account
delegated as IAM's trusted administrator — `AccountNotManagementOrDelegatedAdministrator`
otherwise. Most audits run from inside the **member account being audited**,
where that's expected to fail, not a bug to chase. When it does succeed, the
result is captured in the snapshot's `organization.root_credentials_management_enabled`
field and `run_checks.py` uses it automatically — no exceptions file needed.

When it can't be auto-detected, confirm it out-of-band (ask whoever has
access to the management account to run `aws iam list-organizations-features`,
or check the AWS Organizations console's root access management page) and
record that confirmation in the exceptions file. The collector also records
org membership itself (`organization.in_organization`, `organization.organization_id`,
`organization.management_account_id`) from `organizations:DescribeOrganization`,
which *is* callable from a member account — useful context for deciding
whether it's worth asking the management-account owner to check.

`iam_no_full_admin_policy`'s per-role/user enumeration needs `collect_aws_data.py`
to have run with the `attached_role_names`/`attached_user_names`/`attached_group_names`
fields it now records for every admin-wildcard policy — a snapshot collected
before this feature existed just won't have that data, and the check falls
back to its original per-policy (not per-principal) evaluation, which cannot
be excepted. Re-collect to get attachment-level data if you need to except a
specific role.

## A claim is corroborated, never just trusted

Neither an auto-detected result nor an attestation is applied on its own
authority. Before any of the five root-management-related checks (listed
above) resolve to `"pass"` because of it, `run_checks.py` independently
verifies, from the collected data itself, that root genuinely has no usable
sign-in path: no console login profile (password), no access keys, and no
MFA device. This is what a centrally-managed root user should actually look
like — the claim is a statement of *why* that's true, not a replacement for
checking that it is.

If a claim exists but the data disagrees — for example, an attestation says
root credentials are centrally managed, but the snapshot shows root still
has an active access key — the exception is **not** applied. The affected
check falls through to its normal evaluation logic exactly as if no
exceptions file had been passed at all, and the discrepancy itself is
appended to that finding's evidence in plain language, so it surfaces as a
loud, specific, actionable discrepancy rather than either a false pass or an
unexplained fail. Typical causes: the attestation is stale (management was
turned on after this account's root already had a key), someone later
created root credentials despite management being on, or the attestation
was simply wrong. Either way, treat it as something to investigate before
re-running with a corrected (or removed) exceptions file — see
`accepting-findings-process.md` for how to track that down.

## File format

```json
{
  "root_credentials_centrally_managed": {
    "attested": true,
    "attested_by": "jamesp",
    "attested_date": "2026-10-07",
    "note": "Confirmed via the Organizations management account: iam:ListOrganizationsFeatures shows RootCredentialsManagement enabled for org o-xxxxxxxxxx."
  },
  "root_routine_use_window_days": 180,
  "accepted_admin_principals": [
    {
      "match": "name",
      "pattern": "^OrganizationAccountAccessRole$",
      "note": "AWS-created cross-account management role; expected to hold AdministratorAccess."
    },
    {
      "match": "name",
      "pattern": "(?i)break.?glass",
      "note": "Documented emergency-access role per <internal runbook link>."
    }
  ]
}
```

All three top-level keys are optional — include only what applies to this
account. An auto-detected `root_credentials_management_enabled: true` in the
snapshot takes precedence over `root_credentials_centrally_managed` here, so
you don't need this block at all when the collector could confirm it itself.

- **`root_credentials_centrally_managed.attested`** — set `true` only after
  independently confirming it (see above), not on the auditee's say-so alone.
  `attested_by`, `attested_date`, and `note` are carried verbatim into the
  finding's evidence so the report shows who made the call and why.
- **`root_routine_use_window_days`** — integer; default `365`. Root activity
  (password sign-in or access-key use) older than this is not treated as
  "routine use." Lower it (e.g. `180`) for a stricter review, or if your audit
  cadence is more frequent than annual.
- **`accepted_admin_principals`** — list of match rules. `match` is `"name"`
  (role/user name, the common case) or `"arn"`. `pattern` is a Python regex,
  matched with `re.search` (so `^...$` anchors if you want an exact match,
  omit them for a substring/pattern match). The first matching rule wins;
  order doesn't otherwise matter. `note` is required in spirit even though
  not enforced — it's what shows up next to the finding in the report, and an
  empty justification defeats the point of making this explicit.

## What "accepted" means in the output

Findings this file resolves don't disappear. The root-management-related
checks (`root_mfa_enabled`, `root_hardware_mfa`, `root_no_access_keys`,
`root_not_used_routinely`, and the root row of `iam_credentials_unused_45d`)
become ordinary `"pass"` findings (centralization genuinely satisfies
the control's intent — a root user with no usable credentials at all is
arguably a stronger posture than a self-managed MFA device, not a weaker
one). An admin-principal match becomes a new `"accepted"` status, distinct
from both `"pass"` and `"fail"`: the underlying fact (this role really does
hold `AdministratorAccess`) is still true and still shown, but it's now
labeled as a reviewed, deliberate decision rather than an open issue.
`run_checks.py`'s summary reports an `accepted` count alongside `passed`/`failed`
so this is visible at a glance, not just buried in the findings list. When
building the report (Step 4 of `SKILL.md`), give accepted findings their own
short section rather than folding them into either "Key Findings" or "Passing
Controls" — they're neither.

## Evidence handling

Keep the exceptions file you used for a given audit run alongside its
snapshot and findings in `audit-runs/<account_id>-<YYYYMMDD>/` (see
`evidence-handling.md`) — it's part of what makes the report's judgment calls
reproducible and reviewable later, not a one-off input to discard.

## Related reference files

- **`accepting-findings-process.md`** — the governance process behind this
  file: who gets to accept a finding, what evidence they need before doing
  it, how a contradiction (above) gets investigated and resolved, and how
  accepted findings get reviewed and re-attested over time rather than
  accepted once and forgotten.
- **`documentation-request-template.md`** — a fill-in template to send the
  account/engagement owner *before* or at the start of an audit, so known
  admin roles, root-management status, and other expected exceptions are
  captured up front instead of discovered as false positives after the
  report is already written. Answers to it transcribe directly into this
  file's schema.
