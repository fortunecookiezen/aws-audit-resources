# Process: accepting findings and processing exceptions

`exceptions-and-exclusions.md` documents the *mechanics* of `--exceptions`
(the file format, what's auto-detected, how a claim gets corroborated against
real data). This document is the *governance* that should sit around those
mechanics: who gets to decide a finding isn't a real problem, what has to be
true before they can, and how that decision stays trustworthy over time. A
file format with no process behind it just moves the risk of "someone quietly
waved away a real finding" from the check logic into a JSON file instead of
removing it.

## Principle

A finding is accepted, never deleted. Nothing in this skill ever removes a
failing check's result because an exceptions file matched it — see
`exceptions-and-exclusions.md`'s "What accepted means in the output." The
process below exists to make sure that when a finding *is* marked accepted,
that decision is: backed by specific evidence (not a verbal assurance),
made by someone with the standing to make it, dated and attributable, and
set up to be re-checked rather than accepted once and forgotten.

## Roles

- **Account/engagement owner** — the person who actually knows why a given
  role has `AdministratorAccess`, or whether root credentials are centrally
  managed. They are the source of the facts, and for anything that can't be
  independently verified (see "Corroboration" below), they are also the
  approver. This is usually who fills out `documentation-request-template.md`.
- **Auditor (the person running this skill)** — gathers and records the
  evidence, runs the corroboration checks, writes the exceptions file, and
  is responsible for *not* accepting something just because it would make
  the report look better. The auditor can decline to accept a finding even
  when the account owner asks them to, if the evidence doesn't hold up.
- **Independent verifier (where available)** — e.g., whoever has access to
  the AWS Organizations management account and can run
  `aws iam list-organizations-features` directly, rather than relying on the
  member-account owner's word for it. Prefer this over attestation whenever
  it's available; it's what `_root_centrally_managed()`'s auto-detection
  path uses when the audit role happens to run with the right privileges.

## Before the audit: request documentation up front

Don't wait for a false positive to surface before asking about it. At
kickoff, send the account/engagement owner `documentation-request-template.md`
and ask them to fill it in: known administrator roles, AWS Organizations
root-management status, and any other risk they've already reviewed and
accepted. Answers transcribe directly into `exceptions.json`'s schema, so
the first `run_checks.py` pass can already reflect them instead of
generating findings you'll correct in a second pass. This also forces the
account owner to put their reasoning in writing before they've seen (and
have an incentive to explain away) a specific failing finding — asking "what
should hold AdministratorAccess" before the audit is a cleaner signal than
asking "why does this role have AdministratorAccess" after.

It's fine if the audit still turns up something the template missed — that's
what the reactive workflow below is for — but a template response reviewed
in advance should cover the majority of an account's known exceptions.

## Workflow: accepting a specific finding

1. **Identify the candidate.** Either it's on the documentation-request
   template response, or it surfaced as a finding during review that the
   account owner says is expected/intentional.

2. **Gather corroborating evidence**, proportional to the claim:
   - *Root credentials centrally managed*: ideally, `aws iam
     list-organizations-features` run directly from the Organizations
     management account (or let the audit role's own auto-detection confirm
     it, if it's running with delegated-admin privileges — check
     `organization.root_credentials_management_queryable` in the snapshot).
     If neither is available, the next best thing is a screenshot of the
     Organizations console's root access management page, dated.
   - *A named admin principal*: the role/user's actual name or ARN, and a
     one-line reason it's supposed to hold broad access (break-glass access,
     an AWS-managed automation construct like a StackSets exec role or
     `OrganizationAccountAccessRole`, a platform team's deployment role,
     etc.). "It's always been like that" is not evidence; a runbook link,
     an IaC module that provisions it, or a ticket documenting its creation
     is.
   - *A longer root-reuse window*: the account's actual audit/review
     cadence (e.g., quarterly reviews justify a 90-day window; annual
     reviews justify 365).
   - *Any other failing finding* (`accepted_findings`): the specific
     resource, the compensating control or business reason, and something
     that shows the control exists — a bucket policy, a security group's
     source-restriction rule elsewhere, a ticket for the planned fix. The
     owner who accepts it, and a date to review it again, are required.

3. **Get sign-off** from the account/engagement owner (or, for anything
   independently verifiable, confirm it directly rather than asking). Record
   *who* and *when* — `exceptions.json`'s `attested_by`/`attested_date`
   fields and each `accepted_admin_principals[].note` exist specifically so
   this doesn't get lost.

4. **Write the exceptions file** using the schema in
   `exceptions-and-exclusions.md`. Use a prefix pattern
   (`^stacksets-exec-`, `^AWSReservedSSO_AdministratorAccess_`) rather than
   an exact match for anything AWS generates a suffix for, so the rule keeps
   matching after the role is recreated — an exact match that silently stops
   matching is worse than no exception at all, because it looks resolved in
   the exceptions file while quietly failing again in the findings.

5. **Re-run `run_checks.py --exceptions` and check the actual output** —
   don't assume the exceptions file did what you intended. Confirm the
   specific finding now shows `"pass"` or `"accepted"` as expected, and that
   nothing *else* changed status. If a root-management claim doesn't flip to
   `"pass"`, check the finding's evidence for a contradiction note before
   assuming the exceptions file is broken — it may be correctly declining to
   apply the claim because the data doesn't back it up (see "Handling a
   contradiction" below).

6. **Keep the exceptions file in the evidence package.** It lives alongside
   the snapshot and findings in `audit-runs/<account_id>-<YYYYMMDD>/` (see
   `evidence-handling.md`), together with the completed
   `documentation-request-response.md` and its `evidence/` attachments that
   justify each entry, and should move with them into the private
   evidence repo or archive — an exceptions file with no accompanying
   evidence package is just an unaudited claim with extra steps.

## Handling a contradiction

`run_checks.py` corroborates a root-management claim against the actual
collected data before applying it (see "A claim is corroborated, never just
trusted" in `exceptions-and-exclusions.md`). If a finding's evidence includes
language like *"collected data contradicts this"*, treat that as its own
audit finding, not a tooling bug:

1. Confirm what the data shows (root access key present? a login profile?
   an MFA device?) and when it was collected.
2. Ask the account/management-account owner whether central management was
   actually applied to this specific account, and when — management can be
   enabled org-wide while an individual account's root credentials were
   created earlier and never swept up, or a root credential can be
   recreated after the fact.
3. Either get the account's root credentials actually brought in line with
   the claim (the real fix), or correct/remove the attestation in
   `exceptions.json` so the report reflects reality instead of a claim that
   doesn't hold. Don't re-run with the same attestation unchanged and expect
   a different result — the corroboration check will catch it again.

## What not to accept

- A pattern broad enough to match things you haven't actually reviewed (a
  bare `.*` or an unanchored single-word pattern like `admin` that could
  match a role nobody's looked at). Prefer the narrowest pattern that still
  survives a regenerated suffix.
- An exception with no `note`, or a `note` that doesn't actually explain
  *why* — "approved" or "fine" is not a justification a future reader can
  evaluate.
- Accepting a whole control rather than a reviewed resource — an
  `accepted_findings` rule whose `resource` pattern matches everything that
  check covers. `run_checks.py` warns when a rule matches every resource of
  its check; treat that warning as a reason to narrow the pattern.
- "Temporary" access with no removal plan or review date. If it's temporary,
  track when it should stop being true and re-check then, rather than
  carrying the exception forward indefinitely.
- Anything the account owner can't actually explain, even if they're
  confident it's fine. "Nobody remembers why this role has
  AdministratorAccess, but it's probably fine" is itself the finding — log
  it as a real issue to investigate, not an accepted one.

## Review cadence

An accepted finding reflects the account's state (and the account owner's
judgment) *at the time it was accepted*. Treat `exceptions.json` as
something to revisit on every re-audit, not a permanent fixture:

- Re-confirm `root_credentials_centrally_managed` each time the audit runs
  against this account, especially if it's relying on attestation rather
  than auto-detection — organizational structure changes, and a stale
  attestation is exactly what the corroboration check above is designed to
  catch, but only if the underlying data genuinely still supports it.
- Re-check that each `accepted_admin_principals` entry's pattern still
  matches only what it was meant to. A loosely-scoped pattern that matched
  one role at the time it was written can start matching a second,
  unreviewed role later without anyone noticing, unless this is checked.
  The same applies to `accepted_findings` resource patterns.
- Act on every `WARNING:` from `run_checks.py`. An expired
  `accepted_findings` rule (`review_by` has passed) leaves its finding as
  `"fail"` until the owner re-approves it with a new `review_by`; a rule
  that matches nothing should be removed or corrected, not left in place.
- If an engagement has a fixed cadence (quarterly, annual), review the
  exceptions file as part of audit kickoff — this is also a natural time to
  resend `documentation-request-template.md` and confirm nothing material
  has changed.
