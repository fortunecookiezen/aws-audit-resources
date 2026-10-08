# Process: remediation and retesting

`accepting-findings-process.md` covers findings that get *accepted* rather
than fixed. This document covers the other path: findings someone is
actually going to remediate, and how the skill should re-verify that the fix
worked instead of taking anyone's word for it.

## Principle

A finding stays open until there is fresh evidence it's closed — never until
someone reports that it's fixed. The evidence has to come from the same tool
that found the problem, run again against newly-collected data, because
that's the only way "we fixed it" and "the account actually reflects that"
are checked against each other instead of just asserted. A remediation with
no retest is a TODO with extra steps.

## Roles

- **Remediation owner** — the engineer or team who applies the fix in AWS
  (directly, or more often via the org's existing IaC/change-management
  process — this skill doesn't replace that, it only measures the result).
- **Auditor** — re-collects data, re-runs the checks, confirms the specific
  findings actually flipped status, and updates the evidence package. Same
  responsibilities as in `accepting-findings-process.md`: don't report a
  finding closed because it would be convenient to, only because the retest
  shows it.
- **Account/engagement owner** — tracks remediation status across the full
  findings list (a simple tracker: finding, owner, target date, status) and
  decides, for anything that won't be fixed, whether it goes through the
  acceptance process instead.

Every report this workflow produces is labeled `DRAFT` — on the cover page,
in the page header, and in its own filename — until the explicit
finalization step at the end of this document. That labeling, the "Prepared
By" author block, and the Testing Narrative table (Test Start, Test
Completion, Findings Draft, Findings Review, Findings Completion) all come
from `engagement-info.md`, a per-engagement file alongside `exceptions.json`
— see `engagement-info-template.md` for its format. Keep it updated as the
engagement moves through this workflow; the milestone notes below say which
step updates which row.

## Workflow

1. **Triage findings into a remediation plan.** For every `"fail"` finding
   in the report (Section 2/5), assign an owner and a target date, or route
   it to the exceptions process (`accepting-findings-process.md`) if it's
   going to be risk-accepted rather than fixed. A finding with neither an
   owner nor an acceptance decision is the thing most likely to still be
   open, unnoticed, at the next audit.

2. **Apply the fix in AWS** through whatever change process the
   organization already uses — an IaC PR and review, a console change plus a
   ticket, etc. This skill measures end state; it has no opinion on how the
   change gets made.

3. **Re-collect fresh data — never reuse the old snapshot.** Run
   `collect_aws_data.py` again into the *same* `audit-runs/<account_id>-<YYYYMMDD>/`
   engagement directory, but under a new, distinct snapshot name so the
   pre-remediation snapshot is preserved rather than overwritten:
   ```bash
   python3 scripts/collect_aws_data.py --all-regions \
     -o ../audit-runs/<account_id>-<YYYYMMDD>/snapshot-retest-1.json
   ```
   Retesting against the original snapshot only proves the data didn't
   change between two reads of the same file — it proves nothing about the
   account. Re-collecting is not optional, even for a change that "obviously
   worked" (an API call succeeding doesn't verify the end state the way a
   fresh collector pass does, and a change can have unintended side effects
   elsewhere that only a full re-run would catch — see step 5).

4. **Re-run the checks against the same exceptions file** — unless the
   remediation itself changes a fact an exception was attesting to (e.g.
   root-management status changed), in which case update `exceptions.json`
   first, per `accepting-findings-process.md`, rather than retesting against
   a now-stale attestation:
   ```bash
   python3 scripts/run_checks.py snapshot-retest-1.json \
     --framework <fw> --exceptions exceptions.json -o findings-retest-1.json
   ```

5. **Diff the findings themselves, not just the summary counts.** A pass/fail
   count can mask what actually happened — one finding fixed and a different
   one newly introduced nets out to the same total. Use `scripts/diff_findings.py`
   to compare the baseline and retest findings files per check *and*
   resource, not just in aggregate:
   ```bash
   python3 scripts/diff_findings.py findings-baseline.json findings-retest-1.json
   ```
   It reports, in order: findings that regressed (were passing/accepted,
   now failing — the one category that should stop and get investigated
   before anything else), findings still failing (the remediation plan isn't
   done yet), findings newly fixed, and findings that appeared or
   disappeared entirely because a resource was created or deleted between
   runs (worth a sanity check — e.g. a deleted bucket shouldn't quietly look
   like a "fixed" S3 finding when what actually happened is the resource is
   gone, not corrected).

6. **Update the report and evidence package.** Rebuild the `.docx` report
   from the retest findings with `scripts/build_report.py`:
   ```bash
   python3 scripts/build_report.py ../audit-runs/<account_id>-<YYYYMMDD>/findings-retest-1.json \
     --label retest-1
   ```
   It picks up `snapshot-retest-1.json` and `engagement-info.md` from the
   same directory.
   Keep the superseded snapshot/findings/report from before the fix in the
   evidence package too — don't delete them. Name the retest artifacts so
   the sequence is obvious (`snapshot-retest-1.json`,
   `AWS_Security_Audit_<account_id>_<framework>_retest-1_DRAFT.docx`, etc.)
   so the evidence package shows the account's trajectory over time, not
   just whatever the most recent run happened to find. Set
   `engagement-info.md`'s `Report Variant Note` (or pass it as a build
   argument, `--variant-note`, which overrides it for that build only) to
   something that identifies which retest this is, e.g. "Retest 1 -
   post-remediation." The report stays `DRAFT` — the filename suffix and
   cover banner are automatic from `Report Status` and need no extra step.
   The first time this step runs for an engagement, also set the Testing
   Narrative's `Findings Draft` row to today's date; a later retest doesn't
   change that row, it's a one-time "a draft now exists" milestone.

7. **Close the loop on the remediation tracker.** Mark each fixed finding
   closed with the retest date and a pointer to the specific evidence that
   proves it (which snapshot/findings file, which line). "Fixed" without a
   pointer back to the retest that proved it is exactly the unverified claim
   this whole process exists to avoid.

8. **Repeat per remediation wave** until everything remaining is either
   accepted (`exceptions.json`, via `accepting-findings-process.md`) or
   explicitly out of scope for this engagement.

## Full retest vs. targeted retest

Always re-run the full collector and the full check set for the chosen
framework, even when only one finding was remediated. The collector is cheap
relative to the risk of a narrower pass: a change made to fix one finding
can regress something adjacent (tightening a security group can break a
flow-log export rule; deleting a default VPC can orphan a resource still
attached to it), and a retest scoped to only the check someone meant to fix
won't catch that. There's no `--only-checks` filter in `run_checks.py`
today — running everything and reading the rows that changed, via
`diff_findings.py`, is the supported path. If retest turnaround time becomes
a real bottleneck for an account with many regions/checks, a `--only-checks`
filter would be a reasonable addition to `run_checks.py`; until then, treat
"I only need to check the one thing" as a reason to look at the diff more
carefully, not a reason to collect less data.

On a fixed audit cadence (quarterly, annual), do a full retest at the start
of the next cycle regardless of what was or wasn't remediated in between —
that's also a natural point to resend `documentation-request-template.md`
and refresh `exceptions.json` per `accepting-findings-process.md`'s review
cadence.

## Findings outside the audited framework's scope

Not every legitimate AWS security best practice maps to a control in the
framework being audited, and a finding doesn't stop being real just because
`run_checks.py`'s `refs` for that framework comes back empty. The skill's
checks are scoped to specific framework control mappings (see
`check-catalog.md`); something a human reviewer notices while reading the
raw snapshot — or that Trusted Advisor, Security Hub, or another tool flags
— doesn't disappear because it isn't one of the 27 automated checks, or
because it's automated but unmapped for the framework currently being
reported on.

The concrete example that prompted this section: every region in an account
can have an unused AWS-created default VPC, and `sg_default_restricts_traffic`
only checks whether that VPC's default security group denies all traffic —
it says nothing about whether the VPC itself should still exist. AWS's own
guidance is to delete default VPCs that aren't in active, intentional use:
each one ships pre-configured with public subnets and an internet gateway
already attached, which is a standing, auto-created piece of attack surface
that nobody had to decide to create. That's exactly why `default_vpc_exists`
exists as a check (see `check-catalog.md`) — but it's deliberately not
force-mapped to a CIS, SOC 2, or ISO 27001 control id those frameworks don't
actually have; its `refs` for those three frameworks say so explicitly
rather than displaying a blank cell that could be misread as missing data.

Track a finding like this through the same remediation workflow as any
framework finding — owner, evidence, target date, retest — just note on the
tracker that it's "best practice, not mapped to \<framework>" so it isn't
mistaken for scope creep on the audit itself, and isn't dropped just because
it won't move the framework's headline pass/fail numbers.

## Finalizing

A report only becomes `FINAL` through this explicit step — never by editing
the word on the cover page, and never by default just because remediation
work has stopped. Do this once, when the engagement is actually done:

1. **Confirm every finding is settled.** Run `diff_findings.py` one more
   time against the latest retest. Every open (`"fail"`) finding must be
   either genuinely fixed (confirmed by that retest) or explicitly accepted
   in `exceptions.json` per `accepting-findings-process.md` — "we're not
   going to get to this one" is not a reason to finalize, it's a reason to
   either fix it, accept it, or keep the report `DRAFT` until one of those
   happens.

2. **Fill in the last two Testing Narrative rows in `engagement-info.md`:**
   `Findings Review` (who reviewed the final findings and when — this can
   be the auditor, the account/engagement owner, or both; record whoever
   actually did it) and `Findings Completion` (today's date, once step 1
   above is actually true). Fill in the `Auditor Name/Title/Organization/
   Contact` fields too if they were left blank during drafting — a `FINAL`
   report shouldn't still say "Not provided" for who produced it.

3. **Set `Report Status: FINAL`** in `engagement-info.md`.

4. **Rebuild the report.** Nothing else changes about the build command —
   the cover banner, page header, and output filename all flip from `DRAFT`
   to `FINAL` automatically because they're all driven by `Report Status`.
   `build_report.py` prints a `WARNING:` for anything this checklist says
   should already be settled (findings still `"fail"`, `Pending` Testing
   Narrative rows, blank auditor fields); a `FINAL` built with warnings
   isn't ready to deliver. Verify the rebuilt file before treating it as the deliverable (render to
   PDF, check the cover page says `FINAL` and the Testing Narrative table is
   fully populated with no `Pending` rows left).

5. **Treat every `DRAFT` version as superseded, not deleted.** Keep them in
   the evidence package (per `evidence-handling.md`) so the engagement's
   actual history — including what the findings looked like before each
   round of remediation — stays in the record. The `FINAL` report is the
   one that gets delivered/distributed going forward; a `DRAFT` is not meant
   to circulate as if it were final, which is exactly what the cover banner,
   header, and filename are there to prevent.

If something changes after finalization (a new finding surfaces, a prior
fix regresses, an accepted exception needs revisiting), don't edit the
`FINAL` report in place — that defeats the point of labeling it. Open a new
engagement cycle: a fresh retest, a new `DRAFT`, and its own path back to
`FINAL` once settled.

## Related reference files

- `engagement-info-template.md` — the per-engagement file format for author
  data, report status, and the Testing Narrative this document's milestones
  update
- `accepting-findings-process.md` — the process for findings that get
  accepted rather than remediated
- `exceptions-and-exclusions.md` — the `--exceptions` file format referenced
  in step 4 above
- `check-catalog.md` — the full check list, including which checks are
  framework-mapped vs. best-practice-only
- `evidence-handling.md` — what happens to the `audit-runs/` directory
  (including retest artifacts) once an engagement is done
