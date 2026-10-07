# Engagement Information

*Copy this file to `engagement-info.md` in the engagement's
`audit-runs/<account_id>-<YYYYMMDD>/` directory, alongside `exceptions.json`
and the snapshot/findings files. `scripts/build_report_final.js` reads it
directly and prints its contents on the report's cover page and in the
Testing Narrative table - fill it in before the first report build, and
keep updating it as the engagement progresses (see
`remediation-and-retesting.md`, "Finalizing," for when and how to flip
Report Status to FINAL).*

*The two sections below, "Report Metadata" and "Testing Narrative," are
machine-parsed - keep their exact format (the `- Key: Value` bullet style,
the markdown table). Only the values change. Add anything else you want a
human reader to see as ordinary markdown elsewhere in the file; the builder
ignores everything outside these two sections. Delete this intro block
before filling the file in.*

## Report Metadata

- Report Status: DRAFT
- Report Variant Note:
- Auditor Name:
- Auditor Title:
- Auditor Organization:
- Auditor Contact:
- Account/Engagement Owner:
- Primary Contact:

*Field notes:*
- *`Report Status` is either `DRAFT` or `FINAL` (case-insensitive), exactly.
  Every report built while this says `DRAFT` is watermarked and filed as a
  draft - title, cover banner, page header, and output filename all say so.
  Only change it to `FINAL` as the explicit finalization step described in
  `remediation-and-retesting.md`.*
- *`Report Variant Note` is free text shown under the title (e.g. "Reissued
  with an auditor-reviewed exceptions file applied (see Section 3)" or
  "Retest 1 - post-remediation (see Section 6, Evidence handling)"). Leave
  it blank for a first-pass report.*
- *`Auditor Name/Title/Organization/Contact` identify who performed the
  audit and produced the report - printed as a "Prepared By" block on the
  cover page. `Auditor Contact` is email and/or phone, whichever the auditor
  wants printed.*
- *`Account/Engagement Owner` and `Primary Contact` identify who owns the
  audited account / is the point of contact for the engagement - these can
  be the same person as the auditor (e.g. a self-audit) or different (e.g.
  a consultant auditing a client's account).*

## Testing Narrative

*One row per milestone. Leave `Date` blank for a milestone that hasn't
happened yet - the report shows it as "Pending" rather than inventing a
date. Add a row only if you need an extra milestone beyond the five below;
don't remove any of the five, even if blank.*

| Milestone | Date | By | Notes |
|---|---|---|---|
| Test Start |  |  |  |
| Test Completion |  |  |  |
| Findings Draft |  |  |  |
| Findings Review |  |  |  |
| Findings Completion |  |  |  |

*Milestone definitions:*
- *Test Start / Test Completion - when data collection (`collect_aws_data.py`)
  and the first full check run (`run_checks.py`) began and ended for this
  engagement.*
- *Findings Draft - when the first report was built from those findings
  (`Report Status: DRAFT`).*
- *Findings Review - when someone (the account/engagement owner, a second
  auditor, or both) reviewed the draft findings - record who in `By`.*
- *Findings Completion - when the findings are considered settled: every
  open finding is either remediated-and-retested-clean or explicitly
  risk-accepted via `exceptions.json` (see `accepting-findings-process.md`).
  This is normally the same moment `Report Status` flips to `FINAL`.*

## Additional Notes

*Free-text space for anything else about this engagement's timeline,
scope, or methodology that doesn't fit the table above.*
