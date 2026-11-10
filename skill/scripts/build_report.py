#!/usr/bin/env python3
"""
build_report.py - build the aws-audit Word report from run_checks.py output.

Usage (from the skill/ directory, in the venv - see requirements.txt):
    python3 scripts/build_report.py "$AUDIT_DIR/findings.json"

    # A retest, labeled in the filename and on the cover:
    python3 scripts/build_report.py "$AUDIT_DIR/findings-retest-1.json" \\
        --label retest-1 --variant-note "Retest 1 - post-remediation"

Inputs, all from the engagement directory (the findings file's directory
unless overridden):
  - findings.json        run_checks.py output (required, positional)
  - engagement-info.md   cover page, Prepared By block, Report Status and the
                         Testing Narrative table (required; --engagement-info
                         to override). Format: references/engagement-info-template.md.
  - snapshot.json        optional, for regions and the collecting identity in
                         the methodology appendix. Defaults to the findings
                         file's name with "findings" replaced by "snapshot",
                         if that file exists; --snapshot to override.

Output: AWS_Security_Audit_<account_id>_<framework>[_<label>]_<DRAFT|FINAL>.docx
in the engagement directory (or --out-dir). DRAFT vs FINAL comes only from
engagement-info.md's "Report Status" field and drives the title, cover
banner, page header and filename together - see
references/remediation-and-retesting.md, "Finalizing." --variant-note
overrides engagement-info.md's "Report Variant Note" for this build only.

Building a FINAL report prints a WARNING for anything the finalization
checklist says must be settled first (open "fail" findings, "Pending"
Testing Narrative rows, blank auditor fields). It still builds, so the
warnings can be reviewed against the output, but a FINAL with warnings
isn't ready to deliver. Any build also warns about a Testing Narrative date
that isn't YYYY-MM-DD, since dates are printed exactly as written, and about
the tool versions behind the report: collection, checks or the report build
not run from a release tag, or run from different versions.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

try:
    from docx import Document
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Inches, Pt, RGBColor
except ImportError:
    print("python-docx is required: activate a venv and run pip install -r requirements.txt (from the skill/ directory)", file=sys.stderr)
    sys.exit(1)


from run_checks import CHECKS_META, REGION_LEVEL_CHECKS, _region_inventory, parse_operating_regions
from remediation_tracker import REGION_CHECK, write_tracker
from tool_version import tool_version, version_problem

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECK_CATALOG = os.path.join(SKILL_DIR, "references", "check-catalog.md")

FRAMEWORK_NAMES = {
    "cis": "CIS AWS Foundations Benchmark v7.0.0",
    "well_architected": "AWS Well-Architected Framework, Security Pillar",
    "soc2": "SOC 2 Trust Services Criteria (Common Criteria / Security)",
    "iso27001": "ISO/IEC 27001:2022 Annex A",
    "all": "All supported frameworks (CIS, Well-Architected, SOC 2, ISO 27001)",
}
FRAMEWORK_SHORT = {"cis": "CIS", "well_architected": "Well-Architected", "soc2": "SOC 2", "iso27001": "ISO 27001"}
AREA_ORDER = ["IAM", "MFA", "S3", "CloudTrail / Logging", "Security Groups / VPC", "Root Account",
              "Detection & Monitoring", "Databases", "Encryption & Secrets", "Containers",
              "Regional Footprint"]
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
OUT_OF_SCOPE = (
    "Load balancers, CloudFront, API Gateway, WAF, ACM, Lambda, Cognito, ECS/EKS workloads, "
    "Elastic Beanstalk, CI/CD services (CodeBuild, CodePipeline, CodeCommit), Systems Manager, "
    "CloudFormation, EFS, CloudWatch metric-filter alarms, and AWS Organizations governance."
)

METADATA_KEYS = [
    "Report Status", "Report Variant Note", "Auditor Name", "Auditor Title",
    "Auditor Organization", "Auditor Contact", "Account/Engagement Owner", "Primary Contact",
    "Operating Regions",
]
REQUIRED_MILESTONES = ["Test Start", "Test Completion", "Findings Draft", "Findings Review", "Findings Completion"]
NOT_PROVIDED = "Not provided"
PENDING = "Pending"

# Colors
DRAFT_FILL, FINAL_FILL = "C00000", "2E7D32"
HEADER_FILL = "1F3864"
SEVERITY_FILL = {"Critical": "C00000", "High": "E36C09", "Medium": "BF8F00", "Low": "548235", "Informational": "7F7F7F"}
LIGHT_FILL = "F2F2F2"


class BuildError(Exception):
    pass


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

def _section(text, heading):
    """Return the body of a '## heading' section (up to the next '## ')."""
    m = re.search(rf"^##\s+{re.escape(heading)}\s*$(.*?)(?=^##\s|\Z)", text, re.M | re.S)
    return m.group(1) if m else None


def parse_engagement_info(path):
    """Parse the two machine-read sections of engagement-info.md. Anything
    outside them, and any line in them that isn't a known '- Key: Value'
    bullet or a table row, is ignored (the template's italic notes)."""
    if not os.path.exists(path):
        raise BuildError(
            f"{path} not found. Copy references/engagement-info-template.md there and fill it in "
            "(SKILL.md Step 1)."
        )
    with open(path) as f:
        text = f.read()

    meta_body = _section(text, "Report Metadata")
    if meta_body is None:
        raise BuildError(f"{path} has no '## Report Metadata' section.")
    meta = {}
    for line in meta_body.splitlines():
        m = re.match(r"^\s*-\s+([^:*`]+?):\s*(.*?)\s*$", line)
        if m and m.group(1) in METADATA_KEYS:
            meta[m.group(1)] = m.group(2)
    status = meta.get("Report Status", "").strip().upper()
    if status not in ("DRAFT", "FINAL"):
        raise BuildError(f"{path}: Report Status must be DRAFT or FINAL, got {meta.get('Report Status')!r}.")
    meta["Report Status"] = status

    narrative_body = _section(text, "Testing Narrative")
    if narrative_body is None:
        raise BuildError(f"{path} has no '## Testing Narrative' section.")
    milestones = []
    for line in narrative_body.splitlines():
        line = line.strip()
        if not line.startswith("|") or re.match(r"^\|[\s|:-]+\|$", line):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if cells[0] == "Milestone" or not cells[0]:
            continue
        cells += [""] * (4 - len(cells))
        milestones.append({"milestone": cells[0], "date": cells[1], "by": cells[2], "notes": cells[3]})
    names = [m["milestone"] for m in milestones]
    missing = [m for m in REQUIRED_MILESTONES if m not in names]
    if missing:
        raise BuildError(f"{path}: Testing Narrative is missing row(s): {', '.join(missing)}. Keep all five, even if blank.")
    return meta, milestones


def parse_manual_checks(path=CHECK_CATALOG):
    """The 'Manual/extended checks' bullets from check-catalog.md, as plain text."""
    try:
        with open(path) as f:
            text = f.read()
    except OSError:
        return []
    body = _section(text, "Manual/extended checks (not automated in v1)") or ""
    items = []
    for line in body.splitlines():
        m = re.match(r"^\s*-\s+(.*)$", line)
        if m:
            items.append(m.group(1).replace("**", "").replace("`", ""))
    return items


def default_snapshot_path(findings_path, collected_at):
    """The snapshot these findings came from: snapshot-<label>.json for
    findings-<label>.json, else snapshot.json. Either only counts if its
    collected_at matches the findings', since a retest overwrites
    snapshot.json while older findings files stay."""
    d, name = os.path.split(findings_path)
    candidates = []
    if "findings" in name:
        candidates.append(os.path.join(d, name.replace("findings", "snapshot", 1)))
    candidates.append(os.path.join(d, "snapshot.json"))
    for candidate in candidates:
        if not os.path.exists(candidate):
            continue
        with open(candidate) as f:
            if json.load(f).get("collected_at") == collected_at:
                return candidate
    return None


# ---------------------------------------------------------------------------
# docx helpers
# ---------------------------------------------------------------------------

def _shade(element_pr, fill):
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    element_pr.append(shd)


def shade_cell(cell, fill):
    _shade(cell._tc.get_or_add_tcPr(), fill)


def set_cell_text(cell, text, bold=False, color=None, size=None):
    cell.text = ""
    run = cell.paragraphs[0].add_run(str(text))
    run.bold = bold
    if color:
        run.font.color.rgb = RGBColor.from_string(color)
    if size:
        run.font.size = Pt(size)
    return run


def add_table(doc, headers, rows, widths, header_fill=HEADER_FILL, font_size=9):
    """A full-width grid table with a shaded header row. widths in inches."""
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    for i, h in enumerate(headers):
        cell = table.rows[0].cells[i]
        set_cell_text(cell, h, bold=True, color="FFFFFF", size=font_size)
        shade_cell(cell, header_fill)
    _repeat_header(table.rows[0])
    for row in rows:
        cells = table.add_row().cells
        for i, value in enumerate(row):
            set_cell_text(cells[i], value, size=font_size)
    for row in table.rows:
        for i, w in enumerate(widths):
            row.cells[i].width = Inches(w)
    doc.add_paragraph()
    return table


def _repeat_header(row):
    tr_pr = row._tr.get_or_add_trPr()
    el = OxmlElement("w:tblHeader")
    el.set(qn("w:val"), "true")
    tr_pr.append(el)


def add_bullet(doc, text, bold_prefix=None):
    p = doc.add_paragraph(style="List Bullet")
    if bold_prefix:
        p.add_run(bold_prefix).bold = True
    p.add_run(text)
    return p


def add_field(paragraph, instr):
    """Insert a field (e.g. PAGE) into a paragraph."""
    run = paragraph.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    text = OxmlElement("w:instrText")
    text.set(qn("xml:space"), "preserve")
    text.text = instr
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.append(begin)
    run._r.append(text)
    run._r.append(end)


def banner(doc, text, fill):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _shade(p._p.get_or_add_pPr(), fill)
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(16)
    run.font.color.rgb = RGBColor.from_string("FFFFFF")
    return p


# ---------------------------------------------------------------------------
# Report content
# ---------------------------------------------------------------------------

def format_timestamp(value):
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return str(value)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def shorten_hashes(text):
    """Shorten 64-hex-character SHA-256 values for display."""
    return re.sub(r"\b([0-9a-f]{12})[0-9a-f]{52}\b", r"\1…", str(text))


def refs_text(finding, framework):
    refs = finding.get("refs") or {}
    if framework == "all":
        parts = [f"{FRAMEWORK_SHORT.get(k, k)}: {v}" for k, v in refs.items() if v]
        return "; ".join(parts) or "—"
    return refs.get(framework) or "—"


def area_key(area):
    return AREA_ORDER.index(area) if area in AREA_ORDER else len(AREA_ORDER)


def severity_key(sev):
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


def area_check_counts(ctx):
    """{area: (checks evaluated, checks skipped for missing data)} for every area, in report order."""
    s = ctx["summary"]
    check_area = {c: m["area"] for c, m in CHECKS_META.items()}
    check_area.update({f["check_id"]: f["area"] for f in ctx["findings"]})
    extra = sorted({f["area"] for f in ctx["findings"]} - set(AREA_ORDER))
    counts = {area: [0, 0] for area in AREA_ORDER + extra}
    for i, key in enumerate(("checks_evaluated", "checks_skipped")):
        for c in s.get(key) or []:
            if check_area.get(c) in counts:
                counts[check_area[c]][i] += 1
    return {area: tuple(n) for area, n in counts.items()}


def area_skip_reason(ctx, area):
    """The reason every skipped check in `area` gives (from run_checks'
    checks_skipped_reasons), or None if any was skipped for missing data."""
    reasons = ctx["summary"].get("checks_skipped_reasons") or {}
    skipped = [c for c in ctx["summary"].get("checks_skipped") or []
               if CHECKS_META.get(c, {}).get("area") == area]
    if skipped and all(c in reasons for c in skipped):
        return "; ".join(sorted({reasons[c] for c in skipped}))
    return None


def split_areas(ctx):
    """(areas with at least one evaluated check, areas not evaluated for lack
    of data, {area: reason} for areas not evaluated for another reason)."""
    counts = area_check_counts(ctx)
    evaluated = [a for a, (n_eval, _) in counts.items() if n_eval]
    other = {a: area_skip_reason(ctx, a) for a in counts if a not in evaluated and area_skip_reason(ctx, a)}
    return evaluated, [a for a in counts if a not in evaluated and a not in other], other


def group_by_check(findings):
    """{check_id: [findings]} preserving first-seen order."""
    grouped = {}
    for f in findings:
        grouped.setdefault(f["check_id"], []).append(f)
    return grouped


def build_cover(doc, ctx):
    meta, status = ctx["meta"], ctx["status"]
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run(f"AWS Account Security Audit Report ({status})")
    run.bold = True
    run.font.size = Pt(24)
    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub.add_run(FRAMEWORK_NAMES.get(ctx["framework"], ctx["framework"])).font.size = Pt(14)
    if ctx["variant_note"]:
        vp = doc.add_paragraph()
        vp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        vr = vp.add_run(ctx["variant_note"])
        vr.italic = True

    if status == "DRAFT":
        banner(doc, "DRAFT — NOT FOR DISTRIBUTION AS A FINAL REPORT", DRAFT_FILL)
    else:
        banner(doc, "FINAL", FINAL_FILL)
    doc.add_paragraph()

    s = ctx["summary"]
    rows = [
        ("Report Status", status),
        ("AWS Account ID", s.get("account_id") or "Unknown"),
        ("Framework", FRAMEWORK_NAMES.get(ctx["framework"], ctx["framework"])),
        *([("Audit Result", s["audit_result"]["result"])] if s.get("audit_result") else []),
        ("Data Collected", ctx["collected_at"]),
        ("Report Generated", ctx["generated_at"]),
        ("Account/Engagement Owner", meta.get("Account/Engagement Owner") or NOT_PROVIDED),
        ("Primary Contact", meta.get("Primary Contact") or NOT_PROVIDED),
    ]
    table = doc.add_table(rows=0, cols=2)
    table.style = "Table Grid"
    table.autofit = False
    for label, value in rows:
        cells = table.add_row().cells
        set_cell_text(cells[0], label, bold=True, size=10)
        shade_cell(cells[0], LIGHT_FILL)
        run = set_cell_text(cells[1], value, size=10, bold=(label in ("Report Status", "Audit Result")))
        if label == "Report Status":
            run.font.color.rgb = RGBColor.from_string(DRAFT_FILL if status == "DRAFT" else FINAL_FILL)
        if label == "Audit Result":
            run.font.color.rgb = RGBColor.from_string(PASS_FILL if value == "PASS" else NOT_PASSING_FILL)
    for row in table.rows:
        row.cells[0].width, row.cells[1].width = Inches(2.2), Inches(4.3)
    doc.add_paragraph()

    doc.add_heading("Prepared By", level=2)
    for key in ("Auditor Name", "Auditor Title", "Auditor Organization", "Auditor Contact"):
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(0)
        p.add_run(f"{key.replace('Auditor ', '')}: ").bold = True
        p.add_run(meta.get(key) or NOT_PROVIDED)
    doc.add_paragraph()

    doc.add_heading("Testing Narrative", level=2)
    add_table(
        doc,
        ["Milestone", "Date", "By", "Notes"],
        [(m["milestone"], m["date"] or PENDING, m["by"], m["notes"]) for m in ctx["milestones"]],
        [1.6, 1.1, 1.4, 2.4],
    )


def build_executive_summary(doc, ctx):
    s, findings = ctx["summary"], ctx["findings"]
    # Start the body on a new page with the heading itself, not a break
    # paragraph after the cover: a cover that fills page 1 pushes that
    # paragraph onto page 2, leaving it blank.
    doc.add_heading("1. Executive Summary", level=1).paragraph_format.page_break_before = True
    failed = [f for f in findings if f["status"] == "fail"]
    by_sev = s.get("by_severity") or {}
    crit_high = by_sev.get("Critical", 0) + by_sev.get("High", 0)
    if not failed:
        posture = "No failing findings were identified in the evaluated controls."
    elif crit_high:
        posture = (
            f"{crit_high} critical or high-severity finding(s) require prompt remediation; "
            "they are listed in Key Findings below."
        )
    else:
        posture = "No critical or high-severity findings were identified; the remaining findings are medium or low severity."
    evaluated_areas, missing_data_areas, other_areas = split_areas(ctx)
    total = len(evaluated_areas) + len(missing_data_areas) + len(other_areas)
    if not missing_data_areas and not other_areas:
        coverage = f"across {total} areas: {', '.join(evaluated_areas)}."
    elif not evaluated_areas:
        coverage = f"but none of the {total} areas could be evaluated."
    else:
        coverage = f"across {len(evaluated_areas)} of {total} areas ({', '.join(evaluated_areas)})."
    if missing_data_areas:
        coverage += (f" {len(missing_data_areas)} area(s) could not be evaluated because the snapshot lacked the "
                     f"data their checks need, and have no results in this report: {', '.join(missing_data_areas)}.")
    for area, reason in other_areas.items():
        coverage += f" {area} was not evaluated: {reason}."
    collected = (f"Data was collected {ctx['collected_at']}." if ctx["collected_known"]
                 else "The snapshot does not record when its data was collected.")
    doc.add_paragraph(
        f"This report covers AWS account {s.get('account_id') or 'Unknown'}, evaluated against the "
        f"{FRAMEWORK_NAMES.get(ctx['framework'], ctx['framework'])} {coverage} {collected} {posture}"
    )
    add_audit_result(doc, ctx)
    operating = s.get("operating_regions")
    if operating:
        doc.add_paragraph(
            f"The client operates in {', '.join(operating)}. Region-level controls (detection services, EBS "
            "encryption by default) and AWS-created defaults that fail outside these regions are reported as "
            f"Informational advisories ({s.get('advisory_findings', 0)} in this report), and anything found "
            "outside them is reported under Regional Footprint whether or not it is otherwise compliant."
        )
    elif "operating_regions" in s:
        doc.add_paragraph(
            "No operating regions were declared for this engagement, so every collected region was treated as "
            "one the client operates in."
        )
    rows = [("Failed findings", s.get("failed", 0))]
    rows += [(f"    {sev}", by_sev.get(sev, 0)) for sev in SEVERITY_ORDER]
    rows += [
        ("Passed findings", s.get("passed", 0)),
        ("Accepted findings", s.get("accepted", 0)),
    ]
    if s.get("operating_regions"):
        rows.append(("Advisory findings outside operating regions (counted in Informational)", s.get("advisory_findings", 0)))
    reasons = s.get("checks_skipped_reasons") or {}
    rows += [
        ("Checks evaluated", len(s.get("checks_evaluated") or [])),
        ("Checks skipped (missing data)", len(s.get("checks_skipped") or []) - len(reasons)),
    ]
    if reasons:
        rows.append(("Checks skipped (other reasons)", len(reasons)))
    rows += [
        ("Checks incomplete (collection errors)", len(s.get("checks_incomplete") or {})),
    ]
    add_table(doc, ["Measure", "Count"], rows, [3.5, 1.5], font_size=10)


PASS_FILL, NOT_PASSING_FILL = "2E7D32", "C00000"


def criteria_text(ar):
    """The pass standard in words, from a findings file's audit_result."""
    must = ar["must_remediate"]
    text = f"{', '.join(must[:-1]) + ' and ' + must[-1] if len(must) > 1 else must[0]} findings must be remediated"
    lower = [s for s in ("Critical", "High", "Medium", "Low") if s not in must]
    if lower:
        text += f" and verified by retest; {' and '.join(lower)} findings must be remediated or risk-accepted"
    else:
        text += " and verified by retest"
    return (text + "; every applicable check must be evaluated completely. Informational findings don't affect "
            "the result and are communicated to management.")


def add_audit_result(doc, ctx):
    """The audit result block in the executive summary: the verdict, the
    standard it was measured against, and what blocks a pass."""
    ar = ctx["summary"].get("audit_result")
    if not ar:
        return
    p = doc.add_paragraph()
    p.add_run("Audit result: ").bold = True
    r = p.add_run(ar["result"])
    r.bold = True
    r.font.color.rgb = RGBColor.from_string(PASS_FILL if ar["result"] == "PASS" else NOT_PASSING_FILL)
    doc.add_paragraph(f"Pass standard: {criteria_text(ar)}")
    if ar["blocking"]:
        doc.add_paragraph("What stands between this account and a pass:")
        add_table(doc, ["Blocking item", "Count"],
                  [(k[0].upper() + k[1:], n) for k, n in sorted(
                      ar["blocking_counts"].items(), key=lambda kv: (severity_key(kv[0].split(" ")[0]), kv[0]))],
                  [5.0, 1.0], font_size=9)
        doc.add_paragraph("Each open finding is a row in the remediation tracker; an unevaluated or incomplete "
                          "check needs the missing data collected and the checks run again.")
    if ar.get("communicated_to_management"):
        doc.add_paragraph(f"{ar['communicated_to_management']} accepted or informational item(s) are listed under "
                          "Matters Communicated to Management and in the management letter.")


def build_management_matters(doc, ctx, number):
    """Accepted Lows, expected administrators and Informational findings:
    what management is told about rather than asked to fix."""
    m = management_matters(ctx)
    if not any(m.values()):
        return False
    doc.add_heading(f"{number}. Matters Communicated to Management", level=1)
    doc.add_paragraph(
        "These items don't prevent a passing result, but management should know about them: risks it has "
        "accepted instead of fixing, administrator access that exists by design, and informational findings. "
        f"The same items are in the management letter ({ctx['letter_name']}) for sign-off."
    )
    add_management_tables(doc, m)
    return True


def management_matters(ctx):
    findings = [f for f in ctx["findings"] if f["status"] != "pass"]
    must = (ctx["summary"].get("audit_result") or {}).get("must_remediate", ["Critical", "High", "Medium"])
    kind = lambda f: (f.get("acceptance") or {}).get("kind")
    return {
        "accepted": [f for f in findings if f["status"] == "accepted" and f["severity"] not in must
                     and kind(f) != "expected_admin_principal"],
        "expected_admins": [f for f in findings if kind(f) == "expected_admin_principal"],
        "informational": [f for f in findings if f["severity"] == "Informational" and f["status"] == "fail"],
    }


def add_management_tables(doc, m):
    if m["accepted"]:
        doc.add_heading("Risk-accepted findings", level=2)
        add_table(doc, ["Finding", "Resource", "Severity", "Approved by", "Approved", "Review by", "Reason"],
                  [(f["title"], str(f["resource"]), f["severity"], *(
                      (f.get("acceptance") or {}).get(k, "") for k in ("approved_by", "approved_date", "review_by")),
                    shorten_hashes((f.get("acceptance") or {}).get("note", ""))) for f in
                   sorted(m["accepted"], key=lambda f: (severity_key(f["severity"]), f["check_id"]))],
                  [1.2, 1.1, 0.6, 0.9, 0.7, 0.7, 1.3], font_size=7)
    if m["expected_admins"]:
        doc.add_heading("Administrator access by design", level=2)
        doc.add_paragraph("Principals with full administrator access that the engagement's exceptions file "
                          "documents as intended (accepted_admin_principals). They are reviewed, not remediated.")
        add_table(doc, ["Principal and policy", "Reason"],
                  [(str(f["resource"]), shorten_hashes((f.get("acceptance") or {}).get("note", "")))
                   for f in sorted(m["expected_admins"], key=lambda f: str(f["resource"]))], [3.0, 3.5], font_size=8)
    if m["informational"]:
        doc.add_heading("Informational findings", level=2)
        doc.add_paragraph("Advisories outside the operating regions, and Low findings with no control in the "
                          "audited framework.")
        rows = []
        for fs in group_by_check(sorted(m["informational"], key=lambda f: f["check_id"])).values():
            names = [str(f["resource"]) for f in fs]
            rows.append((fs[0]["title"], len(fs),
                         ", ".join(names[:10]) + (f", and {len(names) - 10} more" if len(names) > 10 else ""),
                         "Advisory outside the operating regions" if fs[0].get("advisory") else
                         "No control in the audited framework"))
        add_table(doc, ["Finding", "Count", "Resources", "Why informational"], rows, [1.8, 0.5, 2.8, 1.4],
                  font_size=8)


def letter_filename(account_id, framework, label, status):
    return output_filename(account_id, framework, label, status).replace(
        f"_{status}.docx", f"_management-letter_{status}.docx")


def build_management_letter(ctx, out_path):
    """A short letter to the account owner: the audit result, and the
    accepted and informational items management is asked to acknowledge."""
    s, meta, ar = ctx["summary"], ctx["meta"], ctx["summary"].get("audit_result") or {}
    doc = setup_document(ctx)
    doc.core_properties.title = f"AWS Security Audit Management Letter ({ctx['status']})"
    if ctx["status"] == "DRAFT":
        banner(doc, "DRAFT — NOT FOR DISTRIBUTION AS A FINAL LETTER", DRAFT_FILL)
    doc.add_paragraph(ctx["generated_at"][:10])
    doc.add_paragraph(f"To: {meta.get('Account/Engagement Owner') or NOT_PROVIDED}")
    doc.add_paragraph(f"From: {meta.get('Auditor Name') or NOT_PROVIDED}, "
                      f"{meta.get('Auditor Organization') or NOT_PROVIDED}")
    doc.add_paragraph(f"Subject: AWS security audit of account {s.get('account_id') or 'Unknown'} — matters "
                      "communicated to management")
    framework = FRAMEWORK_NAMES.get(ctx["framework"], ctx["framework"])
    p = doc.add_paragraph(f"We audited AWS account {s.get('account_id') or 'Unknown'} against the {framework}, "
                          f"using data collected {ctx['collected_at']}. The audit result is ")
    r = p.add_run(ar.get("result", "not recorded"))
    r.bold = True
    if ar:
        p.add_run(f". The pass standard: {criteria_text(ar)}")
        if ar.get("blocking"):
            doc.add_paragraph(f"{len(ar['blocking'])} item(s) must still be resolved before the audit can pass; "
                              f"they are listed in the audit report and the remediation tracker ({ctx['tracker_name']}).")
    doc.add_paragraph(
        "This letter lists the matters below because, although they don't prevent a passing result, management "
        "should be aware of them and accept responsibility for them: findings management has risk-accepted "
        "instead of remediating, administrator access that exists by design, and informational findings. "
        "Accepted risks should be reviewed by the date shown."
    )
    m = management_matters(ctx)
    if any(m.values()):
        add_management_tables(doc, m)
    else:
        doc.add_paragraph("There are no accepted, by-design or informational items to report.")
    doc.add_heading("Acknowledgement", level=2)
    doc.add_paragraph("I have read the matters above and acknowledge them on behalf of management.")
    for label in ("Name", "Title", "Signature", "Date"):
        doc.add_paragraph(f"{label}: " + "_" * 40)
    doc.save(out_path)


def build_key_findings(doc, ctx):
    doc.add_heading("2. Key Findings", level=1)
    key = [f for f in ctx["findings"] if f["status"] == "fail" and f["severity"] in ("Critical", "High")]
    if not key:
        doc.add_paragraph("No critical or high-severity findings.")
        return
    doc.add_paragraph("Critical and high-severity failing findings, most severe first, grouped by area.")
    key.sort(key=lambda f: (severity_key(f["severity"]), area_key(f["area"])))
    for sev in ("Critical", "High"):
        sev_findings = [f for f in key if f["severity"] == sev]
        if not sev_findings:
            continue
        doc.add_heading(sev, level=2)
        for area in sorted({f["area"] for f in sev_findings}, key=area_key):
            doc.add_heading(area, level=3)
            for fs in group_by_check(x for x in sev_findings if x["area"] == area).values():
                resources = ", ".join(str(f["resource"]) for f in fs)
                add_bullet(doc, f" — {resources} ({refs_text(fs[0], ctx['framework'])})", bold_prefix=fs[0]["title"])


def build_accepted(doc, ctx, number):
    accepted = [f for f in ctx["findings"] if f["status"] == "accepted"]
    doc.add_heading(f"{number}. Accepted Findings", level=1)
    doc.add_paragraph(
        "These findings are still true in the collected data, but have been reviewed and explicitly "
        "risk-accepted through the engagement's exceptions file. They are neither open issues nor "
        "passing controls. Each entry shows who accepted it, why, and the rule that matched."
    )
    doc.add_paragraph(
        "SHA-256 hashes are shortened to their first 12 characters here; the full values are in the "
        "exceptions file in the evidence package."
    ).runs[0].italic = True
    accepted.sort(key=lambda f: (severity_key(f["severity"]), area_key(f["area"])))
    # One block per finding rather than a table row: acceptance notes cite
    # evidence files and hashes, and in a table column they run for pages.
    for f in accepted:
        # run_checks.py appends " Accepted: <note> (...)" to the original evidence.
        evidence, sep, acceptance = f["evidence"].partition(" Accepted: ")
        if not sep:
            evidence, acceptance = "", f["evidence"]
        doc.add_heading(str(f["resource"]), level=3)
        meta = doc.add_paragraph()
        meta.add_run(f"{f['title']}  ·  ").italic = True
        sev = meta.add_run(f["severity"])
        sev.bold = True
        sev.font.color.rgb = RGBColor.from_string(SEVERITY_FILL.get(f["severity"], "000000"))
        meta.add_run(f"  ·  {refs_text(f, ctx['framework'])}  ·  {f['check_id']}")
        if evidence:
            p = doc.add_paragraph()
            p.add_run("Finding: ").bold = True
            p.add_run(shorten_hashes(evidence))
        p = doc.add_paragraph()
        p.add_run("Accepted because: ").bold = True
        p.add_run(shorten_hashes(acceptance))


def build_passing(doc, ctx, number):
    doc.add_heading(f"{number}. Passing Controls", level=1)
    grouped = group_by_check(ctx["findings"])
    passing = [(fs[0], len(fs)) for fs in grouped.values() if all(f["status"] == "pass" for f in fs)]
    if not passing:
        doc.add_paragraph("No control passed for every evaluated resource.")
        return
    doc.add_paragraph("Controls that passed for every evaluated resource:")
    passing.sort(key=lambda x: (area_key(x[0]["area"]), x[0]["title"]))
    for f, n in passing:
        suffix = f" ({n} resources)" if n > 1 else ""
        add_bullet(doc, f" — {refs_text(f, ctx['framework'])}{suffix}", bold_prefix=f"{f['area']}: {f['title']}")


def build_detailed(doc, ctx, number):
    doc.add_heading(f"{number}. Detailed Findings by Area", level=1)
    doc.add_paragraph(
        "Every failing finding, by area, with its control reference, evidence and remediation. "
        "Accepted findings are listed in their own section."
    )
    failed = [f for f in ctx["findings"] if f["status"] == "fail"]
    counts = area_check_counts(ctx)
    for i, area in enumerate(counts, 1):
        area_failed = [f for f in failed if f["area"] == area]
        n_eval, n_skip = counts[area]
        doc.add_heading(f"{number}.{i} {area}", level=2)
        skip_note = (
            f"{n_skip} check(s) in this area were skipped because the snapshot lacked the data they need "
            "(see Appendix: Scope & Methodology)."
        )
        if not area_failed:
            reason = area_skip_reason(ctx, area) if n_eval == 0 else None
            if reason:
                doc.add_paragraph(f"Not evaluated: {reason}.")
            elif n_eval == 0 and n_skip:
                doc.add_paragraph(
                    f"Not evaluated: the snapshot had no data for this area's {n_skip} check(s), so none of its "
                    "controls were tested. This is not a passing result (see Appendix: Scope & Methodology)."
                )
            elif n_eval == 0:
                doc.add_paragraph("Not evaluated: no automated check in this framework covers this area.")
            elif n_skip:
                doc.add_paragraph(f"No failing findings in the {n_eval} evaluated check(s). " + skip_note)
            else:
                doc.add_paragraph("No failing findings in this area.")
            continue
        if n_skip:
            doc.add_paragraph(skip_note)
        grouped = group_by_check(area_failed)
        for check_id in sorted(grouped, key=lambda c: (min(severity_key(f["severity"]) for f in grouped[c]), c)):
            ordered = sorted(grouped[check_id], key=lambda f: severity_key(f["severity"]))
            # Advisories (outside the operating regions) are listed in one
            # line after the real findings rather than a row each.
            fs = [f for f in ordered if not f.get("advisory")]
            advisories = [f for f in ordered if f.get("advisory")]
            f0 = (fs or advisories)[0]
            mixed = len({f["severity"] for f in fs}) > 1
            doc.add_heading(f0["title"], level=3)
            p = doc.add_paragraph()
            p.add_run("Severity: ").bold = True
            sev = p.add_run(f0["severity"] + (" (highest; varies by resource)" if mixed else "")
                            + ("" if fs else " (advisory)"))
            sev.bold = True
            sev.font.color.rgb = RGBColor.from_string(SEVERITY_FILL.get(f0["severity"], "000000"))
            p.add_run("    Control: ").bold = True
            p.add_run(refs_text(f0, ctx["framework"]))
            p.add_run("    Check ID: ").bold = True
            p.add_run(check_id)
            if f0.get("outside_framework") and f0["severity"] != "Informational":
                doc.add_paragraph(
                    f"Outside {FRAMEWORK_SHORT.get(ctx['framework'], 'the audited framework')}: no control in the "
                    "audited framework covers this, but it's a security risk at this severity, so it's reported "
                    "and counts toward the audit result."
                ).runs[0].italic = True
            if mixed:
                add_table(doc, ["Resource", "Severity", "Evidence"],
                          [(f["resource"], f["severity"], f["evidence"]) for f in fs], [1.7, 0.7, 4.1])
            elif fs:
                add_table(doc, ["Resource", "Evidence"], [(f["resource"], f["evidence"]) for f in fs], [1.8, 4.7])
            if advisories:
                ap = doc.add_paragraph()
                ap.add_run(f"Advisory, outside the operating regions (Informational, {len(advisories)}): ").bold = True
                ap.add_run(", ".join(f["resource"] for f in advisories)
                           + ". The client doesn't operate here, but activity in an unused region would otherwise "
                             "go unseen; an organization SCP denying these regions, once attested, clears these.")
            rp = doc.add_paragraph()
            rp.add_run("Remediation: ").bold = True
            rp.add_run(f0["remediation"])


def build_region_scope(doc, ctx):
    """The Regions subsection: operating regions, what was collected, and a
    per-region footprint table."""
    s, findings = ctx["summary"], ctx["findings"]
    collected = s.get("regions_collected") or (ctx["snapshot"] or {}).get("regions") or []
    operating = s.get("operating_regions")
    if not collected and not operating:
        return
    doc.add_heading("Regions", level=2)
    if operating:
        doc.add_paragraph(
            f"Operating regions (declared in engagement-info.md): {', '.join(operating)}. Every enabled region "
            "is collected so resources outside them can be found; outside them, region-level controls are "
            "advisory and every resource is still checked at full severity."
        )
    elif "operating_regions" in s:
        doc.add_paragraph("Operating regions: none declared, so every collected region was treated as operating.")
    enabled = s.get("enabled_regions")
    if enabled is not None:
        uncollected = sorted(set(enabled) - set(collected))
        doc.add_paragraph(
            f"{len(enabled)} region(s) are enabled for the account and {len(collected)} were collected"
            + (f"; not collected: {', '.join(uncollected)}." if uncollected else ".")
        )
    scp = s.get("region_deny_scp")
    if scp:
        add_bullet(doc, scp["note"], bold_prefix="Region-deny SCP: ")
    for w in s.get("region_warnings") or []:
        add_bullet(doc, w, bold_prefix="Warning: ")

    inventory = _region_inventory(ctx["snapshot"]) if ctx["snapshot"] else None
    status = {}
    for f in findings:
        if f["check_id"] in ("guardduty_enabled", "securityhub_enabled", "config_recorder_enabled"):
            status[(f["check_id"], f["resource"])] = (
                "On" if f["status"] == "pass" and not f.get("outside_operating_regions") else
                "Off (SCP denies region)" if f["status"] == "pass" else
                "Off (advisory)" if f.get("advisory") else
                "Off" if f["status"] == "fail" else "Accepted")
    rows = []
    for region in sorted(set(collected) | set(operating or [])):
        rows.append((
            region,
            "—" if not operating else ("Yes" if region in operating else "No"),
            "Not collected" if region not in collected else
            "—" if inventory is None else str(len(inventory.get(region) or [])),
            *(status.get((c, region), "—") for c in ("guardduty_enabled", "securityhub_enabled",
                                                     "config_recorder_enabled")),
        ))
    doc.add_paragraph("Resources counts exclude AWS-created defaults (default VPC and security group, "
                      "AWS-managed keys, service-owned secrets).")
    add_table(doc, ["Region", "Operating", "Resources", "GuardDuty", "Security Hub", "AWS Config"],
              rows, [1.3, 0.8, 0.9, 1.2, 1.2, 1.1], font_size=8)


def build_appendix(doc, ctx):
    s = ctx["summary"]
    doc.add_heading("Appendix: Scope & Methodology", level=1)

    doc.add_heading("Scope", level=2)
    evaluated_areas, missing_data_areas, other_areas = split_areas(ctx)
    if missing_data_areas or other_areas:
        doc.add_paragraph(f"In scope and evaluated: {', '.join(evaluated_areas) or 'none'}.")
        if missing_data_areas:
            doc.add_paragraph(
                f"In scope but not evaluated (the snapshot lacked the data their checks need): "
                f"{', '.join(missing_data_areas)}."
            )
        for area, reason in other_areas.items():
            doc.add_paragraph(f"In scope but not evaluated: {area} ({reason}).")
    else:
        doc.add_paragraph(f"In scope: {', '.join(evaluated_areas)}.")
    doc.add_paragraph(f"Out of scope for this version: {OUT_OF_SCOPE}")

    build_region_scope(doc, ctx)

    doc.add_heading("Data source", level=2)
    snap = ctx["snapshot"] or {}
    add_bullet(doc, ctx["data_source"], bold_prefix="Source: ")
    add_bullet(doc, ctx["collected_at"], bold_prefix="Collected: ")
    if snap.get("caller_arn"):
        add_bullet(doc, snap["caller_arn"], bold_prefix="Collected as: ")
    if snap.get("regions"):
        add_bullet(doc, ", ".join(snap["regions"]), bold_prefix="Regions: ")
    add_bullet(doc, os.path.basename(ctx["findings_path"]), bold_prefix="Findings file: ")
    add_bullet(doc, f"{ctx['tracker_name']} (one row per failing or accepted finding, and per resource outside "
                    "the operating regions; kept with this report as the record of how each was handled)",
               bold_prefix="Remediation tracker: ")
    versions = tool_versions(ctx)
    if len(set(versions.values())) == 1:
        add_bullet(doc, f"{versions['collection']} (collection, checks and report)", bold_prefix="Tool version: ")
    else:
        for stage, version in versions.items():
            add_bullet(doc, version, bold_prefix=f"Tool version ({stage}): ")

    doc.add_heading("Controls evaluated", level=2)
    titles = {f["check_id"]: f["title"] for f in ctx["findings"]}
    evaluated = s.get("checks_evaluated") or []
    skipped = s.get("checks_skipped") or []
    incomplete = s.get("checks_incomplete") or {}
    doc.add_paragraph(
        f"{len(evaluated)} automated check(s) evaluated, "
        f"{len(skipped) - len(s.get('checks_skipped_reasons') or {})} skipped because the snapshot lacked the data they need"
        + (f", {len(s['checks_skipped_reasons'])} skipped for the reason shown below"
           if s.get("checks_skipped_reasons") else "")
        + (f", {len(incomplete)} incomplete because an API call they depend on failed during collection." if incomplete else ".")
    )
    add_table(
        doc,
        ["Check ID", "Title", "Result"],
        [(c, titles.get(c, "(no resources evaluated)"), "Incomplete: collection error" if c in incomplete else "Evaluated")
         for c in evaluated]
        + [(c, "—", f"Skipped: {(s.get('checks_skipped_reasons') or {}).get(c, 'missing data')}") for c in skipped],
        [2.4, 3.1, 1.0],
        font_size=8,
    )

    doc.add_heading("Collection errors", level=2)
    if not s.get("collection_errors_recorded"):
        doc.add_paragraph(
            "Not recorded: the snapshot was collected before the collector recorded failed API calls, so a "
            "failed call can't be distinguished from an empty result."
        )
    elif not s.get("collection_errors"):
        doc.add_paragraph("None: every API call made during collection succeeded.")
    else:
        covered = {call: v for v in s.get("verified_values") or [] for call in v.get("covers") or []}
        doc.add_paragraph(
            "These API calls failed during collection. A check marked incomplete above covers only what was "
            "collected: a resource the failed call would have returned is missing from its results, not passing."
            + (" Where a value is shown as verified from evidence, the auditor confirmed it in the account that "
               "owns the resource, and the check used that value." if covered else "")
        )
        if covered:
            add_table(
                doc,
                ["Call", "Error", "Value verified from evidence"],
                [(e.get("call", ""), e.get("error_code", ""),
                  (f"{covered[e.get('call')]['evidence']} ({covered[e.get('call')]['verified_by']}, "
                   f"{covered[e.get('call')]['verified_date']})") if e.get("call") in covered else "—")
                 for e in s["collection_errors"]],
                [2.6, 1.2, 2.7],
                font_size=8,
            )
        else:
            add_table(
                doc,
                ["Call", "Error"],
                [(e.get("call", ""), e.get("error_code", "")) for e in s["collection_errors"]],
                [4.0, 2.5],
                font_size=8,
            )

    manual = ctx["manual_checks"]
    if manual:
        doc.add_heading("Manual/extended checks (not automated)", level=2)
        doc.add_paragraph(
            "These framework controls are not evaluated by the automated checks in this version and are "
            "out of scope for this report:"
        )
        for item in manual:
            add_bullet(doc, item)

    doc.add_heading("Exceptions", level=2)
    if s.get("exceptions_applied"):
        doc.add_paragraph(
            "An exceptions file was applied when the checks were run. It is kept in this engagement's "
            "evidence package alongside the snapshot and findings, together with the documentation "
            "request response and supporting evidence it is based on."
        )
        warnings = s.get("exceptions_warnings") or []
        if warnings:
            doc.add_paragraph("run_checks.py reported these warnings about the exceptions file:")
            for w in warnings:
                add_bullet(doc, w)
    else:
        doc.add_paragraph("No exceptions file was applied.")


def setup_document(ctx):
    doc = Document()
    section = doc.sections[0]
    section.page_width, section.page_height = Inches(8.5), Inches(11)
    for side in ("left_margin", "right_margin", "top_margin", "bottom_margin"):
        setattr(section, side, Inches(1))
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(10.5)

    header = section.header.paragraphs[0]
    header.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    hr = header.add_run(f"{ctx['status']} — AWS Security Audit — Account {ctx['summary'].get('account_id') or 'Unknown'}")
    hr.font.size = Pt(8)
    hr.bold = ctx["status"] == "DRAFT"
    if ctx["status"] == "DRAFT":
        hr.font.color.rgb = RGBColor.from_string(DRAFT_FILL)

    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer.add_run("Page ").font.size = Pt(8)
    add_field(footer, "PAGE")

    props = doc.core_properties
    props.title = f"AWS Account Security Audit Report ({ctx['status']})"
    props.subject = FRAMEWORK_NAMES.get(ctx["framework"], ctx["framework"])
    props.author = ctx["meta"].get("Auditor Name") or ""
    return doc


def tool_versions(ctx):
    """The tool version behind each stage of this report, "not recorded" for
    files produced before the tool recorded it."""
    s, snap = ctx["summary"], ctx["snapshot"] or {}
    return {
        "collection": s.get("snapshot_tool_version") or snap.get("tool_version") or "not recorded",
        "checks": s.get("tool_version") or "not recorded",
        "report": ctx["report_tool_version"],
    }


def tool_version_warnings(ctx):
    """A report should come from one released version of the tool, end to end."""
    versions = tool_versions(ctx)
    warnings = []
    for stage, version in versions.items():
        problem = version_problem(None if version == "not recorded" else version)
        if problem:
            warnings.append(f"{stage.capitalize()}: {problem}.")
    recorded = {k: v for k, v in versions.items() if v != "not recorded"}
    if len(set(recorded.values())) > 1:
        warnings.append(
            "Collection, checks and report were produced with different tool versions ("
            + ", ".join(f"{k} {v}" for k, v in recorded.items())
            + "). Rerun the checks and the report build from the version that collected the snapshot."
        )
    return warnings


def date_warnings(ctx):
    """Testing Narrative dates are printed exactly as written, so flag any
    that aren't YYYY-MM-DD (engagement-info-template.md)."""
    warnings = []
    for m in ctx["milestones"]:
        if m["date"] and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", m["date"]):
            warnings.append(
                f"Testing Narrative \"{m['milestone']}\" date {m['date']!r} is not YYYY-MM-DD; "
                "it is printed as written. Fix it in engagement-info.md."
            )
            continue
        if m["date"]:
            try:
                datetime.strptime(m["date"], "%Y-%m-%d")
            except ValueError:
                warnings.append(f"Testing Narrative \"{m['milestone']}\" date {m['date']!r} is not a real date.")
    return warnings


def finalization_warnings(ctx):
    if ctx["status"] != "FINAL":
        return []
    warnings = []
    open_count = sum(1 for f in ctx["findings"] if f["status"] == "fail")
    if open_count:
        warnings.append(
            f"{open_count} finding(s) are still \"fail\". Every finding must be fixed-and-retested or accepted "
            "before FINAL (remediation-and-retesting.md, Finalizing step 1)."
        )
    incomplete = ctx["summary"].get("checks_incomplete") or {}
    if incomplete:
        warnings.append(
            f"{len(incomplete)} check(s) are incomplete because of collection errors ({', '.join(incomplete)}). "
            "Fix the cause and collect again before FINAL."
        )
    elif not ctx["summary"].get("collection_errors_recorded"):
        warnings.append(
            "The snapshot doesn't record collection errors, so the findings can't show every API call "
            "succeeded. Collect again with the current collector before FINAL."
        )
    pending = [m["milestone"] for m in ctx["milestones"] if not m["date"]]
    if pending:
        warnings.append(f"Testing Narrative row(s) still Pending: {', '.join(pending)}.")
    blank = [k for k in ("Auditor Name", "Auditor Title", "Auditor Organization", "Auditor Contact") if not ctx["meta"].get(k)]
    if blank:
        warnings.append(f"Blank auditor field(s) will print as \"{NOT_PROVIDED}\": {', '.join(blank)}.")
    return warnings


def output_filename(account_id, framework, label, status):
    parts = ["AWS_Security_Audit", account_id or "unknown", framework]
    if label:
        parts.append(re.sub(r"[^A-Za-z0-9._-]+", "-", label))
    parts.append(status)
    return "_".join(parts) + ".docx"


def tracker_filename(account_id, framework, label):
    parts = ["AWS_Security_Audit", account_id or "unknown", framework]
    if label:
        parts.append(re.sub(r"[^A-Za-z0-9._-]+", "-", label))
    return "_".join(parts) + "_remediation-tracker.csv"


def previous_tracker(args, out_dir, tracker_path):
    """The tracker to carry filled-in columns forward from: --previous-tracker,
    else the output file itself, else the newest other tracker for this
    account and framework in the output directory (the baseline's, on a
    retest). None for the first build."""
    if args.previous_tracker:
        if not os.path.exists(args.previous_tracker):
            raise ValueError(f"--previous-tracker {args.previous_tracker} not found")
        return args.previous_tracker
    if os.path.exists(tracker_path):
        return None  # write_tracker merges from, and backs up, the existing file
    prefix = os.path.basename(tracker_path).split("_remediation-tracker.csv")[0]
    stem = "_".join(prefix.split("_")[:4])  # AWS_Security_Audit_<account>_<framework>
    candidates = [os.path.join(out_dir, n) for n in os.listdir(out_dir)
                  if n.startswith(stem) and n.endswith("_remediation-tracker.csv")]
    return max(candidates, key=os.path.getmtime) if candidates else None


def build_region_resources_appendix(doc, ctx):
    """Appendix listing every resource outside the operating regions - the
    full detail behind resources_outside_operating_regions, whose evidence
    names at most 15 per region."""
    entries = [(f, r) for f in ctx["findings"]
               if f["check_id"] == REGION_CHECK and f["status"] in ("fail", "accepted")
               for r in f.get("resources") or []]
    if not entries:
        return
    doc.add_heading("Appendix: Resources Outside the Operating Regions", level=1)
    doc.add_paragraph(
        f"Every resource found outside the operating regions ({', '.join(ctx['summary'].get('operating_regions') or [])}), "
        "AWS-created defaults excluded. Each needs an owner and a decision: delete it, migrate it, or add its "
        "region to the operating regions. Each is also a row in the remediation tracker "
        f"({ctx['tracker_name']}), where that decision is recorded."
    )
    rows = []
    for f, r in sorted(entries, key=lambda e: (e[0]["region"], not e[1]["exposure"], e[1]["type"], e[1]["id"])):
        rows.append((
            f["region"], r["type"], r["id"],
            "; ".join(r["exposure"]) or "No",
            "; ".join(f"{x['check_id']} ({x['severity']})" for x in r["findings"]) or "—",
        ))
    add_table(doc, ["Region", "Type", "Resource", "Internet-exposed", "Other findings"],
              rows, [0.9, 1.1, 1.8, 1.3, 1.5], font_size=8)


def build(args):
    with open(args.findings) as f:
        result = json.load(f)
    summary, findings = result.get("summary") or {}, result.get("findings") or []
    framework = summary.get("framework") or "cis"
    engagement_dir = os.path.dirname(os.path.abspath(args.findings))

    engagement_path = args.engagement_info or os.path.join(engagement_dir, "engagement-info.md")
    meta, milestones = parse_engagement_info(engagement_path)

    snapshot_path = args.snapshot or default_snapshot_path(args.findings, summary.get("collected_at"))
    snapshot = None
    snapshot_warnings = []
    if not snapshot_path:
        snapshot_warnings.append(
            "No snapshot matching these findings' collected_at was found next to them, so the appendix "
            "omits who collected the data and which regions. Pass --snapshot."
        )
    if snapshot_path:
        with open(snapshot_path) as f:
            snapshot = json.load(f)

    ctx = {
        "summary": summary,
        "findings": findings,
        "framework": framework,
        "meta": meta,
        "milestones": milestones,
        "status": meta["Report Status"],
        "variant_note": args.variant_note if args.variant_note is not None else meta.get("Report Variant Note", ""),
        "collected_at": format_timestamp(summary["collected_at"]) if summary.get("collected_at") else "Not recorded",
        "collected_known": bool(summary.get("collected_at")),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "snapshot": snapshot,
        "data_source": args.data_source,
        "findings_path": args.findings,
        "manual_checks": parse_manual_checks(),
        "report_tool_version": tool_version(),
        "tracker_name": tracker_filename(summary.get("account_id"), framework, args.label),
        "letter_name": letter_filename(summary.get("account_id"), framework, args.label, meta["Report Status"]),
    }
    out_dir = args.out_dir or engagement_dir
    tracker_path = os.path.join(out_dir, ctx["tracker_name"])
    previous = previous_tracker(args, out_dir, tracker_path)

    doc = setup_document(ctx)
    build_cover(doc, ctx)
    build_executive_summary(doc, ctx)
    build_key_findings(doc, ctx)
    number = 3
    if any(f["status"] == "accepted" for f in findings):
        build_accepted(doc, ctx, number)
        number += 1
    build_passing(doc, ctx, number)
    build_detailed(doc, ctx, number + 1)
    build_management_matters(doc, ctx, number + 2)
    build_region_resources_appendix(doc, ctx)
    build_appendix(doc, ctx)

    out_path = os.path.join(out_dir, output_filename(summary.get("account_id"), framework, args.label, ctx["status"]))
    doc.save(out_path)
    _, counts, tracker_notes = write_tracker(result, args.findings, tracker_path, previous)
    tracker_notes.insert(0, f"Wrote {tracker_path}: "
                         + ", ".join(f"{n} {k.lower()}" for k, n in sorted(counts.items())) + ".")
    letter_path = os.path.join(out_dir, ctx["letter_name"])
    build_management_letter(ctx, letter_path)
    tracker_notes.insert(1, f"Wrote {letter_path}.")
    return out_path, tracker_notes, (snapshot_warnings + date_warnings(ctx) + tool_version_warnings(ctx)
                                     + finalization_warnings(ctx) + operating_regions_warnings(ctx, engagement_path))


def operating_regions_warnings(ctx, engagement_path):
    """Warn when engagement-info.md's Operating Regions no longer match the
    ones run_checks.py used, e.g. edited after the checks ran."""
    s = ctx["summary"]
    if "operating_regions" not in s:
        return []
    declared, _ = parse_operating_regions(engagement_path)
    if declared == s.get("operating_regions"):
        return []
    return [f"engagement-info.md declares Operating Regions {', '.join(declared or []) or '(none)'}, but the "
            f"findings were evaluated with {', '.join(s.get('operating_regions') or []) or '(none)'}. "
            "Run run_checks.py again so the report matches the engagement scope."]


def main():
    parser = argparse.ArgumentParser(description="Build the aws-audit Word report from a run_checks.py findings file.")
    parser.add_argument("findings", help="findings JSON produced by run_checks.py")
    parser.add_argument("--engagement-info", help="engagement-info.md (default: next to the findings file)")
    parser.add_argument("--snapshot", help="snapshot JSON, for regions/collector identity in the appendix "
                                           "(default: the findings file's name with 'findings' -> 'snapshot', if present)")
    parser.add_argument("--label", help="extra filename label, e.g. retest-1")
    parser.add_argument("--variant-note", help="overrides engagement-info.md's Report Variant Note for this build")
    parser.add_argument("--data-source", default="Live AWS API collection via collect_aws_data.py (read-only audit role)",
                        help="how the snapshot was produced, for the methodology appendix")
    parser.add_argument("--out-dir", help="output directory (default: the findings file's directory)")
    parser.add_argument("--previous-tracker",
                        help="remediation tracker CSV to carry Owner, Disposition and the other filled-in "
                             "columns forward from (default: this build's tracker if it exists, else the newest "
                             "tracker for this account and framework in the output directory)")
    args = parser.parse_args()

    try:
        out_path, notes, warnings = build(args)
    except (BuildError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Wrote {out_path}", file=sys.stderr)
    for n in notes:
        print(n, file=sys.stderr)
    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)


if __name__ == "__main__":
    main()
