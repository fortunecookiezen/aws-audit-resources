#!/usr/bin/env python3
"""
remediation_tracker.py - the engagement's remediation tracker, as a CSV.

One row per failing or accepted finding in a run_checks.py findings file,
and one per resource outside the operating regions (in place of the
region-level resources_outside_operating_regions row). build_report.py
writes it next to the report; it can also be run on its own:

    python3 remediation_tracker.py findings.json [-o tracker.csv] [--previous previous-tracker.csv]

The tracker is evidence of how each finding was handled, so the columns
people fill in (Owner, Target date, Disposition, Ticket, Closed date,
Closure evidence, Notes, and any column they add) are never discarded:

- Each row has a stable Tracker ID (from the check ID and resource), so a
  rebuild or a retest carries those columns forward from --previous, or
  from the existing output file when there's no --previous.
- A row in the previous tracker that no longer fails is kept and marked
  Closed, with the findings file and collection time that showed it -
  unless the check wasn't evaluated, or was incomplete, in this run, in
  which case it's "Not re-verified" rather than closed.
- A closed row that fails again is marked Reopened.
- An existing output file is copied to <name>.<timestamp>.bak.csv before
  it's replaced.

The tracker holds resource IDs from the audited account: keep it in the
engagement directory with the rest of the evidence, never in this repo.
"""

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone

REGION_CHECK = "resources_outside_operating_regions"

MACHINE_COLUMNS = [
    "Tracker ID", "Tracker status", "Blocks pass", "Check ID", "Title", "Area", "Severity", "Advisory",
    "Finding status", "Region", "Resource", "Evidence", "Remediation", "Control",
    "First seen", "Last seen", "Last verified by",
]
HUMAN_COLUMNS = [
    "Owner", "Target date (YYYY-MM-DD)", "Disposition", "Ticket",
    "Closed date (YYYY-MM-DD)", "Closure evidence", "Notes",
]
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
STATUS_ORDER = {"Reopened": 0, "Open": 1, "Not re-verified": 2, "Accepted": 3, "Informational": 4}


def tracker_id(check_id, resource):
    digest = hashlib.sha1(f"{check_id}|{resource}".encode()).hexdigest()[:10]
    return f"F-{digest}"


def _control(refs):
    return "; ".join(f"{k}: {v}" if len(refs) > 1 else str(v) for k, v in (refs or {}).items() if v)


def current_rows(result, findings_name):
    """{tracker id: row} for this run's failing and accepted findings."""
    s = result.get("summary") or {}
    seen = s.get("collected_at") or "unknown"
    verified_by = f"{findings_name} (collected {seen})"
    rows = {}
    ar = s.get("audit_result")
    blocking = {(b["check_id"], b["resource"]) for b in (ar or {}).get("blocking", [])}

    def add(f, resource, evidence, extra=None):
        row = {
            "Tracker ID": tracker_id(f["check_id"], resource),
            "Tracker status": ("Accepted" if f["status"] == "accepted" else
                               "Informational" if f["severity"] == "Informational" else "Open"),
            # Blank for findings from before the tool computed an audit result.
            "Blocks pass": "" if ar is None else ("Yes" if (f["check_id"], f["resource"]) in blocking else "No"),
            "Check ID": f["check_id"],
            "Title": f["title"],
            "Area": f["area"],
            "Severity": f["severity"],
            "Advisory": "Yes" if f.get("advisory") else "",
            "Finding status": f["status"],
            "Region": f.get("region") or "",
            "Resource": resource,
            "Evidence": evidence,
            "Remediation": f.get("remediation", ""),
            "Control": _control(f.get("refs")),
            "First seen": seen,
            "Last seen": seen,
            "Last verified by": verified_by,
        }
        kind = (f.get("acceptance") or {}).get("kind")
        if kind == "expected_admin_principal":
            row["Disposition"] = "Administrator by design (accepted_admin_principals); communicated to management"
        elif f["status"] == "accepted":
            row["Disposition"] = "Risk accepted (exceptions.json)"
        elif f["severity"] == "Informational":
            row["Disposition"] = "Informational; communicated to management"
        row.update(extra or {})
        rows[row["Tracker ID"]] = row

    for f in result.get("findings") or []:
        if f["status"] not in ("fail", "accepted"):
            continue
        if f["check_id"] == REGION_CHECK and f.get("resources"):
            for r in f["resources"]:
                others = ", ".join(f"{x['check_id']} ({x['severity']}, {x['status']})" for x in r["findings"])
                evidence = (f"{r['type']} {r['id']} is in {f['region']}, outside the operating regions"
                            f" ({', '.join(s.get('operating_regions') or [])}).")
                if r["exposure"]:
                    evidence += " Internet-exposed: " + "; ".join(r["exposure"]) + "."
                if others:
                    evidence += " Other findings against it: " + others + "."
                add(f, f"{f['region']} {r['type']} {r['id']}", evidence,
                    {"Severity": "High" if r["exposure"] else "Medium"})
        else:
            add(f, f["resource"], f["evidence"])
    return rows


def _still_present(result, row):
    """For a previous row missing from this run: was its resource evaluated
    again (and passing), gone, or not re-verified?"""
    s = result.get("summary") or {}
    check = row["Check ID"]
    evaluated = set(s.get("checks_evaluated") or [])
    incomplete = set(s.get("checks_incomplete") or {})
    if check not in evaluated or check in incomplete:
        return "Not re-verified"
    if check == REGION_CHECK:
        return "Closed (no longer found outside the operating regions)"
    if any(f["check_id"] == check and f["resource"] == row["Resource"] and f["status"] == "pass"
           for f in result.get("findings") or []):
        return "Closed (passed in retest)"
    return "Closed (resource no longer present)"


def merge(rows, previous, result, findings_name):
    """Carry previous rows' human columns into this run's rows, and keep
    previous rows that are no longer failing, marked closed or not
    re-verified."""
    s = result.get("summary") or {}
    verified_by = f"{findings_name} (collected {s.get('collected_at') or 'unknown'})"
    for pid, prow in previous.items():
        if pid in rows:
            row = rows[pid]
            for col, val in prow.items():
                if col not in MACHINE_COLUMNS and val:
                    row[col] = val
            row["First seen"] = prow.get("First seen") or row["First seen"]
            if (prow.get("Tracker status") or "").startswith("Closed") and row["Tracker status"] == "Open":
                row["Tracker status"] = "Reopened"
            continue
        row = dict(prow)
        if not (prow.get("Tracker status") or "").startswith("Closed"):
            status = _still_present(result, prow)
            row["Tracker status"] = status
            if status.startswith("Closed"):
                row["Last verified by"] = verified_by
        if "audit_result" in s:
            row["Blocks pass"] = "Yes" if row["Tracker status"] == "Not re-verified" else "No"
        rows[pid] = row
    return rows


def read_tracker(path):
    """(rows by tracker id, header) from an earlier tracker CSV."""
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or "Tracker ID" not in reader.fieldnames:
            raise ValueError(f"{path} isn't a remediation tracker (no 'Tracker ID' column)")
        return {r["Tracker ID"]: r for r in reader if r.get("Tracker ID")}, list(reader.fieldnames)


def _sort_key(row):
    status = row.get("Tracker status") or ""
    return (STATUS_ORDER.get(status, 9 if status.startswith("Closed") else 5),
            SEVERITY_ORDER.get(row.get("Severity"), 9), row.get("Check ID", ""), row.get("Resource", ""))


def write_tracker(result, findings_path, out_path, previous_path=None):
    """Write the tracker; return (out_path, counts by tracker status, warnings)."""
    warnings = []
    findings_name = os.path.basename(findings_path)
    rows = current_rows(result, findings_name)
    header = MACHINE_COLUMNS + HUMAN_COLUMNS
    source = previous_path or (out_path if os.path.exists(out_path) else None)
    if source:
        previous, prev_header = read_tracker(source)
        header += [c for c in prev_header if c not in header]
        rows = merge(rows, previous, result, findings_name)
        warnings.append(f"Carried filled-in tracker columns forward from {os.path.basename(source)}.")
    if os.path.exists(out_path):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = f"{os.path.splitext(out_path)[0]}.{stamp}.bak.csv"
        shutil.copy2(out_path, backup)
        warnings.append(f"The tracker it replaces is saved as {os.path.basename(backup)}.")
    with open(out_path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=header, extrasaction="ignore")
        writer.writeheader()
        for row in sorted(rows.values(), key=_sort_key):
            writer.writerow({c: row.get(c, "") for c in header})
    counts = {}
    for row in rows.values():
        counts[row["Tracker status"]] = counts.get(row["Tracker status"], 0) + 1
    return out_path, counts, warnings


def main():
    parser = argparse.ArgumentParser(description="Write the remediation tracker CSV for a findings file.")
    parser.add_argument("findings", help="findings JSON produced by run_checks.py")
    parser.add_argument("-o", "--output", help="tracker CSV (default: remediation-tracker.csv next to the findings)")
    parser.add_argument("--previous", help="an earlier tracker to carry filled-in columns forward from "
                                           "(default: the output file, if it exists)")
    args = parser.parse_args()
    with open(args.findings) as fh:
        result = json.load(fh)
    out = args.output or os.path.join(os.path.dirname(os.path.abspath(args.findings)), "remediation-tracker.csv")
    try:
        path, counts, warnings = write_tracker(result, args.findings, out, args.previous)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Wrote {path}: " + ", ".join(f"{n} {k.lower()}" for k, n in sorted(counts.items())), file=sys.stderr)
    for w in warnings:
        print(f"NOTE: {w}", file=sys.stderr)


if __name__ == "__main__":
    main()
