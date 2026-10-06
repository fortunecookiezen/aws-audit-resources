#!/usr/bin/env python3
"""
diff_findings.py - compare two run_checks.py findings.json files (a
remediation baseline and a retest) and categorize what actually changed, per
(check_id, resource), rather than relying on the two summary blocks' pass/
fail counts. A count diff alone can hide a regression (one finding fixed,
a different one newly broken, net count unchanged) - see
references/remediation-and-retesting.md, step 5, for the workflow this
supports.

Usage:
    python3 diff_findings.py findings-baseline.json findings-retest.json
    python3 diff_findings.py findings-baseline.json findings-retest.json -o diff.json

Exit status is 2 if any finding regressed (was passing/accepted, now
failing), so this can gate a CI/automation step; 0 otherwise.
"""

import argparse
import json
import sys

OK_STATUSES = {"pass", "accepted"}


def _key(f):
    return (f["check_id"], f["resource"])


def _load(path):
    with open(path) as fh:
        return json.load(fh)


def _index(findings):
    return {_key(f): f for f in findings}


def diff(baseline, retest):
    b_idx = _index(baseline["findings"])
    r_idx = _index(retest["findings"])
    b_keys, r_keys = set(b_idx), set(r_idx)

    regressed, still_failing, fixed, unchanged_pass = [], [], [], []
    for k in b_keys & r_keys:
        b, r = b_idx[k], r_idx[k]
        b_ok, r_ok = b["status"] in OK_STATUSES, r["status"] in OK_STATUSES
        if b_ok and not r_ok:
            regressed.append((b, r))
        elif not b_ok and not r_ok:
            still_failing.append((b, r))
        elif not b_ok and r_ok:
            fixed.append((b, r))
        else:
            unchanged_pass.append((b, r))

    new_findings = [r_idx[k] for k in sorted(r_keys - b_keys)]
    removed_resources = [b_idx[k] for k in sorted(b_keys - r_keys)]

    return {
        "regressed": regressed,
        "still_failing": still_failing,
        "fixed": fixed,
        "unchanged_pass": unchanged_pass,
        "new_findings": new_findings,
        "removed_resources": removed_resources,
    }


def _fmt(f):
    return f"{f['check_id']} — {f['resource']} [{f['status']}]"


def print_report(baseline, retest, d):
    bf = baseline["summary"].get("framework")
    rf = retest["summary"].get("framework")
    print(f"Baseline: {baseline['summary'].get('collected_at')} ({bf}, {len(baseline['findings'])} findings)")
    print(f"Retest:   {retest['summary'].get('collected_at')} ({rf}, {len(retest['findings'])} findings)")
    if bf != rf:
        print(
            f"WARNING: baseline framework ({bf}) != retest framework ({rf}) - "
            "pass/fail status is framework-independent (only the displayed "
            "control refs differ), so this diff is still valid, but don't "
            "expect the control references to line up between runs."
        )
    print()

    if d["regressed"]:
        print(f"REGRESSED ({len(d['regressed'])}) - was passing/accepted, now failing. Investigate before anything else:")
        for b, r in d["regressed"]:
            print(f"  - {_fmt(r)}  (was: {b['status']})")
        print()

    if d["still_failing"]:
        print(f"STILL FAILING ({len(d['still_failing'])}) - remediation not yet effective, or not yet applied:")
        for b, r in d["still_failing"]:
            print(f"  - {_fmt(r)}")
        print()

    if d["fixed"]:
        print(f"FIXED ({len(d['fixed'])}) - was failing, now passing/accepted:")
        for b, r in d["fixed"]:
            print(f"  - {_fmt(r)}  (now: {r['status']})")
        print()

    if d["new_findings"]:
        print(
            f"NEW ({len(d['new_findings'])}) - this check/resource pair has no baseline entry "
            "(a new resource was created, or a check was added to the skill since the baseline ran):"
        )
        for f in d["new_findings"]:
            print(f"  - {_fmt(f)}")
        print()

    if d["removed_resources"]:
        print(
            f"NO LONGER PRESENT ({len(d['removed_resources'])}) - was in the baseline, has no matching "
            "entry in the retest (resource deleted, or a check was removed from the skill). Confirm "
            "this is actually resource deletion and not a collection gap before treating it as resolved:"
        )
        for f in d["removed_resources"]:
            print(f"  - {_fmt(f)}")
        print()

    print(f"Unchanged, still passing/accepted: {len(d['unchanged_pass'])}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("baseline", help="Findings JSON from before remediation")
    ap.add_argument("retest", help="Findings JSON from after remediation")
    ap.add_argument("-o", "--output", help="Optional path to write the full diff as JSON")
    args = ap.parse_args()

    baseline = _load(args.baseline)
    retest = _load(args.retest)
    d = diff(baseline, retest)
    print_report(baseline, retest, d)

    if args.output:
        pairwise = {"regressed", "still_failing", "fixed", "unchanged_pass"}
        serializable = {
            k: [{"baseline": b, "retest": r} for b, r in v] if k in pairwise else v
            for k, v in d.items()
        }
        with open(args.output, "w") as fh:
            json.dump(serializable, fh, indent=2)
        print(f"\nWrote full diff to {args.output}")

    if d["regressed"]:
        sys.exit(2)


if __name__ == "__main__":
    main()
