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

A baseline finding with no entry in the retest is only listed as no longer
present when the retest collected that check's data completely. If the
check was incomplete (an API call it depends on failed during collection;
see the retest's summary.checks_incomplete) or skipped, the finding is
listed as not verified instead: the resource may still exist, uncollected.

It also prints the tool version each side was produced with, and a NOTE when
they differ: then a change between the two can come from the tool (a check
or collector fix) rather than from the account.

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
    # A check the retest couldn't collect fully can't show a resource is gone.
    summary = retest.get("summary", {})
    unverifiable = set(summary.get("checks_incomplete") or {}) | set(summary.get("checks_skipped") or [])
    removed_resources, not_verified = [], []
    for k in sorted(b_keys - r_keys):
        (not_verified if k[0] in unverifiable else removed_resources).append(b_idx[k])

    return {
        "regressed": regressed,
        "still_failing": still_failing,
        "fixed": fixed,
        "unchanged_pass": unchanged_pass,
        "new_findings": new_findings,
        "removed_resources": removed_resources,
        "not_verified": not_verified,
    }


def _versions(summary):
    """The tool version(s) behind one findings file: "collected with X,
    checked with Y" collapsed to one value when they match."""
    checks = summary.get("tool_version") or "not recorded"
    collected = summary.get("snapshot_tool_version") or "not recorded"
    return checks if checks == collected else f"collected {collected}, checked {checks}"


def _fmt(f):
    return f"{f['check_id']} — {f['resource']} [{f['status']}]"


def print_report(baseline, retest, d):
    bf = baseline["summary"].get("framework")
    rf = retest["summary"].get("framework")
    bv, rv = _versions(baseline["summary"]), _versions(retest["summary"])
    print(f"Baseline: {baseline['summary'].get('collected_at')} ({bf}, {len(baseline['findings'])} findings; tool {bv})")
    print(f"Retest:   {retest['summary'].get('collected_at')} ({rf}, {len(retest['findings'])} findings; tool {rv})")
    if bv != rv:
        print(
            f"NOTE: the baseline and retest were produced with different tool versions ({bv} vs {rv}), "
            "so a change below can come from the tool rather than the account. Check the release notes "
            "between them for check, collector or exceptions changes."
        )
    if bf != rf:
        print(
            f"WARNING: baseline framework ({bf}) != retest framework ({rf}) - "
            "pass/fail status is framework-independent (only the displayed "
            "control refs differ), so this diff is still valid, but don't "
            "expect the control references to line up between runs."
        )
    if not retest["summary"].get("collection_errors_recorded"):
        print(
            "NOTE: the retest's snapshot doesn't record collection errors (collected before the "
            "collector did), so a finding missing from it may be a failed API call rather than a "
            "deleted resource."
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

    if d["not_verified"]:
        print(
            f"NOT VERIFIED ({len(d['not_verified'])}) - was in the baseline, has no entry in the retest, "
            "but the retest couldn't collect this check's data completely (see its summary's "
            "checks_incomplete / checks_skipped). Collect again before treating these as resolved:"
        )
        for f in d["not_verified"]:
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
