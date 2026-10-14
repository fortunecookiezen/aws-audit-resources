"""The version of this tool, recorded in every snapshot, findings file and
report so an engagement shows which code produced each result. Findings
depend on the code as well as the account: a collector or check fix can
change a result with nothing changed in AWS."""

import os
import re
import subprocess

SCRIPTS_DIR = os.path.dirname(os.path.realpath(__file__))
UNKNOWN = "unknown"
RELEASE_RE = re.compile(r"v\d+\.\d+\.\d+")


def tool_version():
    """`git describe --tags --always --dirty` of the checkout these scripts
    are in: "v0.1.0" at a release, "v0.1.0-3-gabc1234" three commits past
    it, a bare commit before any tag, and "-dirty" on any of these when
    tracked files have uncommitted changes. "unknown" when the scripts
    aren't in a git checkout (a copied skill directory) or git isn't
    installed."""
    try:
        out = subprocess.run(
            ["git", "-C", SCRIPTS_DIR, "describe", "--tags", "--always", "--dirty"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return UNKNOWN
    version = out.stdout.strip()
    return version if out.returncode == 0 and version else UNKNOWN


def is_release(version):
    """True only for an exact release tag (vX.Y.Z, nothing after it)."""
    return bool(version) and RELEASE_RE.fullmatch(version) is not None


def version_problem(version):
    """Why `version` doesn't identify released code, or None if it does."""
    if not version:
        return "no tool version is recorded (produced before the tool recorded it)"
    if version == UNKNOWN:
        return "the tool version is unknown (the scripts weren't run from a git checkout)"
    if version.endswith("-dirty"):
        return f"tool version {version} had uncommitted changes, so the code that ran isn't recorded anywhere"
    if not is_release(version):
        return f"tool version {version} is not a release tag"
    return None
