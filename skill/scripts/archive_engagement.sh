#!/usr/bin/env bash
#
# archive_engagement.sh - close out a finished audit engagement: write a
# SHA-256 manifest of the engagement directory, bundle it into an encrypted
# archive, check the bundle restores to the same files, and print what to
# record about it. See references/evidence-handling.md, "Closing out an
# engagement."
#
# Usage:
#     bash archive_engagement.sh <engagement-dir> --age-recipient <age public key>
#     bash archive_engagement.sh <engagement-dir> --gpg-recipient <key id or email>
#     bash archive_engagement.sh <engagement-dir> --manifest-only
#   Options:
#     --out-dir <dir>      where to write the archive (default: the engagement
#                          directory's parent)
#     --allow-draft        archive although engagement-info.md doesn't say
#                          Report Status: FINAL (an abandoned engagement)
#     --no-encrypt         write an unencrypted .tar.gz; only for storage that
#                          is already encrypted and access-controlled
#
# Every run writes two files into the engagement directory:
#   ARCHIVE-INFO.txt   when and by whom it was archived, the tool commit it
#                      was archived with, and the file count
#   MANIFEST.sha256    SHA-256 of every file (except .git/ and editor/OS
#                      debris), checkable with `shasum -a 256 -c MANIFEST.sha256`
# --manifest-only stops there, for an engagement kept in a private git
# repository: commit both files and tag the commit. Otherwise it writes
# <out-dir>/aws-audit-<engagement dir name>.tar.gz.age (or .gpg) and a .sha256
# file beside it. The plaintext .tar.gz is checked against the manifest and
# then deleted. Word lock files (~$*), .DS_Store and AppleDouble (._*) files
# are left out of both the manifest and the archive.

set -euo pipefail

usage() {
  sed -n '/^# Usage:/,/^#                          is already encrypted/p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

die() { echo "ERROR: $*" >&2; exit 1; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

dir="" out_dir="" age_recipient="" gpg_recipient=""
manifest_only=0 allow_draft=0 no_encrypt=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out-dir) out_dir="${2:-}"; shift 2 ;;
    --age-recipient) age_recipient="${2:-}"; shift 2 ;;
    --gpg-recipient) gpg_recipient="${2:-}"; shift 2 ;;
    --manifest-only) manifest_only=1; shift ;;
    --allow-draft) allow_draft=1; shift ;;
    --no-encrypt) no_encrypt=1; shift ;;
    -h|--help) usage ;;
    -*) die "unknown option $1" ;;
    *) [ -z "$dir" ] || usage; dir="$1"; shift ;;
  esac
done
[ -n "$dir" ] || usage
[ -d "$dir" ] || die "$dir is not a directory"
dir="$(cd "$dir" && pwd)"
name="$(basename "$dir")"
parent="$(dirname "$dir")"

if [ "$manifest_only" -eq 0 ]; then
  modes=0
  [ -n "$age_recipient" ] && modes=$((modes + 1))
  [ -n "$gpg_recipient" ] && modes=$((modes + 1))
  [ "$no_encrypt" -eq 1 ] && modes=$((modes + 1))
  [ "$modes" -eq 1 ] || die "choose exactly one of --age-recipient, --gpg-recipient, --no-encrypt (or --manifest-only)"
  [ -z "$age_recipient" ] || command -v age >/dev/null 2>&1 || die "age is required for --age-recipient but not installed"
  [ -z "$gpg_recipient" ] || command -v gpg >/dev/null 2>&1 || die "gpg is required for --gpg-recipient but not installed"
fi

# The engagement must be finished: a FINAL report status and a FINAL report.
info="$dir/engagement-info.md"
[ -f "$info" ] || die "$info not found; is $dir an engagement directory?"
status="$(sed -n 's/^- Report Status:[[:space:]]*//p' "$info" | head -n 1 | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"
if [ "$status" != "FINAL" ]; then
  [ "$allow_draft" -eq 1 ] || die "engagement-info.md says Report Status: ${status:-<blank>}, not FINAL. Finalize first (remediation-and-retesting.md, \"Finalizing\"), or pass --allow-draft for an engagement that won't be finalized."
  echo "WARNING: archiving with Report Status: ${status:-<blank>} (--allow-draft)." >&2
fi
if ! ls "$dir"/*_FINAL.docx >/dev/null 2>&1 && [ "$allow_draft" -eq 0 ]; then
  die "no *_FINAL.docx report in $dir. Build it first (SKILL.md Step 6)."
fi

# Check the destination before writing anything.
if [ "$manifest_only" -eq 0 ]; then
  out_dir="${out_dir:-$parent}"
  case "$out_dir" in /*) ;; *) out_dir="$PWD/$out_dir" ;; esac
  case "$out_dir/" in "$dir/"*) die "--out-dir can't be inside the engagement directory" ;; esac
  mkdir -p "$out_dir"
  out_dir="$(cd "$out_dir" && pwd)"
  case "$out_dir/" in "$dir/"*) die "--out-dir can't be inside the engagement directory" ;; esac
  tarball="$out_dir/aws-audit-$name.tar.gz"
  [ ! -e "$tarball" ] && [ ! -e "$tarball.age" ] && [ ! -e "$tarball.gpg" ] \
    || die "$tarball(.age/.gpg) already exists; move it or choose another --out-dir"
fi

# Files to keep: everything except .git/ and editor/OS debris.
list_files() {
  (cd "$dir" && find . -type f \
      ! -path './.git/*' ! -name '~$*' ! -name '.DS_Store' ! -name '._*' \
      ! -name 'MANIFEST.sha256' -print | sed 's|^\./||' | LC_ALL=C sort)
}

debris="$(cd "$dir" && find . -type f \( -name '~$*' -o -name '.DS_Store' -o -name '._*' \) ! -path './.git/*' -print)"
[ -z "$debris" ] || { echo "Leaving out of the manifest and archive:" >&2; echo "$debris" | sed 's/^/  /' >&2; }

script_dir="$(cd "$(dirname "$0")" && pwd)"
tool_commit="$(git -C "$script_dir" describe --always --dirty --abbrev=12 2>/dev/null || echo unknown)"
archived_by="$(git config user.name 2>/dev/null || true)"
archived_by="${archived_by:-${USER:-unknown}}"

{
  echo "engagement: $name"
  echo "archived_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "archived_by: $archived_by"
  echo "report_status: ${status:-<blank>}"
  echo "tool_commit_at_archive: $tool_commit"
  echo "files: $(list_files | grep -vcx 'ARCHIVE-INFO.txt' || true) (plus this file and MANIFEST.sha256)"
} > "$dir/ARCHIVE-INFO.txt"

# Built outside the directory so the manifest doesn't list itself.
manifest_tmp="$(mktemp)"
(cd "$dir" && list_files | while IFS= read -r f; do sha256 "$f"; done) > "$manifest_tmp"
mv "$manifest_tmp" "$dir/MANIFEST.sha256"
(cd "$dir" && sha256 -c MANIFEST.sha256 >/dev/null) || die "MANIFEST.sha256 doesn't verify against $dir"
echo "Wrote $dir/MANIFEST.sha256 ($(wc -l < "$dir/MANIFEST.sha256" | tr -d ' ') files) and ARCHIVE-INFO.txt"

if [ "$manifest_only" -eq 1 ]; then
  if git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Next: git -C \"$dir\" add ARCHIVE-INFO.txt MANIFEST.sha256 && git -C \"$dir\" commit -m \"Archive $name\" && git -C \"$dir\" tag final-$(date -u +%Y%m%d) && git -C \"$dir\" push --follow-tags"
  fi
  exit 0
fi

# Until the archive is finished, an exit for any reason removes the scratch
# extraction and every partial output, so a failed encryption never leaves a
# plaintext copy of the evidence behind.
check="$(mktemp -d)"
done_ok=0
cleanup() {
  rm -rf "$check"
  if [ "$done_ok" -eq 0 ]; then
    rm -f "$tarball" "$tarball.age" "$tarball.gpg" "$tarball.sha256" "$tarball.age.sha256" "$tarball.gpg.sha256"
  fi
}
trap cleanup EXIT

# COPYFILE_DISABLE keeps macOS tar from adding AppleDouble (._*) entries.
COPYFILE_DISABLE=1 tar -czf "$tarball" -C "$parent" \
  --exclude '~$*' --exclude '.DS_Store' --exclude '._*' "$name"

# Restore check: extract into a scratch directory and verify the manifest there.
tar -xzf "$tarball" -C "$check"
(cd "$check/$name" && sha256 -c MANIFEST.sha256 >/dev/null) \
  || die "the archive doesn't restore to the manifest; nothing written"
echo "Restore check: archive extracts and matches MANIFEST.sha256"

final="$tarball"
if [ -n "$age_recipient" ]; then
  age -r "$age_recipient" -o "$tarball.age" "$tarball"
  final="$tarball.age"
elif [ -n "$gpg_recipient" ]; then
  gpg --batch --yes --encrypt --recipient "$gpg_recipient" --output "$tarball.gpg" "$tarball"
  final="$tarball.gpg"
fi
if [ "$final" != "$tarball" ]; then
  rm -f "$tarball"
fi

(cd "$out_dir" && sha256 "$(basename "$final")") > "$final.sha256"
hash="$(cut -d' ' -f1 "$final.sha256")"
done_ok=1

cat <<EOF

Archive:  $final
SHA-256:  $hash  (also in $(basename "$final").sha256)

Next (evidence-handling.md, "Closing out an engagement"):
  1. Copy the archive and its .sha256 to the evidence store. Keep a copy of
     the .sha256 somewhere separate from the archive.
  2. Test a restore from the store with the private key.
  3. Record the location and SHA-256 in the engagement register.
  4. Delete $dir and the other local copies (see the checklist).
EOF
