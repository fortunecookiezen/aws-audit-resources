# Evidence handling: clone → audit → evidence → private repo or archive

This repo is a public, shared set of templates and skills — the role definitions in `cloudformation/`/`terraform/` and the audit logic in `skill/` are meant to be reused across engagements and accounts. **A specific audit run is not.** The moment `collect_aws_data.py` touches a real account, its output (`snapshot.json`, `findings.json`, the generated report) contains that account's real IAM users, role names, bucket names, security group rules, and findings about where it's weak. None of that belongs in this repo's git history, public or private fork alike.

This doc is the intended lifecycle for a single audit engagement, start to finish.

## The lifecycle

1. **Clone.** Clone (or use an existing checkout of) this repo to get the role templates and the `skill/` directory. You don't need write access to this repo to run an audit — read access to the templates and scripts is enough.

2. **Deploy the audit role, if it isn't already there.** Per `skill/SKILL.md` Step 2, deploy `cloudformation/security-audit-role.yml` (or the `terraform/security-audit-role/` module) into the target account if `<org_prefix>-CrossAccountSecurityAuditRole` doesn't already exist there. This is a one-time setup per account, not per audit.

3. **Open a per-engagement working directory.** At the repo root, create:

   ```
   audit-runs/<account_id>-<YYYYMMDD>/
   ```

   e.g. `audit-runs/111122223333-20261006/`. This path is covered by this repo's `.gitignore` (see below) specifically so step 4's output can land inside a clone of this repo without any risk of it being swept into a commit here by an `git add -A`/`git add .` run from the repo root.

4. **Run the audit into that directory.** Assume the role, then:

   ```bash
   python3 skill/scripts/collect_aws_data.py --all-regions --role-arn $AUDIT_ROLE_ARN \
     -o audit-runs/111122223333-20261006/snapshot.json
   python3 skill/scripts/run_checks.py audit-runs/111122223333-20261006/snapshot.json \
     --framework cis -o audit-runs/111122223333-20261006/findings.json
   ```

   Build the Word report (`skill/SKILL.md` Step 4) into the same directory, e.g. `audit-runs/111122223333-20261006/report.docx`. At this point the directory holds the full evidence package: raw snapshot, evaluated findings, and the human-readable report.

5. **Decide where the evidence lives.** Once the audit is complete, move `audit-runs/<account_id>-<date>/` to one of:

   - **A private, per-client or per-engagement evidence repository** — never this repo, and never a fork of it that's publicly visible. A reasonable convention: one evidence repo per client or per account, named something like `<client>-audit-evidence`, with each engagement as a dated subdirectory or a dated commit. This gives you git history (who reviewed what, when) without mixing evidence into the tool repo's history.
   - **An archive**, when there's no standing evidence repo for a one-off engagement: tar and checksum the directory —
     ```bash
     tar -czf opspath-audit-111122223333-cis-20261006.tar.gz -C audit-runs 111122223333-20261006
     sha256sum opspath-audit-111122223333-cis-20261006.tar.gz > opspath-audit-111122223333-cis-20261006.tar.gz.sha256
     ```
     and store the bundle + checksum (and, if your evidentiary requirements call for it, a GPG signature) somewhere access-controlled and outside git — encrypted cloud storage, a secure file share, whatever your existing evidence-retention policy already uses for this kind of material.

6. **Clear the local working directory.** Once the evidence is safely in its new home, delete (or securely move) `audit-runs/<account_id>-<date>/` from your local clone of this repo. The `.gitignore` entry stops it from being *committed*, but it doesn't stop it from sitting on disk indefinitely across repeated engagements — treat that directory as scratch space for one audit, not a running archive.

## What this repo does to support that lifecycle

- **`.gitignore`** excludes `/audit-runs/` at the repo root, so step 3–4's output is never accidentally staged even by a broad `git add`.
- **`.gitguardian.yaml`** scopes secret scanning away from `skill/evals/fixtures/` — the *synthetic* data used by the eval suite — precisely so that exclusion stays narrow and doesn't become a habit of suppressing real findings. A real `audit-runs/` directory should never reach a commit in the first place; it has no corresponding allowlist entry here, intentionally.
- **Nothing in this repo stores or transmits audit output anywhere.** `collect_aws_data.py` and `run_checks.py` only read from AWS and write to the local filesystem path you give them. Where that output ends up after that is entirely the steps above — this repo has no opinion on your evidence-repo or archive-storage choice beyond "not here."

## If you're running this through an AI assistant without direct git/archive access

Some environments (for example, a cloud-sandboxed coding assistant) can write files into your working directory but can't run `git commit`/`git push`, create a new private repo, or move files into encrypted storage on your behalf. In that case the assistant can do steps 1–4 (clone context, run the collector and checks, build the report) and hand you the finished `audit-runs/<account_id>-<date>/` directory, but a human completes step 5 (committing to the private evidence repo or archiving) and step 6 (clearing the working copy). Treat an assistant stopping at that handoff as correct behavior, not a missed step.
