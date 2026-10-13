# Evidence handling: tool checkout → engagement directory → private repo or archive

This repo is a public, shared set of templates and skills — the role definitions in `cloudformation/`/`terraform/` and the audit logic in `skill/` are meant to be reused across engagements and accounts. **A specific audit run is not.** The moment `collect_aws_data.py` touches a real account, its output (`snapshot.json`, `findings.json`, the generated report) contains that account's real IAM users, role names, bucket names, security group rules, and findings about where it's weak. None of that belongs in this repo's git history, public or private fork alike.

This doc is the intended lifecycle for a single audit engagement, start to finish.

## Two separate trees

Keep the tool and the engagement apart:

- **The tool checkout** is a clone of this repo, used read-only to run audits. Check it out at a release tag, or a commit you can name, and don't develop in it: changing the tool happens in a different clone, through pull requests. Findings depend on the code that produced them (a collector fix can turn a failure into a pass without anything changing in the account), so record the tool commit each time you collect or run checks — the Testing Narrative's Notes column is the place:

  ```bash
  git -C <tool checkout> describe --always --dirty
  ```

  A `-dirty` result means the checkout has uncommitted changes, so the commit alone doesn't describe the code that ran. Don't audit from it.

- **The engagement directory** holds everything about one engagement, and lives *outside* the tool checkout, for example:

  ```
  ~/audits/<client>/<account_id>-<YYYYMMDD>/
  ```

  `SKILL.md` and the other references call it `$AUDIT_DIR`. Every script takes explicit paths, so nothing requires the engagement to sit under the tool repo. The tool repo's `.gitignore` still excludes `/audit-runs/` at its root, so an engagement placed there by mistake (or deliberately, for a quick one-off) can't be committed by a broad `git add`; treat that as a backstop, not the layout.

Decide at kickoff where the evidence will end up, because it changes how you set up the directory:

| Destination | Set up at kickoff | Close out with |
|---|---|---|
| **Private engagement repository** (an ongoing client, repeated audits) | `git init` in `$AUDIT_DIR` and add a private remote. Commit after each step (documentation request back, exceptions transcribed, each collection and report), so the repository records who changed what and when. | `archive_engagement.sh --manifest-only`, then commit, tag and push. |
| **Encrypted archive on disk** (a one-off engagement) | A plain directory. | `archive_engagement.sh --age-recipient …` or `--gpg-recipient …`, then store the archive. |

A private engagement repository must be private and must not be a fork of this repo: GitHub doesn't allow a fork of a public repository to be private, and a fork's pull requests open against the public repo. Create it as a new, empty repository. One repository per client, with each engagement as a dated directory, works well; give access only to the people who work on that client's engagements. Before every push, check `git remote -v` points at it.

## The lifecycle

1. **Get the tool.** Clone this repo, or update an existing tool checkout, and check out the tag or commit you'll audit with. You don't need write access to this repo to run an audit.

2. **Deploy the audit role, if it isn't already there.** Per `skill/SKILL.md` Step 2, deploy `cloudformation/security-audit-role.yml` (or the `terraform/security-audit-role/` module) into the target account if `<org_prefix>-CrossAccountSecurityAuditRole` doesn't already exist there. This is a one-time setup per account, not per audit.

3. **Create the engagement directory** at kickoff (`skill/SKILL.md` Step 1), not when data collection starts:

   ```bash
   export AUDIT_DIR=~/audits/<client>/111122223333-20261006
   mkdir -p "$AUDIT_DIR/evidence"
   cp <tool checkout>/skill/references/engagement-info-template.md "$AUDIT_DIR/engagement-info.md"
   git -C "$AUDIT_DIR" init   # private engagement repository only
   ```

   `engagement-info.md`, the completed `documentation-request-response.md` (or `.pdf`), its supporting `evidence/` attachments, and `exceptions.json` all go here before the first snapshot is taken.

4. **Run the audit into that directory.** From the tool checkout's `skill/` directory, assume the role, then:

   ```bash
   python3 scripts/collect_aws_data.py --all-regions --role-arn $AUDIT_ROLE_ARN \
     --role-session-name "$AUDIT_SESSION_NAME" -o "$AUDIT_DIR/snapshot.json"
   python3 scripts/run_checks.py "$AUDIT_DIR/snapshot.json" \
     --framework cis -o "$AUDIT_DIR/findings.json"
   python3 scripts/build_report.py "$AUDIT_DIR/findings.json"
   ```

   At this point the directory holds the full evidence package: engagement info, the documentation request response and its evidence, the exceptions file, raw snapshot, evaluated findings, and the human-readable report. Retests and the final report go into the same directory (`skill/references/remediation-and-retesting.md`).

5. **Close out the engagement** once the report is `FINAL` — see the next section.

## Closing out an engagement

1. **Finalize first.** The report is `FINAL` (`SKILL.md` Step 6), and every superseded `DRAFT` stays in the directory as part of the record.

2. **Write the manifest and, for a disk archive, the archive.** From the tool checkout's `skill/` directory:

   ```bash
   # private engagement repository
   bash scripts/archive_engagement.sh "$AUDIT_DIR" --manifest-only
   git -C "$AUDIT_DIR" add ARCHIVE-INFO.txt MANIFEST.sha256
   git -C "$AUDIT_DIR" commit -m "Archive <account_id>-<YYYYMMDD>"
   git -C "$AUDIT_DIR" tag final-<YYYYMMDD> && git -C "$AUDIT_DIR" push --follow-tags

   # encrypted archive on disk (age or gpg)
   bash scripts/archive_engagement.sh "$AUDIT_DIR" --age-recipient <age public key> --out-dir <dir>
   ```

   The script refuses an engagement whose `engagement-info.md` doesn't say `Report Status: FINAL` or that has no `*_FINAL.docx` (pass `--allow-draft` for an engagement that was abandoned rather than finished). It writes `MANIFEST.sha256` (the SHA-256 of every file, checkable with `shasum -a 256 -c MANIFEST.sha256`) and `ARCHIVE-INFO.txt` (when, by whom, and with which tool commit it was archived) into the engagement directory. For a disk archive it then builds `aws-audit-<account_id>-<YYYYMMDD>.tar.gz`, extracts it into a scratch directory to check it matches the manifest, encrypts it, deletes the plaintext, and writes the encrypted file's SHA-256 beside it. Word lock files (`~$*`), `.DS_Store` and AppleDouble (`._*`) files are left out. The archive is encrypted because its contents describe where the account is weak; `--no-encrypt` exists only for storage that is already encrypted and access-controlled.

3. **Store it and test a restore.** Copy the encrypted archive and its `.sha256` to the evidence store your retention policy uses (encrypted cloud storage, a secure file share), and keep a second copy of the `.sha256` somewhere other than next to the archive. Then restore it from the store with the private key and check the manifest:

   ```bash
   age -d -i <identity file> aws-audit-<id>-<date>.tar.gz.age | tar -xzf - -C <scratch dir>
   # or: gpg -d aws-audit-<id>-<date>.tar.gz.gpg | tar -xzf - -C <scratch dir>
   (cd <scratch dir>/<id>-<date> && shasum -a 256 -c MANIFEST.sha256)
   ```

   For a private engagement repository, the equivalent is a fresh clone of the tag and the same manifest check.

4. **Record it in the engagement register.** An archive can't contain its own location or hash, so keep a register outside it: a private, access-controlled list with one entry per engagement — client, account, date the report went `FINAL`, where the archive or repository is, the archive's SHA-256 (or the repository tag), the encryption key that can open it, the retention period, the date it must be deleted by, and who archived it. `engagement-info.md`'s Archive section records the destination, retention and delete-by date from inside the archive.

5. **Remove the local copies.** Once the restore check passes, delete the engagement directory, and also the copies that collect around it:
   - any `audit-runs/` directory in the tool checkout;
   - an AI assistant's working files: scratch or temporary directories it wrote backups, intermediate files or rendered reports into, and its session transcripts, which hold evidence verbatim (for Claude Code, `~/.claude/projects/<project directory>/`);
   - AWS CLI credential caches (`~/.aws/cli/cache/`, `~/.aws/sso/cache/`);
   - downloaded evidence files, and anything Word or a PDF viewer keeps in recent-files lists or AutoRecovery.

6. **Decide about the audit role** with the account owner: leave it deployed for the next audit, or remove it.

7. **At the delete-by date,** destroy the archive and every copy of it, and record the destruction in the register.

## What this repo does to support that lifecycle

- **`.gitignore`** excludes `/audit-runs/` at the repo root, so an engagement directory placed inside the tool checkout is never accidentally staged even by a broad `git add`.
- **`.gitguardian.yaml`** scopes secret scanning away from `skill/evals/fixtures/` — the *synthetic* data used by the eval suite — precisely so that exclusion stays narrow and doesn't become a habit of suppressing real findings. A real engagement directory should never reach a commit here in the first place; it has no corresponding allowlist entry, intentionally.
- **`skill/scripts/archive_engagement.sh`** writes the manifest and the encrypted archive, and checks the archive restores before deleting the plaintext.
- **Nothing in this repo stores or transmits audit output anywhere.** `collect_aws_data.py` and `run_checks.py` only read from AWS and write to the local filesystem path you give them. Where that output ends up after that is entirely the steps above — this repo has no opinion on your evidence-repo or archive-storage choice beyond "not here."

## If you're running this through an AI assistant

An assistant should write only into the engagement directory, and should say where else it put copies (a backup before editing a file, a rendered PDF for checking a report) so step 5 of the close-out can remove them. Its session transcript is itself a copy of the evidence: plan to delete it with the engagement.

Some environments (for example, a cloud-sandboxed coding assistant) can write files into your working directory but can't run `git commit`/`git push`, create a new private repo, or move files into encrypted storage on your behalf. In that case the assistant can do the lifecycle's steps 1–4 (clone context, run the collector and checks, build the report) and hand you the finished engagement directory, but a human completes the close-out. Treat an assistant stopping at that handoff as correct behavior, not a missed step.
