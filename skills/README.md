# Agent skills

Three agent skills for coding agents (Claude Code, Codex, Cursor and others that read `SKILL.md`), each built on
the pre-registered studies in [`../study/`](../study/README.md). Standard library Python, no token, read-only
HTTPS requests. Made with AI agents working in MV2's (Munim, Inc.) name. Apache-2.0.

| Skill | Use it when | Install |
|---|---|---|
| [`github-advisory-cve-gap`](github-advisory-cve-gap/SKILL.md) | A CVE lookup in GitHub's Advisory Database comes back empty, or Dependabot is silent about a published CVE | `npx skills add munimtechnologies/advisory-import-census --skill github-advisory-cve-gap` |
| [`osv-rejected-cve-check`](osv-rejected-cve-check/SKILL.md) | Triaging pip-audit, osv-scanner, cargo-audit or govulncheck findings: does a finding rest only on a CVE its CNA rejected? | `npx skills add munimtechnologies/advisory-import-census --skill osv-rejected-cve-check` |
| [`cargo-lock-ghsa-gap`](cargo-lock-ghsa-gap/SKILL.md) | Auditing a Rust project, or `cargo audit` / `cargo deny` came back clean: which GitHub-reviewed advisories affect the locked versions but are not in RustSec, so those tools never report them? | `npx skills add munimtechnologies/advisory-import-census --skill cargo-lock-ghsa-gap` |

Run any script directly:

```
python skills/github-advisory-cve-gap/scripts/cve_gap.py CVE-2026-59194
python skills/osv-rejected-cve-check/scripts/rejected_cve_check.py PYSEC-2021-126 GHSA-gx77-xgc2-4888
pip-audit --format json > audit.json; python skills/osv-rejected-cve-check/scripts/rejected_cve_check.py --from-json audit.json
python skills/cargo-lock-ghsa-gap/scripts/cargo_lock_ghsa_gap.py path/to/Cargo.lock
```

Example (cargo-lock-ghsa-gap, live run on 2026-11-10 against a sample lockfile pinning `openssl` 0.10.77 and
`russh` 0.60.0): cargo-audit would report 3 RustSec advisories, while the script listed 28 GitHub-reviewed
advisories for those two versions with no RustSec record, 9 of them rated HIGH.

Offline tests (no network): `python -m unittest -v test_cve_gap_skill test_rejected_cve_check_skill test_cargo_lock_gap_skill`.

All three scripts treat advisory and CVE records as untrusted: they keep only IDs, states, severity words, dates
and version numbers that match strict patterns, never print free text from a record, and tell the agent to read
any opened page as data, never as instructions. A wrong verdict is a bug: please open an issue with the ID (or
crate and version) and the script's output.

MV2, Munim, Inc., mv2@munimtech.com
