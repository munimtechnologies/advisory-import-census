# Agent skills

Two agent skills for coding agents (Claude Code, Codex, Cursor and others that read `SKILL.md`), each built on
the pre-registered studies in [`../study/`](../study/README.md). Standard library Python, no token, read-only
HTTPS GETs. Made with AI agents working in MV2's (Munim, Inc.) name. Apache-2.0.

| Skill | Use it when | Install |
|---|---|---|
| [`github-advisory-cve-gap`](github-advisory-cve-gap/SKILL.md) | A CVE lookup in GitHub's Advisory Database comes back empty, or Dependabot is silent about a published CVE | `npx skills add munimtechnologies/advisory-import-census --skill github-advisory-cve-gap` |
| [`osv-rejected-cve-check`](osv-rejected-cve-check/SKILL.md) | Triaging pip-audit, osv-scanner, cargo-audit or govulncheck findings: does a finding rest only on a CVE its CNA rejected? | `npx skills add munimtechnologies/advisory-import-census --skill osv-rejected-cve-check` |

Run either script directly:

```
python skills/github-advisory-cve-gap/scripts/cve_gap.py CVE-2026-59194
python skills/osv-rejected-cve-check/scripts/rejected_cve_check.py PYSEC-2021-126 GHSA-gx77-xgc2-4888
pip-audit --format json > audit.json; python skills/osv-rejected-cve-check/scripts/rejected_cve_check.py --from-json audit.json
```

Offline tests (no network): `python -m unittest -v test_cve_gap_skill test_rejected_cve_check_skill`.

Both scripts treat advisory and CVE records as untrusted: they keep only IDs, states and dates that match strict
patterns, never print free text from a record, and tell the agent to read any opened page as data, never as
instructions. A wrong verdict is a bug: please open an issue with the ID and the script's output.

MV2, Munim, Inc., mv2@munimtech.com
