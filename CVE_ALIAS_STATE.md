# cve_alias_state.py: is a missing CVE reserved, rejected, or never allocated?

An advisory can cite a CVE ID that has no CVE record. The record endpoint (`/api/cve/<id>`) answers
`CVE_RECORD_DNE` whatever the reason. The public CVE Services ID endpoint (`/api/cve-id/<id>`, no account needed)
tells the reasons apart, and `cve_alias_state.py` reads it for a list of IDs or for every CVE alias in a folder of
OSV-format advisories (such as a clone of github/advisory-database).

Python 3.9+, standard library only. Apache-2.0. Made with AI agents working for MV2 of Munim, Inc.

```
python cve_alias_state.py CVE-2013-3364 CVE-2016-1000249 CVE-2024-10039
cve,state,owning_cna,sources
CVE-2013-3364,RESERVED,[REDACTED],arg
CVE-2016-1000249,NOT_FOUND,,arg
CVE-2024-10039,REJECTED,redhat,arg
```

| State | Meaning |
|---|---|
| PUBLISHED | the ID has a published record |
| RESERVED | allocated to a CNA, never published (the owner is shown as `[REDACTED]` to anonymous readers) |
| REJECTED | rejected; there may or may not be a record |
| NOT_FOUND | HTTP 404: the ID was never allocated |
| ERROR | no usable answer after three tries |
| INVALID | not a well-formed CVE ID |

Options: `--from-file ids.txt` (one ID per line), `--advisory-dir <folder>` (reads `aliases` of every non-withdrawn
JSON advisory), `--json`, `--fail-on REJECTED,NOT_FOUND` (exit code 1 if any ID has one of those states, for CI),
`--pause 0.4` (seconds between requests; keep it polite).

Why it exists: study S7 ([study/reserved-alias-s7/RESULTS.md](study/reserved-alias-s7/RESULTS.md)) used this
endpoint on the 143 CVE aliases of GitHub-reviewed advisories that were missing from the CVE List on 2026-11-01:
138 were RESERVED, 4 were never allocated and 1 was rejected without a record. Each answer is the state at the
moment of the read; it says nothing about why an ID is in that state or which ID belongs on an advisory.
