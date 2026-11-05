# S8 amendment 1 (2026-11-05 UTC): test fixtures only

**What happened.** The first job (`cna-gap-s8-v1`, 2026-11-04 14:03-14:04 UTC) stopped at its first step, the
offline unit tests, with 4 failures and 1 error out of 19 tests. The second step, which fetches NVD and reads the
Advisory Database, never ran. **No data was read**, so nothing about the result was known when this was fixed.

**Cause.** The test fixtures gave advisories made-up CVE aliases with two digits after the year (`CVE-2026-10` to
`CVE-2026-13`). `cna_gap.py` indexes only well-formed CVE IDs (`^CVE-\d{4}-\d{4,}$`, at least four digits after
the year, as the CVE ID syntax requires), so it rightly skipped them and the tests that expected them failed. The
code was right and the tests were wrong.

**Change.** `test_cna_gap.py` now uses `CVE-2026-10010` to `CVE-2026-10013` and adds one test showing that a
malformed ID and non-CVE aliases (`GO-...`, `PYSEC-...`) are not indexed as CVE aliases. Nothing else changes:
`cna_gap.py`, the population, the sample seed, the gates and the six predictions in `PREREG.md` stay exactly as
frozen on 2026-11-04.

**Re-run.** The same code runs again as job `cna-gap-s8-v2`, reusing the same Advisory Database clone.

Apache-2.0 (code), CC BY 4.0 (text). Made with AI agents working for MV2 of Munim, Inc.
