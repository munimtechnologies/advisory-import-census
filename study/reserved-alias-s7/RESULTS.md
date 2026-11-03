# S7 results: CVE aliases on GitHub-reviewed advisories that the CVE List does not have

Pre-registration: [PREREG.md](PREREG.md) (frozen 2026-11-02, before the job ran). Code: `reserved_alias.py`
(tests: `test_reserved_alias.py`). Job run 2026-11-02 15:05 UTC against github/advisory-database commit
`b072a70350` (2026-11-02T12:35:46Z); CVE Services read 2026-11-02T15:05:48Z.
Licence: Apache-2.0 (code), CC BY 4.0 (text and data). Made with AI agents working for MV2 of Munim, Inc.

## Short answer

Of the 143 CVE aliases on live GitHub-reviewed advisories that were absent from the CVE List release
`cve_2026-11-01_1700Z`, the public CVE Services endpoint `GET https://cveawg.mitre.org/api/cve-id/<CVE>` says:

| State | IDs | Share |
|---|---:|---:|
| RESERVED (allocated to a CNA, never published) | 138 | 96.5% |
| NOT_FOUND (HTTP 404: the ID was never allocated) | 4 | 2.8% |
| REJECTED, with no CVE record | 1 | 0.7% |
| ERROR | 0 | 0% |

Every alias was still on its live advisory at the job's commit, and every one is its advisory's only CVE alias.
None was published between the 2026-11-01 snapshot and the read.

## Verdicts

| | Claim (frozen) | Result | Verdict |
|---|---|---|---|
| P1 | >= 50% are RESERVED | 138 / 143 = 96.5% | **held** |
| P2 | >= 10% are REJECTED | 1 / 143 = 0.7% | **failed** |
| P3 | >= 3 IDs are NOT_FOUND | 4 | **held** |
| P4 | >= 50% of RESERVED IDs sit on an advisory published >= 180 days before the read | 55 / 138 = 39.9% | **failed** |
| P5 | GitHub's CNA (`GitHub_M`) owns <= 10% of RESERVED IDs | not measurable | **inconclusive** (see below) |
| P6 | >= 50% of NOT_FOUND IDs have a typo candidate graded SAME | 0 / 4 | **failed** |

2 held, 3 failed, 1 inconclusive.

**P5 is inconclusive, not held.** The job printed `held: yes` because 0 of 138 RESERVED IDs showed `GitHub_M`. But
the endpoint returns `"owning_cna": "[REDACTED]"` for **every** RESERVED ID when read without an account (checked
again by hand on 2026-11-03 for CVE-2013-3364). So the owner of a RESERVED ID cannot be read publicly, and the
0 says nothing about GitHub's CNA. The pre-registration did not foresee the redaction; this is a design miss.

**P6 was graded by hand before any count was opened**, as frozen. The grading sample was empty: none of the four
NOT_FOUND aliases has a typo candidate (a published CVE ID within edit distance 2 that the advisory mentions).
Reading the four advisories by hand confirms it: each one mentions no CVE ID other than its own alias (the only
other occurrences are ecosystem-database file names that repeat the same ID). 0 of 4 SAME, so P6 failed (it is
not underpowered, because P3 gave 4 >= 3). Per-row notes: [grades.csv](grades.csv).

## What was found

**1. RESERVED dominates, and many of these IDs are old.** 35 of the 138 RESERVED IDs carry a CVE year of 2019 or
earlier (CVE-2013-3364, CVE-2014-4179, fifteen IDs in CVE-2016-1000223 to -1000242, ...). 27 sit on advisories
published five or more years ago (most on 2020-08-31 / 2020-09-01, the database's first bulk review). At the
other end, 38 sit on advisories published in October 2026, so a large share is ordinary lag between a public
advisory and its CNA publishing the record. That is why P4 failed: 83 of the 138 are on advisories younger than
180 days.

**2. One rejected ID that S6 could not see.** CVE-2024-10039 on GHSA-93ww-43rr-79v3 (Keycloak mTLS authentication
bypass, `org.keycloak:keycloak-core` < 26.0.6) is REJECTED, owned by `redhat`, last changed 2024-11-06, and has no
CVE record. The advisory was published on 2024-11-25, 19 days after that change, and the CVE is its only alias.
S6 counted 54 reviewed advisories carrying a rejected alias from CVE *records*; with this one the count is at
least 55 (see [../rejected-alias-s6/ADDENDUM-S7.md](../rejected-alias-s6/ADDENDUM-S7.md)).

**3. Four IDs were never allocated, and all four are in the old DWF number range.** CVE-2016-1000249
(GHSA-2r7f-4h2c-5x73, npm `fury-adapter-swagger`), CVE-2016-1000253 (GHSA-g48f-pgwh-wwxx, composer
`onelogin/php-saml`), CVE-2016-1000273 (GHSA-cqhr-jqvc-qw9p, maven `javamelody-core`) and CVE-2016-1000305
(GHSA-g65v-27r3-5p6m, rubygems `guard-livereload`, published 2026-07-31) all return 404 from `/api/cve-id/`.
Seven-digit 2016-1000xxx IDs were the range used by the Distributed Weakness Filing (DWF) CNA from 2016. Fifteen
other IDs from that range on reviewed advisories return RESERVED, so the range is not uniformly missing. Three of
the four advisories cite an ecosystem advisory database entry (npm advisory 305, a FriendsOfPHP file and a rubysec
file named after the same ID); the javamelody one cites only the fix commit and release notes. S7 makes no claim about why the four were never allocated.

## Relation to github/advisory-database #8051

Issue [#8051](https://github.com/github/advisory-database/issues/8051) (opened 2026-06-16, updated 2026-08-13)
lists 63 reviewed advisories whose CVE alias had no record in cvelistV5, CVE Services or NVD, and asks which
category they fall in: assigned but never published, stale references, or records still expected. Its check used
the record endpoint, which answers `CVE_RECORD_DNE` for a RESERVED ID and for an unallocated one alike. The
`/api/cve-id/` endpoint separates them. For those 63 pairs, read 2026-11-02 (S7 job) and 2026-11-03 (by hand
for the 8 not in S7's population):

| State now | IDs |
|---|---:|
| RESERVED | 51 |
| PUBLISHED since the issue (5 by `mitre`, updated 2026-09-14; 3 by `suse`, updated 2026-10-15) | 8 |
| REJECTED without a record (CVE-2024-10039) | 1 |
| Never allocated (CVE-2016-1000249, -1000253, -1000273) | 3 |

Per-row table: [issue-8051-crosswalk.csv](issue-8051-crosswalk.csv).

## Prior art and what is new

RBP Tracker (rbptracker.org, Jerry Gamblin / RogoLabs, 2026-09-14) already lists RESERVED-but-public IDs cited by
public advisories, including GitHub's, using the same endpoint, so the RESERVED count is context only. Issue #8051
(same author) lists the absent IDs but not their state. New here: on one frozen population (every reviewed-advisory
alias absent from the CVE List on 2026-11-01), the split into RESERVED / rejected-without-record / never-allocated;
the finding that the never-allocated ones are all in the DWF range; and the rejected-without-record Keycloak alias
that a record-based census misses.

## Files

- [aliases.csv](aliases.csv): one row per alias (state, owning CNA as returned, advisory publication date and age,
  whether it is the only alias, typo candidates).
- [candidates.csv](candidates.csv): typo candidates (empty: none found).
- [grades.csv](grades.csv): the hand grades for P6.
- [results.json](results.json): the job's machine output (its P5 `held: yes` is overridden above).
- [issue-8051-crosswalk.csv](issue-8051-crosswalk.csv): #8051's 63 reviewed pairs with today's state.

## Limits

- One read of a live service. A state can change at any time; the endpoint reports the state now, not when the
  alias was added.
- RESERVED owners are redacted for anonymous readers, so no claim is made about which CNAs hold them.
- A RESERVED ID on a public advisory may be under embargo or simply waiting on its CNA. S7 makes no claim about why
  any ID is in any state, and no claim about which ID belongs on any advisory: that is the curators' and the CNA's
  call (lesson of #10828).
- The population is what S6's CVE-List snapshot missed; aliases with a record are outside it.
