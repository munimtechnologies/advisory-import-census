# Amendment 2 — data access changes from the REST API to public advisory pages

*Pre-registration amendment for the confirmatory application-vs-library
advisory-import-gap census (see `PREREGISTRATION`/`README.md` and
`app_library_census.py`). Published together with the tested HTML collector
(`app_library_census_html.py`, `test_census_html.py`) and **before any census
data is collected through the new route.***

## What happened

The frozen census (compute job `aic-app-lib-census-v1`, queued 2026-10-17) read
each repository's advisories through GitHub's REST endpoint
`/repos/{owner}/{repo}/security-advisories`, unauthenticated. It timed out after
340 minutes still on repository 1 of 80 (`n8n-io/n8n`). Its log showed seven
rate-limit waits of 2,346–3,559 seconds: each time the 60-requests-per-hour
unauthenticated budget reset, it was exhausted again within seconds by other
traffic from the same shared address, so the job never progressed. It wrote no
CSV and no summary. **No advisory rows or outcome data from it were seen or
used.** A re-run would fail the same way, so the REST route is abandoned.

A separate, data-free feasibility probe (`aic-html-probe-v1`, 2026-10-17) then
fetched a small fixed sample of public advisory pages and confirmed the
alternative: 9 listing pages and 2 advisory pages all returned HTTP 200, the
listing markup yields each advisory's GHSA id, publication time and severity,
the advisory page yields its "CVE ID" field, and the REST `core` budget was
untouched (used 2 of 60 before and after — the HTML pages do not draw on it).

## The change (data access only)

The census reads the **same published repository advisories** from the
repository's public pages on github.com instead of the REST endpoint:

- listing pages
  `https://github.com/{owner}/{repo}/security/advisories?page=N&state=published`
  give every published advisory's GHSA id, publication time and severity;
- each **eligible** advisory's own page `.../security/advisories/{GHSA}` gives
  its "CVE ID" field (or "No known CVE"), used only for the OSV CVE-alias
  fallback that the pre-registered measure already permits.

Because these are the same published advisories the REST endpoint returns, the
**eligible set, the 14-day age rule, the publication-period split, the
OSV-based primary (`scanner_blind`) and secondary (`own_id_not_in_osv`)
measures, the OSV canary, the repository-level permutation test (seed 20261017,
10,000 permutations), the robustness checks and the decision rule are all
unchanged.** The classification and statistics code is the same, byte for byte,
as in `app_library_census.py`. The frozen 40-application / 40-library frame is
unchanged (its membership is checked by `test_census_html.py`).

One descriptive-only field is dropped: the REST record's per-advisory package
list (`repo_packages`) is left empty, because it is not read by any measure.

## Safeguards

- The parser was written and unit-tested against the raw pages the feasibility
  probe saved — the real listing-item and "CVE ID" markup, including the
  CVSS-metric decoys (`>High<`, `>Low<`) that make detail-page severity parsing
  unsafe, which is why severity is read only from the listing's
  `title="Severity: …"` attribute — **before** this amendment was published.
- Requests are paced one every 2.5 seconds, public and read-only, for
  open-access research as GitHub's Acceptable Use Policies (section 7) allow.
- Every fetched page is archived with the run's outputs (`/out/raw`), so any
  parsing error can be audited and corrected by re-parsing the archive, never
  by re-sampling.
- Per repository the run logs listing pages read, advisories found, eligible
  advisories and any page that failed. A repository whose pages could not be
  read (a non-200 status, or a page that mentions GHSA ids but parses to zero
  advisories) is reported as **unreadable**, not silently counted as having
  zero advisories, and contributes no rows.

## Known limit

Page markup can change. A listing page that contains a GHSA id but parses to no
advisory stops that repository and is reported as unreadable rather than
undercounted.

Nothing else changes.

## Addendum, 2026-10-18 — first run stopped at its own test gate (no data)

The first sandbox run of this collector (`aic-app-lib-census-html-v1`, started
2026-10-18 05:08 UTC) ran `test_census_html.py` before collecting anything, and
2 of its 26 tests failed, so the census itself never started: **no page was
fetched and no advisory data was seen.** The cause was in the tests, not the
collector. The shared listing fixture includes a "Next → page 2" link; the
collector correctly followed it, the offline fake fetcher had no page 2, and
the repository was (correctly) marked unreadable, which those two tests did not
expect.

An honest correction to the Safeguards above: the tests had not actually been
executed before this amendment was published. The publishing step that was
meant to run them looks for tests only at the top of the repository, so the
tests in `study/app-vs-library/` were skipped there. The sandbox run was their
first real execution.

What changed (test file only): the two per-repository tests now use a
single-page copy of the same fixture; new tests pin that a linked page which
cannot be read makes the whole repository unreadable, and check the "next page"
logic against the real pagination footer saved by the feasibility probe (so
links to pages 22 and 23 are not mistaken for pages 2 and 3). The collector, the
measures, the statistics and the frame are unchanged. The re-run
(`aic-app-lib-census-html-v2`) downloads the collector from the commit that
published it (`eb532df`) and logs its SHA-256, so it runs exactly the code
published here.

*Made with AI agents working for MV2 of Munim, Inc. Every claim here was checked
against the job logs and the archived pages.*
