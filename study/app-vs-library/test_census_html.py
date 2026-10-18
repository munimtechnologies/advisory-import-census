"""Offline tests for the HTML-route census (no network).

Fixtures below reproduce the real github.com advisory-page markup that the
feasibility probe (aic-html-probe-v1) saved: the listing item structure
(Link--primary heading, GHSA id, <relative-time datetime=...>, and the
title="Severity: X" badge) and the detail page's "CVE ID" sidebar block.
The CVSS-metric decoys (>High<, >Low<) are the ones that made detail-page
severity parsing unsafe, which is why severity is read only from the listing's
title attribute. Stdlib only. Apache-2.0, made with AI agents working for MV2.

Fixture fix (2026-10-18, before any census data was collected): the first
sandbox run (aic-app-lib-census-html-v1) stopped at this test gate. LISTING
carries a "Next -> page 2" link, so collect_repo correctly followed it, the
fake fetcher had no page 2 and the repository was marked unreadable. Two
per-repo tests now use LISTING_ONE_PAGE (the same items with no Next link);
the collector, the measure and the statistics are unchanged. A test pinning
that behaviour (a linked page that fails makes the repo unreadable) and one
using the real pagination footer from the probe's saved n8n page were added.
"""
import datetime as dt
import json
import os
import tempfile
import unittest

import app_library_census_html as c

HERE = os.path.dirname(os.path.abspath(__file__))

NEXT_LINK = '<a href="/n8n-io/n8n/security/advisories?state=published&amp;page=2">Next</a>\n'

# --- Real listing markup (two items from n8n-io/n8n p1, lightly trimmed) -------
LISTING = """
<li class="Box-row">
  <div class="lh-condensed flex-auto">
    <a href="/n8n-io/n8n/security/advisories/GHSA-43v8-hjhm-chjp" class="Link--primary v-align-middle no-underline h4">
      Chat Hub: chat-only users can register tool types
    </a>
    <div class="mt-1 text-small color-fg-muted">
      GHSA-43v8-hjhm-chjp
      <span class="opened-by">
        published
        <relative-time datetime="2026-10-14T09:43:15Z" class="no-wrap">Oct 14, 2026</relative-time>
        by <a class="author" href="/CharlieKolb">CharlieKolb</a>
      </span>
    </div>
  </div>
  <div class="pl-md-2">
    <span title="Severity: moderate" data-view-component="true" class="Label Label--warning">
  Moderate
</span>
  </div>
</li>
<li class="Box-row">
  <div class="lh-condensed flex-auto">
    <a href="/n8n-io/n8n/security/advisories/GHSA-m7gv-mpg5-7c9v" class="Link--primary">
      High and Critical words appear in this title on purpose
    </a>
    <div class="mt-1 text-small color-fg-muted">
      GHSA-m7gv-mpg5-7c9v
      <relative-time datetime="2026-10-14T09:36:05Z">Oct 14, 2026</relative-time>
    </div>
  </div>
  <div class="pl-md-2">
    <span title="Severity: high" class="Label Label--danger"> High </span>
  </div>
</li>
<a href="/someone/else/security/advisories/GHSA-2222-3333-4444">foreign repo advisory</a>
""" + NEXT_LINK

# The same two items as the only page of a repository (no Next link).
LISTING_ONE_PAGE = LISTING.replace(NEXT_LINK, "")

# --- Real pagination footer, verbatim from the probe's saved n8n page 1 --------
REAL_FOOTER_P1 = (
    '<a aria-label="Page 22" href="/n8n-io/n8n/security/advisories?page=22&amp;state=published">22</a> '
    '<a aria-label="Page 23" href="/n8n-io/n8n/security/advisories?page=23&amp;state=published">23</a> '
    '<a class="next_page" rel="next" href="/n8n-io/n8n/security/advisories?page=2&amp;state=published">Next</a></div>'
)

# --- Real detail markup: the "CVE ID" sidebar block, with CVSS decoys ----------
DETAIL_WITH_CVE = """
<span title="Severity: moderate" class="Label Label--warning Label--large"> Moderate </span>
<relative-time datetime="2026-03-25T14:58:31Z">Mar 25, 2026</relative-time>
<div class="color-fg-default">Attack complexity<div class="ml-2">High</div></div>
<div class="color-fg-default">Privileges required<div class="ml-2">Low</div></div>
<div class="discussion-sidebar-item">
  <h3 class="f6">CVE ID</h3>
  <div class="color-fg-muted">
    CVE-2026-25645
  </div>
</div>
<p>See also the unrelated CVE-1999-0001 in the references.</p>
"""

DETAIL_NO_CVE = """
<span title="Severity: high" class="Label Label--danger Label--large"> High </span>
<div class="color-fg-default">Attack complexity<div class="ml-2">High</div></div>
<div class="discussion-sidebar-item">
  <h3 class="f6">CVE ID</h3>
  <div class="color-fg-muted">
    No known CVE
  </div>
</div>
<p>Mitigation discussed against CVE-2020-1234 elsewhere.</p>
"""


class TestListing(unittest.TestCase):
    def test_items_parsed_with_lowercase_severity_from_title(self):
        items = c.listing_items(LISTING, "n8n-io/n8n")
        self.assertEqual(items, [
            ("GHSA-43v8-hjhm-chjp", "2026-10-14T09:43:15Z", "moderate"),
            ("GHSA-m7gv-mpg5-7c9v", "2026-10-14T09:36:05Z", "high"),
        ])

    def test_severity_comes_from_title_not_title_text_words(self):
        # The second item's TITLE contains the words "High" and "Critical";
        # severity must still be "high" from the title="Severity:" attribute.
        sev = dict((g, s) for g, _, s in c.listing_items(LISTING, "n8n-io/n8n"))
        self.assertEqual(sev["GHSA-m7gv-mpg5-7c9v"], "high")

    def test_foreign_repo_links_ignored(self):
        ids = [i[0] for i in c.listing_items(LISTING, "n8n-io/n8n")]
        self.assertNotIn("GHSA-2222-3333-4444", ids)

    def test_repo_match_case_insensitive(self):
        html = LISTING.replace("/n8n-io/n8n/", "/N8N-IO/N8N/")
        self.assertEqual(len(c.listing_items(html, "n8n-io/n8n")), 2)

    def test_dedup_keeps_first_occurrence(self):
        dup = LISTING.replace(
            '<a href="/someone/else/security/advisories/GHSA-2222-3333-4444">foreign repo advisory</a>',
            '<a href="/n8n-io/n8n/security/advisories/GHSA-43v8-hjhm-chjp">dup link</a>')
        self.assertEqual(len(c.listing_items(dup, "n8n-io/n8n")), 2)

    def test_has_next_both_param_orders(self):
        self.assertTrue(c.listing_has_next(LISTING, 1))
        self.assertFalse(c.listing_has_next(LISTING, 2))
        self.assertTrue(c.listing_has_next("x?page=4&state=published y", 3))

    def test_one_page_fixture_has_no_next(self):
        self.assertNotEqual(LISTING_ONE_PAGE, LISTING)
        self.assertFalse(c.listing_has_next(LISTING_ONE_PAGE, 1))
        self.assertEqual(c.listing_items(LISTING_ONE_PAGE, "n8n-io/n8n"),
                         c.listing_items(LISTING, "n8n-io/n8n"))

    def test_has_next_real_github_footer(self):
        self.assertTrue(c.listing_has_next(REAL_FOOTER_P1, 1))
        # "page=22"/"page=23" must not be read as a link to page 2 or 3 ...
        no_next = REAL_FOOTER_P1.split('<a class="next_page"')[0]
        self.assertFalse(c.listing_has_next(no_next, 1))
        self.assertFalse(c.listing_has_next(no_next, 2))
        # ... and the last page (23) links no page 24.
        self.assertFalse(c.listing_has_next(REAL_FOOTER_P1, 23))


class TestDetailCve(unittest.TestCase):
    def test_cve_from_label_window_ignores_later_and_cvss(self):
        cve, no_known = c.detail_cve(DETAIL_WITH_CVE)
        self.assertEqual(cve, "CVE-2026-25645")  # not CVE-1999-0001 further down
        self.assertFalse(no_known)

    def test_no_known_cve(self):
        cve, no_known = c.detail_cve(DETAIL_NO_CVE)
        self.assertEqual(cve, "")  # not the CVE-2020-1234 mentioned in prose
        self.assertTrue(no_known)

    def test_missing_label(self):
        self.assertEqual(c.detail_cve("<p>no sidebar here</p>"), ("", False))


class TestClassify(unittest.TestCase):
    """The measure is copied verbatim from app_library_census.py; verify it."""

    def _lookup(self, table):
        return lambda vid: table.get(vid)

    def test_visible_by_own_ghsa(self):
        osv = {"GHSA-aaaa": {"affected": [{"package": {"ecosystem": "npm", "name": "x"}}]}}
        adv = {"ghsa_id": "GHSA-aaaa", "cve_id": "", "identifiers": []}
        own, pkgs, blind = c.classify(adv, self._lookup(osv))
        self.assertTrue(own)
        self.assertFalse(blind)
        self.assertEqual(pkgs, ["npm:x"])

    def test_blind_when_ghsa_absent_and_no_cve(self):
        adv = {"ghsa_id": "GHSA-zzzz", "cve_id": "", "identifiers": []}
        own, pkgs, blind = c.classify(adv, self._lookup({}))
        self.assertFalse(own)
        self.assertTrue(blind)
        self.assertEqual(pkgs, [])

    def test_visible_by_cve_fallback(self):
        # GHSA not in OSV, but its CVE alias record names a package -> visible.
        osv = {"CVE-2026-25645": {"affected": [{"package": {"ecosystem": "PyPI", "name": "requests"}}]}}
        adv = {"ghsa_id": "GHSA-zzzz", "cve_id": "CVE-2026-25645",
               "identifiers": [{"type": "CVE", "value": "CVE-2026-25645"}]}
        own, pkgs, blind = c.classify(adv, self._lookup(osv))
        self.assertFalse(own)        # own GHSA still not in OSV (secondary measure)
        self.assertFalse(blind)      # but visible under the primary measure
        self.assertEqual(pkgs, ["PyPI:requests"])

    def test_blind_when_ghsa_record_has_no_packages_and_no_cve(self):
        osv = {"GHSA-aaaa": {"affected": [{"ranges": []}]}}  # record exists, no package
        adv = {"ghsa_id": "GHSA-aaaa", "cve_id": "", "identifiers": []}
        own, pkgs, blind = c.classify(adv, self._lookup(osv))
        self.assertTrue(own)         # own id resolves
        self.assertTrue(blind)       # but no package anywhere -> blind


class TestStats(unittest.TestCase):
    def test_wilson_and_share(self):
        s = c.share([{"x": 1}, {"x": 0}, {"x": 1}, {"x": 1}], lambda r: r["x"] == 1)
        self.assertEqual((s["k"], s["n"]), (3, 4))
        self.assertEqual(s["pct"], 75.0)
        self.assertEqual(len(s["ci95"]), 2)
        self.assertLessEqual(s["ci95"][0], 0.75)
        self.assertGreaterEqual(s["ci95"][1], 0.75)

    def test_permutation_is_deterministic_and_symmetric(self):
        rows = [
            {"group": "application", "repo": "a1", "scanner_class": "scanner_blind"},
            {"group": "application", "repo": "a2", "scanner_class": "scanner_blind"},
            {"group": "library", "repo": "l1", "scanner_class": "scanner_visible"},
            {"group": "library", "repo": "l2", "scanner_class": "scanner_visible"},
        ]
        a = c.permutation_test(rows, c.is_blind, n_perm=500)
        b = c.permutation_test(rows, c.is_blind, n_perm=500)
        self.assertEqual(a, b)                       # seeded -> reproducible
        self.assertEqual(a["difference_pct_points"], 100.0)
        self.assertEqual(a["unit"], "repository")

    def test_median(self):
        self.assertEqual(c.median([3, 1, 2]), 2)
        self.assertEqual(c.median([4, 1, 2, 3]), 2.5)
        self.assertIsNone(c.median([]))


class FakeFetch:
    """A module-level fetch() replacement that serves canned pages by URL."""
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def __call__(self, url, tries=4, pace=0.0):
        self.calls.append(url)
        status, body = self.pages.get(url, (404, "not found"))
        return status, body, url


class TestCollectRepo(unittest.TestCase):
    def setUp(self):
        self._orig = c.fetch
        self.now = dt.datetime(2026, 10, 31, tzinfo=dt.timezone.utc)

    def tearDown(self):
        c.fetch = self._orig

    def _osv(self, table):
        return lambda vid: table.get(vid) if vid else None

    def test_rows_eligibility_period_and_measures(self):
        repo = "n8n-io/n8n"
        p1 = c.LISTING_URL % (repo, 1)
        d1 = c.DETAIL_URL % (repo, "GHSA-43v8-hjhm-chjp")
        d2 = c.DETAIL_URL % (repo, "GHSA-m7gv-mpg5-7c9v")
        c.fetch = FakeFetch({p1: (200, LISTING_ONE_PAGE), d1: (200, DETAIL_WITH_CVE),
                             d2: (200, DETAIL_NO_CVE)})
        # GHSA-43v8 is visible via its CVE alias; GHSA-m7gv (no CVE) is blind.
        osv = self._osv({"CVE-2026-25645":
                         {"affected": [{"package": {"ecosystem": "npm", "name": "n8n"}}]}})
        rows, diag = c.collect_repo(repo, "application", self.now, osv)
        self.assertFalse(diag["unreadable"])
        self.assertEqual(diag["advisories_listed"], 2)
        self.assertEqual(len(rows), 2)
        by_id = {r["ghsa_id"]: r for r in rows}
        self.assertEqual(by_id["GHSA-43v8-hjhm-chjp"]["scanner_class"], "scanner_visible")
        self.assertEqual(by_id["GHSA-43v8-hjhm-chjp"]["cve_id"], "CVE-2026-25645")
        self.assertEqual(by_id["GHSA-m7gv-mpg5-7c9v"]["scanner_class"], "scanner_blind")
        for r in rows:
            self.assertEqual(r["period"], "from_2026_05")
            self.assertEqual(r["severity"], "high" if "m7gv" in r["ghsa_id"] else "moderate")

    def test_age_filter_drops_recent_advisories(self):
        repo = "n8n-io/n8n"
        p1 = c.LISTING_URL % (repo, 1)
        # now = publication + 10 days < 14-day minimum -> no eligible rows, no detail fetch.
        now = dt.datetime(2026, 10, 24, tzinfo=dt.timezone.utc)
        fake = FakeFetch({p1: (200, LISTING_ONE_PAGE)})
        c.fetch = fake
        rows, diag = c.collect_repo(repo, "application", now, self._osv({}))
        self.assertEqual(rows, [])
        self.assertEqual(diag["eligible"], 0)
        self.assertFalse(diag["unreadable"])
        self.assertEqual(fake.calls, [p1])

    def test_unreadable_when_linked_next_page_fails(self):
        # Page 1 links a page 2 that cannot be read: the whole repo is
        # unreadable (no rows), never a silent partial count.
        repo = "n8n-io/n8n"
        p1 = c.LISTING_URL % (repo, 1)
        c.fetch = FakeFetch({p1: (200, LISTING)})
        rows, diag = c.collect_repo(repo, "application", self.now, self._osv({}))
        self.assertEqual(rows, [])
        self.assertTrue(diag["unreadable"])
        self.assertIn("listing page 2 status=404", diag["notes"])

    def test_empty_listing_is_zero_not_unreadable(self):
        repo = "ollama/ollama"
        p1 = c.LISTING_URL % (repo, 1)
        c.fetch = FakeFetch({p1: (200, "<div>No advisories published</div>")})
        rows, diag = c.collect_repo(repo, "application", self.now, self._osv({}))
        self.assertEqual(rows, [])
        self.assertFalse(diag["unreadable"])

    def test_unreadable_when_ghsa_present_but_unparsed(self):
        repo = "n8n-io/n8n"
        p1 = c.LISTING_URL % (repo, 1)
        # Contains a bare GHSA id but no parsable advisory link -> must not be zero.
        c.fetch = FakeFetch({p1: (200, "GHSA-43v8-hjhm-chjp mentioned with no link")})
        rows, diag = c.collect_repo(repo, "application", self.now, self._osv({}))
        self.assertEqual(rows, [])
        self.assertTrue(diag["unreadable"])

    def test_unreadable_when_listing_errors(self):
        repo = "n8n-io/n8n"
        c.fetch = FakeFetch({})  # every URL -> 404
        rows, diag = c.collect_repo(repo, "application", self.now, self._osv({}))
        self.assertTrue(diag["unreadable"])

    def test_pagination_follows_next(self):
        repo = "psf/requests"
        p1 = c.LISTING_URL % (repo, 1)
        p2 = c.LISTING_URL % (repo, 2)
        page1 = ('<a href="/psf/requests/security/advisories/GHSA-gc5v-m9x4-r6x2">A</a>'
                 '<relative-time datetime="2026-03-25T14:58:31Z"></relative-time>'
                 '<span title="Severity: moderate">M</span>'
                 '<a href="/psf/requests/security/advisories?state=published&page=2">Next</a>')
        page2 = ('<a href="/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7">B</a>'
                 '<relative-time datetime="2025-06-09T16:39:53Z"></relative-time>'
                 '<span title="Severity: moderate">M</span>')
        da = c.DETAIL_URL % (repo, "GHSA-gc5v-m9x4-r6x2")
        db = c.DETAIL_URL % (repo, "GHSA-9hjg-9r4m-mvj7")
        c.fetch = FakeFetch({p1: (200, page1), p2: (200, page2),
                             da: (200, DETAIL_NO_CVE), db: (200, DETAIL_NO_CVE)})
        rows, diag = c.collect_repo(repo, "library", self.now, self._osv({}))
        self.assertEqual(diag["listing_pages"], 2)
        self.assertEqual(diag["advisories_listed"], 2)
        self.assertFalse(diag["unreadable"])


class TestFrameIntegrity(unittest.TestCase):
    """Guard the sandbox frame copies against transcription drift. These repo
    sets are the frozen 40/40 frame (frame_apps.json / frame_libs.json in the
    repo); only membership is used by the census."""
    APPS = {
        "n8n-io/n8n", "ollama/ollama", "immich-app/immich", "Stirling-Tools/Stirling-PDF",
        "syncthing/syncthing", "lobehub/lobehub", "hoppscotch/hoppscotch",
        "coder/code-server", "elastic/elasticsearch", "AppFlowy-IO/appflowy",
        "apache/superset", "hakimel/reveal.js", "dani-garcia/vaultwarden",
        "usememos/memos", "pocketbase/pocketbase", "pi-hole/pi-hole", "penpot/penpot",
        "makeplane/plane", "meilisearch/MeiliSearch", "twentyhq/twenty",
        "appwrite/appwrite", "laurent22/joplin", "odoo/odoo", "huginn/huginn",
        "mudler/LocalAI", "calcom/cal.diy", "gogs/gogs", "apache/airflow",
        "9001/copyparty", "siyuan-note/siyuan", "paperless-ngx/paperless-ngx",
        "DIYgod/RSSHub", "RocketChat/Rocket.Chat", "LibreChat-AI/LibreChat",
        "getsentry/sentry", "juspay/hyperswitch", "payloadcms/payload",
        "reactive-resume/reactive-resume", "Kong/kong", "heyputer/puter",
    }
    LIBS = {
        "chalk/supports-color", "psf/requests", "pmezard/go-difflib",
        "isaacs/fs.realpath", "benjaminp/six", "davecgh/go-spew",
        "jonschlinkert/fill-range", "numpy/numpy", "stretchr/testify",
        "micromatch/to-regex-range", "stub42/pytz", "go-check/check",
        "fsevents/fsevents", "certifi/python-certifi", "stretchr/objx",
        "browserify/resolve", "kjd/idna", "golang/protobuf", "jshttp/statuses",
        "dateutil/dateutil", "google/go-cmp", "wesleytodd/setprototypeof",
        "pallets/click", "kr/text", "stream-utils/unpipe", "pandas-dev/pandas",
        "pkg/errors", "jshttp/fresh", "chardet/chardet", "kr/pretty",
        "pillarjs/send", "pytest-dev/pytest", "BurntSushi/toml",
        "expressjs/serve-static", "benoitc/gunicorn", "mattn/go-isatty",
        "epoberezkin/fast-deep-equal", "pyparsing/pyparsing", "golang/appengine",
        "epoberezkin/fast-json-stable-stringify",
    }

    def _repos(self, fname):
        with open(os.path.join(HERE, fname), encoding="utf-8") as f:
            return [e["repo"] for e in json.load(f)]

    @unittest.skipUnless(os.path.exists(os.path.join(HERE, "frame_apps.json")),
                         "frame_apps.json not alongside the test")
    def test_apps_frame_matches(self):
        repos = self._repos("frame_apps.json")
        self.assertEqual(len(repos), 40)
        self.assertEqual(set(repos), self.APPS)

    @unittest.skipUnless(os.path.exists(os.path.join(HERE, "frame_libs.json")),
                         "frame_libs.json not alongside the test")
    def test_libs_frame_matches(self):
        repos = self._repos("frame_libs.json")
        self.assertEqual(len(repos), 40)
        self.assertEqual(set(repos), self.LIBS)

    def test_groups_disjoint(self):
        self.assertEqual(self.APPS & self.LIBS, set())


class TestSummariseShape(unittest.TestCase):
    def test_summarise_offline_rows(self):
        rows = [
            {"group": "application", "repo": "a1", "scanner_class": "scanner_blind",
             "own_id_in_osv": "False", "period": "from_2026_05"},
            {"group": "application", "repo": "a2", "scanner_class": "scanner_visible",
             "own_id_in_osv": "True", "period": "before_2026_05"},
            {"group": "library", "repo": "l1", "scanner_class": "scanner_visible",
             "own_id_in_osv": "True", "period": "from_2026_05"},
        ]
        out = c.summarise(rows, {"application": 40, "library": 40}, True, "2026-10-18T00:00:00+00:00")
        self.assertEqual(out["groups"]["application"]["repos_in_frame"], 40)
        self.assertIn("blind", out["comparison"])
        self.assertIn("drop_heaviest_repo_each_group", out["robustness"])


if __name__ == "__main__":
    unittest.main()
