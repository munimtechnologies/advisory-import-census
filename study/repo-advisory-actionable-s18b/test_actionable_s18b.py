# SPDX-License-Identifier: Apache-2.0
"""Unit tests for actionable_s18b.py (standard library only, no network)."""
import json
import os
import shutil
import tempfile
import unittest

import actionable_s18b as s

HEADER = "repo,ghsa_id,status,published,severity,cve,rustsec_id,ghsa_reviewed,osv,ecosystems,packages\n"
ROWS = HEADER + (
    "a/b,GHSA-2222-2222-2222,NEITHER,2026-09-01,HIGH,no,,,NOT_IN_OSV,rust,good\n"
    "a/b,GHSA-3333-3333-3333,NEITHER,2026-08-01,LOW,yes,,,NOT_IN_OSV,rust,uu_x\n"
    "c/d,GHSA-5555-5555-5555,NEITHER,2026-07-01,CRITICAL,no,,,NOT_IN_OSV,rust,weird\n"
    "c/d,GHSA-6666-6666-6666,NEITHER,2026-10-30,HIGH,no,,,NOT_IN_OSV,rust,late\n"
    "zip-rs/zip2,GHSA-7777-7777-7777,NEITHER,2026-09-01,HIGH,no,,,NOT_IN_OSV,rust,zip\n"
    "a/b,GHSA-8888-8888-8888,GHSA_ONLY,2026-09-01,HIGH,yes,,yes,,,\n"
    "c/d,GHSA-9999-9999-9999,NEITHER,2026-09-02,HIGH,no,,,NOT_IN_OSV,rust,good\n"
)
EXPECT = (7, 6, 4)

RECORDS = [
    {"id": "GHSA-4444-4444-4444", "aliases": ["CVE-2026-0001"],
     "database_specific": {"github_reviewed": True},
     "affected": [{"package": {"ecosystem": "crates.io", "name": "coreutils"}}]},
    {"id": "RUSTSEC-2026-0001", "aliases": ["GHSA-9999-9999-9999"]},
    {"id": "RUSTSEC-2026-0002", "aliases": ["GHSA-cccc-cccc-cccc", "CVE-2026-0002"], "withdrawn": "2026-01-01"},
    {"id": "GHSA-fffff", "aliases": []},
]


def adv(gid, name, cve=None, eco="rust", withdrawn=None):
    return {"ghsa_id": gid, "cve_id": cve, "withdrawn_at": withdrawn,
            "vulnerabilities": [{"package": {"ecosystem": eco, "name": name},
                                 "vulnerable_version_range": "< 1.0", "patched_versions": "1.0"}]}


def fake_get_factory(calls):
    api_ab = [adv("GHSA-2222-2222-2222", "good"), adv("GHSA-3333-3333-3333", "uu_x", "CVE-2026-0001"),
              adv("GHSA-8888-8888-8888", "x", "CVE-2026-0009")]
    api_cd = [adv("GHSA-5555-5555-5555", "`weird` thing"), adv("GHSA-9999-9999-9999", "good")]
    crates = {"good": {"name": "good", "recent_downloads": 1000, "repository": "https://github.com/A/B"},
              "uu_x": {"name": "uu_x", "recent_downloads": 5, "repository": ""},
              "serde": {"name": "serde", "recent_downloads": 9, "repository": ""}}

    def get(url):
        calls.append(url)
        if url == "https://api.github.com/repos/a/b/security-advisories?state=published&per_page=100":
            return 200, url, json.dumps(api_ab), {}
        if url == "https://api.github.com/repos/c/d/security-advisories?state=published&per_page=100":
            return 200, url, json.dumps(api_cd), {}
        if url.startswith("https://api.osv.dev/v1/vulns/"):
            return 404, url, "", {}
        if url.startswith(s.CRATES_API):
            name = url[len(s.CRATES_API):]
            if name in crates:
                return 200, url, json.dumps({"crate": crates[name]}), {}
            return 404, url, "", {}
        return 0, url, "", {}
    return get


class Helpers(unittest.TestCase):
    def test_repo_of(self):
        self.assertEqual(s.repo_of("https://github.com/uutils/coreutils"), "uutils/coreutils")
        self.assertEqual(s.repo_of("https://github.com/A/B.git"), "a/b")
        self.assertEqual(s.repo_of("https://github.com/a/b/tree/main/x"), "a/b")
        self.assertEqual(s.repo_of("https://gitlab.com/a/b"), "")
        self.assertEqual(s.repo_of(""), "")

    def test_check_rows(self):
        summary, graded = s.check_rows(s.load_rows(ROWS), EXPECT)
        self.assertEqual(summary, {"rows": 7, "neither": 6, "graded": 4, "ok": True})
        self.assertEqual([r["ghsa_id"] for r in graded],
                         ["GHSA-2222-2222-2222", "GHSA-3333-3333-3333", "GHSA-5555-5555-5555",
                          "GHSA-9999-9999-9999"])
        self.assertFalse(s.check_rows(s.load_rows(ROWS))[0]["ok"])

    def test_build_index(self):
        idx = s.build_index(RECORDS)
        self.assertEqual(idx["rustsec_records"], 2)
        self.assertIn("GHSA-4444-4444-4444", idx["known"])
        self.assertIn("GHSA-9999-9999-9999", idx["known"])
        self.assertNotIn("GHSA-cccc-cccc-cccc", idx["known"])
        self.assertEqual(idx["cve"], {"CVE-2026-0001": [{"id": "GHSA-4444-4444-4444", "packages": ["coreutils"]}]})

    def test_unreviewed_ghsa_known_but_not_covering(self):
        idx = s.build_index([{"id": "GHSA-2222-3333-4444", "aliases": ["CVE-2026-0005"],
                              "database_specific": {"github_reviewed": False}}])
        self.assertIn("GHSA-2222-3333-4444", idx["known"])
        self.assertEqual(idx["cve"], {})

    def test_crate_variants(self):
        self.assertEqual(s.crate_variants("Foo_bar"), ["Foo_bar", "foo_bar", "Foo-bar", "foo-bar"])
        self.assertEqual(s.crate_variants("serde"), ["serde"])

    def test_crate_lookup(self):
        calls = []

        def get(url):
            calls.append(url)
            if url == s.CRATES_API + "foo-bar":
                return 200, url, json.dumps({"crate": {"name": "foo-bar", "recent_downloads": 7,
                                                       "repository": "https://github.com/o/r"}}), {}
            return 404, url, "", {}
        res = s.crate_lookup("Foo_bar", get, lambda x: None)
        self.assertEqual(res["status"], "FOUND")
        self.assertEqual(res["canonical"], "foo-bar")
        self.assertEqual(res["recent_downloads"], 7)
        self.assertEqual(len(calls), 4)
        calls[:] = []
        self.assertEqual(s.crate_lookup("`nono-proxy` component of `nono`", get, lambda x: None)["status"],
                         "INVALID_NAME")
        self.assertEqual(calls, [])
        self.assertEqual(s.crate_lookup("missing", get, lambda x: None)["status"], "NOT_FOUND")

    def test_crate_lookup_error(self):
        res = s.crate_lookup("x", lambda url: (500, url, "", {}), lambda x: None)
        self.assertEqual(res["status"], "ERROR")
        res = s.crate_lookup("x", lambda url: (200, url, "not json", {}), lambda x: None)
        self.assertEqual(res["status"], "ERROR")

    def test_repo_api_pagination(self):
        page1 = [adv("GHSA-2222-2222-2222", "good", "CVE-2026-0001"), adv("GHSA-3333-3333-3333", "pkg", eco="npm")]
        page2 = [adv("GHSA-5555-5555-5555", "other", withdrawn="2026-01-01T00:00:00Z"), {"ghsa_id": "bad"}]
        nxt = "https://api.github.com/next"

        def get(url):
            if url == nxt:
                return 200, url, json.dumps(page2), {}
            return 200, url, json.dumps(page1), {"link": '<%s>; rel="next", <x>; rel="last"' % nxt}
        st, out = s.repo_api("a/b", get, lambda: 0, 10, lambda x: None)
        self.assertEqual(st, "OK")
        self.assertEqual(sorted(out), ["GHSA-2222-2222-2222", "GHSA-3333-3333-3333", "GHSA-5555-5555-5555"])
        self.assertEqual(out["GHSA-2222-2222-2222"]["cve_id"], "CVE-2026-0001")
        self.assertEqual(out["GHSA-2222-2222-2222"]["ranges"], ["good < 1.0 -> 1.0"])
        self.assertEqual(out["GHSA-3333-3333-3333"]["rust_packages"], [])
        self.assertTrue(out["GHSA-5555-5555-5555"]["withdrawn"])

    def test_repo_api_rate_limit_past_deadline(self):
        get = lambda url: (403, url, "", {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "5000"})
        st, out = s.repo_api("a/b", get, lambda: 0, 100, lambda x: None)
        self.assertEqual((st, out), ("API_SKIPPED", {}))

    def test_osv_lookup(self):
        rec = {"id": "CVE-1", "affected": [{"package": {"ecosystem": "crates.io", "name": "x"}},
                                           {"package": {"ecosystem": "PyPI", "name": "y"}}, {"ranges": []}]}
        self.assertEqual(s.osv_lookup("CVE-1", lambda u: (200, u, json.dumps(rec), {})), ("IN_OSV", ["x"]))
        self.assertEqual(s.osv_lookup("CVE-1", lambda u: (404, u, "", {})), ("NOT_IN_OSV", []))
        self.assertEqual(s.osv_lookup("CVE-1", lambda u: (500, u, "", {})), ("OSV_ERROR", []))
        self.assertEqual(s.osv_lookup("CVE-1", lambda u: (200, u, json.dumps({"withdrawn": "x"}), {})),
                         ("WITHDRAWN_IN_OSV", []))

    def test_classify(self):
        idx = s.build_index(RECORDS)
        found = {"status": "FOUND"}
        crates = {"a": found, "b": {"status": "NOT_FOUND"}, "c": {"status": "ERROR"}}
        info = {"cve_id": "", "withdrawn": False, "rust_packages": ["a"]}
        self.assertEqual(s.classify("GHSA-x", None, idx, "", None, crates)[0], "API_MISSING")
        self.assertEqual(s.classify("GHSA-x", dict(info, withdrawn=True), idx, "", None, crates)[0], "WITHDRAWN")
        self.assertEqual(s.classify("GHSA-9999-9999-9999", info, idx, "", None, crates)[0], "NOW_KNOWN")
        self.assertEqual(s.classify("GHSA-x", info, idx, "IN_OSV", None, crates)[0], "NOW_KNOWN")
        self.assertEqual(s.classify("GHSA-x", info, idx, "OSV_ERROR", None, crates)[0], "OSV_ERROR")
        self.assertEqual(s.classify("GHSA-x", dict(info, cve_id="CVE-2026-0001"), idx, "NOT_IN_OSV", None, crates),
                         ("CVE_COVERED", "GHSA-4444-4444-4444", ["coreutils"]))
        self.assertEqual(s.classify("GHSA-x", dict(info, cve_id="CVE-7"), idx, "NOT_IN_OSV", ("IN_OSV", ["q"]),
                                    crates), ("CVE_COVERED", "CVE-7", ["q"]))
        self.assertEqual(s.classify("GHSA-x", dict(info, cve_id="CVE-7"), idx, "NOT_IN_OSV", ("IN_OSV", []),
                                    crates)[0], "ACTIONABLE")
        self.assertEqual(s.classify("GHSA-x", dict(info, rust_packages=["b", "a"]), idx, "NOT_IN_OSV", None,
                                    crates)[0], "ACTIONABLE")
        self.assertEqual(s.classify("GHSA-x", dict(info, rust_packages=["b", "c"]), idx, "NOT_IN_OSV", None,
                                    crates)[0], "CRATE_ERROR")
        self.assertEqual(s.classify("GHSA-x", dict(info, rust_packages=["b"]), idx, "NOT_IN_OSV", None,
                                    crates)[0], "NO_CRATE")
        self.assertEqual(s.classify("GHSA-x", dict(info, rust_packages=[]), idx, "NOT_IN_OSV", None,
                                    crates)[0], "NO_CRATE")


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_run(self):
        calls = []
        idx = s.build_index(RECORDS)
        res = s.run(ROWS, idx, fake_get_factory(calls), lambda x: None, lambda: 0, 10, self.tmp, {"t": 1},
                    expect=EXPECT, min_rustsec=1)
        self.assertTrue(res["gate"]["passed"], res["gate"])
        self.assertEqual(res["gate"]["controls"], {"serde": "FOUND", s.NEG_CRATE: "NOT_FOUND"})
        self.assertEqual(res["status_counts"], {"ACTIONABLE": 1, "CVE_COVERED": 1, "NOW_KNOWN": 1, "NO_CRATE": 1})
        self.assertEqual(res["sample"], ["GHSA-2222-2222-2222"])
        self.assertEqual(res["predictions"]["Q2_cve_rows_covered_at_least_20pct"]["held"], True)
        self.assertEqual(res["predictions"]["Q1_actionable_at_least_50pct"]["held"], False)
        self.assertEqual(res["exploratory"]["cve_covered_same_crate"], {"no": 1})
        self.assertEqual(res["exploratory"]["actionable_repo_match"], {"yes": 1})
        top = res["exploratory"]["top_actionable_by_recent_downloads"]
        self.assertEqual([(t["ghsa_id"], t["max_recent_downloads"]) for t in top], [("GHSA-2222-2222-2222", 1000)])
        self.assertFalse(any("GHSA-9999-9999-9999" in c and "osv" in c for c in calls))
        for name in ("s18b_rows.csv", "crates.csv", "results.json", "RESULTS-job.md", "sample.csv"):
            self.assertTrue(os.path.exists(os.path.join(self.tmp, name)), name)
        with open(os.path.join(self.tmp, "results.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["status_counts"]["ACTIONABLE"], 1)

    def test_run_rows_mismatch(self):
        res = s.run(ROWS, s.build_index(RECORDS), lambda u: (0, u, "", {}), lambda x: None, lambda: 0, 10,
                    self.tmp, {}, expect=(1, 1, 1))
        self.assertFalse(res["gate"]["passed"])
        self.assertIn("Gate: FAILED", s.render(res))

    def test_fetch_rows_polls(self):
        seq = [(404, "u", "", {}), (200, "u", "x,y\n", {})]
        slept = []
        self.assertEqual(s.fetch_rows(lambda u: seq.pop(0), slept.append, "u", wait_min=4), "x,y\n")
        self.assertEqual(slept, [120])
        self.assertIsNone(s.fetch_rows(lambda u: (404, u, "", {}), lambda x: None, "u", wait_min=2))


if __name__ == "__main__":
    unittest.main()
