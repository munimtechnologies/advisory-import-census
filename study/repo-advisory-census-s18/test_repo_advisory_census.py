# SPDX-License-Identifier: Apache-2.0
"""Offline tests for repo_advisory_census.py (study S18). Made with AI agents working in MV2's (Munim, Inc.) name."""
import io
import json
import os
import tempfile
import unittest
import zipfile

import repo_advisory_census as rac

A = "GHSA-2222-3333-4444"
B = "GHSA-5555-6666-7777"
C = "GHSA-8888-9999-cccc"
D = "GHSA-ffff-gggg-hhhh"
E = "GHSA-jjjj-mmmm-pppp"


def page(owner_repo, ids):
    links = "".join('<a href="/%s/security/advisories/%s" class="Link">x</a>\n' % (owner_repo, g) for g in ids)
    return "<html><body>%s</body></html>" % links


class Fake:
    def __init__(self, table):
        self.table = table
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        return self.table.get(url, (404, url, "", {}))


def no_sleep(_s):
    return None


class TestBasics(unittest.TestCase):
    def test_norm(self):
        self.assertEqual(rac.norm_ghsa("ghsa-ABCD-efgh-2345"), "GHSA-abcd-efgh-2345")
        self.assertEqual(rac.norm_repo("Zip-RS", "Zip2.git"), "zip-rs/zip2")

    def test_ref_re(self):
        m = rac.REF_RE.fullmatch("https://github.com/Eugeny/russh/security/advisories/" + A)
        self.assertEqual((m.group(1), m.group(2), m.group(3)), ("Eugeny", "russh", A))
        self.assertIsNotNone(rac.REF_RE.fullmatch("https://github.com/o/r/security/advisories/%s?x=1" % A))
        self.assertIsNone(rac.REF_RE.fullmatch("https://github.com/advisories/" + A))
        self.assertIsNone(rac.REF_RE.fullmatch("https://github.com/o/r/security/advisories/%sX" % A))

    def test_parse_list_page_dedupes_and_accepts_absolute(self):
        html = page("o/r", [A, B, A]) + '<a href="https://github.com/o/r/security/advisories/%s">' % C
        html += "<p>mentions %s in a title</p>" % D
        self.assertEqual(rac.parse_list_page(html), [A, B, C])

    def test_next_link(self):
        h = '<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last"'
        self.assertEqual(rac.next_link(h), "https://api.github.com/x?page=2")
        self.assertIsNone(rac.next_link('<https://api.github.com/x?page=1>; rel="prev"'))
        self.assertIsNone(rac.next_link(""))

    def test_norm_sev(self):
        self.assertEqual(rac.norm_sev("medium"), "MODERATE")
        self.assertEqual(rac.norm_sev("high"), "HIGH")
        self.assertEqual(rac.norm_sev(""), "")


def recs():
    return [
        {"id": "RUSTSEC-2026-0001", "aliases": [A, "CVE-2026-1"], "published": "2026-01-02T00:00:00Z"},
        {"id": "RUSTSEC-2026-0002", "aliases": [E], "withdrawn": "2026-02-01T00:00:00Z"},
        {"id": A, "aliases": ["CVE-2026-1"], "published": "2026-01-01T00:00:00Z",
         "database_specific": {"github_reviewed": True, "severity": "HIGH"},
         "references": [{"type": "WEB", "url": "https://github.com/Own/Rep/security/advisories/" + A}]},
        {"id": B, "aliases": [], "published": "2026-03-01T00:00:00Z",
         "database_specific": {"github_reviewed": False, "severity": "LOW"},
         "references": [{"url": "https://github.com/other/thing/security/advisories/" + B},
                        {"url": "https://example.com/not-github"}]},
    ]


class TestIndex(unittest.TestCase):
    def test_build_index(self):
        idx = rac.build_index(recs())
        self.assertEqual(idx["rustsec_records"], 2)
        self.assertEqual(set(idx["rustsec"]), {A})          # E only via a withdrawn record
        self.assertEqual(idx["rustsec"][A]["id"], "RUSTSEC-2026-0001")
        self.assertTrue(idx["ghsa"][A]["reviewed"])
        self.assertTrue(idx["ghsa"][A]["cve"])
        self.assertFalse(idx["ghsa"][B]["reviewed"])
        self.assertEqual(idx["repos"], {"own/rep": {A}, "other/thing": {B}})

    def test_load_records(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.json", json.dumps({"id": A}))
            zf.writestr("b.json", "{not json")
            zf.writestr("readme.txt", "x")
        self.assertEqual(rac.load_records(buf.getvalue()), [{"id": A}])


class TestListRepo(unittest.TestCase):
    def test_pagination_and_canonical(self):
        u = "https://github.com/old/name/security/advisories?state=published&page=%d"
        fin = "https://github.com/New/Name/security/advisories?state=published&page=1"
        get = Fake({u % 1: (200, fin, page("New/Name", [A, B]), {}),
                    u % 2: (200, u % 2, page("New/Name", [C]), {}),
                    u % 3: (200, u % 3, page("New/Name", []), {})})
        st, canon, ids = rac.list_repo("old/name", get, no_sleep)
        self.assertEqual((st, canon, ids), ("OK", "new/name", [A, B, C]))
        self.assertEqual(len(get.calls), 3)

    def test_repeated_page_stops(self):
        u = "https://github.com/o/r/security/advisories?state=published&page=%d"
        get = Fake({u % 1: (200, u % 1, page("o/r", [A]), {}), u % 2: (200, u % 2, page("o/r", [A]), {})})
        self.assertEqual(rac.list_repo("o/r", get, no_sleep), ("OK", "o/r", [A]))

    def test_404_and_failure(self):
        self.assertEqual(rac.list_repo("gone/repo", Fake({}), no_sleep), ("REPO_404", "gone/repo", []))
        u = "https://github.com/o/r/security/advisories?state=published&page=1"
        self.assertEqual(rac.list_repo("o/r", Fake({u: (500, u, "", {})}), no_sleep)[0], "FETCH_FAILED")

    def test_429_retries_then_succeeds(self):
        u = "https://github.com/o/r/security/advisories?state=published&page=1"
        seq = [(429, u, "", {}), (200, u, page("o/r", [A]), {})]
        u2 = u.replace("page=1", "page=2")
        waits = []

        def get(url):
            if url == u:
                return seq.pop(0)
            return (200, u2, page("o/r", []), {})
        st, _, ids = rac.list_repo("o/r", get, waits.append)
        self.assertEqual((st, ids), ("OK", [A]))
        self.assertEqual(waits[0], 60)

    def test_page_limit(self):
        def get(url):
            n = int(url.rsplit("=", 1)[1])
            return (200, url, page("o/r", ["GHSA-%s-2222-2222" % ("2345"[n % 4] * 4)]), {})
        st, _, ids = rac.list_repo("o/r", get, no_sleep, max_pages=3)
        self.assertEqual(st, "PAGE_LIMIT")
        self.assertEqual(len(ids), 3)


class TestLookups(unittest.TestCase):
    def test_osv_lookup(self):
        base = "https://api.osv.dev/v1/vulns/"
        rec = {"id": C, "affected": [{"package": {"ecosystem": "npm", "name": "x"}}, {"package": {}}]}
        get = Fake({base + C: (200, base + C, json.dumps(rec), {}), base + D: (500, base + D, "", {}),
                    base + E: (200, base + E, "{bad", {})})
        self.assertEqual(rac.osv_lookup(C, get), ("IN_OSV", ["npm"]))
        self.assertEqual(rac.osv_lookup(B, get), ("NOT_IN_OSV", []))
        self.assertEqual(rac.osv_lookup(D, get), ("OSV_ERROR", []))
        self.assertEqual(rac.osv_lookup(E, get), ("OSV_ERROR", []))

    def api_item(self, gid, eco="rust", name="zip", sev="high", cve=None, withdrawn=None):
        return {"ghsa_id": gid, "severity": sev, "published_at": "2026-10-20T00:00:00Z", "cve_id": cve,
                "withdrawn_at": withdrawn, "author": {"login": "someone"},
                "vulnerabilities": [{"package": {"ecosystem": eco, "name": name}}]}

    def test_repo_api_pages_and_fields(self):
        u1 = "https://api.github.com/repos/o/r/security-advisories?state=published&per_page=100"
        u2 = "https://api.github.com/repositories/1/security-advisories?page=2"
        get = Fake({u1: (200, u1, json.dumps([self.api_item(C), {"ghsa_id": "nope"}]),
                         {"link": '<%s>; rel="next"' % u2}),
                    u2: (200, u2, json.dumps([self.api_item(D, eco="", name="", sev="medium", cve="CVE-1")]), {})})
        st, out = rac.repo_api("o/r", get, lambda: 0, 100, no_sleep)
        self.assertEqual(st, "OK")
        self.assertEqual(out[C], {"severity": "high", "published": "2026-10-20", "cve": False,
                                  "withdrawn": False, "ecosystems": ["rust"], "packages": ["zip"]})
        self.assertEqual(out[D]["ecosystems"], [])
        self.assertTrue(out[D]["cve"])
        self.assertNotIn("author", out[C])

    def test_repo_api_rate_limit(self):
        u1 = "https://api.github.com/repos/o/r/security-advisories?state=published&per_page=100"
        limited = (403, u1, "", {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1000"})
        # reset beyond the deadline: give up
        self.assertEqual(rac.repo_api("o/r", Fake({u1: limited}), lambda: 900, 950, no_sleep), ("API_SKIPPED", {}))
        # reset inside the deadline: wait, then succeed
        seq = [limited, (200, u1, json.dumps([self.api_item(C)]), {})]
        waits = []
        st, out = rac.repo_api("o/r", lambda url: seq.pop(0), lambda: 900, 5000, waits.append)
        self.assertEqual((st, list(out)), ("OK", [C]))
        self.assertEqual(waits, [105])
        # plain 403 without rate-limit headers: failure
        self.assertEqual(rac.repo_api("o/r", Fake({u1: (403, u1, "", {})}), lambda: 0, 9, no_sleep)[0], "API_FAILED")


class TestClassify(unittest.TestCase):
    def setUp(self):
        self.idx = rac.build_index(recs())

    def info(self, ecos, withdrawn=False):
        return {"severity": "high", "published": "2026-10-01", "cve": False, "withdrawn": withdrawn,
                "ecosystems": ecos, "packages": []}

    def test_statuses(self):
        idx = self.idx
        self.assertEqual(rac.classify(A, idx), "BOTH")
        self.assertEqual(rac.classify(B, idx), "OSV_UNREVIEWED_ONLY")
        idx["ghsa"][B]["reviewed"] = True
        self.assertEqual(rac.classify(B, idx), "GHSA_ONLY")
        idx["ghsa"][B]["withdrawn"] = True
        self.assertEqual(rac.classify(B, idx), "WITHDRAWN")
        idx["rustsec"][D] = {"id": "RUSTSEC-2026-0009", "published": "", "cve": False}
        self.assertEqual(rac.classify(D, idx), "RUSTSEC_ONLY")
        self.assertEqual(rac.classify(C, idx, ("IN_OSV", ["crates.io"])), "OSV_NOT_IN_EXPORT")
        self.assertEqual(rac.classify(C, idx, ("IN_OSV", ["PyPI"])), "OTHER_ECOSYSTEM")
        self.assertEqual(rac.classify(C, idx, ("OSV_ERROR", [])), "OSV_ERROR")
        self.assertEqual(rac.classify(C, idx), "OSV_ERROR")
        self.assertEqual(rac.classify(C, idx, ("NOT_IN_OSV", [])), "UNKNOWN_ECOSYSTEM")
        self.assertEqual(rac.classify(C, idx, ("NOT_IN_OSV", []), self.info(["rust"])), "NEITHER")
        self.assertEqual(rac.classify(C, idx, ("NOT_IN_OSV", []), self.info([])), "NO_PACKAGE")
        self.assertEqual(rac.classify(C, idx, ("NOT_IN_OSV", []), self.info(["npm"])), "OTHER_ECOSYSTEM")
        self.assertEqual(rac.classify(C, idx, ("NOT_IN_OSV", []), self.info(["rust"], True)), "WITHDRAWN")

    def test_make_row(self):
        row = rac.make_row("own/rep", A, self.idx, None, None)
        self.assertEqual((row["status"], row["published"], row["severity"], row["cve"], row["rustsec_id"],
                          row["ghsa_reviewed"]), ("BOTH", "2026-01-01", "HIGH", "yes", "RUSTSEC-2026-0001", "yes"))
        info = dict(self.info(["rust"]), severity="medium", packages=["zip"])
        row = rac.make_row("o/r", C, self.idx, ("NOT_IN_OSV", []), info)
        self.assertEqual((row["status"], row["severity"], row["cve"], row["ecosystems"], row["packages"],
                          row["ghsa_reviewed"], row["osv"]),
                         ("NEITHER", "MODERATE", "no", "rust", "zip", "", "NOT_IN_OSV"))


def row(repo, gid, status, published="2026-10-01", severity="HIGH", cve="no"):
    return {"repo": repo, "ghsa_id": gid, "status": status, "published": published, "severity": severity,
            "cve": cve}


class TestGrade(unittest.TestCase):
    def test_grade(self):
        rows = []
        for i in range(24):
            rows.append(row("r%d/x" % (i % 6), "GHSA-%04d-2222-2222" % i, "NEITHER",
                            severity="HIGH" if i < 6 else "LOW"))
        for i in range(20):
            rows.append(row("c/c", "GHSA-%04d-3333-3333" % i, "BOTH", cve="yes"))
        rows.append(row(rac.SEED_REPO, "GHSA-9999-2222-2222", "NEITHER"))       # seed repo: never graded
        rows.append(row("late/x", "GHSA-9998-2222-2222", "NEITHER", published="2026-11-01"))  # after cutoff
        rows.append(row("o/x", "GHSA-9997-2222-2222", "OTHER_ECOSYSTEM"))       # not Rust
        repo_rows = [{"status": "OK"}] * 9 + [{"status": "FETCH_FAILED"}, {"status": "REPO_404"},
                                              {"status": "DUPLICATE"}]
        graded, neither, preds, sample = rac.grade(rows, repo_rows)
        self.assertEqual(len(graded), 44)
        self.assertEqual(len(neither), 24)
        self.assertTrue(preds["P1_neither_at_least_20"]["held"])
        self.assertEqual(preds["P2_neither_repos_at_least_5"]["value"], 6)
        p3 = preds["P3_no_cve_share_at_least_3x_cve_share"]
        self.assertEqual((p3["no_cve"]["share"], p3["cve"]["share"], p3["held"]), (1.0, 0.0, True))
        self.assertEqual(preds["P4_high_or_critical_share_at_least_25pct"]["share"], 0.25)
        self.assertTrue(preds["P4_high_or_critical_share_at_least_25pct"]["held"])
        p5 = preds["P5_listing_ok_at_least_90pct"]
        self.assertEqual((p5["value"], p5["of"], p5["held"]), (9, 10, True))
        self.assertEqual(len(sample), 8)
        self.assertEqual(sample, sorted(sample))
        self.assertIsNone(preds["P6_hand_check"]["held"])

    def test_grade_empty(self):
        graded, neither, preds, sample = rac.grade([], [])
        self.assertFalse(preds["P1_neither_at_least_20"]["held"])
        self.assertIsNone(preds["P3_no_cve_share_at_least_3x_cve_share"]["held"])
        self.assertIsNone(preds["P4_high_or_critical_share_at_least_25pct"]["held"])
        self.assertIsNone(preds["P5_listing_ok_at_least_90pct"]["held"])
        self.assertEqual(sample, [])


class TestEndToEnd(unittest.TestCase):
    def test_run(self):
        idx = rac.build_index(recs())
        # a second name for own/rep that redirects to it: must be a DUPLICATE
        idx["repos"]["old/rep"] = {A}
        lu = "https://github.com/%s/security/advisories?state=published&page=%d"
        osv = "https://api.osv.dev/v1/vulns/"
        api = "https://api.github.com/repos/%s/security-advisories?state=published&per_page=100"
        item = {"ghsa_id": C, "severity": "critical", "published_at": "2026-10-10T00:00:00Z", "cve_id": None,
                "withdrawn_at": None, "vulnerabilities": [{"package": {"ecosystem": "rust", "name": "rep"}}]}
        table = {
            lu % ("own/rep", 1): (200, lu % ("own/rep", 1), page("own/rep", [A, C]), {}),
            lu % ("own/rep", 2): (200, lu % ("own/rep", 2), page("own/rep", []), {}),
            lu % ("old/rep", 1): (200, lu % ("own/rep", 1), page("own/rep", [A, C]), {}),
            lu % ("other/thing", 1): (200, lu % ("other/thing", 1), page("other/thing", [B, D]), {}),
            lu % ("other/thing", 2): (200, lu % ("other/thing", 2), page("other/thing", []), {}),
            osv + D: (200, osv + D, json.dumps({"id": D, "affected": [{"package": {"ecosystem": "npm"}}]}), {}),
            api % "own/rep": (200, api % "own/rep", json.dumps([item]), {}),
        }
        get = Fake(table)
        with tempfile.TemporaryDirectory() as tmp:
            res = rac.run(idx, tmp, {"source": "test"}, get, no_sleep, lambda: 0, 100,
                          min_repos=1, min_ids=1, min_rustsec=1)
            self.assertTrue(res["gate"]["passed"])
            self.assertEqual(res["status_counts"], {"BOTH": 1, "NEITHER": 1, "OSV_UNREVIEWED_ONLY": 1,
                                                    "OTHER_ECOSYSTEM": 1})
            self.assertEqual(res["repo_status_counts"], {"DUPLICATE": 1, "OK": 2})
            self.assertEqual(res["neither"], 1)
            self.assertEqual(res["sample"], [C])
            for name in ("rows.csv", "repos.csv", "results.json", "RESULTS-job.md", "sample.csv"):
                self.assertTrue(os.path.exists(os.path.join(tmp, name)), name)
            with open(os.path.join(tmp, "rows.csv"), encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("own/rep,%s,NEITHER,2026-10-10,CRITICAL,no" % C, text)
            self.assertNotIn("someone", text)
        # the API was called only for the repository with an advisory unknown to OSV
        self.assertEqual([c for c in get.calls if "api.github.com" in c], [api % "own/rep"])
        # OSV was asked only about IDs missing from the export
        self.assertEqual(sorted(c for c in get.calls if "osv.dev" in c), [osv + C, osv + D])

    def test_gate_fails_on_parser_break(self):
        idx = rac.build_index(recs())
        idx["repos"] = {rac.SEED_REPO: {A}}
        u = "https://github.com/%s/security/advisories?state=published&page=1" % rac.SEED_REPO
        get = Fake({u: (200, u, "<html>layout changed</html>", {})})
        with tempfile.TemporaryDirectory() as tmp:
            res = rac.run(idx, tmp, {}, get, no_sleep, lambda: 0, 100, min_repos=1, min_ids=0, min_rustsec=1)
        self.assertFalse(res["gate"]["passed"])
        self.assertTrue(res["gate"]["seed_in_frame"])
        self.assertNotIn("predictions", res)


if __name__ == "__main__":
    unittest.main()
