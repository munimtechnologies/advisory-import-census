"""Tests for cna_gap.py (study S8). Offline: every HTTP call is faked. Apache-2.0."""
import json
import os
import shutil
import tempfile
import unittest

import cna_gap as cg

G1 = "GHSA-6mc7-6948-w5h4"
G2 = "GHSA-rj8c-c4p8-3c5h"
G3 = "GHSA-2r7f-4h2c-5x73"
G4 = "GHSA-g48f-pgwh-wwxx"


def nvd_cve(cve, published="2026-03-01T10:00:00.000", status="Awaiting Analysis", refs=()):
    return {"id": cve, "sourceIdentifier": "security-advisories@github.com", "published": published,
            "vulnStatus": status, "references": [{"url": u, "source": "x"} for u in refs]}


def write_adv(root, typ_dir, gid, aliases, withdrawn=False):
    d = os.path.join(root, typ_dir, "2026", "03", gid)
    os.makedirs(d, exist_ok=True)
    adv = {"id": gid, "aliases": list(aliases)}
    if withdrawn:
        adv["withdrawn"] = "2026-03-02T00:00:00Z"
    with open(os.path.join(d, gid + ".json"), "w", encoding="utf-8") as f:
        json.dump(adv, f)


class ReduceTests(unittest.TestCase):
    def test_repo_advisory_ref_is_parsed_and_normalised(self):
        r = cg.reduce_nvd(nvd_cve("CVE-2026-49481", refs=[
            "https://github.com/seriousm4x/UpSnap/releases/tag/5.4.0",
            "https://github.com/seriousm4x/UpSnap/security/advisories/GHSA-6MC7-6948-W5H4",
            "https://github.com/seriousm4x/UpSnap/security/advisories/GHSA-6mc7-6948-w5h4"]))
        self.assertEqual(r["cve"], "CVE-2026-49481")
        self.assertEqual(r["published"], "2026-03-01")
        self.assertEqual(r["repo_advs"], [{"owner": "seriousm4x", "repo": "UpSnap", "ghsa": G1}])
        self.assertEqual(r["global_refs"], [])

    def test_global_ref_is_not_a_repo_ref(self):
        r = cg.reduce_nvd(nvd_cve("CVE-2026-1", refs=["https://github.com/advisories/" + G2]))
        self.assertEqual(r["repo_advs"], [])
        self.assertEqual(r["global_refs"], [G2])

    def test_window(self):
        ok = cg.reduce_nvd(nvd_cve("CVE-2025-1", published="2025-01-01T00:00:00"))
        late = cg.reduce_nvd(nvd_cve("CVE-2026-2", published="2026-10-01T00:00:00"))
        rej = cg.reduce_nvd(nvd_cve("CVE-2025-3", published="2025-05-01T00:00:00", status="Rejected"))
        self.assertTrue(cg.in_window(ok))
        self.assertFalse(cg.in_window(late))
        self.assertTrue(cg.in_window(late, cg.LATE))
        self.assertFalse(cg.in_window(rej))


class FetchTests(unittest.TestCase):
    def test_pages_and_dedup(self):
        pages = {0: {"totalResults": 3, "vulnerabilities": [{"cve": nvd_cve("CVE-2026-2")},
                                                            {"cve": nvd_cve("CVE-2026-1")}]},
                 2: {"totalResults": 3, "vulnerabilities": [{"cve": nvd_cve("CVE-2026-1")}]}}

        def get(url):
            start = int(url.rsplit("startIndex=", 1)[1])
            return 200, pages[start]
        recs, total, failed = cg.fetch_nvd(get, pause=0, page=2)
        self.assertEqual([r["cve"] for r in recs], ["CVE-2026-1", "CVE-2026-2"])
        self.assertEqual((total, failed), (3, 0))

    def test_first_page_failure(self):
        recs, total, failed = cg.fetch_nvd(lambda u: (503, None), pause=0)
        self.assertEqual((recs, total, failed), ([], 0, 1))


class IndexClassifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        rv = os.path.join(self.tmp, "reviewed")
        un = os.path.join(self.tmp, "unreviewed")
        write_adv(self.tmp, "reviewed", G2, ["CVE-2026-10", "cve-2026-11"])
        write_adv(self.tmp, "unreviewed", G3, ["CVE-2026-12"])
        write_adv(self.tmp, "reviewed", G4, ["CVE-2026-13"], withdrawn=True)
        write_adv(self.tmp, "reviewed", "GHSA-h6r2-r3xv-333f", [])
        self.by_cve, self.by_ghsa = cg.build_index({"reviewed": rv, "unreviewed": un, "missing": None})

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def rec(self, cve, ghsa=None):
        refs = ["https://github.com/o/r/security/advisories/%s" % ghsa] if ghsa else []
        return cg.reduce_nvd(nvd_cve(cve, refs=refs))

    def test_index(self):
        self.assertEqual(self.by_cve["CVE-2026-11"], [(G2, "reviewed", False)])
        self.assertEqual(self.by_ghsa[G4], ("reviewed", True, ["CVE-2026-13"]))
        self.assertIn("GHSA-h6r2-r3xv-333f", self.by_ghsa)

    def test_reviewed(self):
        row = cg.classify(self.rec("CVE-2026-10", G2), self.by_cve, self.by_ghsa)
        self.assertEqual((row["coverage"], row["uncovered_kind"], row["ref_global_state"]),
                         ("REVIEWED", "", "REVIEWED"))
        self.assertFalse(cg.uncovered(row))

    def test_unreviewed_only(self):
        row = cg.classify(self.rec("CVE-2026-12", G1), self.by_cve, self.by_ghsa)
        self.assertEqual((row["coverage"], row["ref_global_state"]), ("UNREVIEWED_ONLY", "NOT_GLOBAL"))
        self.assertFalse(cg.uncovered(row))

    def test_withdrawn_only(self):
        row = cg.classify(self.rec("CVE-2026-13", G4), self.by_cve, self.by_ghsa)
        self.assertEqual((row["coverage"], row["uncovered_kind"], row["ref_global_state"]),
                         ("WITHDRAWN_ONLY", "GLOBAL_WITHOUT_ALIAS", "REVIEWED_WITHDRAWN"))
        self.assertTrue(cg.uncovered(row))

    def test_repo_only(self):
        row = cg.classify(self.rec("CVE-2026-49481", G1), self.by_cve, self.by_ghsa)
        self.assertEqual((row["coverage"], row["uncovered_kind"]), ("NONE", "REPO_ONLY"))

    def test_global_without_alias(self):
        row = cg.classify(self.rec("CVE-2026-99", "GHSA-h6r2-r3xv-333f"), self.by_cve, self.by_ghsa)
        self.assertEqual((row["coverage"], row["uncovered_kind"]), ("NONE", "GLOBAL_WITHOUT_ALIAS"))

    def test_no_ref(self):
        row = cg.classify(self.rec("CVE-2026-98"), self.by_cve, self.by_ghsa)
        self.assertEqual((row["coverage"], row["uncovered_kind"]), ("NONE", "NO_REPO_ADVISORY_REF"))


def row(cve, published, coverage, kind=""):
    return {"cve": cve, "published": published, "nvd_status": "Deferred", "coverage": coverage, "holders": "",
            "ref_owner": "o", "ref_repo": "r", "ref_ghsa": G1, "ref_global_state": "", "uncovered_kind": kind}


class SampleTests(unittest.TestCase):
    def test_sample_is_seeded_and_only_uncovered(self):
        rows = [row("CVE-2026-%d" % i, "2026-01-01", "NONE", "REPO_ONLY") for i in range(100)]
        rows += [row("CVE-2025-%d" % i, "2025-01-01", "REVIEWED") for i in range(50)]
        a, b = cg.pick_sample(rows), cg.pick_sample(list(reversed(rows)))
        self.assertEqual(len(a), 20)
        self.assertEqual([r["cve"] for r in a], [r["cve"] for r in b])
        self.assertTrue(all(cg.uncovered(r) for r in a))

    def test_read_sample(self):
        def get(url):
            if "cve_id=CVE-2026-1" in url:
                return 200, []
            if "cve_id=CVE-2026-2" in url:
                return 200, [{"ghsa_id": "GHSA-AAAA-bbbb-cccc"}]
            if "security-advisories" in url:
                return 200, {"state": "published", "vulnerabilities": [{"package": {"ecosystem": "", "name": "x"}}]}
            return 403, None
        out = cg.read_sample([row("CVE-2026-1", "2026-01-01", "NONE"), row("CVE-2026-2", "2026-01-01", "NONE"),
                              row("CVE-2026-3", "2026-01-01", "NONE")], get, pause=0)
        self.assertEqual([o["api_cve_lookup"] for o in out], ["EMPTY", "FOUND:GHSA-aaaa-bbbb-cccc", "ERROR:403"])
        self.assertEqual(out[0]["repo_advisory_ecosystems"], "(empty)")
        self.assertEqual(out[0]["repo_advisory_state"], "published")

    def test_unsupported(self):
        self.assertTrue(cg.unsupported("(empty)"))
        self.assertTrue(cg.unsupported("other"))
        self.assertTrue(cg.unsupported("(none)"))
        self.assertFalse(cg.unsupported("(empty);npm"))
        self.assertIsNone(cg.unsupported("ERROR:403"))
        self.assertIsNone(cg.unsupported("NO_REF"))


def sample_row(api, eco):
    return {"cve": "c", "ref_owner": "", "ref_repo": "", "ref_ghsa": "", "api_cve_lookup": api,
            "repo_advisory_state": "", "repo_advisory_ecosystems": eco}


class VerdictTests(unittest.TestCase):
    def test_verdicts(self):
        rows = [row("CVE-2025-%d" % i, "2025-06-01", "REVIEWED") for i in range(900)]
        rows += [row("CVE-2025-x%d" % i, "2025-06-01", "NONE", "REPO_ONLY") for i in range(50)]
        rows += [row("CVE-2026-%d" % i, "2026-06-01", "REVIEWED") for i in range(200)]
        rows += [row("CVE-2026-x%d" % i, "2026-06-01", "NONE", "REPO_ONLY") for i in range(40)]
        rows += [row("CVE-2026-u%d" % i, "2026-06-01", "UNREVIEWED_ONLY") for i in range(10)]
        sample = [sample_row("EMPTY", "(empty)")] * 18 + [sample_row("ERROR:403", "ERROR:403")] * 2
        v = cg.verdicts(rows, 1200, 1200, sample)
        self.assertEqual(v["P1"]["value"], [90, 1200, 7.5])
        self.assertEqual(v["P1"]["held"], "yes")
        self.assertEqual(v["P2"]["value"], [10, 1110, 0.9])
        self.assertEqual(v["P3"]["held"], "yes")
        self.assertEqual(v["P4"]["held"], "yes")
        self.assertEqual(v["P5"]["held"], "yes")
        self.assertEqual(v["P6"]["held"], "yes")
        self.assertIn("claim", v["P1"])

    def test_inconclusive_and_pending(self):
        rows = [row("CVE-2025-%d" % i, "2025-06-01", "REVIEWED") for i in range(10)]
        v = cg.verdicts(rows, 10, 1000, [sample_row("ERROR:403", "ERROR:403")] * 20)
        self.assertTrue(v["P1"]["held"].startswith("INCONCLUSIVE"))
        self.assertTrue(v["P5"]["held"].startswith("PENDING"))
        self.assertTrue(v["P6"]["held"].startswith("PENDING"))

    def test_p5_fails(self):
        rows = [row("CVE-2025-%d" % i, "2025-06-01", "REVIEWED") for i in range(1000)]
        sample = [sample_row("EMPTY", "npm")] * 17 + [sample_row("FOUND:GHSA-x", "npm")] * 3
        v = cg.verdicts(rows, 1000, 1000, sample)
        self.assertEqual(v["P5"]["held"], "no")
        self.assertEqual(v["P6"]["held"], "no")
        self.assertEqual(v["P1"]["held"], "no")


class RunTests(unittest.TestCase):
    def test_end_to_end_offline(self):
        tmp = tempfile.mkdtemp()
        try:
            db = os.path.join(tmp, "db")
            write_adv(os.path.join(db, "advisories"), "github-reviewed", G2, ["CVE-2026-10"])
            page = {"totalResults": 2, "vulnerabilities": [
                {"cve": nvd_cve("CVE-2026-10", refs=["https://github.com/o/r/security/advisories/" + G2])},
                {"cve": nvd_cve("CVE-2026-49481", refs=["https://github.com/o/r/security/advisories/" + G1])}]}

            def get(url):
                if "startIndex=" in url:
                    return 200, page
                if "cveId=" in url:
                    return 404, None
                if "cve_id=" in url:
                    return 200, []
                return 200, {"state": "published", "vulnerabilities": [{"package": {"ecosystem": ""}}]}
            out = os.path.join(tmp, "out")
            res = cg.run(db, out, get, nvd_pause=0, gh_pause=0)
            self.assertEqual(res["nvd_fetched"], 2)
            self.assertEqual(res["descriptive"]["coverage"], {"NONE": 1, "REVIEWED": 1})
            for fn in ("results.json", "RESULTS-job.md", "cves.csv", "uncovered.csv", "sample.csv", "named.csv"):
                self.assertTrue(os.path.exists(os.path.join(out, fn)), fn)
            with open(os.path.join(out, "named.csv"), encoding="utf-8") as f:
                named = f.read()
            self.assertIn("CVE-2026-49481,True", named)
            self.assertIn("CVE-2026-56670,False", named)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
