"""Tests for cna_compare.py (study S10). Stdlib unittest. Apache-2.0.
Fixtures use real-format IDs (GHSA groups drawn from 23456789cfghjmpqrvwx; CVE-YYYY-NNNN+)."""
import json
import os
import tempfile
import unittest
import urllib.parse

import cna_compare as cc

A = "GHSA-2345-6789-cfgh"
B = "GHSA-jmpq-rvwx-2345"
C = "GHSA-cfgh-jmpq-rvwx"
D = "GHSA-6789-cfgh-jmpq"
E = "GHSA-rvwx-2345-6789"
F = "GHSA-wxwx-2323-pqpq"


def nvd(cve, source, published, refs, status="Analyzed"):
    return {"cve": {"id": cve, "sourceIdentifier": source, "published": published + "T12:00:00.000",
                    "vulnStatus": status, "references": [{"url": u} for u in refs]}}


def repo_url(owner, repo, ghsa):
    return "https://github.com/%s/%s/security/advisories/%s" % (owner, repo, ghsa)


def write_adv(root, typ, ghsa, aliases, published, withdrawn=None):
    sub = "github-reviewed" if typ == "reviewed" else "unreviewed"
    d = os.path.join(root, "advisories", sub, published[:4], published[5:7], ghsa)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, ghsa + ".json"), "w", encoding="utf-8") as f:
        json.dump({"id": ghsa, "aliases": aliases, "published": published + "T00:00:00Z",
                   "withdrawn": withdrawn}, f)


def row(arm, cov, ref_state, dup="no", cve="CVE-2026-10000"):
    return {"cve": cve, "arm": arm, "source": "x", "coverage": cov, "ref_global_state": ref_state, "dup": dup,
            "unreviewed_lag_days": "", "published": "2026-01-01", "ref_owner": "o", "ref_repo": "r"}


class TestChunks(unittest.TestCase):
    def test_months(self):
        ch = cc.month_chunks()
        self.assertEqual(len(ch), 21)
        self.assertEqual(ch[0], ("2025-01-01", "2025-01-31"))
        self.assertEqual(ch[-1], ("2026-09-01", "2026-09-30"))
        self.assertIn(("2026-02-01", "2026-02-28"), ch)
        self.assertIn(("2025-12-01", "2025-12-31"), ch)


class TestReduce(unittest.TestCase):
    def test_reduce(self):
        r = cc.reduce_nvd(nvd("CVE-2026-10001", "CVE@MITRE.ORG", "2026-03-04",
                              [repo_url("Own", "Rep", "GHSA-2345-6789-CFGH"), repo_url("Own", "Rep", A),
                               "https://example.com/x"])["cve"])
        self.assertEqual(r["cve"], "CVE-2026-10001")
        self.assertEqual(r["source"], "cve@mitre.org")
        self.assertEqual(r["published"], "2026-03-04")
        self.assertEqual(r["repo_advs"], [{"owner": "Own", "repo": "Rep", "ghsa": A}])
        self.assertEqual(cc.arm_of(r), "O")
        g = cc.reduce_nvd(nvd("CVE-2026-10002", "security-advisories@github.com", "2026-03-04", [])["cve"])
        self.assertEqual(cc.arm_of(g), "G")
        self.assertEqual(g["repo_advs"], [])


class TestFetch(unittest.TestCase):
    def test_paging_and_filter(self):
        data = {
            "2025-01-01": [nvd("CVE-2025-20001", "cve@mitre.org", "2025-01-02", [repo_url("o", "r", A)]),
                           nvd("CVE-2025-20002", "cve@mitre.org", "2025-01-03", ["https://example.com"]),
                           nvd("CVE-2025-20003", "security-advisories@github.com", "2025-01-04",
                               [repo_url("o", "r", B)])],
            "2025-02-01": [nvd("CVE-2025-20004", "disclosure@vulncheck.com", "2025-02-02", [repo_url("o", "r", C)])],
        }

        def get(url):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            s = q["pubStartDate"][0][:10]
            start, n = int(q["startIndex"][0]), int(q["resultsPerPage"][0])
            items = data.get(s, [])
            return 200, {"totalResults": len(items), "vulnerabilities": items[start:start + n]}

        recs, total, fetched, failed, per = cc.fetch_nvd(
            get, [("2025-01-01", "2025-01-31"), ("2025-02-01", "2025-02-28")], pause=0, page=2)
        self.assertEqual(total, 4)
        self.assertEqual(fetched, 4)
        self.assertEqual(failed, 0)
        self.assertEqual([r["cve"] for r in recs], ["CVE-2025-20001", "CVE-2025-20003", "CVE-2025-20004"])
        self.assertEqual(per["cve@mitre.org"], 2)

    def test_failed_first_page(self):
        recs, total, fetched, failed, per = cc.fetch_nvd(lambda u: (503, None), [("2025-01-01", "2025-01-31")],
                                                         pause=0)
        self.assertEqual((len(recs), total, fetched, failed), (0, 0, 0, 1))


class TestClassify(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        write_adv(root, "unreviewed", C, ["CVE-2026-10002"], "2026-03-05")
        write_adv(root, "reviewed", D, ["CVE-2026-10003"], "2026-02-01")
        write_adv(root, "unreviewed", E, ["CVE-2026-10003"], "2026-02-03")
        write_adv(root, "reviewed", F, ["CVE-2026-10004"], "2026-02-01", withdrawn="2026-02-10T00:00:00Z")
        self.by_cve, self.by_ghsa = cc.build_index(
            {"reviewed": os.path.join(root, "advisories", "github-reviewed"),
             "unreviewed": os.path.join(root, "advisories", "unreviewed")})

    def tearDown(self):
        self.tmp.cleanup()

    def rec(self, cve, source, published, ghsa):
        return cc.reduce_nvd(nvd(cve, source, published, [repo_url("o", "r", ghsa)])["cve"])

    def test_g_none(self):
        r = cc.classify(self.rec("CVE-2026-10001", cc.GITHUB_SOURCE, "2026-03-01", A), self.by_cve, self.by_ghsa)
        self.assertEqual((r["arm"], r["coverage"], r["ref_global_state"], r["ref_holds"], r["dup"]),
                         ("G", "NONE", "NOT_GLOBAL", "", "no"))
        self.assertTrue(cc.uncovered(r))
        self.assertTrue(cc.sample_g(r))

    def test_o_unreviewed_only_with_lag(self):
        r = cc.classify(self.rec("CVE-2026-10002", "cve@mitre.org", "2026-03-04", B), self.by_cve, self.by_ghsa)
        self.assertEqual((r["arm"], r["coverage"], r["ref_global_state"]), ("O", "UNREVIEWED_ONLY", "NOT_GLOBAL"))
        self.assertEqual(r["unreviewed_lag_days"], 1)
        self.assertEqual(r["dup"], "no")
        self.assertTrue(cc.sample_o(r))

    def test_o_reviewed_dup(self):
        r = cc.classify(self.rec("CVE-2026-10003", "cve@mitre.org", "2026-02-01", D), self.by_cve, self.by_ghsa)
        self.assertEqual((r["coverage"], r["ref_global_state"], r["ref_holds"]), ("REVIEWED", "REVIEWED", "THIS"))
        self.assertEqual(r["other_live_holders"], E)
        self.assertEqual(r["dup"], "yes")
        self.assertEqual(r["unreviewed_lag_days"], "")

    def test_withdrawn_only(self):
        r = cc.classify(self.rec("CVE-2026-10004", cc.GITHUB_SOURCE, "2026-02-01", F), self.by_cve, self.by_ghsa)
        self.assertEqual((r["coverage"], r["ref_global_state"], r["dup"]),
                         ("WITHDRAWN_ONLY", "REVIEWED_WITHDRAWN", "no"))
        self.assertTrue(cc.uncovered(r))


def synthetic():
    o = ([row("O", "REVIEWED", "REVIEWED", dup="yes" if i < 6 else "no") for i in range(60)] +
         [row("O", "UNREVIEWED_ONLY", "NOT_GLOBAL") for _ in range(35)] +
         [row("O", "NONE", "NOT_GLOBAL") for _ in range(5)])
    g = ([row("G", "NONE", "NOT_GLOBAL") for _ in range(50)] +
         [row("G", "REVIEWED", "REVIEWED", dup="yes" if i < 1 else "no") for i in range(50)])
    return o + g


def samples(agree_n, err_n=0):
    out = []
    for i in range(20):
        if i < err_n:
            out.append({"agrees": ""})
        elif i < err_n + agree_n:
            out.append({"agrees": "yes"})
        else:
            out.append({"agrees": "no"})
    return out


class TestVerdicts(unittest.TestCase):
    def test_all_hold(self):
        v = cc.verdicts(synthetic(), 1000, 1000, samples(20))
        self.assertEqual({k: x["held"] for k, x in v.items()},
                         {"Q1": "yes", "Q2": "yes", "Q3": "yes", "Q4": "yes", "Q5": "yes", "Q6": "yes"})
        self.assertEqual(v["Q1"]["value"], [5, 100, 5.0])
        self.assertEqual(v["Q3"]["value"]["O"], [35, 40, 87.5])
        self.assertEqual(v["Q4"]["value"]["O"], [35, 95, 36.8])
        self.assertEqual(v["Q6"]["value"]["O"], [6, 60, 10.0])

    def test_fail_and_scaling(self):
        rows = synthetic()
        for r in rows[60:80]:          # 20 O UNREVIEWED_ONLY rows become NONE
            r["coverage"] = "NONE"
        v = cc.verdicts(rows, 1000, 1000, samples(15, err_n=3))
        self.assertEqual(v["Q1"]["held"], "no")       # 25%
        self.assertEqual(v["Q3"]["held"], "no")       # 15/40
        self.assertEqual(v["Q5"]["held"], "no")       # 15 of 17 < 15.3
        self.assertEqual(v["Q5"]["value"], [15, 17, 88.2])

    def test_gate(self):
        v = cc.verdicts(synthetic(), 900, 1000, samples(20, err_n=5))
        self.assertTrue(v["Q1"]["held"].startswith("INCONCLUSIVE"))
        self.assertTrue(v["Q6"]["held"].startswith("INCONCLUSIVE"))
        self.assertTrue(v["Q5"]["held"].startswith("PENDING"))
        small = [r for r in synthetic() if r["arm"] == "G"] + [row("O", "REVIEWED", "REVIEWED")]
        v = cc.verdicts(small, 1000, 1000, samples(20))
        self.assertTrue(v["Q2"]["held"].startswith("INCONCLUSIVE"))


class TestSample(unittest.TestCase):
    def test_pick_deterministic(self):
        rows = [dict(row("O", "UNREVIEWED_ONLY", "NOT_GLOBAL"), cve="CVE-2026-%05d" % (20000 + i)) for i in range(30)]
        a = cc.pick(rows, cc.sample_o)
        b = cc.pick(list(reversed(rows)), cc.sample_o)
        self.assertEqual([r["cve"] for r in a], [r["cve"] for r in b])
        self.assertEqual(len(a), 10)
        self.assertEqual([r["cve"] for r in a], sorted(r["cve"] for r in a))

    def test_read_sample(self):
        s = [dict(row("O", "UNREVIEWED_ONLY", "NOT_GLOBAL"), cve="CVE-2026-30001", ref_ghsa=A),
             dict(row("G", "NONE", "NOT_GLOBAL"), cve="CVE-2026-30002", ref_ghsa=B),
             dict(row("G", "NONE", "NOT_GLOBAL"), cve="CVE-2026-30003", ref_ghsa=C)]
        answers = {"CVE-2026-30001": (200, [{"ghsa_id": "GHSA-CFGH-JMPQ-RVWX"}]),
                   "CVE-2026-30002": (200, []), "CVE-2026-30003": (403, None)}
        out = cc.read_sample(s, lambda u: answers[u.rsplit("=", 1)[1]], pause=0)
        self.assertEqual([x["api_cve_lookup"] for x in out], ["FOUND:" + C, "EMPTY", "ERROR:403"])
        self.assertEqual([x["agrees"] for x in out], ["yes", "yes", ""])


class TestRun(unittest.TestCase):
    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as out:
            write_adv(root, "unreviewed", C, ["CVE-2026-10002"], "2026-03-05")
            items = [nvd("CVE-2026-10001", cc.GITHUB_SOURCE, "2026-03-01", [repo_url("o", "r", A)]),
                     nvd("CVE-2026-10002", "cve@mitre.org", "2026-03-04", [repo_url("o", "r", B)]),
                     nvd("CVE-2026-10005", "cve@mitre.org", "2026-03-04", [repo_url("o", "r", D)],
                         status="Rejected")]

            def get(url):
                if "api.github.com" in url:
                    return 200, ([] if url.endswith("10001") else [{"ghsa_id": C}])
                q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                start = int(q["startIndex"][0])
                return 200, {"totalResults": len(items), "vulnerabilities": items[start:]}

            res = cc.run(root, out, get, nvd_pause=0, gh_pause=0, chunks=[("2026-03-01", "2026-03-31")])
            self.assertEqual(res["descriptive"]["arm_sizes"], {"O": 1, "G": 1})
            self.assertTrue(res["verdicts"]["Q1"]["held"].startswith("INCONCLUSIVE"))
            for fn in ("results.json", "RESULTS-job.md", "rows.csv", "sample.csv"):
                self.assertTrue(os.path.exists(os.path.join(out, fn)), fn)
            with open(os.path.join(out, "sample.csv"), encoding="utf-8") as f:
                self.assertEqual(len(f.read().strip().splitlines()), 3)


if __name__ == "__main__":
    unittest.main()
