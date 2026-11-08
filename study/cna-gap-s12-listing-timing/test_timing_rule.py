# Tests for S12 timing_rule.py. Copyright 2026 Munim, Inc. Licensed under the Apache License, Version 2.0.
# Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com). Stdlib only, no network.
import hashlib
import unittest

import timing_rule as t


def row(cve, arm="O", source="cna@example.org", state="NOT_GLOBAL", cov="NONE", ghsa="GHSA-2345-6789-cfgh",
        published="2026-07-01"):
    return {"cve": cve, "arm": arm, "source": source, "ref_global_state": state, "coverage": cov,
            "ref_ghsa": ghsa, "ref_owner": "o", "ref_repo": "r", "published": published}


def page(field, published="2026-06-30T10:00:00Z"):
    return ('<html><body><relative-time datetime="%s">Jun 30</relative-time>'
            '<script>var x = "CVE ID No known CVE";</script>'
            '<h2>Package</h2><div>npm x</div><h2>CVE ID</h2><div>%s</div></body></html>' % (published, field))


def cell(**kw):
    d = {k: 0 for k in ["NO_CVE", "LISTS_OTHER", "LT_EARLY", "LT_LATE", "LT_NODATE", "UNPARSED", "GONE",
                        "ERROR"]}
    d.update(kw)
    return d


class TestParse(unittest.TestCase):
    def test_lists_this(self):
        self.assertEqual(t.classify(page("CVE-2026-12345"), "CVE-2026-12345"),
                         ("LISTS_THIS", "CVE-2026-12345", "2026-06-30T10:00:00Z"))

    def test_lists_other(self):
        self.assertEqual(t.classify(page("CVE-2026-99999"), "CVE-2026-12345")[0:2],
                         ("LISTS_OTHER", "CVE-2026-99999"))

    def test_no_cve_ignores_scripts(self):
        self.assertEqual(t.classify(page("No known CVE"), "CVE-2026-12345")[0], "NO_CVE")
        self.assertEqual(t.classify("<html>nothing</html>", "CVE-2026-12345"), ("UNPARSED", "", ""))


class TestTiming(unittest.TestCase):
    def test_same_day_is_early(self):
        self.assertEqual(t.timing("2026-07-01T23:59:00Z", "2026-07-01"), "EARLY")

    def test_before_and_after(self):
        self.assertEqual(t.timing("2026-06-30T00:00:00Z", "2026-07-01"), "EARLY")
        self.assertEqual(t.timing("2026-07-02T00:00:01Z", "2026-07-01"), "LATE")

    def test_missing(self):
        self.assertEqual(t.timing("", "2026-07-01"), "NODATE")
        self.assertEqual(t.timing("2026-07-01T00:00:00Z", ""), "NODATE")


class TestFrame(unittest.TestCase):
    def test_stratum(self):
        self.assertEqual(t.stratum(row("CVE-2026-1001")), "OO_UNC")
        self.assertEqual(t.stratum(row("CVE-2026-1001", cov="UNREVIEWED_ONLY")), "OO_COV")
        self.assertIsNone(t.stratum(row("CVE-2026-1001", source=t.VULNCHECK)))
        self.assertIsNone(t.stratum(row("CVE-2026-1001", arm="G")))
        self.assertIsNone(t.stratum(row("CVE-2026-1001", state="REVIEWED")))

    def test_s11_strata(self):
        rows = [row("CVE-2026-1001"), row("CVE-2026-1002", source=t.VULNCHECK, cov="REVIEWED"),
                row("CVE-2026-1003", arm="G"), row("CVE-2026-1004", arm="G", cov="WITHDRAWN_ONLY")]
        s = t.s11_strata_sizes(rows)
        self.assertEqual((s["OO_UNC"], s["OV_COV"], s["G_UNC"], s["OO_COV"]), (1, 1, 2, 0))

    def test_join_parts_round_trip(self):
        text = "cve,arm\nCVE-1,O\nCVE-2,G\nCVE-3,O\n"
        parts = ["cve,arm\nCVE-1,O\n", "cve,arm\nCVE-2,G\nCVE-3,O\n"]
        self.assertEqual(t.join_parts(parts), text)
        self.assertEqual(hashlib.sha256(t.join_parts(parts).encode()).hexdigest(),
                         hashlib.sha256(text.encode()).hexdigest())
        with self.assertRaises(ValueError):
            t.join_parts(["cve,arm\nCVE-1,O\n", "other\nx\n"])

    def test_pools_exclude_s11_and_known(self):
        rows = [row("CVE-2026-1003"), row("CVE-2026-1001"), row("CVE-2026-1002"),
                row("CVE-2026-1004", ghsa="GHSA-hfww-j92m-x8fv")]
        by = t.pools(rows, {"CVE-2026-1002"})
        self.assertEqual([r["cve"] for r in by["OO_UNC"]], ["CVE-2026-1001", "CVE-2026-1003"])

    def test_draw_is_seeded_and_cov_complete(self):
        by = {"OO_COV": [row("CVE-2026-%d" % i, cov="REVIEWED") for i in range(1000, 1005)],
              "OO_UNC": [row("CVE-2026-%d" % i) for i in range(2000, 2300)]}
        a, b = t.draw(by), t.draw(by)
        self.assertEqual(len(a["OO_COV"]), 5)
        self.assertEqual(len(a["OO_UNC"]), t.UNC_SAMPLE)
        self.assertEqual([r["cve"] for r in a["OO_UNC"]], [r["cve"] for r in b["OO_UNC"]])


class TestGrade(unittest.TestCase):
    def test_cells(self):
        res = [{"stratum": "OO_COV", "state": "LISTS_THIS", "timing": "LATE"},
               {"stratum": "OO_COV", "state": "GONE", "timing": ""},
               {"stratum": "OO_UNC", "state": "LISTS_THIS", "timing": "EARLY"}]
        c = t.cells(res)
        self.assertEqual(c["OO_COV"]["LT_LATE"], 1)
        self.assertEqual(c["OO_COV"]["GONE"], 1)
        self.assertEqual(c["OO_UNC"]["LT_EARLY"], 1)

    def test_weighted_share(self):
        # COV pool 100: 40 parsed, 10 early-listing -> 25 est.; UNC pool 900: 200 parsed, 190 early -> 855 est.
        c = {"OO_COV": cell(LT_EARLY=10, LT_LATE=20, NO_CVE=10, GONE=5),
             "OO_UNC": cell(LT_EARLY=190, LT_LATE=2, LISTS_OTHER=8)}
        v = t.cov_share(c, {"OO_COV": 100, "OO_UNC": 900}, "LT_EARLY")
        self.assertEqual(v[:3], [25.0, 880.0, 2.8])
        self.assertEqual(v[3], 200)

    def test_rule_accuracy(self):
        c = {"OO_COV": cell(LT_EARLY=10, LT_LATE=20, NO_CVE=10), "OO_UNC": cell(LT_EARLY=190, LISTS_OTHER=10)}
        self.assertEqual(t.rule_accuracy(c, {"OO_COV": 100, "OO_UNC": 900}), [930.0, 1000.0, 93.0])

    def test_grade_all_hold(self):
        c = {"OO_COV": cell(LT_EARLY=10, LT_LATE=40, NO_CVE=30, LISTS_OTHER=5),
             "OO_UNC": cell(LT_EARLY=195, LT_LATE=2, LISTS_OTHER=3)}
        v = t.grade(c, {"OO_COV": 230, "OO_UNC": 820})
        self.assertEqual({k: v[k]["held"] for k in v},
                         {"T1": "yes", "T2": "yes", "T3": "yes", "T4": "yes", "T5": "yes", "T6": "yes"})

    def test_grade_fails_and_inconclusive(self):
        c = {"OO_COV": cell(LT_EARLY=40, LT_LATE=2, NO_CVE=3), "OO_UNC": cell(LT_EARLY=150, LT_LATE=40, NO_CVE=10)}
        v = t.grade(c, {"OO_COV": 230, "OO_UNC": 820})
        self.assertEqual(v["T1"]["held"], "no")
        self.assertEqual(v["T4"]["held"], "no")
        self.assertEqual(v["T3"]["held"], "no")  # 13 raw pages, 27.2% covered
        small = {"OO_COV": cell(LT_EARLY=5, NO_CVE=5), "OO_UNC": cell(LT_EARLY=195, LISTS_OTHER=5)}
        self.assertTrue(all(x["held"] == "inconclusive" for x in t.grade(small, {"OO_COV": 10,
                                                                                "OO_UNC": 820}).values()))


class TestGate(unittest.TestCase):
    def ok_results(self, n=100):
        return [{"stratum": "OO_UNC", "http": 200, "state": "LISTS_THIS", "timing": "EARLY"} for _ in range(n)]

    def test_frame_sha_line_endings(self):
        crlf = "cve,arm\r\nCVE-1,O\r\n"
        lf = "cve,arm\nCVE-1,O\n"
        want = hashlib.sha256(crlf.encode()).hexdigest()
        self.assertEqual(t.frame_sha(crlf, want), (want, "as served"))
        self.assertEqual(t.frame_sha(lf, want), (want, "line endings restored to CRLF"))
        self.assertEqual(t.frame_sha("cve,arm\nCVE-2,O\n", want)[1], "as served")

    def test_gate_passes(self):
        ok, g = t.gate_checks(t.FRAME_SHA256, t.FRAME_ROWS, dict(t.S11_STRATA), t.S11_ROWS, self.ok_results(), True)
        self.assertTrue(ok, g)

    def test_gate_catches_each(self):
        res = self.ok_results()
        self.assertFalse(t.gate_checks("0" * 64, t.FRAME_ROWS, dict(t.S11_STRATA), t.S11_ROWS, res, True)[0])
        bad = dict(t.S11_STRATA, OO_COV=286)
        self.assertFalse(t.gate_checks(t.FRAME_SHA256, t.FRAME_ROWS, bad, t.S11_ROWS, res, True)[0])
        errs = res[:90] + [{"stratum": "OO_UNC", "http": 0, "state": "ERROR", "timing": ""}] * 10
        self.assertFalse(t.gate_checks(t.FRAME_SHA256, t.FRAME_ROWS, dict(t.S11_STRATA), t.S11_ROWS, errs,
                                       True)[1]["errors"])
        nod = res[:90] + [{"stratum": "OO_UNC", "http": 200, "state": "LISTS_THIS", "timing": "NODATE"}] * 10
        self.assertFalse(t.gate_checks(t.FRAME_SHA256, t.FRAME_ROWS, dict(t.S11_STRATA), t.S11_ROWS, nod,
                                       True)[1]["dates"])
        gone = res[:70] + [{"stratum": "OO_COV", "http": 404, "state": "GONE", "timing": ""}] * 30
        self.assertTrue(t.gate_checks(t.FRAME_SHA256, t.FRAME_ROWS, dict(t.S11_STRATA), t.S11_ROWS, gone,
                                      True)[0])


if __name__ == "__main__":
    unittest.main()
