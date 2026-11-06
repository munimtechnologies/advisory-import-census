"""Offline tests for split_source.py (S9b). Apache-2.0. Made with AI agents working for MV2 of Munim, Inc."""
import csv
import json
import os
import tempfile
import unittest

import split_source as s

UMB = "GHSA-5f42-97gr-vfhq"        # Moquette umbrella (holds CVE-2026-85724 in the global database)
SUB1 = "GHSA-pqwr-fmcp-mjq7"       # hidden source advisory of CVE-2026-95842
SUB2 = "GHSA-h285-r7h3-gfjg"       # hidden source advisory of CVE-2026-95848
CADDY = "GHSA-j8px-rmrx-76h9"
CSUB = "GHSA-5wr5-c398-ph72"
NOKO = "GHSA-8678-w3jw-xfc2"


def record(cve, source, refs, state="PUBLISHED", assigner="GitHub_M"):
    cna = {"references": [{"url": u} for u in refs]}
    if source is not None:
        cna["source"] = {"advisory": source, "discovery": "UNKNOWN"}
    return {"cveMetadata": {"cveId": cve, "state": state, "assignerShortName": assigner},
            "containers": {"cna": cna}}


def adv_url(owner, repo, g):
    return "https://github.com/%s/%s/security/advisories/%s" % (owner, repo, g)


class ReduceTests(unittest.TestCase):
    def test_split(self):
        rec = s.reduce_record(record("CVE-2026-95848", SUB2, [adv_url("moquette-io", "moquette", UMB),
                                                              "https://github.com/moquette-io/moquette/pull/967"]))
        self.assertEqual(rec["source_ghsa"], SUB2)
        self.assertEqual(rec["ref_ghsas"], [UMB])
        self.assertEqual(rec["where"][UMB], ("moquette-io", "moquette"))
        self.assertEqual(s.source_class(rec), "SPLIT")

    def test_match_case_insensitive(self):
        rec = s.reduce_record(record("CVE-2026-57234", "GHSA-8678-W3JW-XFC2",
                                     [adv_url("sparklemotion", "nokogiri", NOKO.upper())]))
        self.assertEqual(rec["source_ghsa"], NOKO)
        self.assertEqual(rec["ref_ghsas"], [NOKO])
        self.assertEqual(s.source_class(rec), "MATCH")

    def test_other_classes(self):
        self.assertEqual(s.source_class(s.reduce_record(record("CVE-2025-1000", None, [adv_url("a", "b", NOKO)]))),
                         "NO_SOURCE")
        self.assertEqual(s.source_class(s.reduce_record(record("CVE-2025-1001", "not-a-ghsa", []))), "NO_SOURCE")
        self.assertEqual(s.source_class(s.reduce_record(record("CVE-2025-1002", NOKO,
                                                               ["https://example.com/x"]))), "NO_REF")
        self.assertEqual(s.source_class(s.reduce_record(record("CVE-2025-1003", NOKO, [], state="REJECTED"))),
                         "NOT_PUBLISHED")

    def test_odd_shapes(self):
        obj = {"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": {"source": "GHSA-8678-w3jw-xfc2",
                                                                              "references": [None, {"url": None}]}}}
        rec = s.reduce_record(obj)
        self.assertEqual(rec["source_ghsa"], "")
        self.assertEqual(rec["ref_ghsas"], [])
        self.assertEqual(s.source_class(s.reduce_record({})), "NOT_PUBLISHED")

    def test_global_advisory_url_is_not_a_repo_ref(self):
        rec = s.reduce_record(record("CVE-2025-1004", NOKO, ["https://github.com/advisories/" + NOKO]))
        self.assertEqual(rec["ref_ghsas"], [])
        self.assertEqual(s.source_class(rec), "NO_REF")


class FetchTests(unittest.TestCase):
    def test_fetch_all_statuses_and_retry(self):
        calls = {}

        def get(url):
            cve = url.rsplit("/", 1)[1]
            calls[cve] = calls.get(cve, 0) + 1
            if cve == "CVE-2025-2000":
                return 200, record(cve, NOKO, [adv_url("a", "b", NOKO)])
            if cve == "CVE-2025-2001":
                return 404, None
            if cve == "CVE-2025-2002":   # fails once, then works on the second pass
                return (500, None) if calls[cve] == 1 else (200, record(cve, NOKO, [adv_url("a", "b", NOKO)]))
            return 503, None

        out = s.fetch_all(["CVE-2025-2000", "CVE-2025-2001", "CVE-2025-2002", "CVE-2025-2003"], get, workers=2)
        self.assertEqual(out["CVE-2025-2000"][0], "OK")
        self.assertEqual(out["CVE-2025-2001"], ("NO_RECORD", None))
        self.assertEqual(out["CVE-2025-2002"][0], "OK")
        self.assertEqual(out["CVE-2025-2003"], ("FETCH_ERROR", None))
        self.assertEqual(calls["CVE-2025-2003"], 2)


def write_adv(root, sub, ghsa, aliases, withdrawn=None):
    d = os.path.join(root, "advisories", sub, "2026", "09", ghsa)
    os.makedirs(d, exist_ok=True)
    adv = {"id": ghsa, "aliases": aliases}
    if withdrawn:
        adv["withdrawn"] = withdrawn
    with open(os.path.join(d, ghsa + ".json"), "w", encoding="utf-8") as f:
        json.dump(adv, f)


class RowsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        write_adv(root, "github-reviewed", UMB, ["CVE-2026-85724"])
        write_adv(root, "github-reviewed", NOKO, [])
        write_adv(root, "unreviewed", CADDY, ["CVE-2026-77281"], withdrawn="2026-10-01T00:00:00Z")
        self.by_ghsa = s.build_index(root)
        moq = adv_url("moquette-io", "moquette", UMB)
        cad = adv_url("caddyserver", "caddy", CADDY)
        self.pop = [
            {"cve": "CVE-2026-85724", "published": "2026-09-23", "coverage": "REVIEWED"},
            {"cve": "CVE-2026-95842", "published": "2026-09-23", "coverage": "NONE"},
            {"cve": "CVE-2026-95848", "published": "2026-09-23", "coverage": "NONE"},
            {"cve": "CVE-2026-92284", "published": "2026-09-23", "coverage": "WITHDRAWN_ONLY"},
            {"cve": "CVE-2026-57234", "published": "2026-06-25", "coverage": "NONE"},
            {"cve": "CVE-2026-99999", "published": "2026-09-01", "coverage": "NONE"},
            {"cve": "CVE-2026-99998", "published": "2026-09-01", "coverage": "NONE"},
        ]
        self.recs = {
            "CVE-2026-85724": ("OK", s.reduce_record(record("CVE-2026-85724", UMB, [moq]))),
            "CVE-2026-95842": ("OK", s.reduce_record(record("CVE-2026-95842", SUB1, [moq]))),
            "CVE-2026-95848": ("OK", s.reduce_record(record("CVE-2026-95848", SUB2, [moq]))),
            "CVE-2026-92284": ("OK", s.reduce_record(record("CVE-2026-92284", CSUB, [cad]))),
            "CVE-2026-57234": ("OK", s.reduce_record(record("CVE-2026-57234", NOKO,
                                                            [adv_url("sparklemotion", "nokogiri", NOKO)]))),
            "CVE-2026-99999": ("NO_RECORD", None),
            "CVE-2026-99998": ("FETCH_ERROR", None),
        }
        self.rows = s.build_rows(self.pop, self.recs, self.by_ghsa)
        self.by = {r["cve"]: r for r in self.rows}

    def tearDown(self):
        self.tmp.cleanup()

    def test_index(self):
        self.assertEqual(self.by_ghsa[UMB], ("reviewed", False, ["CVE-2026-85724"]))
        self.assertEqual(self.by_ghsa[CADDY], ("unreviewed", True, ["CVE-2026-77281"]))
        self.assertEqual(s.global_state(SUB1, self.by_ghsa), "NONE")
        self.assertEqual(s.global_state(CADDY, self.by_ghsa), "UNREVIEWED_WITHDRAWN")
        self.assertEqual(s.global_state("", self.by_ghsa), "")

    def test_rows(self):
        r = self.by["CVE-2026-95842"]
        self.assertEqual(r["class"], "SPLIT")
        self.assertEqual((r["umbrella"], r["umbrella_owner"], r["umbrella_repo"]), (UMB, "moquette-io", "moquette"))
        self.assertEqual(r["split_bundle"], 2)
        self.assertEqual(r["source_global"], "NONE")
        self.assertEqual(r["umbrella_global"], "REVIEWED")
        self.assertEqual(r["umbrella_aliases"], "CVE-2026-85724")
        self.assertEqual(r["in_umbrella_aliases"], "no")
        self.assertEqual(r["umbrella_own_cves"], "CVE-2026-85724")
        c = self.by["CVE-2026-92284"]
        self.assertEqual((c["split_bundle"], c["umbrella_global"], c["umbrella_own_cves"]),
                         (1, "UNREVIEWED_WITHDRAWN", ""))
        m = self.by["CVE-2026-85724"]
        self.assertEqual((m["class"], m["umbrella"], m["split_bundle"], m["source_global"]), ("MATCH", "", 0, ""))
        self.assertEqual(self.by["CVE-2026-99999"]["class"], "NO_RECORD")
        self.assertEqual(self.by["CVE-2026-99998"]["class"], "FETCH_ERROR")

    def test_grade(self):
        p = {x["id"]: x for x in s.grade(self.rows)}
        # read = 6 (all but FETCH_ERROR); SPLIT = 3; MATCH = 2
        self.assertEqual(p["P1"]["value"], [3, 6, 50.0])
        self.assertFalse(p["P1"]["held"])
        self.assertEqual(p["P2"]["value"], [2, 5, 40.0])
        self.assertFalse(p["P2"]["held"])
        self.assertEqual(p["P3"]["value"], [3, 3, 100.0])
        self.assertTrue(p["P3"]["held"])
        self.assertEqual(p["P4"]["value"], [3, 3, 100.0])
        self.assertTrue(p["P4"]["held"])
        self.assertEqual(p["P5"]["value"], [2, 3, 66.67])
        self.assertTrue(p["P5"]["held"])
        # live umbrellas: the two Moquette rows (Caddy's is withdrawn)
        self.assertEqual(p["P6"]["value"], [2, 2, 100.0])
        self.assertTrue(p["P6"]["held"])

    def test_p1_bounds(self):
        rows = [{"class": "SPLIT", "source_global": "NONE", "s8_coverage": "NONE", "split_bundle": 1,
                 "umbrella_global": "NONE", "in_umbrella_aliases": ""}]
        rows += [{"class": "MATCH", "source_global": "", "s8_coverage": "REVIEWED", "split_bundle": 0,
                  "umbrella_global": "", "in_umbrella_aliases": ""} for _ in range(99)]
        p = {x["id"]: x for x in s.grade(rows)}
        self.assertEqual(p["P1"]["value"], [1, 100, 1.0])
        self.assertTrue(p["P1"]["held"])
        self.assertTrue(p["P2"]["held"])
        self.assertEqual(p["P6"]["value"], [0, 0, None])
        self.assertFalse(p["P6"]["held"])

    def test_gate(self):
        ok, checks = s.gate(self.rows, known={"CVE-2026-95842": "SPLIT", "CVE-2026-57234": "MATCH"},
                            expected_rows=7, min_fetch=0.8)
        self.assertTrue(ok, checks)
        ok, checks = s.gate(self.rows, known={"CVE-2026-95842": "MATCH"}, expected_rows=7, min_fetch=0.8)
        self.assertFalse(checks["known_cases"])
        ok, checks = s.gate(self.rows, known={}, expected_rows=7, min_fetch=0.9)
        self.assertFalse(checks["read_share"])
        ok, checks = s.gate(self.rows, known={"CVE-2020-0001": "SPLIT"}, expected_rows=8, min_fetch=0.8)
        self.assertEqual(checks, {"rows": False, "read_share": True, "known_cases": False})

    def test_sample_and_outputs(self):
        sample = s.pick_sample(self.rows, n=10)
        self.assertEqual([r["cve"] for r in sample], ["CVE-2026-92284", "CVE-2026-95842", "CVE-2026-95848"])
        two = s.pick_sample(self.rows, n=2, seed=1)
        self.assertEqual(len(two), 2)
        self.assertEqual(two, sorted(two, key=lambda r: r["cve"]))
        got = s.read_sample(sample, status=lambda url: 404, pause=0)
        self.assertEqual(got[1]["page_url"],
                         "https://github.com/moquette-io/moquette/security/advisories/" + SUB1)
        desc = s.describe(self.rows, got)
        self.assertEqual(desc["class"]["SPLIT"], 3)
        self.assertEqual(desc["split_umbrellas"], 2)
        self.assertEqual(desc["split_umbrellas_with_own_match_cve"], 1)
        self.assertEqual(desc["split_bundle_sizes"], {1: 1, 2: 1})
        self.assertEqual(desc["sample_http_status"], {404: 3})
        preds = s.grade(self.rows)
        meta = {"db_head": "x", "cves_sha256": "y", "read_at": "z"}
        with tempfile.TemporaryDirectory() as out:
            s.write_outputs(out, self.rows, self.recs, got, preds, desc, True, {"rows": True}, meta)
            with open(os.path.join(out, "rows.csv"), encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 7)
            self.assertEqual(list(rows[0].keys()), s.ROW_COLS)
            with open(os.path.join(out, "records.jsonl"), encoding="utf-8") as f:
                lines = [json.loads(x) for x in f]
            self.assertEqual(len(lines), 7)
            self.assertEqual(lines[0]["cve"], "CVE-2026-57234")
            with open(os.path.join(out, "results.json"), encoding="utf-8") as f:
                self.assertTrue(json.load(f)["gate_ok"])
            with open(os.path.join(out, "RESULTS-job.md"), encoding="utf-8") as f:
                self.assertIn("| P3 |", f.read())

    def test_read_pop(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "cves.csv")
            with open(p, "w", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                w.writerow(["cve", "published", "nvd_status", "coverage"])
                w.writerow(["cve-2026-95842", "2026-09-23", "Received", "NONE"])
                w.writerow(["", "", "", ""])
            self.assertEqual(s.read_pop(p), [{"cve": "CVE-2026-95842", "published": "2026-09-23",
                                              "coverage": "NONE"}])


if __name__ == "__main__":
    unittest.main()
