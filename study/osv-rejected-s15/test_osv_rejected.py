"""Offline tests for osv_rejected.py (S15). Stdlib only. Apache-2.0.

Made with AI agents working for MV2 of Munim, Inc.
"""
import json
import os
import tempfile
import unittest
import zipfile

import osv_rejected as m


def cve(cid, state, assigner="mitre", published="2024-01-01T00:00:00", rejected="", reason="", replaced=None):
    cna = {}
    if reason:
        cna["rejectedReasons"] = [{"lang": "en", "value": reason}]
    if replaced:
        cna["replacedBy"] = replaced
    return {"cveMetadata": {"cveId": cid, "state": state, "assignerShortName": assigner,
                            "datePublished": published, "dateRejected": rejected},
            "containers": {"cna": cna}}


def osv(vid, aliases=(), published="2024-02-01T00:00:00Z", withdrawn=None, review=None, pkg="p"):
    o = {"id": vid, "aliases": list(aliases), "published": published, "modified": "2026-10-14T10:56:59.75Z",
         "affected": [{"package": {"name": pkg, "ecosystem": "Go"}}], "summary": "s " + vid}
    if withdrawn:
        o["withdrawn"] = withdrawn
    if review:
        o["database_specific"] = {"review_status": review}
    return o


def table(*recs):
    d = {r["cveMetadata"]["cveId"]: m.parse_cve(r) for r in recs}
    return d.get


class Basics(unittest.TestCase):
    def test_prefix(self):
        self.assertEqual(m.prefix("GO-2024-2611"), "GO")
        self.assertEqual(m.prefix("RUSTSEC-2026-0001"), "RUSTSEC")
        self.assertEqual(m.prefix("EEF-CVE-2025-4748"), "EEF")
        self.assertEqual(m.prefix("ghsa-8r3f-844c-mc37"), "GHSA")

    def test_cve_and_ghsa_fullmatch(self):
        self.assertTrue(m.is_cve("CVE-2024-24786"))
        self.assertFalse(m.is_cve("CVE-2024-24786x"))
        self.assertFalse(m.is_cve("xCVE-2024-24786"))
        self.assertTrue(m.is_ghsa("GHSA-8r3f-844c-mc37"))
        self.assertFalse(m.is_ghsa("GHSA-8r3f-844c-mc37-"))
        self.assertEqual(m.norm_ghsa("GHSA-8R3F-844C-MC37"), "GHSA-8r3f-844c-mc37")

    def test_parse_osv(self):
        r = m.parse_osv(osv("GO-2024-1", ["CVE-2024-11111", "CVE-2024-1", "GHSA-AAAA-bbbb-cccc", "junk"],
                            review="UNREVIEWED"), "Go")
        self.assertEqual(r["source"], "GO")
        self.assertEqual(r["cves"], ["CVE-2024-11111"])  # CVE-2024-1 is not a valid CVE ID
        self.assertEqual(r["ghsas"], ["GHSA-aaaa-bbbb-cccc"])
        self.assertEqual(r["review_status"], "UNREVIEWED")
        self.assertEqual(r["published"], "2024-02-01T00:00:00")

    def test_merge_keeps_one_record(self):
        store = {}
        m.merge_record(store, m.parse_osv(osv("HSEC-2024-0001"), "Hackage"))
        m.merge_record(store, m.parse_osv(osv("HSEC-2024-0001"), "GHC"))
        self.assertEqual(len(store), 1)
        self.assertEqual(store["HSEC-2024-0001"]["ecosystems"], ["GHC", "Hackage"])


class Zip(unittest.TestCase):
    def test_load_zip_splits_sources_and_ghsas(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "Go.zip")
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("GO-2024-0001.json", json.dumps(osv("GO-2024-0001", ["CVE-2024-11111"])))
                z.writestr("GHSA-aaaa-bbbb-cccc.json", json.dumps(osv("GHSA-aaaa-bbbb-cccc", withdrawn="2025-01-01T00:00:00Z")))
                z.writestr("GHSA-dddd-eeee-ffff.json", json.dumps(osv("GHSA-dddd-eeee-ffff")))
                z.writestr("MAL-2024-1.json", json.dumps(osv("MAL-2024-1")))
                z.writestr("CVE-2024-2.json", json.dumps(osv("CVE-2024-22222")))
                z.writestr("broken.json", "{not json")
                z.writestr("readme.txt", "x")
            sources, ghsas, errors = {}, {}, []
            n = m.load_zip(p, "Go", sources, ghsas, errors)
            self.assertEqual(n, 6)
            self.assertEqual(list(sources), ["GO-2024-0001"])
            self.assertEqual(ghsas, {"GHSA-aaaa-bbbb-cccc": True, "GHSA-dddd-eeee-ffff": False})
            self.assertEqual(len(errors), 1)


class CveParsing(unittest.TestCase):
    def test_replacement_after_300_chars_and_replacedBy(self):
        long_reason = "x " * 200 + "conflicts with an existing CVE (CVE-2023-48022)"
        r = m.parse_cve(cve("CVE-2025-34351", "REJECTED", reason=long_reason))
        self.assertIn("CVE-2023-48022", r["named"])
        self.assertNotIn("CVE-2023-48022", r["reason"])  # display copy is truncated, search is not
        r2 = m.parse_cve(cve("CVE-2025-10001", "REJECTED", reason="rejected", replaced=["CVE-2025-20002"]))
        self.assertEqual(r2["named"], ["CVE-2025-20002"])

    def test_reason_class(self):
        self.assertEqual(m.reason_class("This CVE ID has been rejected or withdrawn by its CVE Numbering Authority."), "unspecified")
        self.assertEqual(m.reason_class("DO NOT USE. duplicate of CVE-2024-2", "CVE-2024-1"), "duplicate")
        self.assertEqual(m.reason_class("Further investigation showed that it was not a security issue."), "not_vuln")


class Analyse(unittest.TestCase):
    def setUp(self):
        self.lookup = table(
            cve("CVE-2024-10001", "REJECTED", "@huntr_ai", rejected="2026-08-13T00:00:00",
                reason="This CVE ID has been rejected or withdrawn by its CVE Numbering Authority."),
            cve("CVE-2024-10002", "REJECTED", rejected="2024-03-01T00:00:00",
                reason="DO NOT USE. ConsultIDs: CVE-2024-10003. duplicate"),
            cve("CVE-2024-10003", "PUBLISHED"),
            cve("CVE-2024-10004", "PUBLISHED"),
            cve("CVE-2024-10005", "REJECTED", rejected="2023-01-01T00:00:00", reason="in error"),
        )
        recs = [
            osv("GO-2024-0001", ["CVE-2024-10001", "GHSA-aaaa-bbbb-cccc"], review="UNREVIEWED"),
            osv("GO-2024-0002", ["CVE-2024-10002"]),
            osv("RUSTSEC-2024-0001", ["CVE-2024-10001", "CVE-2024-10004"]),
            osv("RUSTSEC-2024-0002", ["CVE-2024-10005"]),  # rejected before published
            osv("PYSEC-2024-1", ["CVE-2024-10001"]),
            osv("PYSEC-2024-2", ["CVE-2024-10004"]),
            osv("GO-2024-0003", ["CVE-2024-10001"], withdrawn="2026-09-01T00:00:00Z"),
            osv("GO-2024-0004", ["CVE-2024-99999"]),  # missing from the CVE List
            osv("GO-2024-0005", []),
        ]
        self.sources = {}
        for r in recs:
            m.merge_record(self.sources, m.parse_osv(r, "x"))
        self.ghsas = {"GHSA-aaaa-bbbb-cccc": False}
        self.res = m.analyse(self.sources, self.ghsas, self.lookup)
        self.by = {r["id"]: r for r in self.res["rows"]}

    def test_rows_and_actions(self):
        self.assertEqual(sorted(self.by), ["GO-2024-0001", "GO-2024-0002", "PYSEC-2024-1",
                                           "RUSTSEC-2024-0001", "RUSTSEC-2024-0002"])
        self.assertEqual(self.by["GO-2024-0001"]["action"], "WITHDRAW_CANDIDATE")
        self.assertEqual(self.by["GO-2024-0002"]["action"], "REPLACE_ALIAS")
        self.assertEqual(self.by["GO-2024-0002"]["replacement"], "CVE-2024-10003")
        self.assertEqual(self.by["RUSTSEC-2024-0001"]["action"], "DROP_ALIAS")
        self.assertNotIn("GO-2024-0003", self.by)  # withdrawn records are not rows

    def test_dates_and_ghsa(self):
        self.assertTrue(self.by["GO-2024-0001"]["rejected_after_publish"])
        self.assertFalse(self.by["RUSTSEC-2024-0002"]["rejected_after_publish"])
        self.assertEqual(self.by["GO-2024-0001"]["ghsa_state"], "live")
        self.assertEqual(self.by["GO-2024-0002"]["ghsa_state"], "none")
        self.assertEqual(m.ghsa_state(["GHSA-zzzz-zzzz-zzzz"], self.ghsas), "not_in_export")

    def test_per_source_counts(self):
        ps = self.res["per_source"]
        self.assertEqual(ps["GO"], {"records": 5, "live": 4, "live_with_cve": 3, "rows": 2})
        self.assertEqual(ps["RUSTSEC"], {"records": 2, "live": 2, "live_with_cve": 2, "rows": 2})
        self.assertEqual(ps["PYSEC"], {"records": 2, "live": 2, "live_with_cve": 2, "rows": 1})
        self.assertEqual([x["cve"] for x in self.res["missing"]], ["CVE-2024-99999"])

    def test_verdicts(self):
        v = m.verdicts(self.res)
        self.assertEqual(v["P1"]["value"], 4)
        self.assertEqual(v["P1"]["held"], "no")
        self.assertTrue(v["P2"]["held"].startswith("INCONCLUSIVE"))
        # P5: GO+RUSTSEC 4 rows of 5 live-with-CVE (80%) vs PYSEC 1 of 2 (50%) -> not lower
        self.assertEqual(v["P5"]["value"][:2], [4, 5])
        self.assertEqual(v["P5"]["held"], "no")
        self.assertEqual(v["P6"]["held"], "graded by hand after the run")

    def test_verdicts_powered(self):
        rows = [{"source": "GO", "review_status": "UNREVIEWED", "ghsa_state": "live"}] * 4 + \
               [{"source": "RUSTSEC", "review_status": "", "ghsa_state": "withdrawn"}] * 2 + \
               [{"source": "PYSEC", "review_status": "", "ghsa_state": "none"}]
        res = {"rows": rows, "per_source": {"GO": {"rows": 4, "live_with_cve": 4000},
                                            "RUSTSEC": {"rows": 2, "live_with_cve": 1000},
                                            "PYSEC": {"rows": 21, "live_with_cve": 7562}}}
        v = m.verdicts(res)
        self.assertEqual(v["P1"]["held"], "yes")
        self.assertEqual(v["P2"]["value"], [4, 6, 66.7])
        self.assertEqual(v["P2"]["held"], "yes")
        self.assertEqual(v["P3"]["held"], "yes")
        self.assertEqual(v["P4"]["value"], [4, 6, 66.7])
        self.assertEqual(v["P5"]["held"], "yes")  # 0.12% < 0.278%

    def test_sample_excludes_pysec_and_is_seeded(self):
        s1 = [r["id"] for r in m.grading_sample(self.res["rows"])]
        s2 = [r["id"] for r in m.grading_sample(self.res["rows"])]
        self.assertEqual(s1, s2)
        self.assertNotIn("PYSEC-2024-1", s1)
        self.assertTrue(all(self.by[i]["action"] == "WITHDRAW_CANDIDATE" for i in s1))


class Gate(unittest.TestCase):
    def test_gate(self):
        ok = {"go_records": 4000, "rustsec_records": 900, "pysec_records": 7000, "ghsa_records": 5000,
              "cve_records": 400000, "osv_files": 50000, "parse_errors": 0}
        self.assertEqual(m.gate(ok), [])
        bad = dict(ok, go_records=10, parse_errors=5000)
        self.assertEqual(len(m.gate(bad)), 2)


class Outputs(unittest.TestCase):
    def test_csv_lineterminator(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.csv")
            m.write_csv(p, ["a"], [{"a": 1}])
            with open(p, "rb") as fh:
                self.assertNotIn(b"\r\n", fh.read())


if __name__ == "__main__":
    unittest.main()
