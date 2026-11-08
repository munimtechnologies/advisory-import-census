"""Offline tests for pysec_rejected.py (study S13). Apache-2.0. Made with AI agents working for MV2 of Munim, Inc."""
import csv
import datetime
import io
import json
import os
import tempfile
import unittest
import zipfile

import pysec_rejected as m

YAML_TEXT = """id: PYSEC-2026-0001
published: "2026-01-02T03:04:05.123456Z"
modified: 2026-02-03T04:05:06Z
aliases:
- CVE-2025-1111
- GHSA-2345-6789-cfgh
summary: Example flaw
affected:
- package:
    name: examplepkg
    ecosystem: PyPI
"""


def cve(cid, state, rejected="", reason="", published="2025-12-01T00:00:00"):
    return {"id": cid, "state": state, "assigner": "GitHub_M", "published": published,
            "rejected": rejected, "reason": reason}


def pysec(pid, cves, ghsas=(), published="2026-01-01T00:00:00", modified="2026-01-01T00:00:00",
          withdrawn=""):
    return {"id": pid, "path": "vulns/x/%s.yaml" % pid, "withdrawn": withdrawn, "published": published,
            "modified": modified, "cves": list(cves), "ghsas": list(ghsas), "packages": ["x"],
            "summary": "s"}


CVES = {
    "CVE-2025-0001": cve("CVE-2025-0001", "REJECTED", "2026-03-01T00:00:00", "This CVE ID has been rejected."),
    "CVE-2025-0002": cve("CVE-2025-0002", "REJECTED", "2026-03-01T00:00:00",
                         "Duplicate of CVE-2025-0003."),
    "CVE-2025-0003": cve("CVE-2025-0003", "PUBLISHED"),
    "CVE-2025-0004": cve("CVE-2025-0004", "PUBLISHED"),
    "CVE-2025-0005": cve("CVE-2025-0005", "REJECTED", "2025-06-01T00:00:00", "Not a vulnerability."),
}
REVIEWED = {"GHSA-2222-3333-4444": {"withdrawn": True, "cves": []},
            "GHSA-5555-6666-7777": {"withdrawn": False, "cves": []}}


class FakeYaml:
    """Tiny stand-in so the loader test does not depend on PyYAML internals."""

    def __init__(self, objs):
        self.objs = objs

    def safe_load(self, fh):
        name = os.path.basename(fh.name)
        obj = self.objs[name]
        if obj == "BROKEN":
            raise ValueError("bad yaml")
        return obj


class TestHelpers(unittest.TestCase):
    def test_ts(self):
        self.assertEqual(m.ts("2026-07-22T19:11:48.123Z"), "2026-07-22T19:11:48")
        self.assertEqual(m.ts(None), "")
        dt = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
        self.assertEqual(m.ts(dt), "2026-01-02T03:04:05")
        self.assertEqual(m.ts(datetime.date(2026, 1, 2)), "2026-01-02T00:00:00")

    def test_parse_pysec(self):
        r = m.parse_pysec({"id": "PYSEC-2026-1", "aliases": ["CVE-2024-7033", "GHSA-3P9Q-7w63-3f8q", "OSV-1"],
                           "withdrawn": "2026-07-22T19:11:48Z",
                           "affected": [{"package": {"name": "open-webui", "ecosystem": "PyPI"}}]},
                          "vulns\\open-webui\\PYSEC-2026-1.yaml")
        self.assertEqual(r["cves"], ["CVE-2024-7033"])
        self.assertEqual(r["ghsas"], ["GHSA-3p9q-7w63-3f8q"])
        self.assertEqual(r["withdrawn"], "2026-07-22T19:11:48")
        self.assertEqual(r["path"], "vulns/open-webui/PYSEC-2026-1.yaml")
        self.assertEqual(r["packages"], ["open-webui"])

    def test_reason_class(self):
        self.assertEqual(m.reason_class("Duplicate of CVE-2025-0003", "CVE-2025-0002"), "duplicate")
        self.assertEqual(m.reason_class("This CVE ID has been rejected or withdrawn by its CVE Numbering Authority."),
                         "unspecified")
        self.assertEqual(m.reason_class("The CNA does not consider this a valid issue; not a vulnerability."),
                         "not_vuln")
        self.assertEqual(m.reason_class("Assigned in error."), "error")
        self.assertEqual(m.reason_class("Something else."), "other")

    def test_ghsa_state(self):
        self.assertEqual(m.ghsa_state([], REVIEWED), "none")
        self.assertEqual(m.ghsa_state(["GHSA-2222-3333-4444", "GHSA-5555-6666-7777"], REVIEWED), "withdrawn")
        self.assertEqual(m.ghsa_state(["GHSA-5555-6666-7777"], REVIEWED), "live")
        self.assertEqual(m.ghsa_state(["GHSA-9999-9999-9999"], REVIEWED), "not_in_reviewed")


class TestLoaders(unittest.TestCase):
    def test_load_pysec_counts_errors(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "vulns", "a"))
            for name in ("PYSEC-2026-1.yaml", "PYSEC-2026-2.yaml", "README.md"):
                open(os.path.join(d, "vulns", "a", name), "w").close()
            fy = FakeYaml({"PYSEC-2026-1.yaml": {"id": "PYSEC-2026-1", "aliases": ["CVE-2025-0001"]},
                           "PYSEC-2026-2.yaml": "BROKEN"})
            recs, n, errors = m.load_pysec(d, fy)
            self.assertEqual(n, 2)
            self.assertEqual(len(recs), 1)
            self.assertEqual(len(errors), 1)
            self.assertEqual(recs[0]["path"], "vulns/a/PYSEC-2026-1.yaml")

    def test_load_pysec_real_yaml(self):
        import yaml
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "vulns", "examplepkg"))
            with open(os.path.join(d, "vulns", "examplepkg", "PYSEC-2026-0001.yaml"), "w", encoding="utf-8") as f:
                f.write(YAML_TEXT)
            recs, n, errors = m.load_pysec(d, yaml)
            self.assertEqual((n, len(errors)), (1, 0))
            r = recs[0]
            self.assertEqual(r["published"], "2026-01-02T03:04:05")
            self.assertEqual(r["modified"], "2026-02-03T04:05:06")
            self.assertEqual(r["cves"], ["CVE-2025-1111"])
            self.assertEqual(r["ghsas"], ["GHSA-2345-6789-cfgh"])
            self.assertEqual(r["withdrawn"], "")

    def test_load_reviewed(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "advisories", "github-reviewed", "2026", "01", "GHSA-2222-3333-4444")
            os.makedirs(p)
            with open(os.path.join(p, "GHSA-2222-3333-4444.json"), "w") as f:
                json.dump({"id": "GHSA-2222-3333-4444", "withdrawn": "2026-01-01T00:00:00Z",
                           "aliases": ["CVE-2025-0001"]}, f)
            rv = m.load_reviewed(d)
            self.assertTrue(rv["GHSA-2222-3333-4444"]["withdrawn"])

    def test_cvelist_nested_zip(self):
        with tempfile.TemporaryDirectory() as d:
            inner = io.BytesIO()
            with zipfile.ZipFile(inner, "w") as z:
                z.writestr("cves/2025/0xxx/CVE-2025-0001.json", json.dumps({
                    "cveMetadata": {"cveId": "CVE-2025-0001", "state": "REJECTED", "assignerShortName": "GitHub_M",
                                    "dateRejected": "2026-03-01T00:00:00.000Z"},
                    "containers": {"cna": {"rejectedReasons": [{"value": "Duplicate of CVE-2025-0003."}]}}}))
            outer = os.path.join(d, "x_all_CVEs_at_midnight.zip.zip")
            with zipfile.ZipFile(outer, "w") as z:
                z.writestr("cves.zip", inner.getvalue())
            cl = m.CveList(outer, d)
            self.assertTrue(cl.uses_inner())
            self.assertEqual(len(cl), 1)
            rec = cl.get("CVE-2025-0001")
            self.assertEqual(rec["state"], "REJECTED")
            self.assertEqual(rec["rejected"], "2026-03-01T00:00:00")
            self.assertIsNone(cl.get("CVE-2025-9999"))
            cl.close()


class TestAnalyse(unittest.TestCase):
    def setUp(self):
        self.recs = [
            pysec("PYSEC-2026-1", ["CVE-2025-0001"], ["GHSA-2222-3333-4444"]),        # withdraw, GH withdrawn
            pysec("PYSEC-2026-2", ["CVE-2025-0002"]),                                 # replace alias
            pysec("PYSEC-2026-3", ["CVE-2025-0001", "CVE-2025-0004"], ["GHSA-5555-6666-7777"]),  # drop alias
            pysec("PYSEC-2026-4", ["CVE-2025-0004"]),                                 # fine
            pysec("PYSEC-2026-5", ["CVE-2025-0001"], withdrawn="2026-04-01T00:00:00"),  # already withdrawn
            pysec("PYSEC-2026-6", ["CVE-2025-0005"], modified="2026-05-01T00:00:00"),  # rejected before publish
            pysec("PYSEC-2026-7", ["CVE-2025-7777"]),                                 # missing
        ]
        self.res = m.analyse(self.recs, REVIEWED, CVES.get)

    def test_rows_and_actions(self):
        by = {r["pysec"]: r for r in self.res["rows"]}
        self.assertEqual(sorted(by), ["PYSEC-2026-1", "PYSEC-2026-2", "PYSEC-2026-3", "PYSEC-2026-6"])
        self.assertEqual(by["PYSEC-2026-1"]["action"], "WITHDRAW_CANDIDATE")
        self.assertEqual(by["PYSEC-2026-1"]["ghsa_state"], "withdrawn")
        self.assertEqual(by["PYSEC-2026-2"]["action"], "REPLACE_ALIAS")
        self.assertEqual(by["PYSEC-2026-2"]["replacement"], "CVE-2025-0003")
        self.assertEqual(by["PYSEC-2026-3"]["action"], "DROP_ALIAS")
        self.assertEqual(by["PYSEC-2026-3"]["ghsa_state"], "live")
        self.assertTrue(by["PYSEC-2026-1"]["untouched_since_rejection"])
        self.assertTrue(by["PYSEC-2026-1"]["rejected_after_publish"])
        self.assertFalse(by["PYSEC-2026-6"]["untouched_since_rejection"])
        self.assertFalse(by["PYSEC-2026-6"]["rejected_after_publish"])

    def test_stats_and_missing(self):
        st = self.res["stats"]
        self.assertEqual(st["pysec_records"], 7)
        self.assertEqual(st["pysec_withdrawn"], 1)
        self.assertEqual(st["alias_states"]["MISSING"], 1)
        self.assertEqual(self.res["missing"][0]["cve"], "CVE-2025-7777")

    def test_verdicts(self):
        v = m.verdicts(self.res)
        self.assertEqual(v["P1"]["held"], "no")  # 4 rows < 10
        self.assertTrue(v["P2"]["held"].startswith("INCONCLUSIVE"))  # 4 rows < MIN_ROWS
        big = {"rows": self.res["rows"] * 3, "missing": [], "stats": {}}
        v = m.verdicts(big)
        self.assertEqual(v["P1"]["held"], "yes")
        self.assertEqual(v["P2"]["value"], [6, 12, 50.0])
        self.assertEqual(v["P3"]["value"], [3, 6, 50.0])
        self.assertEqual(v["P4"]["value"], [9, 12, 75.0])
        self.assertEqual(v["P5"]["value"], [9, 12, 75.0])
        self.assertEqual(v["P5"]["held"], "no")

    def test_gate(self):
        ok = {"pysec_files": 5000, "pysec_parse_errors": 3, "cve_records": 300000, "reviewed_ghsas": 30000}
        self.assertEqual(m.gate(ok), [])
        bad = dict(ok, pysec_parse_errors=100, cve_records=10)
        self.assertEqual(len(m.gate(bad)), 2)

    def test_sample_and_outputs(self):
        s = m.grading_sample(self.res["rows"])
        self.assertEqual([r["pysec"] for r in s], ["PYSEC-2026-1", "PYSEC-2026-6"])
        with tempfile.TemporaryDirectory() as d:
            result = {"pypa_commit": "a", "pypa_commit_date": "b", "ghdb_commit": "c", "ghdb_commit_date": "d",
                      "cve_release": "e", "cve_asset": "f", "cve_read_at": "g", "gate_failures": [],
                      "counts": {}, "verdicts": m.verdicts(self.res), "descriptive": m.descriptive(self.res)}
            m.write_outputs(d, result, self.res, s)
            with open(os.path.join(d, "rows.csv"), "rb") as f:
                raw = f.read()
            self.assertNotIn(b"\r\n", raw)
            with open(os.path.join(d, "pr_candidates.csv"), encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual([r["pysec"] for r in rows], ["PYSEC-2026-1", "PYSEC-2026-6"])
            with open(os.path.join(d, "RESULTS-job.md"), encoding="utf-8") as f:
                self.assertIn("Gate: PASSED", f.read())


if __name__ == "__main__":
    unittest.main()
