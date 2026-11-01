"""Offline tests for rejected_alias.py (study S6). Apache-2.0. Made with AI agents working for MV2 of Munim, Inc."""
import csv
import io
import json
import os
import tempfile
import unittest
import zipfile

import rejected_alias as ra

R1, R2, R3, R4, R5, R6 = ("GHSA-aaaa-aaaa-aaaa", "GHSA-cccc-cccc-cccc", "GHSA-dddd-dddd-dddd",
                          "GHSA-eeee-eeee-eeee", "GHSA-gggg-gggg-gggg", "GHSA-ffff-ffff-ffff")
U1, U2 = "GHSA-bbbb-bbbb-bbbb", "GHSA-hhhh-hhhh-hhhh"


def ghsa(gid, cves, pkgs=(), linked=(), withdrawn=False, modified="2026-01-01T00:00:00Z"):
    obj = {"id": gid, "aliases": list(cves) + ["PYSEC-2026-1"], "modified": modified,
           "published": "2026-01-01T00:00:00Z", "summary": "summary of " + gid, "details": "details " * 5,
           "references": [{"url": "https://github.com/acme/x/security/advisories/" + gid}]
           + [{"url": "https://github.com/advisories/" + g} for g in linked],
           "affected": [{"package": {"ecosystem": "npm", "name": p}} for p in pkgs]}
    if withdrawn:
        obj["withdrawn"] = "2026-02-01T00:00:00Z"
    return obj


def cve(cid, state, assigner="VulnCheck", ghsas=(), reason="", rejected="", text="text of "):
    cna = {"references": [{"url": "https://github.com/acme/x/security/advisories/" + g} for g in ghsas]}
    if state == "REJECTED":
        cna["rejectedReasons"] = [{"lang": "en", "value": reason}]
    else:
        cna["descriptions"] = [{"lang": "en", "value": text + cid}]
    meta = {"cveId": cid, "state": state, "assignerShortName": assigner,
            "datePublished": "2026-01-15T00:00:00.000Z"}
    if rejected:
        meta["dateRejected"] = rejected
    return {"dataType": "CVE_RECORD", "cveMetadata": meta, "containers": {"cna": cna}}


def world():
    reviewed = [
        ghsa(R1, ["CVE-2026-1001"], pkgs=["a"]),
        ghsa(R2, ["CVE-2026-1002", "CVE-2026-1003"], pkgs=["b"]),
        ghsa(R3, ["CVE-2026-1004"], pkgs=["c"]),
        ghsa(R4, ["CVE-2026-1005"], pkgs=["d"]),
        ghsa(R5, ["CVE-2026-1001"], pkgs=["e"], withdrawn=True),
        ghsa(R6, ["CVE-2026-1006"], pkgs=["f"]),
    ]
    unreviewed = [ghsa(U1, ["CVE-2026-2001"], linked=[R1]), ghsa(U2, ["CVE-2026-2003"], linked=[R6])]
    records = [
        cve("CVE-2026-1001", "REJECTED", "GitHub_M", reason="This CVE was assigned in error.",
            rejected="2026-02-01T00:00:00.000Z"),
        cve("CVE-2026-1002", "REJECTED", reason="This CVE ID has been rejected or withdrawn by its CVE "
            "Numbering Authority as it's a duplicate of CVE-2026-2002.", rejected="2026-02-01T00:00:00.000Z"),
        cve("CVE-2026-1003", "PUBLISHED", ghsas=[R2]),
        cve("CVE-2026-1004", "PUBLISHED", ghsas=["GHSA-zzzz-zzzz-zzzz"]),
        cve("CVE-2026-1006", "REJECTED", "Kong", reason="This CVE ID has been rejected.",
            rejected="2025-12-01T00:00:00.000Z"),
        cve("CVE-2026-2001", "PUBLISHED", ghsas=[R1]),
        cve("CVE-2026-2002", "PUBLISHED"),
        cve("CVE-2026-2003", "PUBLISHED"),
    ]
    rev = [ra.parse_record(o, keep_text=True) for o in reviewed]
    unr = [ra.parse_record(o, keep_text=False) for o in unreviewed]
    table = {}
    for o in records:
        p = ra.parse_cve(o)
        table[p["id"]] = p
    return rev, unr, table


class ParseTests(unittest.TestCase):
    def test_parse_record(self):
        r = ra.parse_record(ghsa(U1, ["CVE-2026-2001"], linked=[R1, "GHSA-AbCd-1234-wxyz"]), keep_text=False)
        self.assertEqual(r["cves"], ["CVE-2026-2001"])
        self.assertEqual(r["linked"], [R1, "GHSA-abcd-1234-wxyz"])
        self.assertEqual(r["packages"], [])
        self.assertNotIn("summary", r)
        self.assertFalse(r["withdrawn"])

    def test_parse_cve(self):
        p = ra.parse_cve(cve("CVE-2026-56120", "REJECTED", reason="duplicate of CVE-2026-56784",
                             rejected="2026-06-23T21:03:57.607Z"))
        self.assertEqual(p["state"], "REJECTED")
        self.assertEqual(p["assigner"], "VulnCheck")
        self.assertEqual(p["rejected"], "2026-06-23T21:03:57")
        self.assertIn("CVE-2026-56784", p["reason"])
        q = ra.parse_cve(cve("CVE-2026-1", "PUBLISHED", ghsas=["GHSA-AAAA-bbbb-cccc"]))
        self.assertEqual(q["ghsas"], ["GHSA-aaaa-bbbb-cccc"])
        self.assertEqual(q["reason"], "")

    def test_reason_class(self):
        c = ra.reason_class
        self.assertEqual(c("This CVE was assigned in error."), "error")
        self.assertEqual(c("This CVE ID has been rejected."), "unspecified")
        self.assertEqual(c("This CVE ID has been rejected or withdrawn by its CVE Numbering Authority."),
                         "unspecified")
        self.assertEqual(c(""), "unspecified")
        self.assertEqual(c("This CVE ID has been rejected or withdrawn by its CVE Numbering Authority. "
                           "CVE-2026-73294 published by GitHub", "CVE-2026-73682"), "duplicate")
        self.assertEqual(c("This record is a duplicate; use CVE-2026-56397 instead.", "CVE-2026-56395"),
                         "duplicate")
        self.assertEqual(c("The reported behavior is not a vulnerability."), "not_vuln")
        self.assertEqual(c("Withdrawn at the request of the vendor."), "other")
        self.assertEqual(c("See CVE-2026-5 for details", "CVE-2026-5"), "other")


class CveListTests(unittest.TestCase):
    def _member(self, cid, state):
        year, num = cid.split("-")[1], int(cid.split("-")[2])
        return "cves/%s/%dxxx/%s.json" % (year, num // 1000, cid), json.dumps(cve(cid, state))

    def test_nested_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                for cid, st in (("CVE-2026-56120", "REJECTED"), ("CVE-2026-56784", "PUBLISHED")):
                    name, body = self._member(cid, st)
                    z.writestr(name, body)
                z.writestr("cves/delta.json", "{}")
            outer = os.path.join(tmp, "2026-11-01_all_CVEs_at_midnight.zip.zip")
            with zipfile.ZipFile(outer, "w") as z:
                z.writestr("cves.zip", buf.getvalue())
            lst = ra.CveList(outer, tmp)
            self.assertTrue(lst.uses_inner())
            self.assertEqual(lst.get("CVE-2026-56120")["state"], "REJECTED")
            self.assertEqual(lst.get("CVE-2026-56784")["state"], "PUBLISHED")
            self.assertIsNone(lst.get("CVE-2026-1"))
            self.assertEqual(len(lst.index), 2)
            lst.close()
            self.assertFalse(os.path.exists(os.path.join(tmp, "inner-cves.zip")))

    def test_flat_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "flat.zip")
            with zipfile.ZipFile(path, "w") as z:
                name, body = self._member("CVE-2024-5187", "PUBLISHED")
                z.writestr(name, body)
            lst = ra.CveList(path, tmp)
            self.assertFalse(lst.uses_inner())
            self.assertEqual(lst.get("CVE-2024-5187")["state"], "PUBLISHED")
            lst.close()

    def test_pick_asset(self):
        rel = {"tag_name": "t", "assets": [
            {"name": "2026-11-01_delta_CVEs_at_1300Z.zip", "browser_download_url": "u1"},
            {"name": "2026-11-01_all_CVEs_at_midnight.zip.zip", "browser_download_url": "u2"}]}
        self.assertEqual(ra.pick_asset(rel), ("2026-11-01_all_CVEs_at_midnight.zip.zip", "u2"))
        with self.assertRaises(ValueError):
            ra.pick_asset({"tag_name": "t", "assets": []})


class AnalyseTests(unittest.TestCase):
    def setUp(self):
        rev, unr, table = world()
        self.res = ra.analyse(rev, unr, table.get)

    def test_rows(self):
        rows = {r["reviewed"]: r for r in self.res["rows"]}
        self.assertEqual(sorted(rows), sorted([R1, R2, R6]))
        self.assertTrue(rows[R1]["only_alias"])
        self.assertFalse(rows[R2]["only_alias"])
        self.assertEqual(rows[R2]["live_aliases"], "CVE-2026-1003")
        self.assertEqual(rows[R1]["reason_class"], "error")
        self.assertEqual(rows[R2]["reason_class"], "duplicate")
        self.assertEqual(rows[R6]["reason_class"], "unspecified")
        self.assertTrue(rows[R1]["untouched_since_rejection"])
        self.assertFalse(rows[R6]["untouched_since_rejection"])
        self.assertTrue(rows[R1]["has_replacement"])
        self.assertTrue(rows[R2]["has_replacement"])
        self.assertFalse(rows[R6]["has_replacement"])

    def test_replacements(self):
        rep = {x["reviewed"]: x for x in self.res["replacements"]}
        self.assertEqual(len(self.res["replacements"]), 2)
        self.assertEqual(rep[R1]["replacement"], "CVE-2026-2001")
        self.assertEqual(rep[R1]["via"], "cites")
        self.assertTrue(rep[R1]["only_packageless_unreviewed"])
        self.assertEqual(rep[R1]["holders"], U1)
        self.assertEqual(rep[R2]["replacement"], "CVE-2026-2002")
        self.assertEqual(rep[R2]["via"], "reason")
        self.assertTrue(rep[R2]["held_by_none"])
        self.assertFalse(rep[R2]["only_packageless_unreviewed"])

    def test_states_mismatch_missing(self):
        self.assertEqual(self.res["stats"]["alias_states"], {"MISSING": 1, "PUBLISHED": 2, "REJECTED": 3})
        self.assertEqual([m["reviewed"] for m in self.res["mismatch"]], [R3])
        self.assertEqual([m["cve"] for m in self.res["missing"]], ["CVE-2026-1005"])
        self.assertEqual(self.res["stats"]["live_reviewed"], 5)

    def test_verdicts_underpowered(self):
        v = ra.verdicts(self.res)
        self.assertEqual(v["P1"]["value"], 3)
        self.assertEqual(v["P1"]["held"], "no")
        self.assertTrue(v["P3"]["held"].startswith("INCONCLUSIVE"))
        self.assertEqual(set(v), {"P1", "P2", "P3", "P4", "P5", "P6"})
        self.assertTrue(all("claim" in x for x in v.values()))

    def test_verdicts_powered(self):
        rows = [{"only_alias": i < 3, "has_replacement": i < 2, "rejected": "CVE-2026-%d" % (10 + i),
                 "rejected_assigner": ("GitHub_M", "VulnCheck", "Kong", "VulnCheck", "mitre")[i]}
                for i in range(5)]
        repl = [{"replacement": "CVE-2026-1", "only_packageless_unreviewed": True},
                {"replacement": "CVE-2026-1", "only_packageless_unreviewed": False},
                {"replacement": "CVE-2026-2", "only_packageless_unreviewed": False}]
        v = ra.verdicts({"rows": rows, "replacements": repl})
        self.assertEqual(v["P2"]["value"], [3, 5, 60.0])
        self.assertEqual(v["P2"]["held"], "yes")
        self.assertEqual(v["P3"]["value"], [2, 5, 40.0])
        self.assertEqual(v["P3"]["held"], "yes")
        self.assertEqual(v["P4"]["value"], [3, 5, 60.0])
        self.assertEqual(v["P5"]["value"], [1, 2, 50.0])
        self.assertEqual(v["P5"]["held"], "no")

    def test_sample_and_outputs(self):
        s1 = ra.grading_sample(self.res["replacements"])
        s2 = ra.grading_sample(self.res["replacements"])
        self.assertEqual([x["reviewed"] for x in s1], [x["reviewed"] for x in s2])
        self.assertEqual(len(s1), 2)
        result = {"db_commit": "abc", "db_commit_date": "d", "cve_release": "t", "cve_asset": "a",
                  "cve_read_at": "r", "verdicts": ra.verdicts(self.res),
                  "descriptive": ra.descriptive(self.res), "sample": []}
        with tempfile.TemporaryDirectory() as tmp:
            ra.write_outputs(tmp, result, self.res, s1)
            for f in ("results.json", "RESULTS-job.md", "rows.csv", "replacements.csv", "mismatch.csv",
                      "missing.csv", "grading_sample.csv"):
                self.assertTrue(os.path.exists(os.path.join(tmp, f)), f)
            with open(os.path.join(tmp, "grading_sample.csv"), encoding="utf-8") as fh:
                header = next(csv.reader(fh))
            self.assertEqual(header, ra.SAMPLE_COLS + ["grade"])
            self.assertNotIn("holders", header)


if __name__ == "__main__":
    unittest.main()
