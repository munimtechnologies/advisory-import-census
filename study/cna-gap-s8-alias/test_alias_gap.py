"""Offline tests for alias_gap.py. Apache-2.0. Made with AI agents working for MV2 of Munim, Inc."""
import csv
import json
import os
import tempfile
import unittest

import alias_gap as ag

G1 = "GHSA-2222-3333-4444"   # live, no CVE alias      -> MISSING_ALIAS (candidate)
G2 = "GHSA-5555-6666-7777"   # live, holds another CVE -> HOLDS_OTHER_CVE (bundle of 2)
G3 = "GHSA-cccc-ffff-gggg"   # withdrawn               -> WITHDRAWN_ADVISORY
G4 = "GHSA-hhhh-jjjj-mmmm"   # not in the clone        -> ADVISORY_NOT_FOUND
G5 = "GHSA-pppp-qqqq-rrrr"   # live, no alias, but the CVE record cites two advisories -> not a candidate


def adv_json(gid, aliases, withdrawn="", published="2026-06-19T16:36:11Z", summary="Thing: bug", eco="RubyGems"):
    return {"schema_version": "1.4.0", "id": gid, "modified": "2026-06-19T16:36:12Z", "published": published,
            "withdrawn": withdrawn, "aliases": aliases, "summary": summary,
            "affected": [{"package": {"ecosystem": eco, "name": "thing"}}]}


def cve_json(cve, advs, assigner="GitHub_M", state="PUBLISHED", title="Thing: bug",
             published="2026-06-25T14:30:20.478Z"):
    refs = [{"url": "https://github.com/o/r/security/advisories/%s" % g} for g in advs]
    return {"cveMetadata": {"cveId": cve, "state": state, "assignerShortName": assigner,
                            "datePublished": published},
            "containers": {"cna": {"title": title, "references": refs}}}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = os.path.join(self.tmp.name, "advisories", "github-reviewed", "2026", "06")
        for gid, adv in [(G1, adv_json(G1, [])), (G2, adv_json(G2, ["CVE-2026-10099"])),
                         (G3, adv_json(G3, [], withdrawn="2026-07-01T00:00:00Z")), (G5, adv_json(G5, []))]:
            d = os.path.join(root, gid)
            os.makedirs(d)
            with open(os.path.join(d, gid + ".json"), "w", encoding="utf-8") as f:
                json.dump(adv, f)
        self.db = self.tmp.name
        self.rows_path = os.path.join(self.tmp.name, "rows.csv")
        cols = ["cve", "published", "nvd_status", "coverage", "holders", "ref_owner", "ref_repo", "ref_ghsa",
                "ref_global_state", "uncovered_kind"]
        rows = [["CVE-2026-10010", "2026-06-25", "Analyzed", "NONE", "", "o", "r", G1, "REVIEWED",
                 "GLOBAL_WITHOUT_ALIAS"],
                ["CVE-2026-10011", "2026-06-25", "Analyzed", "NONE", "", "o", "r", G2, "REVIEWED",
                 "GLOBAL_WITHOUT_ALIAS"],
                ["CVE-2026-10012", "2026-06-25", "Analyzed", "NONE", "", "o", "r", G2.upper().replace(
                    "GHSA-", "GHSA-"), "REVIEWED", "GLOBAL_WITHOUT_ALIAS"],
                ["CVE-2026-10013", "2026-06-25", "Analyzed", "WITHDRAWN_ONLY", "", "o", "r", G3,
                 "REVIEWED_WITHDRAWN", "GLOBAL_WITHOUT_ALIAS"],
                ["CVE-2026-10014", "2026-06-25", "Analyzed", "NONE", "", "o", "r", G4, "REVIEWED",
                 "GLOBAL_WITHOUT_ALIAS"],
                ["CVE-2026-10015", "2026-06-25", "Analyzed", "NONE", "", "o", "r", G5, "REVIEWED",
                 "GLOBAL_WITHOUT_ALIAS"],
                ["CVE-2026-10016", "2026-06-25", "Analyzed", "NONE", "", "o", "r", G1, "NOT_GLOBAL",
                 "REPO_ONLY"]]
        with open(self.rows_path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(cols)
            w.writerows(rows)
        self.records = {
            "CVE-2026-10010": cve_json("CVE-2026-10010", [G1]),
            "CVE-2026-10011": cve_json("CVE-2026-10011", [G2]),
            "CVE-2026-10012": cve_json("CVE-2026-10012", [G2]),
            "CVE-2026-10013": cve_json("CVE-2026-10013", [G3]),
            "CVE-2026-10014": cve_json("CVE-2026-10014", [G4]),
            "CVE-2026-10015": cve_json("CVE-2026-10015", [G5, G1]),
        }

    def tearDown(self):
        self.tmp.cleanup()

    def get(self, url):
        cve = url.rsplit("/", 1)[1]
        rec = self.records.get(cve)
        return (200, rec) if rec else (404, None)

    def run_all(self):
        rows = ag.read_rows(self.rows_path)
        files = ag.index_files(os.path.join(self.db, "advisories", "github-reviewed"))
        return ag.run(rows, files, self.get, pause=0)


class TestReadRows(Fixture):
    def test_only_global_without_alias_rows(self):
        rows = ag.read_rows(self.rows_path)
        self.assertEqual([r["cve"] for r in rows], ["CVE-2026-10010", "CVE-2026-10011", "CVE-2026-10012",
                                                     "CVE-2026-10013", "CVE-2026-10014", "CVE-2026-10015"])


class TestClassify(Fixture):
    def test_kinds(self):
        out, errors = self.run_all()
        kinds = {r["cve"]: r["kind"] for r in out}
        self.assertEqual(kinds, {"CVE-2026-10010": "MISSING_ALIAS", "CVE-2026-10011": "HOLDS_OTHER_CVE",
                                 "CVE-2026-10012": "HOLDS_OTHER_CVE", "CVE-2026-10013": "WITHDRAWN_ADVISORY",
                                 "CVE-2026-10014": "ADVISORY_NOT_FOUND", "CVE-2026-10015": "MISSING_ALIAS"})
        self.assertEqual(errors, 0)

    def test_candidate_rule(self):
        out, _ = self.run_all()
        cand = {r["cve"]: r["candidate"] for r in out}
        self.assertEqual(cand["CVE-2026-10010"], "yes")
        self.assertEqual(cand["CVE-2026-10015"], "no")   # record cites two advisories
        self.assertEqual(cand["CVE-2026-10011"], "no")

    def test_candidate_needs_github_cna(self):
        self.records["CVE-2026-10010"] = cve_json("CVE-2026-10010", [G1], assigner="mitre")
        out, _ = self.run_all()
        self.assertEqual([r["candidate"] for r in out if r["cve"] == "CVE-2026-10010"], ["no"])

    def test_bundle_size_and_fields(self):
        out, _ = self.run_all()
        r = {x["cve"]: x for x in out}
        self.assertEqual(r["CVE-2026-10011"]["bundle_size"], 2)
        self.assertEqual(r["CVE-2026-10011"]["adv_aliases"], "CVE-2026-10099")
        self.assertEqual(r["CVE-2026-10010"]["days_adv_to_cve"], 5)
        self.assertEqual(r["CVE-2026-10010"]["title_matches_summary"], "yes")
        self.assertEqual(r["CVE-2026-10010"]["adv_ecosystems"], "RubyGems")
        self.assertEqual(r["CVE-2026-10014"]["adv_ecosystems"], "")

    def test_cveawg_error_counted(self):
        del self.records["CVE-2026-10010"]
        out, errors = self.run_all()
        self.assertEqual(errors, 1)
        self.assertEqual([r["candidate"] for r in out if r["cve"] == "CVE-2026-10010"], ["no"])


class TestSummaryAndOutputs(Fixture):
    def test_summary(self):
        out, errors = self.run_all()
        s = ag.summarize(out, errors)
        self.assertEqual(s["kinds"], {"MISSING_ALIAS": 2, "HOLDS_OTHER_CVE": 2, "WITHDRAWN_ADVISORY": 1,
                                      "ADVISORY_NOT_FOUND": 1})
        self.assertEqual(s["candidates"], 1)
        self.assertEqual(s["missing_alias_cve_after_advisory"], 2)
        self.assertEqual(s["bundled_ghsas"], [G2])
        self.assertEqual(s["missing_alias_ecosystems"], {"RubyGems": 2})

    def test_write_outputs(self):
        out, errors = self.run_all()
        d = os.path.join(self.tmp.name, "out")
        ag.write_outputs(d, out, ag.summarize(out, errors), {"db_commit": "abc", "read_at": "t"})
        for fn in ("alias_gap.csv", "summary.json", "ALIAS-GAP.md"):
            self.assertTrue(os.path.isfile(os.path.join(d, fn)))
        with open(os.path.join(d, "alias_gap.csv"), encoding="utf-8") as f:
            self.assertEqual(len(list(csv.DictReader(f))), 6)


class TestHelpers(unittest.TestCase):
    def test_norm_ghsa(self):
        self.assertEqual(ag.norm_ghsa("GHSA-8678-W3JW-XFC2"), "GHSA-8678-w3jw-xfc2")

    def test_cve_facts_reads_adp_refs(self):
        rec = cve_json("CVE-2026-10010", [G1])
        rec["containers"]["adp"] = [{"references": [
            {"url": "https://github.com/o/r/security/advisories/%s" % G1},
            {"url": "https://github.com/advisories/%s" % G2}]}]
        f = ag.cve_facts(rec)
        self.assertEqual(f["repo_advisories"], [G1])   # global /advisories/ URLs are not repository advisories
        self.assertEqual(f["assigner"], "GitHub_M")

    def test_cve_facts_empty(self):
        self.assertEqual(ag.cve_facts(None)["repo_advisories"], [])

    def test_days_between(self):
        self.assertEqual(ag.days_between("2026-06-19T16:36:11Z", "2026-06-25T14:30:20.478Z"), 5)
        self.assertEqual(ag.days_between("", "2026-06-25T14:30:20Z"), "")


if __name__ == "__main__":
    unittest.main()
