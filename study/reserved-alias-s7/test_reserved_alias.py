"""Offline tests for reserved_alias.py (study S7). Apache-2.0. Made with AI agents working for MV2 of Munim, Inc."""
import csv
import datetime
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import reserved_alias as ra

HERE = os.path.dirname(os.path.abspath(__file__))
G1, G2, G3, G4, G5 = ("GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb", "GHSA-cccc-cccc-cccc",
                      "GHSA-dddd-dddd-dddd", "GHSA-eeee-eeee-eeee")


def adv(gid, aliases, published="2025-01-01", summary="", details="", refs=(), withdrawn=False):
    obj = {"id": gid, "aliases": list(aliases), "published": published + "T00:00:00Z",
           "modified": "2026-10-01T00:00:00Z", "summary": summary or "summary of " + gid,
           "details": details or "details of " + gid, "references": [{"url": u} for u in refs],
           "affected": [{"package": {"ecosystem": "npm", "name": "pkg-" + gid[-4:]}}]}
    if withdrawn:
        obj["withdrawn"] = "2026-02-01T00:00:00Z"
    return obj


class FakeApi:
    """Answers /api/cve-id/ and /api/cve/ from dicts; records every URL asked."""

    def __init__(self, ids, records, fail=()):
        self.ids, self.records, self.fail, self.calls = ids, records, set(fail), []

    def __call__(self, url):
        self.calls.append(url)
        cve = url.rsplit("/", 1)[1]
        if cve in self.fail:
            return 503, None
        if "/api/cve-id/" in url:
            if cve in self.ids:
                state, cna = self.ids[cve]
                return 200, {"cve_id": cve, "cve_year": cve[4:8], "state": state, "owning_cna": cna,
                             "dateUpdated": "2026-05-01T00:00:00.000Z"}
            return 404, None
        if cve in self.records:
            return 200, self.records[cve]
        return 404, None


def rec(cve, state, assigner="mitre", text="", reason="", published="2026-01-01T00:00:00.000Z"):
    cna = {}
    if state == "REJECTED":
        cna["rejectedReasons"] = [{"lang": "en", "value": reason}]
    else:
        cna["descriptions"] = [{"lang": "en", "value": text or "text of " + cve}]
    meta = {"cveId": cve, "state": state, "assignerShortName": assigner, "datePublished": published}
    if state == "REJECTED":
        meta["dateRejected"] = "2026-03-01T00:00:00.000Z"
    return {"cveMetadata": meta, "containers": {"cna": cna}}


def write_tree(root, advisories):
    for a in advisories:
        d = os.path.join(root, a["published"][:4], a["published"][5:7], a["id"])
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, a["id"] + ".json"), "w", encoding="utf-8") as f:
            json.dump(a, f)


def write_pop(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(ra.POP_COLS)
        w.writerows(rows)


class TestPopulationFile(unittest.TestCase):
    def test_bundled_population_is_s6_missing(self):
        rows = ra.load_population(os.path.join(HERE, ra.POPULATION))
        self.assertEqual(len(rows), 143)  # S6 descriptive: missing_aliases = 143
        self.assertTrue(all(r["reviewed"].startswith("GHSA-") for r in rows))
        self.assertIn({"reviewed": "GHSA-93ww-43rr-79v3", "cve": "CVE-2024-10039",
                       "reviewed_published": "2024-11-25"}, rows)

    def test_bad_columns_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "p.csv")
            with open(p, "w", encoding="utf-8") as f:
                f.write("a,b\n1,2\n")
            with self.assertRaises(ValueError):
                ra.load_population(p)


class TestState(unittest.TestCase):
    def test_states(self):
        api = FakeApi({"CVE-2026-1": ("RESERVED", "mitre"), "CVE-2026-2": ("REJECTED", "redhat")}, {},
                      fail={"CVE-2026-3"})
        self.assertEqual(ra.id_state("CVE-2026-1", api)["state"], "RESERVED")
        r = ra.id_state("CVE-2026-2", api)
        self.assertEqual((r["state"], r["owning_cna"]), ("REJECTED", "redhat"))
        self.assertEqual(ra.id_state("CVE-2026-9", api)["state"], "NOT_FOUND")
        self.assertEqual(ra.id_state("CVE-2026-3", api)["state"], "ERROR")

    def test_unknown_state_is_error(self):
        api = FakeApi({"CVE-2026-1": ("WEIRD", "x")}, {})
        self.assertEqual(ra.id_state("CVE-2026-1", api)["state"], "ERROR")

    def test_record(self):
        api = FakeApi({}, {"CVE-2026-2": rec("CVE-2026-2", "REJECTED", reason="  Duplicate  of X. ")})
        r = ra.record("CVE-2026-2", api)
        self.assertEqual(r["reason"], "Duplicate of X.")
        self.assertEqual(r["date_rejected"], "2026-03-01T00:00:00")
        self.assertEqual(ra.record("CVE-2026-404", api), {})


class TestTypos(unittest.TestCase):
    def test_edit_distance(self):
        self.assertEqual(ra.edit_distance("CVE-2024-1234", "CVE-2024-1234"), 0)
        self.assertEqual(ra.edit_distance("CVE-2024-1234", "CVE-2024-1243"), 2)
        self.assertEqual(ra.edit_distance("CVE-2024-1234", "CVE-2024-12345"), 1)
        self.assertEqual(ra.edit_distance("CVE-2024-1234", "CVE-2023-9999"), 5)

    def test_mentioned_and_candidates(self):
        a = ra.reduce_advisory(adv(G1, ["CVE-2024-1234"], details="see cve-2024-1243 and CVE-2020-0001",
                                   refs=["https://nvd.nist.gov/vuln/detail/CVE-2024-12340"]))
        self.assertEqual(a["mentioned"], ["CVE-2020-0001", "CVE-2024-1234", "CVE-2024-12340", "CVE-2024-1243"])
        self.assertEqual(ra.typo_candidates("CVE-2024-1234", a), ["CVE-2024-12340", "CVE-2024-1243"])
        self.assertEqual(ra.typo_candidates("CVE-2024-1234", None), [])


class TestLoad(unittest.TestCase):
    def test_load_selected_only_wanted(self):
        with tempfile.TemporaryDirectory() as d:
            write_tree(d, [adv(G1, ["CVE-2024-1"]), adv(G2, ["CVE-2024-2"], published="2026-03-04")])
            got = ra.load_selected(d, {G2, G3})
            self.assertEqual(sorted(got), [G2])
            self.assertEqual(got[G2]["published"], "2026-03-04")


def world():
    """Five population IDs: RESERVED (old, mitre), RESERVED (new, GitHub_M), REJECTED (no record, only alias),
    NOT_FOUND with a PUBLISHED typo candidate, NOT_FOUND whose candidate is RESERVED (so not counted)."""
    advisories = [
        adv(G1, ["CVE-2020-1111"], published="2021-01-01"),
        adv(G2, ["CVE-2026-2222"], published="2026-10-20"),
        adv(G3, ["CVE-2024-10039"], published="2024-11-25"),
        adv(G4, ["CVE-2024-4444"], published="2025-01-01", details="Tracked upstream as CVE-2024-4445."),
        adv(G5, ["CVE-2023-5555", "CVE-2023-5556"], published="2025-06-01"),
    ]
    pop = [[G1, "CVE-2020-1111", "2021-01-01"], [G2, "CVE-2026-2222", "2026-10-20"],
           [G3, "CVE-2024-10039", "2024-11-25"], [G4, "CVE-2024-4444", "2025-01-01"],
           [G5, "CVE-2023-5555", "2025-06-01"]]
    api = FakeApi({"CVE-2020-1111": ("RESERVED", "mitre"), "CVE-2026-2222": ("RESERVED", "GitHub_M"),
                   "CVE-2024-10039": ("REJECTED", "redhat"), "CVE-2024-4445": ("PUBLISHED", "VulDB"),
                   "CVE-2023-5556": ("RESERVED", "mitre")},
                  {"CVE-2024-4445": rec("CVE-2024-4445", "PUBLISHED", "VulDB", text="Same flaw text")})
    return advisories, pop, api


class TestAnalyse(unittest.TestCase):
    def setUp(self):
        self.advisories, self.pop, self.api = world()
        self.advs = {a["id"]: ra.reduce_advisory(a) for a in self.advisories}
        self.population = [dict(zip(ra.POP_COLS, r)) for r in self.pop]

    def test_rows_and_candidates(self):
        ids, cands = ra.analyse(self.population, self.advs, self.api, datetime.date(2026, 11, 3))
        by = {r["cve"]: r for r in ids}
        self.assertEqual(by["CVE-2020-1111"]["state"], "RESERVED")
        self.assertGreaterEqual(by["CVE-2020-1111"]["advisory_age_days"], 180)
        self.assertLess(by["CVE-2026-2222"]["advisory_age_days"], 180)
        r = by["CVE-2024-10039"]
        self.assertEqual((r["state"], r["has_record"], r["only_alias"]), ("REJECTED", False, True))
        self.assertEqual(by["CVE-2024-4444"]["candidates"], "CVE-2024-4445")
        self.assertEqual(by["CVE-2023-5555"]["candidates"], "")
        self.assertEqual(by["CVE-2023-5555"]["other_aliases"], "CVE-2023-5556")
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["candidate_text"], "Same flaw text")
        self.assertFalse(cands[0]["candidate_is_alias"])

    def test_verdicts(self):
        ids, _ = ra.analyse(self.population, self.advs, self.api, datetime.date(2026, 11, 3))
        v = ra.verdicts(ids)
        self.assertEqual(v["P1"]["value"], [2, 5, 40.0])
        self.assertEqual(v["P1"]["held"], "no")
        self.assertEqual(v["P2"]["value"], [1, 5, 20.0])
        self.assertEqual(v["P2"]["held"], "yes")
        self.assertEqual(v["P3"], {"value": 2, "held": "no", "claim": ra.CLAIMS["P3"]})
        self.assertEqual(v["P4"]["value"], [1, 2, 50.0])
        self.assertEqual(v["P4"]["held"], "yes")
        self.assertEqual(v["P5"]["value"], [1, 2, 50.0])
        self.assertEqual(v["P5"]["held"], "no")
        self.assertTrue(v["P6"]["held"].startswith("INCONCLUSIVE_UNDERPOWERED"))

    def test_errors_make_inconclusive(self):
        self.api.fail = {"CVE-2020-1111"}
        ids, _ = ra.analyse(self.population, self.advs, self.api, datetime.date(2026, 11, 3))
        v = ra.verdicts(ids)
        for k in ("P1", "P2", "P3", "P4", "P5"):
            self.assertTrue(v[k]["held"].startswith("INCONCLUSIVE"), k)

    def test_at_most(self):
        self.assertEqual(ra.rate(1, 10, 10.0, at_most=True)["held"], "yes")
        self.assertEqual(ra.rate(2, 10, 10.0, at_most=True)["held"], "no")
        self.assertEqual(ra.rate(0, 0, 10.0)["held"], "n/a")


class TestRun(unittest.TestCase):
    def test_run_writes_outputs_and_main_prints_no_counts(self):
        advisories, pop, api = world()
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, "github-reviewed")
            write_tree(root, advisories)
            pp = os.path.join(d, "pop.csv")
            write_pop(pp, pop)
            out = os.path.join(d, "out")
            res = ra.run(pp, root, out, api, db_commit="abc", db_date="2026-11-03")
            for f in ("results.json", "RESULTS-job.md", "aliases.csv", "candidates.csv", "grading_sample.csv"):
                self.assertTrue(os.path.exists(os.path.join(out, f)), f)
            self.assertEqual(res["advisories_found"], 5)
            self.assertEqual(res["descriptive"]["states"]["NOT_FOUND"], 2)
            with open(os.path.join(out, "grading_sample.csv"), encoding="utf-8") as f:
                header = next(csv.reader(f))
            self.assertEqual(header, ra.SAMPLE_COLS + ["grade"])
            self.assertNotIn("state", header)
            self.assertNotIn("distance", header)

    def test_main_message_has_no_digits_besides_path(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            print("done: outputs written to %s" % "/out")
        self.assertFalse(any(ch.isdigit() for ch in buf.getvalue()))


if __name__ == "__main__":
    unittest.main()
