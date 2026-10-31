"""Offline tests for osv_bridge.py (no network). Apache-2.0. Made with AI agents working for MV2 of Munim, Inc."""
import json
import os
import tempfile
import unittest
import urllib.error

import osv_bridge as ob

G1 = "GHSA-aaaa-bbbb-cccc"
G2 = "GHSA-dddd-eeee-ffff"
C1 = "CVE-2026-100001"
C2 = "CVE-2025-20002"


def http_404(url):
    return urllib.error.HTTPError(url, 404, "Not Found", None, None)


class FakeGet:
    """Serves bytes per URL; a value that is an exception is raised instead."""

    def __init__(self, table):
        self.table = table
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        v = self.table[url]
        if isinstance(v, list):
            v = v.pop(0)
        if isinstance(v, Exception):
            raise v
        return v


class TestFetch(unittest.TestCase):
    def test_fetch_csv_rows_and_sha(self):
        get = FakeGet({"u": b"reviewed,twin,cve\nGHSA-a,GHSA-b,CVE-2026-1\n"})
        rows, sha = ob.fetch_csv("u", get=get)
        self.assertEqual(rows, [{"reviewed": "GHSA-a", "twin": "GHSA-b", "cve": "CVE-2026-1"}])
        self.assertEqual(len(sha), 64)

    def test_fetch_csv_waits_on_404(self):
        get = FakeGet({"u": [http_404("u"), b"ghsa,cve\nGHSA-a,CVE-2026-1\n"]})
        rows, _ = ob.fetch_csv("u", wait_minutes=1, sleep=0, get=get)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(get.calls), 2)

    def test_fetch_csv_gives_up(self):
        get = FakeGet({"u": [http_404("u")]})
        with self.assertRaises(urllib.error.HTTPError):
            ob.fetch_csv("u", wait_minutes=0, sleep=0, get=get)

    def test_check_rows(self):
        rows = [{"ghsa": "x", "cve": "y"}]
        ob.check_rows(rows, 1, ("ghsa", "cve"))
        with self.assertRaises(ValueError):
            ob.check_rows(rows, 2, ("ghsa", "cve"))
        with self.assertRaises(ValueError):
            ob.check_rows(rows, 1, ("reviewed",))

    def test_osv_get_ok_404_error_and_cache(self):
        get = FakeGet({
            ob.OSV_URL + G1: json.dumps({"id": G1}).encode(),
            ob.OSV_URL + C1: http_404(C1),
            ob.OSV_URL + C2: [OSError("boom"), OSError("boom")],
        })
        cache = {}
        self.assertEqual(ob.osv_get(G1, get=get, cache=cache, pause=0, delay=0), {"id": G1})
        self.assertIsNone(ob.osv_get(C1, get=get, cache=cache, pause=0, delay=0))
        self.assertEqual(ob.osv_get(C2, get=get, cache=cache, tries=2, pause=0, delay=0), ob.ERROR)
        n = len(get.calls)
        ob.osv_get(G1, get=get, cache=cache, pause=0, delay=0)
        self.assertEqual(len(get.calls), n)

    def test_osv_get_retries_then_succeeds(self):
        get = FakeGet({ob.OSV_URL + G1: [OSError("x"), json.dumps({"id": G1}).encode()]})
        self.assertEqual(ob.osv_get(G1, get=get, pause=0, delay=0), {"id": G1})


class TestChecks(unittest.TestCase):
    def test_links(self):
        self.assertTrue(ob.links({"id": G1}, G1))
        self.assertTrue(ob.links({"id": C1, "aliases": [G1]}, G1))
        self.assertTrue(ob.links({"id": C1, "related": [G1]}, G1))
        self.assertTrue(ob.links({"id": C1, "upstream": [G1]}, G1))
        self.assertFalse(ob.links({"id": C1, "related": [G1]}, G1, ("aliases",)))
        self.assertFalse(ob.links(None, G1))
        self.assertFalse(ob.links(ob.ERROR, G1))

    def test_has_package(self):
        self.assertTrue(ob.has_package({"affected": [{"package": {"ecosystem": "PyPI", "name": "x"}}]}))
        self.assertFalse(ob.has_package({"affected": [{"ranges": [{"type": "GIT"}]}]}))
        self.assertFalse(ob.has_package({"affected": [{"package": {"name": "x"}}]}))
        self.assertFalse(ob.has_package(None))

    def test_check_pairs(self):
        recs = {G1: {"id": G1, "aliases": [C1]}, C1: {"id": C1, "aliases": [G1],
                "affected": [{"package": {"ecosystem": "npm", "name": "p"}}]},
                G2: {"id": G2}, C2: None}
        rows = ob.check_pairs([(G1, C1), (G2, C2)], recs.get, "s3", ("aliases",))
        self.assertTrue(rows[0]["ghsa_lists_cve"] and rows[0]["cve_links_ghsa"] and rows[0]["cve_has_package"])
        self.assertFalse(rows[1]["ghsa_lists_cve"] or rows[1]["cve_links_ghsa"])
        self.assertEqual(rows[1]["cve_status"], "missing")


def row(side, a, b, gs="ok", cs="ok"):
    return {"side": side, "ghsa": G1, "cve": C1, "ghsa_status": gs, "cve_status": cs,
            "ghsa_lists_cve": a, "cve_links_ghsa": b, "cve_has_package": False}


class TestVerdicts(unittest.TestCase):
    def test_hold(self):
        rows = [row("s3", True, True)] * 19 + [row("s3", False, False)] + \
               [row("s2", False, False)] * 9 + [row("s2", True, True)]
        v = ob.verdicts(rows)
        self.assertEqual(v["Q1"]["held"], "yes")
        self.assertEqual(v["Q1"]["value"], [19, 20, 95.0])
        self.assertEqual(v["Q2"]["held"], "yes")
        self.assertEqual(v["Q3"]["held"], "yes")
        self.assertEqual(v["Q4"]["held"], "yes")

    def test_fail(self):
        rows = [row("s3", True, False)] * 5 + [row("s3", False, False)] * 5 + \
               [row("s2", True, True)] * 5
        v = ob.verdicts(rows)
        self.assertEqual(v["Q1"]["held"], "no")
        self.assertEqual(v["Q2"]["held"], "no")
        self.assertEqual(v["Q3"]["held"], "no")
        self.assertEqual(v["Q4"]["held"], "no")

    def test_errors_inconclusive(self):
        rows = [row("s3", True, True)] * 18 + [row("s3", False, False, cs="error")] * 2 + \
               [row("s2", False, False)] * 10
        v = ob.verdicts(rows)
        self.assertEqual(v["Q1"]["held"], "INCONCLUSIVE_ERRORS")
        self.assertEqual(v["Q1"]["errors"], 2)
        self.assertEqual(v["Q3"]["held"], "yes")

    def test_empty_side_inconclusive(self):
        v = ob.verdicts([row("s3", True, True)])
        self.assertEqual(v["Q3"]["held"], "INCONCLUSIVE_ERRORS")

    def test_descriptive_and_outputs(self):
        rows = [row("s3", True, False), row("s3", False, False, cs="missing"), row("s2", False, True)]
        d = ob.descriptive(rows)
        self.assertEqual(d["s3"]["either_direction"], 1)
        self.assertEqual(d["s3"]["neither_direction"], 1)
        self.assertEqual(d["s3"]["cve_missing_on_osv"], 1)
        self.assertEqual(d["s2"]["either_direction"], 1)
        meta = {"s3_sha256": "a", "s2_sha256": "b", "started": "s", "finished": "f"}
        with tempfile.TemporaryDirectory() as t:
            ob.write_outputs(t, rows, ob.verdicts(rows), d, meta)
            self.assertEqual(sorted(os.listdir(t)), ["RESULTS.md", "results.json", "rows.csv"])
            with open(os.path.join(t, "rows.csv"), encoding="utf-8") as f:
                self.assertEqual(len(f.read().strip().splitlines()), 4)


if __name__ == "__main__":
    unittest.main()
