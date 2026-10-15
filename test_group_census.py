"""Offline tests for group_census.py (no network). Apache-2.0."""
import io
import json
import os
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from datetime import datetime, timezone

import group_census as gc


class FakeResp:
    def __init__(self, obj, status=200, headers=None):
        self.raw = json.dumps(obj).encode("utf-8")
        self.status = status
        self.headers = headers or {}

    def read(self):
        return self.raw

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(code, headers=None):
    return urllib.error.HTTPError("https://x", code, "err", headers or {}, None)


def adv(ghsa, cve=None, pkgs=(), published="2026-01-01T00:00:00Z", severity="high"):
    return {"ghsa_id": ghsa, "cve_id": cve, "severity": severity, "published_at": published,
            "html_url": "https://github.com/o/r/security/advisories/" + ghsa,
            "vulnerabilities": [{"package": {"ecosystem": e, "name": n}} for e, n in pkgs]}


class HelperTests(unittest.TestCase):
    def test_rate_limit_wait(self):
        self.assertEqual(gc.rate_limit_wait({"X-RateLimit-Remaining": "0",
                                             "X-RateLimit-Reset": "1100"}, 1000), 103)
        self.assertEqual(gc.rate_limit_wait({"Retry-After": "7"}, 0), 7)
        self.assertIsNone(gc.rate_limit_wait({"X-RateLimit-Remaining": "12"}, 0))
        self.assertIsNone(gc.rate_limit_wait(None, 0))

    def test_next_link(self):
        link = ('<https://api.github.com/x?page=2>; rel="next", '
                '<https://api.github.com/x?page=5>; rel="last"')
        self.assertEqual(gc.next_link(link), "https://api.github.com/x?page=2")
        self.assertIsNone(gc.next_link('<https://api.github.com/x?page=1>; rel="prev"'))
        self.assertIsNone(gc.next_link(""))

    def test_period_and_age(self):
        self.assertEqual(gc.period("2026-04-30T23:59:59Z"), "before_2026_05")
        self.assertEqual(gc.period("2026-05-01T00:00:00Z"), "from_2026_05")
        self.assertEqual(gc.period(""), "")
        snap = datetime(2026, 1, 11, tzinfo=timezone.utc)
        row = gc.build_row("ai", "o/r", adv("GHSA-a"), None, "no_package", [], snap)
        self.assertEqual(row["age_days"], 10.0)
        self.assertFalse(row["own_id_in_osv"])

    def test_wilson(self):
        lo, hi = gc.wilson(5, 10)
        self.assertAlmostEqual(lo, 0.2366, places=3)
        self.assertAlmostEqual(hi, 0.7634, places=3)
        self.assertEqual(gc.wilson(0, 0), [None, None])
        self.assertEqual(gc.wilson(0, 20)[0], 0.0)

    def test_median(self):
        self.assertEqual(gc.median([3, 1, 2]), 2)
        self.assertEqual(gc.median([1, 2, 3, 4]), 2.5)
        self.assertIsNone(gc.median([]))


class ClassifyTests(unittest.TestCase):
    def test_no_package(self):
        a = adv("GHSA-a", pkgs=[("other", "app")])
        self.assertEqual(gc.classify(a, None, lambda e, n: set())[0], "no_package")
        self.assertEqual(gc.classify(adv("GHSA-b"), None, lambda e, n: set())[0], "no_package")

    def test_visible_from_own_record_with_normalized_name(self):
        a = adv("GHSA-a", pkgs=[("pip", "Foo_Bar")])
        record = {"id": "GHSA-a", "affected": [{"package": {"ecosystem": "PyPI", "name": "foo-bar"}}]}
        called = []
        cls, pkgs = gc.classify(a, record, lambda e, n: called.append(n) or set())
        self.assertEqual(cls, "scanner_visible")
        self.assertEqual(pkgs, [("pip", "Foo_Bar")])
        self.assertEqual(called, [])

    def test_own_record_for_other_package_is_not_enough(self):
        a = adv("GHSA-a", pkgs=[("npm", "flowise")])
        record = {"id": "GHSA-a", "affected": [{"package": {"ecosystem": "npm", "name": "other"}}]}
        self.assertEqual(gc.classify(a, record, lambda e, n: set())[0], "package_not_in_osv")

    def test_visible_through_cve_alias(self):
        a = adv("GHSA-a", cve="CVE-2026-1", pkgs=[("npm", "flowise")])
        self.assertEqual(gc.classify(a, None, lambda e, n: {"GHSA-zzz", "CVE-2026-1"})[0],
                         "scanner_visible")

    def test_package_not_in_osv(self):
        a = adv("GHSA-a", cve="CVE-2026-1", pkgs=[("npm", "flowise"), ("npm", "flowise-components")])
        self.assertEqual(gc.classify(a, None, lambda e, n: {"GHSA-other"})[0], "package_not_in_osv")

    def test_ids_are_case_sensitive(self):
        a = adv("GHSA-abcd-efgh-ijkl", pkgs=[("pip", "x")])
        self.assertEqual(gc.classify(a, None, lambda e, n: {"GHSA-ABCD-EFGH-IJKL"})[0],
                         "package_not_in_osv")


def rows_for(group, repo, n_blind, n_visible, published="2026-01-01T00:00:00Z"):
    snap = datetime(2026, 10, 15, tzinfo=timezone.utc)
    out = []
    for i in range(n_blind):
        out.append(gc.build_row(group, repo, adv("GHSA-%s-b%d" % (repo, i), published=published),
                                None, "no_package", [], snap))
    for i in range(n_visible):
        out.append(gc.build_row(group, repo, adv("GHSA-%s-v%d" % (repo, i), published=published),
                                {"id": "x"}, "scanner_visible", [("pip", "x")], snap))
    return out


class SummaryTests(unittest.TestCase):
    def test_eligible_drops_recent_and_errors(self):
        rows = rows_for("ai", "o/a", 1, 1)
        rows += rows_for("ai", "o/b", 1, 0, published="2026-10-10T00:00:00Z")
        rows[0]["scanner_class"] = "error"
        self.assertEqual(len(gc.eligible(rows)), 1)

    def test_group_summary(self):
        rows = rows_for("ai", "o/a", 3, 1) + rows_for("ai", "o/b", 0, 2) + rows_for("ai", "o/c", 2, 0)
        s = gc.group_summary(rows)
        self.assertEqual(s["eligible"], 8)
        self.assertEqual(s["scanner_blind"]["k"], 5)
        self.assertEqual(s["scanner_blind"]["pct"], 62.5)
        self.assertEqual(s["own_id_not_in_osv"]["k"], 5)
        self.assertEqual(s["repos_all_blind"], ["o/c"])
        self.assertEqual(s["repos_none_blind"], ["o/b"])
        self.assertEqual(s["repo_median_blind_pct"], 75.0)
        self.assertEqual(s["by_period"]["before_2026_05"]["scanner_blind"]["n"], 8)
        self.assertEqual(s["by_period"]["from_2026_05"]["scanner_blind"]["n"], 0)

    def test_permutation_no_difference(self):
        rows = []
        for i in range(4):
            rows += rows_for("ai", "a/%d" % i, 1, 1) + rows_for("control", "c/%d" % i, 1, 1)
        t = gc.permutation_test(rows, gc.is_blind, n_perm=500)
        self.assertEqual(t["difference_pct_points"], 0.0)
        self.assertEqual(t["p_two_sided"], 1.0)
        self.assertEqual(t["repositories"], 8)

    def test_permutation_full_separation(self):
        rows = []
        for i in range(4):
            rows += rows_for("ai", "a/%d" % i, 3, 0) + rows_for("control", "c/%d" % i, 0, 3)
        t = gc.permutation_test(rows, gc.is_blind, n_perm=4000)
        self.assertEqual(t["difference_pct_points"], 100.0)
        # 2 of the C(8,4) = 70 labelings are as extreme: p is about 0.029.
        self.assertLess(t["p_two_sided"], 0.06)
        again = gc.permutation_test(rows, gc.is_blind, n_perm=4000)
        self.assertEqual(t, again)

    def test_permutation_needs_both_groups(self):
        self.assertIsNone(gc.permutation_test(rows_for("ai", "a/1", 1, 1), gc.is_blind, n_perm=10))
        self.assertIsNone(gc.permutation_test([], gc.is_blind, n_perm=10))


class NetTests(unittest.TestCase):
    def make(self, responses):
        sleeps = []
        it = iter(responses)

        def opener(req, timeout=None):
            r = next(it)
            if isinstance(r, Exception):
                raise r
            return r
        return gc.Net(pace=0, sleep=sleeps.append, opener=opener), sleeps

    def test_ok_and_404(self):
        net, _ = self.make([FakeResp({"id": "GHSA-a"}), http_error(404)])
        self.assertEqual(net.request("https://api.osv.dev/v1/vulns/GHSA-a")[:2],
                         (200, {"id": "GHSA-a"}))
        self.assertEqual(net.request("https://api.osv.dev/v1/vulns/GHSA-b")[:2], (404, None))
        self.assertEqual(net.counts["osv"], 2)

    def test_rate_limit_then_ok(self):
        import time as _t
        reset = str(int(_t.time()) + 30)
        net, sleeps = self.make([
            http_error(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset}),
            FakeResp([])])
        status, obj, _ = net.request("https://api.github.com/repos/o/r/security-advisories")
        self.assertEqual((status, obj), (200, []))
        self.assertTrue(any(s >= 30 for s in sleeps))
        self.assertEqual(net.counts["github"], 2)

    def test_plain_403_raises(self):
        net, _ = self.make([http_error(403)])
        with self.assertRaises(RuntimeError):
            net.request("https://api.github.com/x")

    def test_server_errors_retry_then_raise(self):
        net, _ = self.make([http_error(502)] * 6)
        with self.assertRaises(RuntimeError):
            net.request("https://api.osv.dev/v1/query", data={})

    def test_list_advisories_paginates(self):
        page1 = FakeResp([{"ghsa_id": "GHSA-1"}],
                         headers={"Link": '<https://api.github.com/p2>; rel="next"'})
        page2 = FakeResp([{"ghsa_id": "GHSA-2"}])
        net, _ = self.make([page1, page2])
        advs, status = gc.list_advisories(net, "o/r")
        self.assertEqual(status, "ok")
        self.assertEqual([a["ghsa_id"] for a in advs], ["GHSA-1", "GHSA-2"])

    def test_osv_package_ids_paginates(self):
        p1 = FakeResp({"vulns": [{"id": "GHSA-1", "aliases": ["CVE-1"]}], "next_page_token": "t"})
        p2 = FakeResp({"vulns": [{"id": "PYSEC-2"}]})
        net, _ = self.make([p1, p2])
        self.assertEqual(gc.osv_package_ids(net, "pip", "x"), {"GHSA-1", "CVE-1", "PYSEC-2"})


class FakeNet:
    """Routes URLs to canned answers for an end-to-end run of main()."""
    instances = []

    def __init__(self, pace=0, **kw):
        self.counts = {"github": 0, "osv": 0}
        FakeNet.instances.append(self)

    def request(self, url, data=None, accept=None):
        if url.endswith("/repos/a/one/security-advisories?state=published&per_page=100"):
            return 200, [adv("GHSA-aaaa-0001", pkgs=[("pip", "one")]),
                         adv("GHSA-aaaa-0002")], {}
        if url.endswith("/repos/c/two/security-advisories?state=published&per_page=100"):
            return 200, [adv("GHSA-cccc-0001", cve="CVE-2026-9", pkgs=[("npm", "two")])], {}
        if "/repos/" in url:
            return 404, None, {}
        if url.endswith("/v1/vulns/" + gc.CANARY[0]):
            return 200, {"id": gc.CANARY[0]}, {}
        if url.endswith("/v1/vulns/GHSA-aaaa-0001"):
            return 200, {"id": "GHSA-aaaa-0001",
                         "affected": [{"package": {"ecosystem": "PyPI", "name": "one"}}]}, {}
        if "/v1/vulns/" in url:
            return 404, None, {}
        if url.endswith("/v1/query"):
            name = data["package"]["name"]
            if name == gc.CANARY[2]:
                return 200, {"vulns": [{"id": gc.CANARY[0]}]}, {}
            if name == "two":
                return 200, {"vulns": [{"id": "GHSA-zzzz", "aliases": ["CVE-2026-9"]}]}, {}
            return 200, {}, {}
        raise AssertionError(url)


class MainTests(unittest.TestCase):
    def test_end_to_end(self):
        saved = gc.Net, gc.GROUPS
        gc.Net, gc.GROUPS = FakeNet, (("ai", ["a/one", "a/gone"]), ("control", ["c/two"]))
        try:
            with tempfile.TemporaryDirectory() as d, redirect_stdout(io.StringIO()):
                self.assertEqual(gc.main(["--out-dir", d, "--permutations", "50"]), 0)
                with open(os.path.join(d, "summary_groups.json"), encoding="utf-8") as fh:
                    s = json.load(fh)
                with open(os.path.join(d, "group_census.csv"), encoding="utf-8") as fh:
                    lines = fh.read().splitlines()
        finally:
            gc.Net, gc.GROUPS = saved
        self.assertTrue(s["package_query"])
        self.assertEqual(s["rows"], 3)
        self.assertEqual(len(lines), 4)
        self.assertEqual(s["repos"]["a/gone"]["status"], "not_found")
        ai, control = s["groups"]["ai"], s["groups"]["control"]
        self.assertEqual(ai["classes"], {"scanner_visible": 1, "package_not_in_osv": 0,
                                         "no_package": 1})
        self.assertEqual(control["classes"]["scanner_visible"], 1)
        self.assertEqual(control["own_id_not_in_osv"]["k"], 1)
        self.assertEqual(s["comparison"]["scanner_blind"]["difference_pct_points"], 50.0)

    def test_self_check_failure_stops(self):
        class DeadOSV(FakeNet):
            def request(self, url, data=None, accept=None):
                return 404, None, {}
        saved = gc.Net
        gc.Net = DeadOSV
        try:
            with tempfile.TemporaryDirectory() as d, redirect_stdout(io.StringIO()):
                self.assertEqual(gc.main(["--out-dir", d]), 2)
                self.assertFalse(os.path.exists(os.path.join(d, "summary_groups.json")))
        finally:
            gc.Net = saved


if __name__ == "__main__":
    unittest.main()
