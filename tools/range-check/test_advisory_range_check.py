# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. Made by AI agents working for MV2 of Munim, Inc.
"""Offline tests for advisory_range_check (no network)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import advisory_range_check as arc  # noqa: E402

RECURSOR = [("0.24.%d" % i, False) for i in range(5)] + [
    ("0.25.0-alpha.1", False), ("0.25.0-alpha.2", False), ("0.25.0-alpha.3", False),
    ("0.25.0-alpha.4", False), ("0.25.0-alpha.5", False), ("0.26.0-alpha.1", False),
    ("0.26.0-beta.1", False)]
PROTO = [("0.24.4", False), ("0.25.0-alpha.1", False), ("0.25.0-alpha.2", True),
         ("0.25.0", False), ("0.25.1", False), ("0.25.2", False), ("0.26.0-alpha.1", False),
         ("0.26.0", False), ("0.26.1", False), ("0.26.2-rc.1", False), ("0.26.2", False)]


def codes(found):
    return sorted(f["code"] for f in found)


class FakeNet(object):
    def __init__(self, osv=None, gh=None, releases=None, pkg=None):
        self._osv, self._gh, self._rel, self._pkg = osv or {}, gh or {}, releases or {}, pkg or {}

    def osv(self, vid):
        return self._osv.get(vid)

    def osv_package(self, name):
        return self._pkg.get(name, [])

    def github(self, ghsa, repo=None):
        return self._gh.get((ghsa, repo)) or self._gh.get((ghsa, None))

    def releases(self, name):
        return self._rel.get(name, [])


class Versions(unittest.TestCase):
    def test_order(self):
        vs = ["0.26.0", "0.26.0-alpha.1", "0.26.0-beta.1", "0.25.2", "0.26.0-alpha.10", "0.26.0-alpha.2"]
        self.assertEqual(sorted(vs, key=arc.semver_key),
                         ["0.25.2", "0.26.0-alpha.1", "0.26.0-alpha.2", "0.26.0-alpha.10",
                          "0.26.0-beta.1", "0.26.0"])

    def test_short_and_bad(self):
        self.assertEqual(arc.semver_key("1.0"), arc.semver_key("1.0.0"))
        self.assertIsNone(arc.semver_key("abc"))
        self.assertIsNone(arc.semver_key("1.2.3.4"))

    def test_versions_in_text(self):
        self.assertEqual(arc.versions_in_text(">= 0.24.5, 0.25.3"), ["0.24.5", "0.25.3"])
        self.assertEqual(arc.versions_in_text("v1.2.0-rc.1"), ["1.2.0-rc.1"])
        self.assertEqual(arc.versions_in_text(""), [])
        self.assertEqual(arc.versions_in_text(None), [])


class Parse(unittest.TestCase):
    def test_github_reviewed_style(self):
        (iv,) = arc.parse_range_text(">= 0.25.0, < 0.25.2")
        self.assertTrue(iv.contains("0.25.1"))
        self.assertFalse(iv.contains("0.25.2"))
        self.assertFalse(iv.contains("0.25.0-alpha.1"))

    def test_upper_only_and_exact(self):
        (iv,) = arc.parse_range_text("<= 1.4.0")
        self.assertTrue(iv.contains("0.1.0") and iv.contains("1.4.0"))
        (iv,) = arc.parse_range_text("= 2.0.1")
        self.assertTrue(iv.contains("2.0.1"))
        self.assertFalse(iv.contains("2.0.2"))

    def test_free_text_spans(self):
        (iv,) = arc.parse_range_text("0.26.0-beta.1 .. 0.26.1 ")
        self.assertTrue(iv.contains("0.26.0-beta.1") and iv.contains("0.26.1"))
        self.assertFalse(iv.contains("0.26.0-alpha.1"))
        (iv,) = arc.parse_range_text("1.0 - 1.4")
        self.assertTrue(iv.contains("1.2.0"))
        (iv,) = arc.parse_range_text("1.0.0-1")  # a pre-release, not a span
        self.assertTrue(iv.contains("1.0.0-1"))
        self.assertFalse(iv.contains("1.0.0"))

    def test_alternatives_and_garbage(self):
        self.assertEqual(len(arc.parse_range_text("< 0.3.0 || >= 0.4.0, < 0.4.2")), 2)
        self.assertIsNone(arc.parse_range_text("all versions before the fix"))
        self.assertIsNone(arc.parse_range_text(""))


class Checks(unittest.TestCase):
    def test_unpublished_bound_and_prerelease_gap(self):
        # hickory-recursor shape: "0.25.0 .. 0.26.0-alpha.1", but 0.25.0 was never published
        ivs = arc.parse_range_text("0.25.0 .. 0.26.0-alpha.1")
        found = arc.check_package("hickory-recursor", ivs, [], RECURSOR)
        self.assertIn("R1", codes(found))
        r2 = [f for f in found if f["code"] == "R2"][0]
        self.assertEqual(r2["versions"][0], "0.25.0-alpha.1")
        self.assertEqual(len(r2["versions"]), 5)

    def test_yanked_prerelease_not_a_gap(self):
        ivs = arc.parse_range_text(">= 0.25.0, < 0.25.2")
        r2 = [f for f in arc.check_package("hickory-proto", ivs, [], PROTO) if f["code"] == "R2"][0]
        self.assertEqual(r2["versions"], ["0.25.0-alpha.1"])  # alpha.2 is yanked

    def test_gap_covered_by_other_range_or_versions(self):
        ivs = arc.parse_range_text(">= 0.25.0-alpha.1, < 0.25.0-alpha.3 || >= 0.25.0, < 0.25.2")
        self.assertNotIn("R2", codes(arc.check_package("hickory-proto", ivs, [], PROTO)))
        ivs = arc.parse_range_text(">= 0.25.0, < 0.25.2")
        self.assertNotIn("R2", codes(arc.check_package("hickory-proto", ivs, ["0.25.0-alpha.1"], PROTO)))

    def test_fix_prereleases_and_clean(self):
        ivs = arc.parse_range_text(">= 0.26.0, < 0.26.2")
        found = arc.check_package("hickory-proto", ivs, [], PROTO)
        self.assertEqual(codes(found), ["R2", "R4"])  # 0.26.0-alpha.1 gap; 0.26.2-rc.1 counted affected
        ivs = arc.parse_range_text("< 0.24.4")
        self.assertEqual(codes(arc.check_package("hickory-proto", ivs, [], PROTO)), ["R5"])
        ivs = arc.parse_range_text(">= 0.24.4, < 0.25.0-alpha.1")
        self.assertEqual(codes(arc.check_package("hickory-proto", ivs, [], PROTO)), [])

    def test_synthetic_lowest_prerelease_bound(self):
        # '>= 0.25.0-0' is the usual way to include every 0.25.0 pre-release: no R1, no R2
        ivs = arc.parse_range_text(">= 0.25.0-0, < 0.25.2")
        self.assertEqual(codes(arc.check_package("hickory-proto", ivs, [], PROTO)), [])

    def test_fix_unpublished(self):
        ivs = arc.parse_range_text("< 0.27.0")
        self.assertIn("R3", codes(arc.check_package("hickory-proto", ivs, [], PROTO)))

    def test_rustsec_cross_check(self):
        rs = {"id": "RUSTSEC-2026-0001", "aliases": ["GHSA-aaaa-bbbb-cccc"],
              "affected": [{"package": {"ecosystem": "crates.io", "name": "hickory-proto"},
                            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.25.2"}]}]}]}
        ivs = arc.parse_range_text(">= 0.25.0, < 0.25.2")
        found = arc.check_package("hickory-proto", ivs, [], PROTO, {"GHSA-aaaa-bbbb-cccc"}, [rs])
        r2 = [f for f in found if f["code"] == "R2"][0]
        self.assertEqual(r2["rustsec_affected"], ["0.25.0-alpha.1"])
        self.assertNotIn("R7", codes(found))
        found = arc.check_package("hickory-proto", ivs, [], PROTO, {"GHSA-zzzz-zzzz-zzzz"}, [rs])
        self.assertIn("R7", codes(found))

    def test_unparsed(self):
        self.assertEqual(codes(arc.check_package("x", [], [], PROTO, unparsed=["before the fix"])), ["R6"])


class Sources(unittest.TestCase):
    def test_osv_record(self):
        rec = {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-1"],
               "affected": [{"package": {"ecosystem": "crates.io", "name": "hickory-proto"},
                             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0.25.0"}, {"fixed": "0.25.2"}]}]},
                            {"package": {"ecosystem": "PyPI", "name": "other"}, "ranges": []}]}
        net = FakeNet(osv={"GHSA-aaaa-bbbb-cccc": rec}, releases={"hickory-proto": PROTO})
        rep = arc.run("GHSA-aaaa-bbbb-cccc", net)
        self.assertEqual(rep["source"], "osv")
        self.assertEqual(list(rep["packages"]), ["hickory-proto"])
        p = rep["packages"]["hickory-proto"]
        self.assertEqual(p["affected_published"], 2)
        self.assertIn("R2", codes(p["findings"]))
        self.assertIn("R7", codes(p["findings"]))  # no RustSec record in the fake
        self.assertEqual(arc.exit_code(rep), 1)
        self.assertIn("R2 1 published pre-release", arc.render(rep))

    def test_repository_advisory(self):
        doc = {"ghsa_id": "GHSA-29q9-p769-j8gq", "state": "published", "cve_id": None,
               "vulnerabilities": [
                   {"ecosystem": "rust", "name": "hickory-recursor",
                    "vulnerable_version_range": "0.25.0 .. 0.26.0-alpha.1", "patched_versions": ""},
                   {"ecosystem": "rust", "name": "hickory-proto",
                    "vulnerable_version_range": ">= 0.26.0", "patched_versions": "0.26.2"}]}
        net = FakeNet(gh={("GHSA-29q9-p769-j8gq", "hickory-dns/hickory-dns"): doc},
                      releases={"hickory-recursor": RECURSOR, "hickory-proto": PROTO})
        rep = arc.run("GHSA-29q9-p769-j8gq", net, repo="hickory-dns/hickory-dns", rustsec=False)
        self.assertEqual(rep["source"], "github-repo")
        self.assertIn("R1", codes(rep["packages"]["hickory-recursor"]["findings"]))
        proto = rep["packages"]["hickory-proto"]
        self.assertEqual(proto["ranges"], [">= 0.26.0"])
        self.assertEqual(proto["affected_published"], 3)  # 0.26.0, 0.26.1, 0.26.2-rc.1; fix applied
        self.assertIn("R4", codes(proto["findings"]))

    def test_patched_versions_free_text(self):
        # repository advisories often type '>= X' or a list of fixed versions per branch
        doc = {"ghsa_id": "GHSA-y", "state": "published", "vulnerabilities": [
            {"package": {"ecosystem": "rust", "name": "a"}, "vulnerable_version_range": ">= 0.25.0",
             "patched_versions": ">= 0.24.5, 0.25.3"},
            {"package": {"ecosystem": "rust", "name": "b"}, "vulnerable_version_range": ">= 1.0.0",
             "patched_versions": "none yet"}]}
        refs, pk = arc.from_github(doc)
        (iv,) = pk["a"][0]
        self.assertEqual((iv.hi, iv.hi_incl, iv.hi_kind), ("0.25.3", False, "fixed"))
        (iv,) = pk["b"][0]
        self.assertIsNone(iv.hi)

    def test_global_advisory_object_fix(self):
        doc = {"ghsa_id": "GHSA-x", "cve_id": "CVE-2026-2",
               "vulnerabilities": [{"package": {"ecosystem": "rust", "name": "hickory-proto"},
                                    "vulnerable_version_range": "< 0.25.2",
                                    "first_patched_version": {"identifier": "0.25.2"}}]}
        refs, pk = arc.from_github(doc)
        self.assertEqual(refs, {"GHSA-x", "CVE-2026-2"})
        (iv,) = pk["hickory-proto"][0]
        self.assertEqual((iv.hi, iv.hi_kind), ("0.25.2", "fixed"))

    def test_cve_follows_alias(self):
        cve = {"id": "CVE-2026-3", "aliases": ["GHSA-aaaa-bbbb-cccc"], "affected": []}
        gh = {"id": "GHSA-aaaa-bbbb-cccc", "affected": [
            {"package": {"ecosystem": "crates.io", "name": "hickory-proto"},
             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.25.2"}]}]}]}
        net = FakeNet(osv={"CVE-2026-3": cve, "GHSA-aaaa-bbbb-cccc": gh}, releases={"hickory-proto": PROTO})
        rep = arc.run("CVE-2026-3", net, rustsec=False)
        self.assertEqual(rep["source"], "osv via GHSA-aaaa-bbbb-cccc")
        self.assertIn("CVE-2026-3", rep["refs"])

    def test_not_found(self):
        with self.assertRaises(SystemExit):
            arc.run("GHSA-none", FakeNet())


if __name__ == "__main__":
    unittest.main()
