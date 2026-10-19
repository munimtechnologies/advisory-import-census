"""Offline unit tests for the frozen E1 analysis (ecosystem_adjusted_analysis.py).

These verify the derived-variable rule, the Mantel-Haenszel statistic, the
within-stratum permutation test, the power floor, and the P2 composition test on
small synthetic inputs -- no network, no A4 data. Run before A4's census exists so
the frozen code is known-correct when the real census arrives.

Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import csv
import json
import os
import tempfile
import unittest

import ecosystem_adjusted_analysis as e1


def row(repo, group, stratum, visible, pt="package", included=True):
    return {
        "repo": repo, "group": group, "visible": visible,
        "ecosystem_stratum": stratum, "included": included,
        "advisory_product_type": pt, "advisory_ecosystems": "",
        "named_packages": "", "named_pkg_resolution": "", "real_package": "",
        "ghsa_id": "", "cve_id": "",
        "scanner_class": "scanner_visible" if visible else "scanner_blind",
        "stratum_source": "test",
    }


class TestDerivedVariables(unittest.TestCase):
    def test_canon_eco(self):
        self.assertEqual(e1.canon_eco("npm"), "npm")
        self.assertEqual(e1.canon_eco("pip"), "PyPI")
        self.assertEqual(e1.canon_eco("PyPI"), "PyPI")
        self.assertEqual(e1.canon_eco("composer"), "Packagist")
        self.assertEqual(e1.canon_eco("rust"), "crates.io")
        self.assertEqual(e1.canon_eco("go"), "Go")
        self.assertEqual(e1.canon_eco("rubygems"), "RubyGems")
        self.assertEqual(e1.canon_eco("maven"), "Maven")
        self.assertEqual(e1.canon_eco("somethingnew"), "other")

    def test_parse_named_packages_page_order(self):
        self.assertEqual(
            e1.parse_named_packages("npm:foo;pypi:bar"),
            [("npm", "foo"), ("pypi", "bar")])
        self.assertEqual(e1.parse_named_packages(""), [])
        # scoped npm name keeps its slash; split on the FIRST colon only.
        self.assertEqual(e1.parse_named_packages("npm:@scope/pkg"),
                         [("npm", "@scope/pkg")])

    def test_derive_stratum_software_is_none_bucket(self):
        s, src = e1.derive_stratum({"advisory_product_type": "software"})
        self.assertEqual(s, "none")
        self.assertEqual(src, "software")

    def test_derive_stratum_package_uses_first_named(self):
        s, src = e1.derive_stratum({
            "advisory_product_type": "package",
            "named_packages": "pypi:foo;npm:bar",
            "advisory_ecosystems": "npm;pip"})
        self.assertEqual(s, "PyPI")           # first named coordinate wins
        self.assertEqual(src, "named_package_first")

    def test_derive_stratum_package_fallback_to_ecosystem(self):
        s, src = e1.derive_stratum({
            "advisory_product_type": "package",
            "named_packages": "",
            "advisory_ecosystems": "go;pip"})   # sorted -> 'go' first
        self.assertEqual(s, "Go")
        self.assertEqual(src, "ecosystem_fallback")

    def test_derive_stratum_other_is_excluded(self):
        s, src = e1.derive_stratum({"advisory_product_type": "other"})
        self.assertIsNone(s)
        self.assertEqual(src, "excluded_other")


class TestMantelHaenszel(unittest.TestCase):
    def test_single_stratum_is_the_raw_difference(self):
        self.assertAlmostEqual(e1._mh_rd([(10, 8, 10, 2)]), 0.6)

    def test_two_strata_weighted(self):
        # (5*0.6 + 2*(-0.5)) / 7 = 2/7
        self.assertAlmostEqual(e1._mh_rd([(10, 8, 10, 2), (4, 1, 4, 3)]), 2.0 / 7.0)

    def test_empty_group_contributes_nothing(self):
        self.assertAlmostEqual(e1._mh_rd([(0, 0, 5, 1), (6, 6, 6, 0)]), 1.0)


class TestUsabilityAndPowerFloor(unittest.TestCase):
    def test_stratum_needs_two_repos_each_group(self):
        rows = []
        # npm: 2 reg + 1 no_registry repo -> NOT usable (no_registry < 2).
        rows += [row("r/a", "registry", "npm", True),
                 row("r/b", "registry", "npm", True),
                 row("n/a", "no_registry", "npm", False)]
        table = e1.build_stratum_table(rows)
        self.assertEqual(e1.usable_strata(table), [])

    def test_two_usable_strata_still_underpowered(self):
        # Two usable strata (each 2+2) -> below the 3-usable-strata floor.
        rows = []
        for st in ("npm", "PyPI"):
            rows += [row("reg/%s1" % st, "registry", st, True),
                     row("reg/%s2" % st, "registry", st, True),
                     row("nor/%s1" % st, "no_registry", st, False),
                     row("nor/%s2" % st, "no_registry", st, False)]
        p1 = e1.compute_p1(rows, n_perm=500)
        self.assertEqual(p1["verdict"], "INCONCLUSIVE_UNDERPOWERED")
        self.assertTrue(p1["power_floor"]["underpowered"])
        self.assertIsNone(p1["permutation_p_two_sided"])


class TestP1Permutation(unittest.TestCase):
    def _separated(self):
        rows = []
        for st in ("npm", "PyPI", "Go"):
            # 2 registry repos fully visible, 2 no_registry repos fully blind.
            rows += [row("reg/%s1" % st, "registry", st, True),
                     row("reg/%s2" % st, "registry", st, True),
                     row("nor/%s1" % st, "no_registry", st, False),
                     row("nor/%s2" % st, "no_registry", st, False)]
        return rows

    def test_full_separation_survives(self):
        p1 = e1.compute_p1(self._separated(), n_perm=3000)
        self.assertEqual(p1["usable_strata_count"], 3)
        self.assertEqual(p1["distinct_repos_in_usable_count"], 12)
        self.assertEqual(p1["adjusted_difference_pts"], 100.0)
        self.assertLess(p1["permutation_p_two_sided"], 0.05)
        self.assertEqual(p1["verdict"], "SURVIVES")

    def test_permutation_is_deterministic(self):
        a = e1.compute_p1(self._separated(), n_perm=800)
        b = e1.compute_p1(self._separated(), n_perm=800)
        self.assertEqual(a["permutation_p_two_sided"],
                         b["permutation_p_two_sided"])
        self.assertEqual(a["permutation_p_one_sided"],
                         b["permutation_p_one_sided"])

    def test_no_association_does_not_survive(self):
        # Every repo visible regardless of group -> adjusted diff 0, large p.
        rows = []
        for st in ("npm", "PyPI", "Go"):
            rows += [row("reg/%s1" % st, "registry", st, True),
                     row("reg/%s2" % st, "registry", st, True),
                     row("nor/%s1" % st, "no_registry", st, True),
                     row("nor/%s2" % st, "no_registry", st, True)]
        p1 = e1.compute_p1(rows, n_perm=800)
        self.assertEqual(p1["adjusted_difference_pts"], 0.0)
        self.assertEqual(p1["verdict"], "DOES_NOT_SURVIVE")


class TestP2Composition(unittest.TestCase):
    def test_strong_composition_difference(self):
        rows = []
        # 4 registry apps: all advisories in npm (well-indexed) -> share 1.0
        for i in range(4):
            rows += [row("reg/%d" % i, "registry", "npm", True),
                     row("reg/%d" % i, "registry", "npm", False)]
        # 4 no_registry apps: all advisories software-typed 'none' -> share 0.0
        for i in range(4):
            rows += [row("nor/%d" % i, "no_registry", "none", False, pt="software"),
                     row("nor/%d" % i, "no_registry", "none", True, pt="software")]
        p2 = e1.compute_p2(rows, n_perm=4000)
        self.assertEqual(p2["n_registry_apps"], 4)
        self.assertEqual(p2["n_no_registry_apps"], 4)
        self.assertEqual(p2["mean_well_indexed_share_registry"], 1.0)
        self.assertEqual(p2["mean_well_indexed_share_no_registry"], 0.0)
        self.assertEqual(p2["share_difference"], 1.0)
        self.assertLess(p2["permutation_p_two_sided"], 0.05)


class TestP3Coverage(unittest.TestCase):
    def test_visible_rate_by_stratum(self):
        rows = [row("a/a", "registry", "npm", True),
                row("a/a", "registry", "npm", False),
                row("b/b", "no_registry", "none", False)]
        p3 = e1.compute_p3(rows)
        self.assertEqual(p3["npm"], {"n": 2, "visible": 1, "visible_pct": 50.0,
                                     "ci95": e1.wilson(1, 2)})
        self.assertEqual(p3["none"]["visible_pct"], 0.0)


class TestEndToEndFromCsv(unittest.TestCase):
    def test_load_run_and_write(self):
        cols = ["group", "repo", "ghsa_id", "cve_id", "severity", "published_at",
                "age_days", "period", "own_id_in_osv", "osv_packages",
                "scanner_class", "advisory_product_type", "advisory_ecosystems",
                "named_packages", "named_pkg_resolution", "real_package", "url"]
        census = []

        def add(repo, pt, eco, named, visible):
            census.append({
                "group": "application", "repo": repo, "ghsa_id": "GHSA-x",
                "cve_id": "", "severity": "high", "published_at": "2026-01-01T00:00:00Z",
                "age_days": "99", "period": "before_2026_05", "own_id_in_osv": "True",
                "osv_packages": "", "scanner_class":
                "scanner_visible" if visible else "scanner_blind",
                "advisory_product_type": pt, "advisory_ecosystems": eco,
                "named_packages": named, "named_pkg_resolution": "", "real_package": "",
                "url": "http://x"})

        # Two in-frame apps + one off-frame library that must be skipped.
        add("open-webui/open-webui", "package", "pip", "pypi:open-webui", True)
        add("coollabsio/coolify", "software", "", "", False)
        add("some/library", "package", "npm", "npm:thing", True)   # off-frame
        classification = {"classification": {
            "open-webui/open-webui": {"group": "registry"},
            "coollabsio/coolify": {"group": "no_registry"}}}

        d = tempfile.mkdtemp()
        cpath = os.path.join(d, "real_package_census.csv")
        jpath = os.path.join(d, "registry_classification.json")
        with open(cpath, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(census)
        with open(jpath, "w", encoding="utf-8") as f:
            json.dump(classification, f)

        cls = e1.load_classification(jpath)
        rows, skipped = e1.load_rows(cpath, cls)
        self.assertEqual(skipped, 1)                      # the library
        self.assertEqual(len(rows), 2)
        strata = {r["repo"]: r["ecosystem_stratum"] for r in rows}
        self.assertEqual(strata["open-webui/open-webui"], "PyPI")
        self.assertEqual(strata["coollabsio/coolify"], "none")

        out = os.path.join(d, "out")
        os.makedirs(out)
        rc = e1.main(["--census-csv", cpath, "--classification", jpath,
                      "--out-dir", out, "--n-perm", "50"])
        self.assertEqual(rc, 0)
        with open(os.path.join(out, "ecosystem_adjusted_summary.json")) as f:
            summary = json.load(f)
        # Thin frame -> P1 must be inconclusive, but P2/P3 still populate.
        self.assertEqual(summary["P1_adjusted"]["verdict"],
                         "INCONCLUSIVE_UNDERPOWERED")
        self.assertIn("none", summary["P3_osv_coverage_by_ecosystem"])
        self.assertTrue(os.path.exists(os.path.join(out, "ecosystem_census.csv")))
        self.assertTrue(os.path.exists(
            os.path.join(out, "ecosystem_adjusted_meta.json")))


if __name__ == "__main__":
    unittest.main()
