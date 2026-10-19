"""Deterministic unit tests for the registry-channel A3 attribution study.

Covers the new attribution parser (attribution_census.advisory_product) against
markup copied from real archived GitHub advisory pages, and the analysis
statistics (P1 within-repo permutation, P2 repo-level permutation, P3 mediation)
on toy data with hand-computed answers. No network. Run with:
    python -m unittest -v test_attribution
Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import unittest

from attribution_census import advisory_product
import attribution_analysis as A


# Markup fragments copied from real archived advisory pages (A1 raw/).
PACKAGE_HTML = (
    '<h2 class="text-small color-fg-muted mb-1">Package</h2>'
    '<span class="f4 color-fg-default text-bold">nocodb</span>'
    '(<a href="/advisories?query=ecosystem%3Anpm" class="Link Link--muted">npm</a>)'
)
SOFTWARE_HTML = (
    '<h2 class="text-small color-fg-muted mb-1">Software</h2>'
    '<span class="f4 color-fg-default text-bold">Discourse</span>'
)
MULTI_HTML = (
    '<h2 class="text-small color-fg-muted mb-1">Package</h2>'
    '<a href="/advisories?query=ecosystem%3Anpm">npm</a>'
    '<a href="/advisories?query=ecosystem%3APyPI">pip</a>'
)
OTHER_HTML = '<div>no affected products box at all</div>'


class TestParser(unittest.TestCase):
    def test_package(self):
        pt, ecos = advisory_product(PACKAGE_HTML)
        self.assertEqual(pt, "package")
        self.assertEqual(ecos, ["npm"])

    def test_software(self):
        pt, ecos = advisory_product(SOFTWARE_HTML)
        self.assertEqual(pt, "software")
        self.assertEqual(ecos, [])

    def test_other(self):
        pt, ecos = advisory_product(OTHER_HTML)
        self.assertEqual(pt, "other")
        self.assertEqual(ecos, [])

    def test_multi_ecosystem_lowercased(self):
        pt, ecos = advisory_product(MULTI_HTML)
        self.assertEqual(pt, "package")
        self.assertEqual(ecos, ["npm", "pypi"])

    def test_empty(self):
        self.assertEqual(advisory_product(""), ("other", []))


def _row(repo, group, product, visible, own=True):
    return {"repo": repo, "group": group, "advisory_product_type": product,
            "scanner_class": "scanner_visible" if visible else "scanner_blind",
            "own_id_in_osv": "True" if own else "False", "advisory_ecosystems": ""}


class TestP1WithinRepo(unittest.TestCase):
    def test_perfect_separation_three_repos(self):
        # 3 repos, each: 2 package (visible), 2 software (blind) -> diff +100 pts.
        rows = []
        for repo in ("a/a", "b/b", "c/c"):
            rows += [_row(repo, "registry", "package", True),
                     _row(repo, "registry", "package", True),
                     _row(repo, "registry", "software", False),
                     _row(repo, "registry", "software", False)]
        res = A.within_repo_permutation(rows, A.is_visible)
        self.assertEqual(res["difference_pct_points"], 100.0)
        self.assertEqual(res["repositories_with_both_types"], 3)
        self.assertLess(res["p_two_sided"], 0.05)

    def test_null_within_repo(self):
        # Within each repo, visibility is independent of product type -> diff 0.
        rows = []
        for repo in ("a/a", "b/b"):
            rows += [_row(repo, "registry", "package", True),
                     _row(repo, "registry", "package", False),
                     _row(repo, "registry", "software", True),
                     _row(repo, "registry", "software", False)]
        res = A.within_repo_permutation(rows, A.is_visible)
        self.assertEqual(res["difference_pct_points"], 0.0)
        self.assertGreater(res["p_two_sided"], 0.05)

    def test_requires_both_types(self):
        # A repo with only one product type contributes no within-repo unit.
        rows = [_row("a/a", "registry", "package", True),
                _row("a/a", "registry", "package", False)]
        self.assertIsNone(A.within_repo_permutation(rows, A.is_visible))


class TestP3Mediation(unittest.TestCase):
    def test_known_arithmetic(self):
        rows = []
        # registry: 8 package (6 visible), 2 software (0 visible)
        rows += [_row("r/r", "registry", "package", i < 6) for i in range(8)]
        rows += [_row("r/r", "registry", "software", False) for _ in range(2)]
        # no_registry: 2 package (1 visible), 8 software (0 visible)
        rows += [_row("n/n", "no_registry", "package", i < 1) for i in range(2)]
        rows += [_row("n/n", "no_registry", "software", False) for _ in range(8)]
        m = A.mediation(rows, A.is_visible)
        self.assertEqual(m["support_n"], 20)
        self.assertEqual(m["total_effect_pct_points"], 50.0)
        self.assertEqual(m["direct_effect_pct_points"], 12.5)
        self.assertEqual(m["mediated_effect_pct_points"], 37.5)
        self.assertEqual(m["mediated_fraction"], 0.75)


class TestP2RepoLevel(unittest.TestCase):
    def test_registry_drives_attribution(self):
        # 2 registry repos all package, 2 no_registry repos all software.
        rows = []
        for repo in ("a/a", "b/b"):
            rows += [_row(repo, "registry", "package", True) for _ in range(3)]
        for repo in ("c/c", "d/d"):
            rows += [_row(repo, "no_registry", "software", False) for _ in range(3)]
        res = A.permutation_test(rows, A.is_package)
        self.assertEqual(res["difference_pct_points"], 100.0)
        self.assertEqual(res["repositories"], 4)


class TestEcosystemSplit(unittest.TestCase):
    def test_split(self):
        rows = [
            {"repo": "a/a", "group": "registry", "advisory_product_type": "package",
             "scanner_class": "scanner_visible", "own_id_in_osv": "True",
             "advisory_ecosystems": "npm"},
            {"repo": "a/a", "group": "registry", "advisory_product_type": "package",
             "scanner_class": "scanner_blind", "own_id_in_osv": "False",
             "advisory_ecosystems": "npm"},
            {"repo": "b/b", "group": "registry", "advisory_product_type": "package",
             "scanner_class": "scanner_visible", "own_id_in_osv": "True",
             "advisory_ecosystems": "pypi"},
        ]
        es = A.ecosystem_split(rows)
        self.assertEqual(es["npm"]["n"], 2)
        self.assertEqual(es["npm"]["visible"], 1)
        self.assertEqual(es["npm"]["visible_pct"], 50.0)
        self.assertEqual(es["pypi"]["visible_pct"], 100.0)


if __name__ == "__main__":
    unittest.main()
