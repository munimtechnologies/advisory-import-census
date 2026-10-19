"""Deterministic unit tests for the registry-channel A4 real-package study.

Covers:
  - the named-package parser (real_package_census.named_packages) against markup
    copied VERBATIM from real archived GitHub advisory pages (A1 raw/);
  - the github.com repo extractor;
  - the registry-resolution probe (resolve_package) with injected OFFLINE getters,
    and the real_package_resolution / real_package_label classifiers, including the
    coolify (named-but-not-real) vs nocodb (real) distinction A4 exists to measure;
  - the analysis statistics (P1 within-repo permutation, P2 repo-level permutation,
    P3 mediation) on toy data with hand-computed answers.

No network. Run with:  python -m unittest -v test_real_package
Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import unittest

import real_package_census as C
import real_package_analysis as A


# Markup copied verbatim from A1 raw/ advisory pages (coolify + nocodb both name an
# npm package; only nocodb's is the project's real release -- the A4 test case).
COOLIFY_HTML = (
    '      <span class="f4 color-fg-default text-bold">coolify</span>'
    '        <span class="color-fg-muted f4 d-inline-flex text-underline" >\n'
    '            (<a href="/advisories?query=ecosystem%3Anpm" '
    'data-view-component="true" class="Link Link--muted">npm</a>)\n'
    '        </span>'
)
NOCODB_HTML = (
    '      <span class="f4 color-fg-default text-bold">nocodb</span>'
    '        <span class="color-fg-muted f4 d-inline-flex text-underline" >\n'
    '            (<a href="/advisories?query=ecosystem%3Anpm" '
    'data-view-component="true" class="Link Link--muted">npm</a>)\n'
    '        </span>'
)
SOFTWARE_HTML = (
    '<h2 class="text-small color-fg-muted mb-1">Software</h2>'
    '<span class="f4 color-fg-default text-bold">Discourse</span>'
)


class TestNamedPackagesParser(unittest.TestCase):
    def test_coolify(self):
        self.assertEqual(C.named_packages(COOLIFY_HTML), [("npm", "coolify")])

    def test_nocodb(self):
        self.assertEqual(C.named_packages(NOCODB_HTML), [("npm", "nocodb")])

    def test_software_has_no_named_package(self):
        # A "Software" box names a product but has no ecosystem link, so no coord.
        self.assertEqual(C.named_packages(SOFTWARE_HTML), [])

    def test_dedup(self):
        self.assertEqual(C.named_packages(NOCODB_HTML + NOCODB_HTML),
                         [("npm", "nocodb")])

    def test_product_type_still_package(self):
        # The A3 product-type parser must still fire on the same markup.
        self.assertEqual(C.advisory_product(COOLIFY_HTML), ("package", ["npm"]))


class TestGithubRepoExtractor(unittest.TestCase):
    def test_git_plus_https_dot_git(self):
        self.assertEqual(C.github_repos_in("git+https://github.com/nocodb/nocodb.git"),
                         {"nocodb/nocodb"})

    def test_ssh_and_plain(self):
        self.assertEqual(C.github_repos_in("git@github.com:owner/Repo"),
                         {"owner/repo"})
        self.assertEqual(C.github_repos_in("https://github.com/A/B/tree/main"),
                         {"a/b"})

    def test_ignores_non_repo_paths(self):
        self.assertEqual(C.github_repos_in("https://github.com/sponsors/foo"), set())

    def test_no_github(self):
        self.assertEqual(C.github_repos_in("https://gitlab.com/x/y"), set())


def _npm_getter(repo_url):
    def getter(url):
        if repo_url is None:
            return 404, None
        return 200, {"repository": {"url": repo_url},
                     "dist-tags": {"latest": "1.0.0"}, "versions": {}}
    return getter


class TestResolveProbe(unittest.TestCase):
    def test_npm_real_release_points_to_repo(self):
        r = C.resolve_package("npm", "nocodb",
                              getter_json=_npm_getter("git+https://github.com/nocodb/nocodb.git"))
        self.assertTrue(r["checked"] and r["exists"])
        self.assertIn("nocodb/nocodb", r["repos"])

    def test_npm_exists_but_points_elsewhere(self):
        r = C.resolve_package("npm", "coolify",
                              getter_json=_npm_getter("https://github.com/other/coolify-cli"))
        self.assertTrue(r["exists"])
        self.assertNotIn("coollabsio/coolify", {x.lower() for x in r["repos"]})

    def test_npm_absent(self):
        r = C.resolve_package("npm", "no-such-pkg-xyz",
                              getter_json=_npm_getter(None))
        self.assertTrue(r["checked"])
        self.assertFalse(r["exists"])

    def test_unprobed_ecosystem_is_unchecked(self):
        r = C.resolve_package("maven", "org.foo:bar")
        self.assertFalse(r["checked"])

    def test_go_repo_from_module_path(self):
        r = C.resolve_package("go", "github.com/gitea/gitea",
                              getter_text=lambda url: (200, "{}"))
        self.assertTrue(r["exists"])
        self.assertIn("gitea/gitea", r["repos"])


class TestResolutionClassifier(unittest.TestCase):
    def _res(self, repos, exists=True, checked=True):
        return lambda eco, name: {"checked": checked, "exists": exists,
                                  "repos": set(repos), "detail": ""}

    def test_yes_when_match(self):
        label, _ = C.real_package_resolution(
            "nocodb/nocodb", [("npm", "nocodb")], self._res({"nocodb/nocodb"}))
        self.assertEqual(label, "yes")

    def test_no_match_when_points_elsewhere(self):
        label, _ = C.real_package_resolution(
            "coollabsio/coolify", [("npm", "coolify")], self._res({"other/coolify"}))
        self.assertEqual(label, "no_match")

    def test_absent_when_not_exists(self):
        label, _ = C.real_package_resolution(
            "a/b", [("npm", "x")], self._res(set(), exists=False))
        self.assertEqual(label, "absent")

    def test_unchecked_when_probe_cannot(self):
        label, _ = C.real_package_resolution(
            "a/b", [("maven", "g:a")], self._res(set(), checked=False))
        self.assertEqual(label, "unchecked")

    def test_case_insensitive_match(self):
        label, _ = C.real_package_resolution(
            "TryGhost/Ghost", [("npm", "ghost")], self._res({"tryghost/ghost"}))
        self.assertEqual(label, "yes")


class TestRealPackageLabel(unittest.TestCase):
    def test_labels(self):
        self.assertEqual(C.real_package_label("package", "yes"), "real")
        self.assertEqual(C.real_package_label("package", "no_match"), "not_real")
        self.assertEqual(C.real_package_label("package", "absent"), "not_real")
        self.assertEqual(C.real_package_label("package", "unchecked"), "other")
        self.assertEqual(C.real_package_label("software", ""), "not_real")
        self.assertEqual(C.real_package_label("other", ""), "other")


def _row(repo, group, real_package, visible, own=True):
    return {"repo": repo, "group": group, "real_package": real_package,
            "advisory_product_type": "package" if real_package == "real" else "software",
            "scanner_class": "scanner_visible" if visible else "scanner_blind",
            "own_id_in_osv": "True" if own else "False",
            "advisory_ecosystems": "npm", "named_pkg_resolution": "yes"}


class TestP1WithinRepo(unittest.TestCase):
    def test_perfect_separation_three_repos(self):
        rows = []
        for repo in ("a/a", "b/b", "c/c"):
            rows += [_row(repo, "registry", "real", True),
                     _row(repo, "registry", "real", True),
                     _row(repo, "registry", "not_real", False),
                     _row(repo, "registry", "not_real", False)]
        res = A.within_repo_permutation(rows, A.is_visible)
        self.assertEqual(res["difference_pct_points"], 100.0)
        self.assertEqual(res["repositories_with_both_strata"], 3)
        self.assertLess(res["p_two_sided"], 0.05)

    def test_null_within_repo(self):
        rows = []
        for repo in ("a/a", "b/b"):
            rows += [_row(repo, "registry", "real", True),
                     _row(repo, "registry", "real", False),
                     _row(repo, "registry", "not_real", True),
                     _row(repo, "registry", "not_real", False)]
        res = A.within_repo_permutation(rows, A.is_visible)
        self.assertEqual(res["difference_pct_points"], 0.0)
        self.assertGreater(res["p_two_sided"], 0.05)

    def test_requires_both_strata(self):
        rows = [_row("a/a", "registry", "real", True),
                _row("a/a", "registry", "real", False)]
        self.assertIsNone(A.within_repo_permutation(rows, A.is_visible))


class TestP3Mediation(unittest.TestCase):
    def test_known_arithmetic(self):
        rows = []
        rows += [_row("r/r", "registry", "real", i < 6) for i in range(8)]
        rows += [_row("r/r", "registry", "not_real", False) for _ in range(2)]
        rows += [_row("n/n", "no_registry", "real", i < 1) for i in range(2)]
        rows += [_row("n/n", "no_registry", "not_real", False) for _ in range(8)]
        m = A.mediation(rows, A.is_visible)
        self.assertEqual(m["support_n"], 20)
        self.assertEqual(m["total_effect_pct_points"], 50.0)
        self.assertEqual(m["direct_effect_pct_points"], 12.5)
        self.assertEqual(m["mediated_effect_pct_points"], 37.5)
        self.assertEqual(m["mediated_fraction"], 0.75)


class TestP2RepoLevel(unittest.TestCase):
    def test_registry_drives_real_package(self):
        rows = []
        for repo in ("a/a", "b/b"):
            rows += [_row(repo, "registry", "real", True) for _ in range(3)]
        for repo in ("c/c", "d/d"):
            rows += [_row(repo, "no_registry", "not_real", False) for _ in range(3)]
        res = A.permutation_test(rows, A.is_real)
        self.assertEqual(res["difference_pct_points"], 100.0)
        self.assertEqual(res["repositories"], 4)


if __name__ == "__main__":
    unittest.main()
