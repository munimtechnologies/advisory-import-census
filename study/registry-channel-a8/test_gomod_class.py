"""Offline unit tests for gomod_class_analysis.py (registry-channel A8).

The covariate and verdict helpers are tested with no network and no other files.
The end-to-end tests need the published A5 statistics module (go_rescue_analysis.py,
fetched by fetch_inputs.py) and are skipped when it is absent.
Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import unittest

import gomod_class_analysis as G


def probe(repo, included="True", status="200", match="True", module=""):
    return {"repo": repo, "included": included, "gomod_status": status,
            "gomod_match": match, "gomod_module": module, "language": "Go"}


def adv(repo, visible, kind="software"):
    return {"repo": repo, "registry_group": "no_registry",
            "advisory_product_type": kind,
            "scanner_class": "scanner_visible" if visible else "scanner_blind"}


class ModuleClassTest(unittest.TestCase):
    def test_root_match(self):
        p = probe("a/b", module="github.com/a/b/v2")
        self.assertEqual(G.module_class(p), "root_match")

    def test_non_root(self):
        p = probe("FiloSottile/mkcert", match="False", module="filippo.io/mkcert")
        self.assertEqual(G.module_class(p), "non_root")

    def test_no_gomod(self):
        self.assertEqual(G.module_class(probe("a/b", status="404", match="False")),
                         "no_gomod")

    def test_unparsed_gomod(self):
        self.assertEqual(G.module_class(probe("a/b", match="False", module="")),
                         "unparsed_gomod")

    def test_excluded(self):
        self.assertIsNone(G.module_class(probe("a/b", included="False")))

    def test_non_root_kind(self):
        self.assertEqual(G.non_root_kind("filippo.io/mkcert"), "vanity_domain")
        self.assertEqual(G.non_root_kind("gopkg.in/yaml.v3"), "vanity_domain")
        self.assertEqual(G.non_root_kind("github.com/other/repo"), "github_nonroot")
        self.assertEqual(G.non_root_kind("GitHub.com/a/b/sub"), "github_nonroot")


class VerdictTest(unittest.TestCase):
    R = {"root_match": 5, "non_root": 3}

    def test_empty_class(self):
        n = {"root_match": 5, "non_root": 0}
        a = {"root_match": 50, "non_root": 0}
        self.assertEqual(G.verdict(n, a, None, None, None), "CONFOUNDED_INSEPARABLE")
        self.assertEqual(G.verdict_prose_reading(n, a, None, None, None),
                         "CONFOUNDED_INSEPARABLE")

    def test_few_non_root_advisories(self):
        a = {"root_match": 50, "non_root": 2}
        self.assertEqual(G.verdict(self.R, a, 80.0, 0.01, 0.0),
                         "CONFOUNDED_INSEPARABLE")
        self.assertEqual(G.verdict_prose_reading(self.R, a, 80.0, 0.01, 0.0),
                         "INCONCLUSIVE_UNDERPOWERED")

    def test_few_root_advisories(self):
        a = {"root_match": 3, "non_root": 20}
        self.assertEqual(G.verdict(self.R, a, 80.0, 0.01, 0.0),
                         "CONFOUNDED_INSEPARABLE")

    def test_confined(self):
        a = {"root_match": 50, "non_root": 20}
        self.assertEqual(G.verdict(self.R, a, 40.0, 0.049, 20.0), "CONFINED")

    def test_not_confined(self):
        a = {"root_match": 50, "non_root": 20}
        self.assertEqual(G.verdict(self.R, a, 39.9, 0.01, 0.0), "NOT_CONFINED")
        self.assertEqual(G.verdict(self.R, a, 80.0, 0.05, 0.0), "NOT_CONFINED")
        self.assertEqual(G.verdict(self.R, a, 80.0, 0.01, 20.1), "NOT_CONFINED")
        self.assertEqual(G.verdict(self.R, a, None, None, 0.0), "NOT_CONFINED")


@unittest.skipIf(G.A is None, "go_rescue_analysis.py not fetched")
class AnalyseTest(unittest.TestCase):
    def setUp(self):
        self.probes = [
            probe("r/one", module="github.com/r/one"),
            probe("r/two", module="github.com/r/two/v3"),
            probe("v/one", match="False", module="example.org/one"),
            probe("v/two", match="False", module="github.com/other/two"),
            probe("n/one", status="404", match="False"),
            probe("x/old", included="False"),
        ]
        self.census = []
        for repo in ("r/one", "r/two"):
            self.census += [adv(repo, True) for _ in range(3)]
        for repo in ("v/one", "v/two"):
            self.census += [adv(repo, False) for _ in range(3)]
        self.census += [adv("n/one", False), adv("n/one", False)]
        # package-typed advisories and archived repos never enter the analysis
        self.census += [adv("v/one", True, kind="package") for _ in range(5)]
        self.census += [adv("x/old", True)]

    def test_counts_and_shares(self):
        s = G.analyse(self.census, self.probes)
        self.assertEqual(s["repos_by_class"]["root_match"], 2)
        self.assertEqual(s["repos_by_class"]["non_root"], 2)
        self.assertEqual(s["repos_by_class"]["no_gomod"], 1)
        self.assertEqual(s["package_less_advisories_by_class"]["root_match"], 6)
        self.assertEqual(s["package_less_advisories_by_class"]["non_root"], 6)
        self.assertEqual(s["visible_by_class"]["root_match"]["pct"], 100.0)
        self.assertEqual(s["visible_by_class"]["non_root"]["pct"], 0.0)
        self.assertEqual(s["visible_by_class"]["no_gomod"]["n"], 2)

    def test_primary_and_verdict(self):
        s = G.analyse(self.census, self.probes)
        self.assertEqual(s["P1_primary"]["difference_pct_points"], 100.0)
        # 4 repos, 2 per class: 2 of 6 labelings are as extreme -> p well above 0.05
        self.assertGreater(s["P1_primary"]["p_two_sided"], 0.05)
        self.assertEqual(s["verdict"], "NOT_CONFINED")
        self.assertTrue(s["P2_non_root_not_rescued"]["holds"])

    def test_non_root_split(self):
        s = G.analyse(self.census, self.probes)
        self.assertEqual(s["non_root_split"]["repos"]["vanity_domain"], ["v/one"])
        self.assertEqual(s["non_root_split"]["repos"]["github_nonroot"], ["v/two"])
        self.assertEqual(s["non_root_split"]["visible"]["vanity_domain"]["n"], 3)

    def test_per_repo_excludes_archived(self):
        s = G.analyse(self.census, self.probes)
        repos = [t["repo"] for t in s["per_repo"]]
        self.assertNotIn("x/old", repos)
        self.assertEqual(len(repos), 5)


if __name__ == "__main__":
    unittest.main()
