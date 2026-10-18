"""Offline, deterministic tests for the registry-channel subgroup analysis.

No network and no dependence on the real census CSV: synthetic rows exercise the
relabelling and the (verbatim) permutation test, and the frozen classification
file is checked for structural integrity. Run in the sandbox with
`python -m unittest -v`.
Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import json
import os
import unittest

import registry_channel_analysis as a

HERE = os.path.dirname(os.path.abspath(__file__))
CLASSIFICATION = os.path.join(HERE, "registry_classification.json")


def row(repo, group, blind, own_in_osv=None):
    if own_in_osv is None:
        own_in_osv = "False" if blind else "True"
    return {"repo": repo, "group": group,
            "scanner_class": "scanner_blind" if blind else "scanner_visible",
            "own_id_in_osv": own_in_osv}


class PermutationTest(unittest.TestCase):
    def test_fully_separated_gives_100_points(self):
        rows = [row("r1", "registry", False), row("r2", "registry", False),
                row("n1", "no_registry", True), row("n2", "no_registry", True)]
        res = a.permutation_test(rows, a.is_blind)
        # registry 0% blind, no_registry 100% blind -> -100 points.
        self.assertEqual(res["difference_pct_points"], -100.0)
        self.assertEqual(res["repositories"], 4)
        # 2-of-6 label assignments are as-extreme -> p around 1/3, never tiny here.
        self.assertGreater(res["p_two_sided"], 0.15)

    def test_is_deterministic(self):
        rows = [row("r1", "registry", True), row("r2", "registry", False),
                row("n1", "no_registry", True), row("n2", "no_registry", False),
                row("n3", "no_registry", True)]
        r1 = a.permutation_test(rows, a.is_blind)
        r2 = a.permutation_test(rows, a.is_blind)
        self.assertEqual(r1, r2)

    def test_pooled_difference_uses_advisory_counts(self):
        # registry: r1 has 3 advisories all blind, r2 has 1 visible -> 3/4 = 75%.
        # no_registry: n1 has 1 visible -> 0%. Pooled diff = +75 points.
        rows = ([row("r1", "registry", True)] * 3 + [row("r2", "registry", False)]
                + [row("n1", "no_registry", False)])
        res = a.permutation_test(rows, a.is_blind)
        self.assertEqual(res["difference_pct_points"], 75.0)

    def test_own_missing_predicate(self):
        self.assertTrue(a.own_missing({"own_id_in_osv": "False"}))
        self.assertFalse(a.own_missing({"own_id_in_osv": "True"}))
        self.assertTrue(a.own_missing({}))


class Relabel(unittest.TestCase):
    def test_relabel_sets_group(self):
        mapping = {"foo/bar": "registry", "baz/qux": "no_registry"}
        rows = [row("foo/bar", "application", True),
                row("baz/qux", "application", False)]
        out = a.relabel(rows, mapping)
        self.assertEqual([r["group"] for r in out], ["registry", "no_registry"])
        # original rows are not mutated
        self.assertEqual(rows[0]["group"], "application")

    def test_relabel_rejects_unclassified(self):
        with self.assertRaises(ValueError):
            a.relabel([row("new/repo", "application", True)], {"foo/bar": "registry"})


class FrozenClassification(unittest.TestCase):
    def setUp(self):
        self.mapping, self.doc = a.load_classification(CLASSIFICATION)

    def test_counts_and_disjoint(self):
        groups = list(self.mapping.values())
        self.assertEqual(len(self.mapping), 27)
        self.assertEqual(groups.count("registry"), 12)
        self.assertEqual(groups.count("no_registry"), 15)

    def test_all_groups_valid(self):
        self.assertTrue(set(self.mapping.values()) <= set(a.GROUPS))

    def test_every_entry_has_a_basis(self):
        for repo, info in self.doc["classification"].items():
            self.assertTrue(info.get("basis"), "missing basis for %s" % repo)

    def test_source_commit_pinned(self):
        self.assertEqual(self.doc["source_csv"]["repo_commit"], "141a3ade")


class EndToEndSynthetic(unittest.TestCase):
    def test_analyse_shape(self):
        rows = [row("r1", "registry", False), row("r2", "registry", True),
                row("n1", "no_registry", True), row("n2", "no_registry", True)]
        out = a.analyse(rows)
        self.assertIn("registry", out["groups"])
        self.assertIn("no_registry", out["groups"])
        self.assertEqual(out["groups"]["registry"]["repos"], 2)
        self.assertEqual(out["groups"]["no_registry"]["repos"], 2)
        self.assertEqual(len(out["per_repo"]), 4)
        self.assertIsNotNone(out["comparison"]["blind"])


if __name__ == "__main__":
    unittest.main()
