"""Offline, deterministic unit tests for the A7 release-cadence analysis.

They exercise only the pure functions (no network): the tertile split, the
stratified direct/mediation effect, the within-tertile permutation, the power
floor, the verdict rule, Spearman, and the Link-header release count. Run by the
publish lane's test_first before the code ships.
Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import unittest

from release_cadence_analysis import (
    tertile_labels, stratified_effect, adjusted_permutation, power_good,
    compute_verdict, spearman, release_count_from,
)


def rows_for(repo, group, n_visible, n_blind):
    out = []
    for _ in range(n_visible):
        out.append({"repo": repo, "group": group, "scanner_class": "scanner_visible"})
    for _ in range(n_blind):
        out.append({"repo": repo, "group": group, "scanner_class": "scanner_blind"})
    return out


class TestTertiles(unittest.TestCase):
    def test_equal_blocks(self):
        cad = {"r1": 1.0, "r2": 2.0, "r3": 3.0, "r4": 4.0, "r5": 5.0, "r6": 6.0}
        t = tertile_labels(cad)
        self.assertEqual(t, {"r1": "T1", "r2": "T1", "r3": "T2", "r4": "T2",
                             "r5": "T3", "r6": "T3"})

    def test_extras_go_to_lower_tertiles(self):
        cad = {"a": 1.0, "b": 2.0, "c": 3.0, "d": 4.0, "e": 5.0}  # N=5 -> [2,2,1]
        t = tertile_labels(cad)
        self.assertEqual(t["a"], "T1")
        self.assertEqual(t["b"], "T1")
        self.assertEqual(t["c"], "T2")
        self.assertEqual(t["d"], "T2")
        self.assertEqual(t["e"], "T3")


class TestStratifiedEffect(unittest.TestCase):
    def test_within_stratum_effect_powered(self):
        # every tertile has one registry (all visible) and one no_registry (all blind)
        tert = {"r1": "T1", "r2": "T1", "r3": "T2", "r4": "T2", "r5": "T3", "r6": "T3"}
        groups = {"r1": "registry", "r2": "no_registry", "r3": "registry",
                  "r4": "no_registry", "r5": "registry", "r6": "no_registry"}
        rows = []
        for repo, g in groups.items():
            if g == "registry":
                rows += rows_for(repo, g, 4, 0)
            else:
                rows += rows_for(repo, g, 0, 4)
        s = stratified_effect(rows, tert)
        self.assertEqual(s["total_effect_pct_points"], 100.0)
        self.assertEqual(s["direct_effect_pct_points"], 100.0)
        self.assertEqual(s["mediated_fraction"], 0.0)
        self.assertEqual(power_good(rows, tert), 3)
        adj = adjusted_permutation(rows, tert, n_perm=200)
        self.assertEqual(adj["direct_pct_points"], 100.0)
        self.assertTrue(0.0 < adj["p_two_sided"] <= 1.0)

    def test_confounded_is_inseparable(self):
        # registry only in high-cadence tertile, no_registry only in low: no overlap
        tert = {"r1": "T1", "r2": "T1", "r3": "T3", "r4": "T3"}
        groups = {"r1": "no_registry", "r2": "no_registry",
                  "r3": "registry", "r4": "registry"}
        rows = []
        for repo, g in groups.items():
            if g == "registry":
                rows += rows_for(repo, g, 4, 0)
            else:
                rows += rows_for(repo, g, 0, 4)
        s = stratified_effect(rows, tert)
        self.assertEqual(s["total_effect_pct_points"], 100.0)
        self.assertEqual(s["direct_effect_pct_points"], 0.0)
        self.assertEqual(s["mediated_fraction"], 1.0)
        good = power_good(rows, tert)
        self.assertEqual(good, 0)
        self.assertEqual(compute_verdict(s["direct_effect_pct_points"], 1.0, good),
                         "CONFOUNDED_INSEPARABLE")


class TestVerdict(unittest.TestCase):
    def test_rule(self):
        self.assertEqual(compute_verdict(40.0, 0.01, 3), "SURVIVES")
        self.assertEqual(compute_verdict(10.0, 0.01, 3), "DOES_NOT_SURVIVE")
        self.assertEqual(compute_verdict(40.0, 0.20, 3), "DOES_NOT_SURVIVE")
        self.assertEqual(compute_verdict(40.0, 0.01, 1), "INCONCLUSIVE_UNDERPOWERED")
        self.assertEqual(compute_verdict(40.0, 0.01, 0), "CONFOUNDED_INSEPARABLE")


class TestSpearmanAndLink(unittest.TestCase):
    def test_spearman_monotonic(self):
        self.assertEqual(spearman([(1, 10), (2, 20), (3, 25), (4, 40), (5, 55)]), 1.0)

    def test_release_count_from(self):
        link = ('<https://api.github.com/repositories/1/releases?per_page=1&page=2>; '
                'rel="next", <https://api.github.com/repositories/1/releases?'
                'per_page=1&page=7>; rel="last"')
        self.assertEqual(release_count_from(link, "[]"), 7)
        self.assertEqual(release_count_from("", "[]"), 0)
        self.assertEqual(release_count_from("", '[{"id": 1}]'), 1)


if __name__ == "__main__":
    unittest.main()
