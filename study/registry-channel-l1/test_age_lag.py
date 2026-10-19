"""Offline unit tests for L1's age-lag analysis.

These test L1's own new code (age binning, the within-repo permutation, the verdict
rule, the loaders and the per-repo table). They do NOT need A5's go_rescue_analysis
module, so they run in the publish test_first lane where that module is absent.
Apache-2.0. Made with AI agents working for MV2 of Munim, Inc.
"""
import json
import os
import tempfile
import unittest

import age_lag_analysis as L


class AgeBinTest(unittest.TestCase):
    def test_floor_drops_below_14(self):
        self.assertIsNone(L.age_bin(0))
        self.assertIsNone(L.age_bin(13.9))
        self.assertIsNone(L.age_bin(None))

    def test_boundaries(self):
        self.assertEqual(L.age_bin(14), "young")
        self.assertEqual(L.age_bin(89.9), "young")
        self.assertEqual(L.age_bin(90), "mid")
        self.assertEqual(L.age_bin(364), "mid")
        self.assertEqual(L.age_bin(365), "old")
        self.assertEqual(L.age_bin(5000), "old")


class ClassificationTest(unittest.TestCase):
    def test_nested_a4_shape(self):
        doc = {"classification": {
            "Owner/Repo": {"group": "registry", "stars": 1},
            "Two/Two": {"group": "no_registry"},
            "Bad/One": {"group": "library"},
        }}
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(doc, f)
            out = L.load_classification(p)
        self.assertEqual(out, {"owner/repo": "registry", "two/two": "no_registry"})

    def test_flat_shape(self):
        doc = {"Owner/Repo": "registry", "Two/Two": "no_registry", "x/y": "other"}
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(doc, f)
            out = L.load_classification(p)
        self.assertEqual(out, {"owner/repo": "registry", "two/two": "no_registry"})


class LoadRowsTest(unittest.TestCase):
    def _write(self, d, rows):
        import csv
        p = os.path.join(d, "census.csv")
        fields = ["repo", "age_days", "scanner_class", "advisory_product_type"]
        with open(p, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in rows:
                w.writerow(r)
        return p

    def test_filters_and_counts(self):
        rows = [
            {"repo": "a/a", "age_days": "500", "scanner_class": "scanner_visible", "advisory_product_type": "software"},
            {"repo": "a/a", "age_days": "10", "scanner_class": "blind", "advisory_product_type": "software"},  # < floor
            {"repo": "b/b", "age_days": "", "scanner_class": "blind", "advisory_product_type": "package"},      # missing age
            {"repo": "z/z", "age_days": "50", "scanner_class": "blind", "advisory_product_type": "package"},    # off-frame
            {"repo": "b/b", "age_days": "50", "scanner_class": "blind", "advisory_product_type": "package"},
        ]
        classification = {"a/a": "no_registry", "b/b": "registry"}
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, rows)
            kept, counts = L.load_rows(p, classification)
        self.assertEqual(counts["kept"], 2)
        self.assertEqual(counts["off_frame"], 1)
        self.assertEqual(counts["age_missing"], 1)
        self.assertEqual(counts["age_below_floor"], 1)
        bins = sorted((r["repo"], r["bin"], r["visible"]) for r in kept)
        self.assertEqual(bins, [("a/a", "old", True), ("b/b", "young", False)])


class PooledDiffTest(unittest.TestCase):
    def test_basic(self):
        items = [
            {"repo": "r", "bin": "old", "visible": True},
            {"repo": "r", "bin": "old", "visible": True},
            {"repo": "r", "bin": "young", "visible": False},
            {"repo": "r", "bin": "young", "visible": False},
        ]
        self.assertAlmostEqual(L.pooled_old_young_diff(items), 1.0)

    def test_empty_bin_none(self):
        items = [{"repo": "r", "bin": "old", "visible": True}]
        self.assertIsNone(L.pooled_old_young_diff(items))


class WithinRepoPermutationTest(unittest.TestCase):
    def test_single_repo_two_two_p_one_third(self):
        # One repo, 2 young (both invisible) + 2 old (both visible). Of the 6 distinct
        # label assignments, exactly 2 are as or more extreme than observed -> p ~ 1/3.
        items = [
            {"repo": "r", "bin": "young", "visible": False},
            {"repo": "r", "bin": "young", "visible": False},
            {"repo": "r", "bin": "old", "visible": True},
            {"repo": "r", "bin": "old", "visible": True},
        ]
        res = L.within_repo_permutation(items)
        self.assertEqual(res["difference_pct_points"], 100.0)
        self.assertEqual(res["repos_both_bins"], 1)
        self.assertEqual(res["permutations"], L.N_PERM)
        self.assertTrue(0.30 <= res["p_two_sided"] <= 0.37, res["p_two_sided"])

    def test_no_repo_has_both_bins_gives_p_one(self):
        # repo1 all young, repo2 all old: within-repo shuffles are no-ops, so every
        # permutation equals the observed statistic -> p == 1.0, null spread is zero.
        items = [
            {"repo": "r1", "bin": "young", "visible": False},
            {"repo": "r1", "bin": "young", "visible": True},
            {"repo": "r2", "bin": "old", "visible": True},
            {"repo": "r2", "bin": "old", "visible": True},
        ]
        res = L.within_repo_permutation(items)
        self.assertEqual(res["repos_both_bins"], 0)
        self.assertEqual(res["difference_pct_points"], 50.0)
        self.assertEqual(res["p_two_sided"], 1.0)

    def test_reproducible(self):
        items = [
            {"repo": "r", "bin": "young", "visible": False},
            {"repo": "r", "bin": "old", "visible": True},
            {"repo": "r", "bin": "young", "visible": True},
            {"repo": "r", "bin": "old", "visible": False},
        ]
        self.assertEqual(L.within_repo_permutation(items),
                         L.within_repo_permutation(items))


class VerdictTest(unittest.TestCase):
    def test_underpowered(self):
        self.assertEqual(L.decide_verdict(True, 99.0, 0.01, True),
                         "INCONCLUSIVE_UNDERPOWERED")

    def test_lag(self):
        self.assertEqual(L.decide_verdict(False, 20.0, 0.01, False), "LAG")

    def test_lag_needs_significance(self):
        # d1 big but not significant -> not LAG; d1 >= 15 so not PERMANENT -> MIXED
        self.assertEqual(L.decide_verdict(False, 20.0, 0.5, True), "MIXED")

    def test_permanent(self):
        self.assertEqual(L.decide_verdict(False, 5.0, 0.9, True), "PERMANENT")

    def test_mixed_small_d1_no_p2(self):
        self.assertEqual(L.decide_verdict(False, 5.0, 0.9, False), "MIXED")


class PerRepoTableTest(unittest.TestCase):
    def test_counts_and_pct(self):
        rows = [
            {"repo": "a/a", "group": "no_registry", "bin": "young", "visible": True},
            {"repo": "a/a", "group": "no_registry", "bin": "young", "visible": False},
            {"repo": "a/a", "group": "no_registry", "bin": "old", "visible": False},
        ]
        t = L.per_repo_table(rows)
        self.assertEqual(len(t), 1)
        row = t[0]
        self.assertEqual(row["young_n"], 2)
        self.assertEqual(row["young_visible"], 1)
        self.assertEqual(row["young_pct"], 50.0)
        self.assertEqual(row["old_n"], 1)
        self.assertEqual(row["old_pct"], 0.0)
        self.assertEqual(row["mid_n"], 0)
        self.assertEqual(row["mid_pct"], "")


if __name__ == "__main__":
    unittest.main()
