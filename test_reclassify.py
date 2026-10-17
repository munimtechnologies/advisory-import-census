"""Offline tests for reclassify.py. Apache-2.0, MV2 of Munim, Inc."""
import csv
import json
import os
import tempfile
import unittest

import reclassify as rc

COLS = ["group", "repo", "ghsa_id", "cve_id", "severity", "published_at", "age_days",
        "period", "own_id_in_osv", "scanner_class", "packages", "url"]


def row(group, repo, ghsa, own, cls, age="30.0"):
    return {"group": group, "repo": repo, "ghsa_id": ghsa, "cve_id": "", "severity": "high",
            "published_at": "", "age_days": age, "period": "from_2026_05",
            "own_id_in_osv": own, "scanner_class": cls, "packages": "", "url": ""}


def with_pkg(name="github.com/grafana/grafana"):
    return {"affected": [{"package": {"ecosystem": "Go", "name": name}}]}


class ReclassifyTests(unittest.TestCase):
    def test_no_package_but_own_record_names_one_is_visible(self):
        rows = [row("control", "grafana/grafana", "GHSA-7rqg-hjwc-6mjf", "True", "no_package")]
        stats = rc.reclassify(rows, lambda g: with_pkg())
        self.assertEqual(rows[0]["scanner_class_fixed"], "visible_by_own_record")
        self.assertEqual(rows[0]["osv_record_packages"], "Go:github.com/grafana/grafana")
        self.assertFalse(rc.fixed_blind(rows[0]))
        self.assertTrue(rc.prereg_blind(rows[0]))
        self.assertEqual(stats, {"rows_checked_in_osv": 1, "lookups_failed": 0})

    def test_free_text_package_name_with_own_record_is_visible(self):
        rows = [row("control", "traefik/traefik", "GHSA-x", "True", "package_not_in_osv")]
        rc.reclassify(rows, lambda g: with_pkg("github.com/traefik/traefik/v3"))
        self.assertFalse(rc.fixed_blind(rows[0]))

    def test_own_record_without_package_stays_blind(self):
        rows = [row("ai", "a/b", "GHSA-x", "True", "no_package")]
        rc.reclassify(rows, lambda g: {"affected": []})
        self.assertEqual(rows[0]["scanner_class_fixed"], "no_package")
        self.assertTrue(rc.fixed_blind(rows[0]))

    def test_not_in_osv_is_not_looked_up(self):
        calls = []
        rows = [row("ai", "a/b", "GHSA-x", "False", "no_package"),
                row("ai", "a/b", "GHSA-y", "True", "scanner_visible")]
        stats = rc.reclassify(rows, lambda g: calls.append(g) or with_pkg())
        self.assertEqual(calls, [])
        self.assertEqual(stats["rows_checked_in_osv"], 0)
        self.assertTrue(rc.fixed_blind(rows[0]))
        self.assertFalse(rc.fixed_blind(rows[1]))

    def test_failed_lookup_stays_blind(self):
        def boom(g):
            raise OSError("network down")
        rows = [row("ai", "a/b", "GHSA-x", "True", "no_package")]
        stats = rc.reclassify(rows, boom)
        self.assertEqual(rows[0]["scanner_class_fixed"], "unchecked")
        self.assertTrue(rc.fixed_blind(rows[0]))
        self.assertEqual(stats["lookups_failed"], 1)


class StatsTests(unittest.TestCase):
    def test_wilson(self):
        lo, hi = rc.wilson(207, 596)
        self.assertAlmostEqual(lo, 0.3102, places=4)
        self.assertAlmostEqual(hi, 0.3864, places=4)
        self.assertIsNone(rc.wilson(0, 0))

    def test_median(self):
        self.assertEqual(rc.median([3, 1, 2]), 2)
        self.assertEqual(rc.median([1, 2, 3, 4]), 2.5)
        self.assertIsNone(rc.median([]))

    def test_permutation_identical_groups(self):
        rows = []
        for i in range(4):
            rows += [row("ai", "ai/%d" % i, "G%d" % i, "False", "no_package"),
                     row("control", "c/%d" % i, "H%d" % i, "False", "no_package")]
        res = rc.permutation_test(rows, rc.prereg_blind, ("ai", "control"), n_perm=200)
        self.assertEqual(res["difference_pct_points"], 0.0)
        self.assertEqual(res["p_two_sided"], 1.0)
        self.assertEqual(res["repositories"], 8)

    def test_permutation_needs_both_groups(self):
        rows = [row("ai", "a/b", "G", "False", "no_package")]
        self.assertIsNone(rc.permutation_test(rows, rc.prereg_blind, ("ai", "control")))


class IoTests(unittest.TestCase):
    def write_csv(self, d, rows):
        path = os.path.join(d, "group_census.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=COLS)
            w.writeheader()
            w.writerows(rows)
        return path

    def test_load_rows_drops_recent_and_unclassified(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.write_csv(d, [
                row("ai", "a/b", "G1", "False", "no_package", age="13.9"),
                row("ai", "a/b", "G2", "False", "no_package", age="14.0"),
                row("ai", "a/b", "G3", "False", "", age="40"),
                row("ai", "a/b", "G4", "False", "no_package", age=""),
            ])
            self.assertEqual([r["ghsa_id"] for r in rc.load_rows(path)], ["G2"])

    def test_end_to_end_offline_with_self_check(self):
        rows = [row("ai", "a/one", "G1", "True", "no_package"),
                row("ai", "a/one", "G2", "False", "no_package"),
                row("ai", "a/two", "G3", "True", "scanner_visible"),
                row("control", "discourse/discourse", "H1", "False", "no_package"),
                row("control", "grafana/grafana", "H2", "True", "no_package"),
                row("control", "pallets/jinja", "H3", "True", "scanner_visible")]
        with tempfile.TemporaryDirectory() as d:
            path = self.write_csv(d, rows)
            eligible = rc.load_rows(path)
            for r in eligible:
                r["scanner_class_fixed"] = r["scanner_class"]
            pre = rc.summarise(eligible)
            census = {"snapshot_utc": "2026-10-17T00:00:00+00:00", "groups": {
                g: {"scanner_blind": {"k": pre["groups"][g]["prereg_blind"]["k"],
                                      "n": pre["groups"][g]["prereg_blind"]["n"]}}
                for g in ("ai", "control")},
                "comparison": {"scanner_blind": pre["comparison"]["prereg_blind"]}}
            cpath = os.path.join(d, "summary_groups.json")
            with open(cpath, "w", encoding="utf-8") as f:
                json.dump(census, f)
            out = os.path.join(d, "out")
            self.assertEqual(rc.main(["--csv", path, "--census-summary", cpath,
                                      "--out-dir", out, "--offline"]), 0)
            with open(os.path.join(out, "summary_reclassified.json"), encoding="utf-8") as f:
                s = json.load(f)
            self.assertEqual(s["self_check_against_census"], "match")
            self.assertEqual(s["groups"]["ai"]["prereg_blind"]["k"], 2)
            self.assertEqual(s["groups"]["ai"]["fixed_blind"]["k"], 1)
            self.assertEqual(s["groups"]["control"]["fixed_blind"]["k"], 1)
            exp = s["exploratory_control_app_vs_lib"]
            self.assertEqual(exp["control_app"]["eligible"], 2)
            self.assertEqual(exp["control_lib"]["eligible"], 1)
            self.assertTrue(os.path.exists(os.path.join(out, "group_census_reclassified.csv")))

    def test_self_check_reports_drift(self):
        summary = {"groups": {g: {"prereg_blind": {"k": 1, "n": 2}} for g in ("ai", "control")},
                   "comparison": {"prereg_blind": {"difference_pct_points": 0.0,
                                                   "p_two_sided": 1.0}}}
        census = {"groups": {"ai": {"scanner_blind": {"k": 1, "n": 2}},
                             "control": {"scanner_blind": {"k": 2, "n": 2}}},
                  "comparison": {"scanner_blind": {"difference_pct_points": 0.0,
                                                   "p_two_sided": 0.5}}}
        problems = rc.check_against_census(summary, census)
        self.assertEqual(len(problems), 2)


if __name__ == "__main__":
    unittest.main()
