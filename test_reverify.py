# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
"""Offline unit tests for reverify.py (no network). Run: python -m unittest -v."""
import io
import tempfile
import unittest

import reverify


class TestParseBool(unittest.TestCase):
    def test_true_values(self):
        for v in ["true", "True", "TRUE", "1", "yes", "t"]:
            self.assertTrue(reverify.parse_bool(v))

    def test_false_values(self):
        for v in ["false", "False", "0", "no", "f", ""]:
            self.assertFalse(reverify.parse_bool(v))

    def test_bad_value(self):
        with self.assertRaises(ValueError):
            reverify.parse_bool("maybe")


class TestReadCensus(unittest.TestCase):
    def test_reads_rows_and_skips_blank_ghsa(self):
        csv_text = (
            "repo,ghsa_id,severity,in_global_db\n"
            "o/r,GHSA-aaaa,high,false\n"
            "o/r,GHSA-bbbb,critical,true\n"
            "o/r,,low,false\n"  # blank ghsa -> skipped
        )
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="") as fh:
            fh.write(csv_text)
            path = fh.name
        rows = reverify.read_census(path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["ghsa_id"], "GHSA-aaaa")
        self.assertFalse(rows[0]["in_global_db"])
        self.assertTrue(rows[1]["in_global_db"])


class TestClassify(unittest.TestCase):
    def test_still_missing(self):
        self.assertEqual(reverify.classify(False, "missing"), "still_missing")

    def test_imported_since(self):
        self.assertEqual(reverify.classify(False, "present"), "imported_since")

    def test_still_present(self):
        self.assertEqual(reverify.classify(True, "present"), "still_present")

    def test_dropped_since(self):
        self.assertEqual(reverify.classify(True, "missing"), "dropped_since")

    def test_inconclusive(self):
        self.assertEqual(reverify.classify(False, "http_500"), "inconclusive")


class TestRunAndSummarize(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {"repo": "o/r", "ghsa_id": "GHSA-miss1", "severity": "high", "in_global_db": False},
            {"repo": "o/r", "ghsa_id": "GHSA-miss2", "severity": "critical", "in_global_db": False},
            {"repo": "o/r", "ghsa_id": "GHSA-gone", "severity": "high", "in_global_db": False},
            {"repo": "o/r", "ghsa_id": "GHSA-pres1", "severity": "low", "in_global_db": True},
        ]
        # GHSA-gone has since been imported; the present one is still present.
        self._table = {
            "GHSA-miss1": "missing",
            "GHSA-miss2": "missing",
            "GHSA-gone": "present",
            "GHSA-pres1": "present",
        }

    def fake_fetch(self, ghsa):
        return self._table[ghsa]

    def test_run_classifies_every_row(self):
        results = reverify.run(self.rows, self.fake_fetch, pause=0)
        verdicts = [r["verdict"] for r in results]
        self.assertEqual(
            verdicts,
            ["still_missing", "still_missing", "imported_since", "still_present"],
        )

    def test_missing_only_skips_present(self):
        results = reverify.run(self.rows, self.fake_fetch, pause=0, also_present=False)
        self.assertEqual(len(results), 3)
        self.assertTrue(all(not r["in_global_db"] for r in results))

    def test_summary_rates(self):
        results = reverify.run(self.rows, self.fake_fetch, pause=0)
        s = reverify.summarize(results)
        self.assertEqual(s["missing_checked"], 3)
        self.assertEqual(s["still_missing"], 2)
        self.assertEqual(s["imported_since"], 1)
        self.assertAlmostEqual(s["gap_persistence"], 2 / 3)
        # 3 of 4 verdicts agree with the census (the imported-since one changed).
        self.assertAlmostEqual(s["proxy_agreement"], 3 / 4)


if __name__ == "__main__":
    unittest.main()
