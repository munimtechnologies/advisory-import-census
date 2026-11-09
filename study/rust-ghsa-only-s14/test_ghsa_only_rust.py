# SPDX-License-Identifier: Apache-2.0
"""Offline tests for ghsa_only_rust.py (study S14). Every record is made up; no network.
Made with AI agents working in MV2's (Munim, Inc.) name."""
import csv
import io
import json
import os
import tempfile
import unittest
import zipfile

import ghsa_only_rust as m


def ghsa(i, crate="foo", published="2025-03-01T00:00:00Z", aliases=(), related=(), refs=(),
         reviewed=True, withdrawn=None, severity="HIGH", cwes=("CWE-79",), eco="crates.io"):
    rec = {
        "id": i, "published": published, "aliases": list(aliases), "related": list(related),
        "affected": [{"package": {"ecosystem": eco, "name": crate}}],
        "references": [{"type": "WEB", "url": u} for u in refs],
        "database_specific": {"github_reviewed": reviewed, "severity": severity, "cwe_ids": list(cwes),
                              "github_reviewed_at": published},
    }
    if withdrawn:
        rec["withdrawn"] = withdrawn
    return rec


def rustsec(i, crate="foo", aliases=(), related=(), withdrawn=None):
    rec = {"id": i, "aliases": list(aliases), "related": list(related),
           "affected": [{"package": {"ecosystem": "crates.io", "name": crate}}]}
    if withdrawn:
        rec["withdrawn"] = withdrawn
    return rec


def make_zip(recs):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for r in recs:
            zf.writestr(r["id"] + ".json", json.dumps(r))
        zf.writestr("README.txt", "not json")
    return buf.getvalue()


RA = "https://github.com/o/r/security/advisories/GHSA-2222-3333-4444"

FIXTURE = [
    ghsa("GHSA-aaaa-0001-0001", aliases=["RUSTSEC-2025-0001"]),                      # alias_in_ghsa
    ghsa("GHSA-aaaa-0002-0002"),                                                       # alias_in_rustsec
    rustsec("RUSTSEC-2025-0002", aliases=["GHSA-AAAA-0002-0002"]),
    ghsa("GHSA-aaaa-0003-0003", aliases=["CVE-2025-1003"]),                            # shared_cve
    rustsec("RUSTSEC-2025-0003", aliases=["cve-2025-1003"]),
    ghsa("GHSA-aaaa-0004-0004", refs=["https://rustsec.org/advisories/RUSTSEC-2021-0004.html"]),  # reference
    ghsa("GHSA-aaaa-0005-0005", aliases=["CVE-2025-1005"]),                            # covered_withdrawn
    rustsec("RUSTSEC-2025-0005", aliases=["CVE-2025-1005"], withdrawn="2025-06-01T00:00:00Z"),
    ghsa("GHSA-aaaa-0006-0006", crate="bar", refs=[RA], severity="CRITICAL"),          # ghsa_only
    ghsa("GHSA-aaaa-0007-0007", crate="baz", published="2020-05-01T00:00:00Z", severity="LOW",
         cwes=("CWE-400",)),                                                           # ghsa_only, old, dos
    ghsa("GHSA-aaaa-0008-0008", published="2026-10-20T00:00:00Z"),                     # after cutoff
    ghsa("GHSA-aaaa-0009-0009", reviewed=False),                                       # not eligible
    ghsa("GHSA-aaaa-0010-0010", withdrawn="2025-01-01T00:00:00Z"),                     # not eligible
    ghsa("GHSA-aaaa-0011-0011", eco="PyPI"),                                           # not eligible
    ghsa("GHSA-aaaa-0012-0012", published="2020-06-01T00:00:00Z", related=["RUSTSEC-2020-0012"]),  # old, covered
    rustsec("RUSTSEC-2024-0099", crate="foo"),
]


class Classify(unittest.TestCase):
    def setUp(self):
        self.rows, self.counts = m.classify(m.load_records(make_zip(FIXTURE)))
        self.by = {r["ghsa_id"]: r for r in self.rows}

    def test_eligibility(self):
        self.assertEqual(self.counts["eligible_ghsa"], 9)
        for gone in ("GHSA-aaaa-0009-0009", "GHSA-aaaa-0010-0010", "GHSA-aaaa-0011-0011"):
            self.assertNotIn(gone, self.by)
        self.assertEqual(self.counts["rustsec_records"], 4)

    def test_reasons(self):
        want = {
            "GHSA-aaaa-0001-0001": ("COVERED", "alias_in_ghsa"),
            "GHSA-aaaa-0002-0002": ("COVERED", "alias_in_rustsec"),
            "GHSA-aaaa-0003-0003": ("COVERED", "shared_cve"),
            "GHSA-aaaa-0004-0004": ("COVERED", "reference"),
            "GHSA-aaaa-0005-0005": ("COVERED_WITHDRAWN", "shared_cve"),
            "GHSA-aaaa-0006-0006": ("GHSA_ONLY", ""),
            "GHSA-aaaa-0007-0007": ("GHSA_ONLY", ""),
            "GHSA-aaaa-0008-0008": ("GHSA_ONLY", ""),
            "GHSA-aaaa-0012-0012": ("COVERED", "alias_in_ghsa"),
        }
        for k, v in want.items():
            self.assertEqual((self.by[k]["status"], self.by[k]["reason"]), v, k)

    def test_row_fields(self):
        r = self.by["GHSA-aaaa-0006-0006"]
        self.assertEqual((r["repo_advisory"], r["severity"], r["crates"], r["crate_in_rustsec"]),
                         ("yes", "CRITICAL", "bar", "no"))
        r = self.by["GHSA-aaaa-0007-0007"]
        self.assertEqual((r["dos_like"], r["published"]), ("yes", "2020-05-01"))
        self.assertEqual(self.by["GHSA-aaaa-0008-0008"]["crate_in_rustsec"], "yes")
        self.assertEqual(self.by["GHSA-aaaa-0003-0003"]["cve_ids"], "CVE-2025-1003")


class Grade(unittest.TestCase):
    def test_grade(self):
        rows, _ = m.classify(m.load_records(make_zip(FIXTURE)))
        graded, only, preds, sample = m.grade(rows)
        self.assertEqual(len(graded), 8)                       # 0008 is after the cutoff
        self.assertEqual(sorted(r["ghsa_id"] for r in only), ["GHSA-aaaa-0006-0006", "GHSA-aaaa-0007-0007"])
        p2 = preds["P2_recent_minus_old_at_least_10pts"]
        self.assertEqual((p2["recent"]["n"], p2["recent"]["ghsa_only"]), (6, 1))
        self.assertEqual((p2["old"]["n"], p2["old"]["ghsa_only"]), (2, 1))
        self.assertFalse(p2["held"])
        self.assertEqual(preds["P1_ghsa_only_at_least_100"], {"value": 2, "held": False})
        self.assertEqual(preds["P3_repo_advisory_share_at_least_50pct"]["held"], True)
        self.assertEqual(preds["P4_high_or_critical_share_at_least_30pct"]["held"], True)
        self.assertEqual(preds["P5_distinct_crates_at_least_50"]["value"], 2)
        self.assertEqual(sample, ["GHSA-aaaa-0006-0006", "GHSA-aaaa-0007-0007"])

    def test_sample_is_seeded(self):
        rows = [{"ghsa_id": "GHSA-x-%03d" % i, "status": "GHSA_ONLY", "published": "2025-01-02",
                 "repo_advisory": "no", "severity": "LOW", "crates": "c%d" % i} for i in range(40)]
        a = m.grade(rows)[3]
        b = m.grade(list(reversed(rows)))[3]
        self.assertEqual(a, b)
        self.assertEqual(len(a), 8)


class Run(unittest.TestCase):
    def test_gate_fails_on_small_input(self):
        with tempfile.TemporaryDirectory() as d:
            res = m.run(make_zip(FIXTURE), d, {"source": "fixture"})
            self.assertFalse(res["gate"]["passed"])
            self.assertNotIn("predictions", res)
            self.assertTrue(os.path.exists(os.path.join(d, "rows.csv")))
            self.assertIn("Gate: FAILED", open(os.path.join(d, "RESULTS-job.md"), encoding="utf-8").read())

    def test_gate_passes_and_writes_outputs(self):
        old = (m.GATE_MIN_RUSTSEC, m.GATE_MIN_GHSA)
        m.GATE_MIN_RUSTSEC, m.GATE_MIN_GHSA = 1, 1
        try:
            with tempfile.TemporaryDirectory() as d:
                res = m.run(make_zip(FIXTURE), d, {"source": "fixture"})
                self.assertTrue(res["gate"]["passed"])
                self.assertEqual(res["ghsa_only"], 2)
                self.assertEqual(res["exploratory"]["ghsa_only_on_or_after_cutoff"], 1)
                with open(os.path.join(d, "rows.csv"), newline="", encoding="utf-8") as fh:
                    self.assertEqual(len(list(csv.DictReader(fh))), 9)
                with open(os.path.join(d, "rows.csv"), "rb") as fh:
                    self.assertNotIn(b"\r\n", fh.read())
                with open(os.path.join(d, "sample.csv"), newline="", encoding="utf-8") as fh:
                    self.assertEqual(len(list(csv.DictReader(fh))), 2)
                json.load(open(os.path.join(d, "results.json"), encoding="utf-8"))
        finally:
            m.GATE_MIN_RUSTSEC, m.GATE_MIN_GHSA = old

    def test_main_with_local_zip(self):
        with tempfile.TemporaryDirectory() as d:
            z = os.path.join(d, "x.zip")
            with open(z, "wb") as fh:
                fh.write(make_zip(FIXTURE))
            import contextlib
            with contextlib.redirect_stdout(io.StringIO()):
                code = m.main(["--zip", z, "--out-dir", os.path.join(d, "out"), "--data-dir", os.path.join(d, "data")])
            self.assertEqual(code, 3)
            self.assertTrue(os.path.exists(os.path.join(d, "out", "results.json")))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(m.main(["--version"]), 0)
            self.assertEqual(buf.getvalue().strip(), "ghsa_only_rust.py 0.1.0")


if __name__ == "__main__":
    unittest.main()
