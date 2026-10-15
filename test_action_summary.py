#!/usr/bin/env python3
"""Offline unit tests for action_summary.py (no network, no GitHub runner).

Made with AI agents working for MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import tempfile
import unittest

import action_summary as A


def _finding(**kw):
    base = {
        "ecosystem": "npm", "package": "flowise", "version": "3.1.3",
        "repo": "FlowiseAI/Flowise", "ghsa_id": "GHSA-vcwp-f9rq-3887",
        "cve_id": "", "severity": "critical", "summary": "Authenticated RCE via MCP npx",
        "published_at": "2026-09-01", "vulnerable_range": "<= 3.1.4", "patched": "?",
        "affects_your_version": "yes", "scanner_visible": False, "ignored": False, "url":
        "https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-vcwp-f9rq-3887",
    }
    base.update(kw)
    return base


def _report(findings, **kw):
    blind = [f for f in findings if not f["scanner_visible"] and not f.get("ignored")]
    rep = {
        "dependencies_checked": 1, "mapped_to_repo": 1, "repos_with_advisories": 1,
        "advisories_that_apply": len(findings), "blind_spots": len(blind),
        "ignored_blind_spots": 0, "findings": findings, "unmapped": [],
    }
    rep.update(kw)
    return rep


class TestTruthy(unittest.TestCase):
    def test_true_values(self):
        for v in ("1", "true", "TRUE", "Yes", " on "):
            self.assertTrue(A.truthy(v))

    def test_false_values(self):
        for v in ("0", "false", "no", "", None, "maybe"):
            self.assertFalse(A.truthy(v))


class TestRender(unittest.TestCase):
    def test_blind_spot_listed_first_with_link(self):
        md = A.render_markdown(_report([_finding()]))
        self.assertIn("1 blind spot", md)
        self.assertNotIn("blind spots", md)  # singular, not plural
        self.assertIn("GHSA-vcwp-f9rq-3887", md)
        self.assertIn("(https://github.com/FlowiseAI/Flowise/security/advisories/"
                      "GHSA-vcwp-f9rq-3887)", md)
        self.assertIn("`flowise`", md)

    def test_plural_count(self):
        md = A.render_markdown(_report([_finding(), _finding(ghsa_id="GHSA-x7x8-95gh-42xm")]))
        self.assertIn("2 blind spots", md)

    def test_no_blind_spots(self):
        md = A.render_markdown(_report([_finding(scanner_visible=True)]))
        self.assertIn("No blind spots", md)
        # a visible advisory goes in the collapsed section, not the blind list
        self.assertIn("that apply and OSV does report", md)

    def test_cve_and_ghsa_both_shown(self):
        md = A.render_markdown(_report([_finding(cve_id="CVE-2026-100606")]))
        self.assertIn("GHSA-vcwp-f9rq-3887 / CVE-2026-100606", md)

    def test_pipe_in_summary_is_escaped(self):
        md = A.render_markdown(_report([_finding(summary="a | b")]))
        self.assertIn("a \\| b", md)

    def test_unclear_range_annotated(self):
        md = A.render_markdown(_report([_finding(affects_your_version="unknown")]))
        self.assertIn("range unclear", md)

    def test_unmapped_reported(self):
        rep = _report([], unmapped=[{"ecosystem": "pip", "package": "mystery", "version": None}])
        md = A.render_markdown(rep)
        self.assertIn("No GitHub repo found", md)
        self.assertIn("`mystery`", md)

    def test_long_summary_truncated(self):
        md = A.render_markdown(_report([_finding(summary="x" * 200)]))
        self.assertIn("…", md)
        self.assertNotIn("x" * 200, md)

    def test_accepted_blind_spot_in_its_own_section(self):
        rep = _report([_finding(ignored=True)], blind_spots=0, ignored_blind_spots=1)
        md = A.render_markdown(rep)
        # The gate is clean (the only gap was accepted), but it is still shown.
        self.assertIn("No blind spots", md)
        self.assertIn("accepted with `ignore`", md)
        self.assertIn("1 accepted blind spot", md)
        self.assertIn("GHSA-vcwp-f9rq-3887", md)

    def test_accepted_alongside_a_real_blind_spot(self):
        rep = _report([_finding(), _finding(ghsa_id="GHSA-x7x8-95gh-42xm", ignored=True)],
                      blind_spots=1, ignored_blind_spots=1)
        md = A.render_markdown(rep)
        self.assertIn("1 blind spot", md)  # the un-accepted one
        self.assertIn("1 accepted blind spot", md)

    def test_unchecked_repos_make_the_report_incomplete(self):
        rep = _report([_finding(scanner_visible=True)],
                      unchecked_repos=["langgenius/dify", "o/other"])
        md = A.render_markdown(rep)
        self.assertIn("Incomplete: 2 repos not checked", md)
        self.assertIn("`langgenius/dify`, `o/other`", md)
        self.assertIn("No blind spots in the repos that were checked", md)

    def test_long_unchecked_list_is_capped(self):
        repos = ["o/r%d" % i for i in range(A.MAX_UNCHECKED_LISTED + 5)]
        md = A.render_markdown(_report([], unchecked_repos=repos))
        self.assertIn("and 5 more", md)
        self.assertNotIn("`o/r%d`" % (A.MAX_UNCHECKED_LISTED + 4), md)

    def test_old_report_without_unchecked_key(self):
        md = A.render_markdown(_report([_finding(scanner_visible=True)]))
        self.assertNotIn("Incomplete", md)


class TestMain(unittest.TestCase):
    def _run(self, report, fail_on_blind):
        tmp = tempfile.mkdtemp()
        report_path = os.path.join(tmp, "report.json")
        summary_path = os.path.join(tmp, "summary.md")
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh)
        old = dict(os.environ)
        os.environ["GITHUB_STEP_SUMMARY"] = summary_path
        os.environ["BLINDSPOT_FAIL_ON_BLIND"] = fail_on_blind
        try:
            rc = A.main([report_path])
        finally:
            os.environ.clear()
            os.environ.update(old)
        with open(summary_path, encoding="utf-8") as fh:
            return rc, fh.read()

    def test_fail_on_blind_exits_1(self):
        rc, summary = self._run(_report([_finding()]), "true")
        self.assertEqual(rc, 1)
        self.assertIn("blind spot", summary)

    def test_no_fail_when_disabled(self):
        rc, _ = self._run(_report([_finding()]), "false")
        self.assertEqual(rc, 0)

    def test_clean_report_exits_0(self):
        rc, summary = self._run(_report([_finding(scanner_visible=True)]), "true")
        self.assertEqual(rc, 0)
        self.assertIn("No blind spots", summary)

    def test_accepted_only_passes_the_gate(self):
        rep = _report([_finding(ignored=True)], blind_spots=0, ignored_blind_spots=1)
        rc, summary = self._run(rep, "true")
        self.assertEqual(rc, 0)
        self.assertIn("accepted", summary)

    def test_incomplete_check_fails_the_gate(self):
        rep = _report([_finding(scanner_visible=True)], unchecked_repos=["langgenius/dify"])
        rc, summary = self._run(rep, "true")
        self.assertEqual(rc, 1)  # no blind spot found, but not everything was checked
        self.assertIn("Incomplete", summary)
        rc, _ = self._run(rep, "false")
        self.assertEqual(rc, 0)

    def test_missing_arg_returns_2(self):
        self.assertEqual(A.main([]), 2)


if __name__ == "__main__":
    unittest.main()
