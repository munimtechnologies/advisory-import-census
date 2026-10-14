"""Unit tests for the pure helpers in census.py. No network, no clone."""
import unittest
from datetime import datetime, timezone

import census


class TestHelpers(unittest.TestCase):
    def test_ghsa_regex_matches_real_ids(self):
        for ghsa in ("GHSA-q5vh-j6x8-9f53", "GHSA-63x5-9mcr-7447",
                     "GHSA-mjgh-prrr-9qw5", "GHSA-vcwp-f9rq-3887"):
            m = census.GHSA_RE.search(f"advisories/github-reviewed/2026/08/{ghsa}/{ghsa}.json")
            self.assertIsNotNone(m, ghsa)
            self.assertEqual(m.group(0), ghsa)

    def test_ghsa_regex_rejects_non_ghsa(self):
        self.assertIsNone(census.GHSA_RE.search("advisories/README.md"))
        self.assertIsNone(census.GHSA_RE.search("CVE-2026-91931"))

    def test_next_link_parses_rel_next(self):
        header = ('<https://api.github.com/x?after=A>; rel="next", '
                  '<https://api.github.com/x?after=Z>; rel="last"')
        self.assertEqual(census.next_link(header),
                         "https://api.github.com/x?after=A")

    def test_next_link_none_when_absent(self):
        self.assertIsNone(census.next_link('<https://x>; rel="prev"'))
        self.assertIsNone(census.next_link(""))

    def test_days_between_positive(self):
        now = datetime(2026, 10, 14, tzinfo=timezone.utc)
        self.assertEqual(census.days_between("2026-10-04T00:00:00Z", now), 10.0)

    def test_days_between_bad_input(self):
        now = datetime(2026, 10, 14, tzinfo=timezone.utc)
        self.assertIsNone(census.days_between("not-a-date", now))

    def test_target_repos_unique_and_nonempty(self):
        self.assertTrue(len(census.TARGET_REPOS) >= 20)
        self.assertEqual(len(census.TARGET_REPOS), len(set(census.TARGET_REPOS)))
        for r in census.TARGET_REPOS:
            self.assertRegex(r, r"^[^/]+/[^/]+$")


if __name__ == "__main__":
    unittest.main()
