# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. Made by AI agents working for MV2 of Munim, Inc.
import unittest

import prerelease_gap_s21 as s


def rec(rid, ranges, name="demo", aliases=(), versions=()):
    return {"id": rid, "aliases": list(aliases),
            "affected": [{"package": {"ecosystem": "crates.io", "name": name},
                          "ranges": [{"type": "SEMVER", "events": ev} for ev in ranges],
                          "versions": list(versions)}]}


def rel(*vs, yanked=()):
    return [(v, None, v in yanked) for v in vs]


HICKORY_LIKE = rel("0.25.2", "0.26.0-alpha.1", "0.26.0-beta.1", "0.26.0", "0.26.1", "0.26.2")


class Order(unittest.TestCase):
    def test_prerelease_sorts_before_release(self):
        self.assertLess(s.semver_key("0.26.0-beta.1"), s.semver_key("0.26.0"))
        self.assertLess(s.semver_key("0.26.0-alpha.2"), s.semver_key("0.26.0-alpha.10"))
        self.assertLess(s.semver_key("0.26.0-alpha.9"), s.semver_key("0.26.0-beta.1"))
        self.assertLess(s.semver_key("0.25.9"), s.semver_key("0.26.0-alpha.1"))
        self.assertIsNone(s.semver_key("not-a-version"))

    def test_build_metadata_ignored(self):
        self.assertEqual(s.semver_key("1.0.0+abc"), s.semver_key("1.0.0"))


class Gap(unittest.TestCase):
    def test_introduced_stable_leaves_out_prereleases(self):
        r = rec("GHSA-a", [[{"introduced": "0.26.0"}, {"fixed": "0.26.2"}]])
        rows, _ = s.analyse(r, HICKORY_LIKE, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["gap_pre"], "0.26.0-alpha.1 0.26.0-beta.1")
        self.assertFalse(rows[0]["bound_unpublished"])

    def test_unpublished_bound(self):
        r = rec("GHSA-b", [[{"introduced": "0.25.0"}, {"fixed": "0.25.2"}]])
        rows, _ = s.analyse(r, rel("0.24.4", "0.25.0-alpha.1", "0.25.0-alpha.3", "0.25.1", "0.25.2"), [])
        self.assertTrue(rows[0]["bound_unpublished"])
        self.assertEqual(rows[0]["n_gap_pre"], 2)

    def test_other_range_covers_prereleases(self):
        r = rec("GHSA-c", [[{"introduced": "0.26.0-alpha.1"}, {"fixed": "0.26.0"}],
                           [{"introduced": "0.26.0"}, {"fixed": "0.26.2"}]])
        rows, _ = s.analyse(r, HICKORY_LIKE, [])
        self.assertEqual(rows, [])

    def test_explicit_versions_list_covers(self):
        r = rec("GHSA-d", [[{"introduced": "0.26.0"}, {"fixed": "0.26.2"}]],
                versions=("0.26.0-alpha.1", "0.26.0-beta.1"))
        rows, _ = s.analyse(r, HICKORY_LIKE, [])
        self.assertEqual(rows, [])

    def test_yanked_prerelease_ignored(self):
        r = rec("GHSA-e", [[{"introduced": "0.26.0"}, {"fixed": "0.26.2"}]])
        rows, _ = s.analyse(r, rel("0.26.0-alpha.1", "0.26.0", "0.26.2", yanked=("0.26.0-alpha.1",)), [])
        self.assertEqual(rows, [])

    def test_zero_introduced_is_not_a_gap(self):
        r = rec("GHSA-f", [[{"introduced": "0"}, {"fixed": "0.26.2"}]])
        rows, _ = s.analyse(r, HICKORY_LIKE, [])
        self.assertEqual(rows, [])

    def test_prerelease_bound_is_not_checked(self):
        r = rec("GHSA-g", [[{"introduced": "0.26.0-beta.1"}, {"fixed": "0.26.2"}]])
        rows, _ = s.analyse(r, HICKORY_LIKE, [])
        self.assertEqual(rows, [])

    def test_other_minor_prereleases_not_counted(self):
        r = rec("GHSA-h", [[{"introduced": "0.26.1"}, {"fixed": "0.26.2"}]])
        rows, _ = s.analyse(r, HICKORY_LIKE, [])
        self.assertEqual(rows, [])

    def test_rustsec_link(self):
        g = rec("GHSA-i", [[{"introduced": "0.26.0"}, {"fixed": "0.26.2"}]], aliases=("CVE-1",))
        rs = rec("RUSTSEC-2026-0001", [[{"introduced": "0"}, {"fixed": "0.26.2"}]], aliases=("GHSA-i",))
        rows, _ = s.analyse(g, HICKORY_LIKE, [rs])
        self.assertEqual(rows[0]["rustsec_ids"], "RUSTSEC-2026-0001")
        self.assertEqual(rows[0]["n_rustsec_covers"], 2)

    def test_rustsec_other_package_ignored(self):
        g = rec("GHSA-j", [[{"introduced": "0.26.0"}, {"fixed": "0.26.2"}]])
        rs = rec("RUSTSEC-2026-0002", [[{"introduced": "0"}]], name="other")
        rows, _ = s.analyse(g, HICKORY_LIKE, [rs])
        self.assertEqual(rows[0]["rustsec_ids"], "")
        self.assertEqual(rows[0]["n_rustsec_covers"], 0)

    def test_last_affected_end(self):
        r = rec("GHSA-k", [[{"introduced": "0.26.0"}, {"last_affected": "0.26.1"}]])
        rows, _ = s.analyse(r, HICKORY_LIKE, [])
        self.assertEqual(rows[0]["end_kind"], "last_affected")
        self.assertEqual(rows[0]["n_gap_pre"], 2)


class FixedSide(unittest.TestCase):
    def test_fixed_stable_counts_prereleases_affected(self):
        r = rec("GHSA-l", [[{"introduced": "0"}, {"fixed": "0.26.0"}]])
        _, fx = s.analyse(r, HICKORY_LIKE, [])
        self.assertEqual(len(fx), 1)
        self.assertEqual(fx[0]["n_pre_counted_affected"], 2)
        self.assertTrue(fx[0]["fixed_published"])

    def test_fixed_without_prereleases(self):
        r = rec("GHSA-m", [[{"introduced": "0"}, {"fixed": "0.26.2"}]])
        _, fx = s.analyse(r, HICKORY_LIKE, [])
        self.assertEqual(fx, [])


class Summary(unittest.TestCase):
    def test_summary_counts(self):
        r = rec("GHSA-n", [[{"introduced": "0.25.0"}, {"fixed": "0.25.2"}]], aliases=("CVE-9",))
        rows, fx = s.analyse(r, rel("0.25.0-alpha.1", "0.25.1", "0.25.2"), [])
        st = s.summarize(rows, fx, 1, 1)
        self.assertEqual(st["gap_rows"], 1)
        self.assertEqual(st["bound_unpublished_rows"], 1)
        self.assertEqual(st["bound_unpublished_with_gap"], 1)
        self.assertEqual(st["gap_ghsa_records"], 1)

    def test_needs_lookup(self):
        self.assertEqual(s.needs_lookup(rec("GHSA-o", [[{"introduced": "0"}, {"fixed": "1.0.0"}]])), {"demo"})
        self.assertEqual(s.needs_lookup(rec("GHSA-p", [[{"introduced": "0"}, {"fixed": "1.0.0-rc.1"}]])), set())


if __name__ == "__main__":
    unittest.main()
