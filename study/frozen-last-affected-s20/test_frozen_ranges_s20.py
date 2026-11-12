# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. Made by AI agents working for MV2 of Munim, Inc.
import unittest
from collections import defaultdict

import frozen_ranges_s20 as s

D = s.parse_ts

# crates.io release dates of `coreutils`, as served by crates.io on 2026-11-12.
COREUTILS = [
    ("0.12.0", D("2026-09-17T11:27:06Z"), False),
    ("0.11.0", D("2026-09-01T06:41:53Z"), False),
    ("0.10.0", D("2026-08-05T21:26:27Z"), False),
    ("0.9.0", D("2026-05-30T21:54:59Z"), False),
    ("0.8.0", D("2026-04-07T06:01:54Z"), False),
    ("0.7.0", D("2026-03-09T21:13:50Z"), False),
]

# GHSA-q6m9-xj2w-xmrc as served by api.osv.dev on 2026-11-12 (trimmed).
Q6M9 = {
    "id": "GHSA-q6m9-xj2w-xmrc", "published": "2026-04-22T18:31:45Z",
    "modified": "2026-09-10T03:51:02Z", "aliases": ["CVE-2026-35360"],
    "affected": [{"package": {"name": "coreutils", "ecosystem": "crates.io"},
                  "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "0.8.0"}]}]}],
    "database_specific": {"github_reviewed_at": "2026-04-30T17:30:18Z", "severity": "MODERATE"},
}


def other(id_, aliases, events, name="coreutils", eco="crates.io"):
    return {"id": id_, "aliases": aliases,
            "affected": [{"package": {"name": name, "ecosystem": eco},
                          "ranges": [{"type": "SEMVER", "events": events}]}]}


class Versions(unittest.TestCase):
    def test_semver_order(self):
        k = s.semver_key
        self.assertLess(k("0.9.0"), k("0.10.0"))
        self.assertLess(k("1.0.0-beta.2"), k("1.0.0-beta.11"))
        self.assertLess(k("1.0.0-beta.11"), k("1.0.0"))
        self.assertLess(k("1.0.0-alpha"), k("1.0.0-alpha.1"))
        self.assertEqual(k("1.2"), k("1.2.0"))
        self.assertTrue(s.semver_is_pre("0.26.0-beta.1"))
        self.assertFalse(s.semver_is_pre("0.26.0+build.5"))

    def test_covers_last_affected_inclusive(self):
        aff = Q6M9["affected"][0]
        self.assertTrue(s.covers("crates.io", aff, "0.8.0"))
        self.assertTrue(s.covers("crates.io", aff, "0.1.0"))
        self.assertFalse(s.covers("crates.io", aff, "0.9.0"))

    def test_covers_fixed_exclusive_and_versions_list(self):
        aff = {"package": {"name": "x", "ecosystem": "crates.io"}, "versions": ["2.0.0"],
               "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.4.0"}]}]}
        self.assertTrue(s.covers("crates.io", aff, "1.3.9"))
        self.assertFalse(s.covers("crates.io", aff, "1.4.0"))
        self.assertFalse(s.covers("crates.io", aff, "0.9.0"))
        self.assertTrue(s.covers("crates.io", aff, "2.0.0"))

    def test_open_range(self):
        aff = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}
        self.assertTrue(s.covers("crates.io", aff, "99.0.0"))

    def test_git_ranges_ignored(self):
        aff = {"ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc"}]}]}
        self.assertFalse(s.covers("crates.io", aff, "1.0.0"))


class Ends(unittest.TestCase):
    def test_only_last_affected_ends(self):
        rec = {"affected": [
            {"package": {"name": "a", "ecosystem": "crates.io"},
             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "1.0.0"}]},
                        {"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.1.0"}]}]},
            {"package": {"name": "b", "ecosystem": "PyPI"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "3"}]}]}]}
        got = [(a["package"]["name"], v) for a, v in s.last_affected_ends(rec, "crates.io")]
        self.assertEqual(got, [("a", "1.0.0")])


class Classify(unittest.TestCase):
    def test_positive_control_uutils(self):
        row = s.classify("crates.io", Q6M9, Q6M9["affected"][0], "0.8.0", COREUTILS, [])
        self.assertTrue(row["frozen"])
        self.assertEqual(row["newest_stable_at_publish"], "0.8.0")
        self.assertEqual(row["first_later_uncovered"], "0.9.0")
        self.assertEqual(row["first_later_date"], "2026-05-30")
        self.assertEqual(row["n_later_uncovered"], 4)
        self.assertEqual(row["latest_version"], "0.12.0")
        self.assertEqual(row["reviewed"], "2026-04-30")
        self.assertEqual(row["n_disputed"], 0)
        self.assertEqual(s.positive_control([row]), {"coreutils_0.8.0_rows": 1, "frozen_with_0.9.0_first_later": 1})

    def test_disputed_by_second_db(self):
        rs = other("RUSTSEC-2026-9999", ["CVE-2026-35360"], [{"introduced": "0"}, {"fixed": "0.10.0"}])
        row = s.classify("crates.io", Q6M9, Q6M9["affected"][0], "0.8.0", COREUTILS, [rs])
        self.assertEqual(row["n_disputed"], 1)
        self.assertEqual(row["disputed_sample"], "0.9.0")
        self.assertEqual(row["other_db_fixed"], "0.10.0")
        self.assertEqual(row["other_db_ids"], "RUSTSEC-2026-9999")

    def test_second_db_other_package_ignored(self):
        rs = other("RUSTSEC-2026-9998", ["CVE-2026-35360"], [{"introduced": "0"}], name="uu_touch")
        row = s.classify("crates.io", Q6M9, Q6M9["affected"][0], "0.8.0", COREUTILS, [rs])
        self.assertEqual(row["n_disputed"], 0)
        self.assertEqual(row["other_db_ids"], "")

    def test_not_frozen_when_newer_release_existed(self):
        rec = dict(Q6M9, database_specific={"github_reviewed_at": "2026-06-10T00:00:00Z"})
        row = s.classify("crates.io", rec, rec["affected"][0], "0.8.0", COREUTILS, [])
        self.assertFalse(row["frozen"])
        self.assertEqual(row["newest_stable_at_publish"], "0.9.0")

    def test_later_range_covers(self):
        rec = dict(Q6M9, affected=[dict(Q6M9["affected"][0], ranges=[
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "0.8.0"}]},
            {"type": "SEMVER", "events": [{"introduced": "0.9.0"}, {"fixed": "0.11.0"}]}])])
        row = s.classify("crates.io", rec, rec["affected"][0], "0.8.0", COREUTILS, [])
        self.assertEqual(row["n_later_uncovered"], 2)
        self.assertEqual(row["first_later_uncovered"], "0.11.0")

    def test_yanked_and_prerelease(self):
        rel = COREUTILS + [("0.13.0", D("2026-10-01T00:00:00Z"), True),
                           ("0.13.0-rc.1", D("2026-09-20T00:00:00Z"), False)]
        row = s.classify("crates.io", Q6M9, Q6M9["affected"][0], "0.8.0", rel, [])
        self.assertEqual(row["n_later_uncovered"], 5)
        self.assertEqual(row["n_later_uncovered_stable"], 4)
        self.assertEqual(row["latest_version"], "0.13.0-rc.1")

    def test_summarize(self):
        rs = other("RUSTSEC-2026-9999", ["CVE-2026-35360"], [{"introduced": "0"}, {"fixed": "0.10.0"}])
        row = s.classify("crates.io", Q6M9, Q6M9["affected"][0], "0.8.0", COREUTILS, [rs])
        got = s.summarize([row])
        self.assertEqual(got["frozen"], 1)
        self.assertEqual(got["disputed"], 1)
        self.assertEqual(got["frozen_and_later_uncovered_stable"], 1)
        self.assertEqual(got.get("disputed_high_or_critical", 0), 0)


class Registry(unittest.TestCase):
    def test_pypi_doc(self):
        doc = {"releases": {
            "1.0": [{"upload_time_iso_8601": "2024-01-02T03:04:05.000000Z", "yanked": False},
                    {"upload_time_iso_8601": "2024-01-01T03:04:05.000000Z", "yanked": False}],
            "1.1": [{"upload_time_iso_8601": "2024-02-01T00:00:00Z", "yanked": True}],
            "1.2": []}}
        got = {v: (d.date().isoformat() if d else None, y) for v, d, y in s.pypi_releases_from_doc(doc)}
        self.assertEqual(got, {"1.0": ("2024-01-01", False), "1.1": ("2024-02-01", True), "1.2": (None, False)})

    def test_link_others_by_cve_and_ghsa(self):
        a = other("RUSTSEC-1", ["CVE-2026-35360"], [])
        b = other("RUSTSEC-2", ["GHSA-q6m9-xj2w-xmrc"], [])
        c = other("RUSTSEC-3", ["CVE-1999-0001"], [])
        idx = defaultdict(list)
        for o in (a, b, c):
            for k in set(o["aliases"]) | {o["id"]}:
                idx[k].append(o)
        got = sorted(o["id"] for o in s.link_others(Q6M9, idx))
        self.assertEqual(got, ["RUSTSEC-1", "RUSTSEC-2"])

    def test_norm_name(self):
        self.assertEqual(s.norm_name("PyPI", "Foo_Bar.baz"), "foo-bar-baz")
        self.assertEqual(s.norm_name("crates.io", "Foo_Bar"), "Foo_Bar")


if __name__ == "__main__":
    unittest.main()
