"""Offline unit tests (fixtures only, no network) for the application-vs-library
census frame builder and census. Run with `python -m unittest -v`.
Apache-2.0, made with AI agents working for MV2 of Munim, Inc."""
import datetime as dt
import unittest

import build_frame as bf
import app_library_census as c


class TestYaml(unittest.TestCase):
    SAMPLE = (
        "# a comment\n"
        "name: Gitea\n"
        'source_code_url: "https://github.com/go-gitea/gitea"\n'
        "stargazers_count: 58536\n"
        "archived: false\n"
        "tags:\n"
        "  - Software Development\n"
        "  - Git\n"
        "licenses:\n"
        "  - MIT\n"
        "description: A painless self-hosted Git service.\n"
    )

    def test_scalars_extracted(self):
        d = bf.parse_flat_yaml(self.SAMPLE)
        self.assertEqual(d["name"], "Gitea")
        self.assertEqual(d["source_code_url"], "https://github.com/go-gitea/gitea")
        self.assertEqual(d["stargazers_count"], "58536")
        self.assertEqual(d["archived"], "false")

    def test_block_lists_skipped(self):
        d = bf.parse_flat_yaml(self.SAMPLE)
        self.assertNotIn("tags", d)   # block list value is empty -> skipped
        self.assertNotIn("licenses", d)
        self.assertNotIn("Software Development", d)  # indented, never a key

    def test_as_int_bool(self):
        self.assertEqual(bf._as_int("58536"), 58536)
        self.assertIsNone(bf._as_int("not-a-number"))
        self.assertIsNone(bf._as_int(None))
        self.assertTrue(bf._as_bool("true"))
        self.assertTrue(bf._as_bool("Yes"))
        self.assertFalse(bf._as_bool("false"))
        self.assertFalse(bf._as_bool(None))


class TestRepoNorm(unittest.TestCase):
    def test_variants(self):
        self.assertEqual(bf.normalize_repo("https://github.com/go-gitea/gitea"),
                         "go-gitea/gitea")
        self.assertEqual(bf.normalize_repo("https://github.com/npm/node-semver.git"),
                         "npm/node-semver")
        self.assertEqual(bf.normalize_repo("git+https://github.com/lodash/lodash"),
                         "lodash/lodash")

    def test_rejects(self):
        self.assertIsNone(bf.normalize_repo("https://gitlab.com/foo/bar"))
        self.assertIsNone(bf.normalize_repo(""))
        self.assertIsNone(bf.normalize_repo(None))
        self.assertIsNone(bf.normalize_repo("https://github.com/sponsors/someone"))


class TestLibMetric(unittest.TestCase):
    def test_metric_priority(self):
        key, val = bf._dependents_metric(
            {"dependent_repos_count": 10, "dependent_packages_count": 5})
        self.assertEqual((key, val), ("dependent_repos_count", 10))
        key, val = bf._dependents_metric({"dependent_packages_count": 7})
        self.assertEqual((key, val), ("dependent_packages_count", 7))
        self.assertEqual(bf._dependents_metric({})[1], None)

    def test_archived(self):
        self.assertTrue(bf._lib_archived({"repo_metadata": {"archived": True}}))
        self.assertFalse(bf._lib_archived({"repo_metadata": {"archived": False}}))
        self.assertFalse(bf._lib_archived({}))


def adv(ghsa, cves=(), severity="high", pub="2026-06-01T00:00:00Z", pkgs=()):
    return {
        "ghsa_id": ghsa, "state": "published", "severity": severity,
        "published_at": pub, "html_url": "https://x/%s" % ghsa,
        "identifiers": [{"type": "CVE", "value": v} for v in cves],
        "vulnerabilities": [{"package": {"ecosystem": "npm", "name": p}} for p in pkgs],
    }


class TestClassify(unittest.TestCase):
    def test_visible_by_own_ghsa(self):
        osv = {"GH1": {"affected": [{"package": {"ecosystem": "npm", "name": "foo"}}]}}
        own, pkgs, blind = c.classify(adv("GH1"), lambda v: osv.get(v))
        self.assertTrue(own)
        self.assertEqual(pkgs, ["npm:foo"])
        self.assertFalse(blind)

    def test_visible_by_cve_alias(self):
        osv = {"CVE-2026-1": {"affected": [{"package": {"ecosystem": "pypi", "name": "bar"}}]}}
        own, pkgs, blind = c.classify(adv("GH2", cves=["CVE-2026-1"]),
                                      lambda v: osv.get(v))
        self.assertFalse(own)         # GHSA not in OSV
        self.assertEqual(pkgs, ["pypi:bar"])
        self.assertFalse(blind)       # but rescued via CVE alias

    def test_blind_no_package_anywhere(self):
        osv = {"GH3": {"affected": [{"package": {}}]}}  # record names no package
        own, pkgs, blind = c.classify(adv("GH3", cves=["CVE-2026-2"]),
                                      lambda v: osv.get(v))
        self.assertTrue(own)
        self.assertEqual(pkgs, [])
        self.assertTrue(blind)

    def test_blind_nothing_in_osv(self):
        own, pkgs, blind = c.classify(adv("GH4"), lambda v: None)
        self.assertFalse(own)
        self.assertTrue(blind)

    def test_cve_extraction(self):
        self.assertEqual(c.advisory_cves(adv("GH5", cves=["CVE-2026-9"])), ["CVE-2026-9"])
        self.assertEqual(c.advisory_repo_packages(adv("GH6", pkgs=["flowise"])),
                         ["npm:flowise"])


class TestStats(unittest.TestCase):
    def test_wilson_and_share(self):
        s = c.share([{"scanner_class": "scanner_blind"}] * 3
                    + [{"scanner_class": "scanner_visible"}], c.is_blind)
        self.assertEqual((s["k"], s["n"], s["pct"]), (3, 4, 75.0))
        self.assertEqual(len(s["ci95"]), 2)
        self.assertEqual(c.wilson(0, 0), None)

    def _rows(self):
        # apps heavily blind, libs not -> a large, detectable difference
        rows = []
        for repo in ("a/app1", "a/app2", "a/app3"):
            rows += [{"group": "application", "repo": repo,
                      "scanner_class": "scanner_blind", "own_id_in_osv": "False",
                      "period": "from_2026_05"} for _ in range(8)]
        for repo in ("l/lib1", "l/lib2", "l/lib3"):
            rows += [{"group": "library", "repo": repo,
                      "scanner_class": "scanner_visible", "own_id_in_osv": "True",
                      "period": "from_2026_05"} for _ in range(8)]
        return rows

    def test_permutation_deterministic_and_directional(self):
        rows = self._rows()
        r1 = c.permutation_test(rows, c.is_blind)
        r2 = c.permutation_test(rows, c.is_blind)
        self.assertEqual(r1, r2)                      # seeded -> reproducible
        self.assertEqual(r1["difference_pct_points"], 100.0)
        self.assertEqual(r1["repositories"], 6)
        self.assertLess(r1["p_two_sided"], 0.2)       # 3 vs 3, min p = 1/20

    def test_repo_median_and_heaviest(self):
        rows = self._rows()
        self.assertEqual(c.repo_median_pct(
            [r for r in rows if r["group"] == "application"], c.is_blind), 100.0)
        rows.append({"group": "application", "repo": "a/app1",
                     "scanner_class": "scanner_visible", "own_id_in_osv": "True",
                     "period": "from_2026_05"})
        self.assertEqual(c.heaviest_repo(rows, "application"), "a/app1")

    def test_summarise_shape(self):
        out = c.summarise(self._rows(),
                          {"application": 3, "library": 3}, True, "2026-10-17T00:00:00+00:00")
        self.assertEqual(out["groups"]["application"]["blind"]["pct"], 100.0)
        self.assertEqual(out["groups"]["library"]["blind"]["pct"], 0.0)
        self.assertIn("drop_heaviest_repo_each_group", out["robustness"])
        self.assertTrue(out["osv_canary"]["resolved"])


class TestAge(unittest.TestCase):
    def test_age_days(self):
        now = dt.datetime(2026, 10, 17, tzinfo=dt.timezone.utc)
        self.assertAlmostEqual(
            c.iso_age_days("2026-10-03T00:00:00Z", now), 14.0, places=3)


if __name__ == "__main__":
    unittest.main()
