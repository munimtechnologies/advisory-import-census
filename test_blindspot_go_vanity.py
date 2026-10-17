"""Tests for Go vanity-host module mapping in blindspot.py (v0.9.2).

Before 0.9.2, a Go module whose path was not github.com/OWNER/REPO was always
reported "unmapped", so its maintainer's GitHub repository security advisories
were never checked -- even for gopkg.in packages (in almost every Go project)
and well-known vanity hosts such as Gitea. These tests pin the new behaviour:

  - gopkg.in follows its own documented redirect rule
    (gopkg.in/pkg.vN -> github.com/go-pkg/pkg; gopkg.in/user/pkg.vN ->
    github.com/user/pkg), verified at https://gopkg.in (2026-10-17);
  - a small map of vanity hosts verified from each project's go.mod
    `module` line (2026-10-17): code.gitea.io/gitea and gitea.dev ->
    go-gitea/gitea; gorm.io/gorm -> go-gorm/gorm;
  - everything else (golang.org/x/..., private hosts) stays unmapped, so the
    tool never guesses a repo.

Offline only: no network, no tokens.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import blindspot as bs  # noqa: E402


class TestGopkgInRule(unittest.TestCase):
    def test_short_form(self):
        # gopkg.in/pkg.vN -> github.com/go-pkg/pkg
        self.assertEqual(bs.gopkg_in_repo("gopkg.in/yaml.v3"), "go-yaml/yaml")
        self.assertEqual(bs.gopkg_in_repo("gopkg.in/yaml.v2"), "go-yaml/yaml")
        self.assertEqual(bs.gopkg_in_repo("gopkg.in/ini.v1"), "go-ini/ini")
        self.assertEqual(bs.gopkg_in_repo("gopkg.in/check.v1"), "go-check/check")

    def test_user_form(self):
        # gopkg.in/user/pkg.vN -> github.com/user/pkg
        self.assertEqual(bs.gopkg_in_repo("gopkg.in/natefinch/lumberjack.v2"),
                         "natefinch/lumberjack")
        self.assertEqual(bs.gopkg_in_repo("gopkg.in/square/go-jose.v2"),
                         "square/go-jose")

    def test_nested_subpackage_does_not_change_repo(self):
        self.assertEqual(bs.gopkg_in_repo("gopkg.in/DataDog/dd-trace-go.v1/ddtrace"),
                         "DataDog/dd-trace-go")

    def test_not_gopkg_or_no_version(self):
        self.assertIsNone(bs.gopkg_in_repo("github.com/foo/bar"))
        self.assertIsNone(bs.gopkg_in_repo("gopkg.in/yaml"))   # no .vN selector
        self.assertIsNone(bs.gopkg_in_repo("gopkg.in"))
        self.assertIsNone(bs.gopkg_in_repo(""))
        self.assertIsNone(bs.gopkg_in_repo(None))


class TestGoVanityRepos(unittest.TestCase):
    def test_gitea_release_and_current_module_paths(self):
        # go.mod module line: v1.22.x releases say code.gitea.io/gitea,
        # current main says gitea.dev; both are the same project.
        self.assertEqual(bs.go_module_repo("code.gitea.io/gitea"), "go-gitea/gitea")
        self.assertEqual(bs.go_module_repo("gitea.dev"), "go-gitea/gitea")

    def test_gorm(self):
        self.assertEqual(bs.go_module_repo("gorm.io/gorm"), "go-gorm/gorm")

    def test_major_version_suffix_tolerated(self):
        # A /vN major-version element on a mapped vanity path still resolves.
        self.assertEqual(bs.go_module_repo("code.gitea.io/gitea/v2"), "go-gitea/gitea")

    def test_gopkg_in_routed_through_go_module_repo(self):
        self.assertEqual(bs.go_module_repo("gopkg.in/yaml.v3"), "go-yaml/yaml")
        self.assertEqual(bs.go_module_repo("gopkg.in/natefinch/lumberjack.v2"),
                         "natefinch/lumberjack")

    def test_github_and_unmapped_unchanged(self):
        # Existing behaviour must not regress.
        self.assertEqual(bs.go_module_repo("github.com/gin-gonic/gin"), "gin-gonic/gin")
        self.assertEqual(bs.go_module_repo("github.com/foo/bar/v2"), "foo/bar")
        self.assertIsNone(bs.go_module_repo("golang.org/x/text"))
        self.assertIsNone(bs.go_module_repo("example.com/private/thing"))
        self.assertIsNone(bs.go_module_repo(""))


class TestVanityBlindSpotEndToEnd(unittest.TestCase):
    """A gopkg.in dependency now maps to a repo, so a maintainer advisory OSV
    does not report is surfaced as a blind spot (fully offline)."""

    def test_gopkg_in_dependency_blind_spot(self):
        advisories = {
            "go-yaml/yaml": [{
                "ghsa_id": "GHSA-yyyy-0000-0000",
                "cve_id": "CVE-2026-00000",
                "severity": "high",
                "summary": "example gopkg.in/yaml.v3 advisory",
                "html_url": "https://github.com/go-yaml/yaml/security/advisories/GHSA-yyyy-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "gopkg.in/yaml.v3"},
                    "vulnerable_version_range": "< 3.0.2",
                    "patched_versions": "3.0.2",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "gopkg.in/yaml.v3", "v3.0.1")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "go-yaml/yaml")
        self.assertEqual(f["ghsa_id"], "GHSA-yyyy-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertTrue(f["package_named"])
        self.assertFalse(f["scanner_visible"])


if __name__ == "__main__":
    unittest.main()
