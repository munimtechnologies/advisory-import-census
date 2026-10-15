"""Unit tests for blindspot.py. No network: GitHub and OSV are faked."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

import blindspot as bs


class TestVersions(unittest.TestCase):
    def test_ordering(self):
        ordered = ["0.9", "1.0.0rc1", "1.0", "1.0.0.post1", "1.0.1", "1.2.3", "1.10.0", "2"]
        for a, b in zip(ordered, ordered[1:]):
            self.assertEqual(bs.compare_versions(a, b), -1, (a, b))

    def test_equal_with_trailing_zeros_and_prefix(self):
        self.assertEqual(bs.compare_versions("1.0.0", "1"), 0)
        self.assertEqual(bs.compare_versions("v3.1.3", "3.1.3"), 0)
        self.assertEqual(bs.compare_versions("1.2.3+local.7", "1.2.3"), 0)

    def test_prereleases(self):
        self.assertEqual(bs.compare_versions("1.0.0-beta.1", "1.0.0"), -1)
        self.assertEqual(bs.compare_versions("1.0a1", "1.0rc1"), -1)
        self.assertEqual(bs.compare_versions("1.0.dev1", "1.0a1"), -1)

    def test_unparseable(self):
        self.assertIsNone(bs.compare_versions("latest", "1.0"))


class TestRanges(unittest.TestCase):
    def test_github_range_forms(self):
        self.assertTrue(bs.in_range("3.1.3", "<= 3.1.3"))
        self.assertFalse(bs.in_range("3.1.4", "<= 3.1.3"))
        self.assertTrue(bs.in_range("0.27.9", "< 0.28.0"))
        self.assertFalse(bs.in_range("0.28.0", "< 0.28.0"))
        self.assertTrue(bs.in_range("1.5.0", ">= 1.0.0, < 1.6.0"))
        self.assertFalse(bs.in_range("0.9.0", ">= 1.0.0, < 1.6.0"))
        self.assertTrue(bs.in_range("2.0.0", "= 2.0.0"))
        self.assertTrue(bs.in_range("2.5", "< 1.0 || >= 2.0, < 3.0"))

    def test_unknown(self):
        self.assertIsNone(bs.in_range(None, "< 1.0"))
        self.assertIsNone(bs.in_range("1.0", ""))
        self.assertIsNone(bs.in_range("1.0", "< latest"))
        self.assertIsNone(bs.in_range("1.0", "~> 1.0"))


class TestManifests(unittest.TestCase):
    def test_requirements(self):
        text = "\n".join([
            "# comment",
            "vllm==0.10.1",
            "Open_WebUI[all] == 0.6.5 ; python_version >= '3.11'",
            "litellm>=1.0",
            "-r other.txt",
            "--index-url https://example.invalid/simple",
            "git+https://github.com/x/y.git",
            "requests  # unpinned",
            "",
        ])
        self.assertEqual(bs.parse_requirements(text), [
            ("vllm", "0.10.1"), ("Open_WebUI", "0.6.5"), ("litellm", None), ("requests", None)])

    def test_package_lock_v3(self):
        data = {"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/flowise": {"version": "3.1.3"},
            "node_modules/@scope/pkg": {"version": "1.0.0"},
            "node_modules/a/node_modules/flowise": {"version": "2.0.0"},
            "node_modules/linked": {"link": True, "version": "9.9.9"},
        }}
        self.assertEqual(bs.parse_package_lock(data), [
            ("@scope/pkg", "1.0.0"), ("flowise", "2.0.0"), ("flowise", "3.1.3")])

    def test_package_lock_v1(self):
        data = {"lockfileVersion": 1, "dependencies": {
            "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}}
        self.assertEqual(bs.parse_package_lock(data), [("a", "1.0.0"), ("b", "2.0.0")])

    def test_package_json(self):
        data = {"dependencies": {"flowise": "3.1.3", "x": "^1.2.0"},
                "devDependencies": {"y": "=2.0.0"}}
        self.assertEqual(bs.parse_package_json(data), [
            ("flowise", "3.1.3"), ("x", None), ("y", "2.0.0")])

    def test_package_arg(self):
        self.assertEqual(bs.parse_package_arg("pip:vllm==0.10.1"), ("pip", "vllm", "0.10.1"))
        self.assertEqual(bs.parse_package_arg("PyPI:vllm"), ("pip", "vllm", None))
        self.assertEqual(bs.parse_package_arg("npm:flowise@3.1.3"), ("npm", "flowise", "3.1.3"))
        self.assertEqual(bs.parse_package_arg("npm:@scope/x@1.0.0"), ("npm", "@scope/x", "1.0.0"))
        self.assertEqual(bs.parse_package_arg("npm:@scope/x"), ("npm", "@scope/x", None))
        self.assertEqual(bs.parse_package_arg("repo:langgenius/dify@1.4.0"),
                         ("repo", "langgenius/dify", "1.4.0"))
        with self.assertRaises(ValueError):
            bs.parse_package_arg("vllm==1")
        with self.assertRaises(ValueError):
            bs.parse_package_arg("cobol:x==1")


class TestRepoUrls(unittest.TestCase):
    def test_repo_from_urls(self):
        self.assertEqual(bs.repo_from_urls(["git+https://github.com/BerriAI/litellm.git"]),
                         "BerriAI/litellm")
        self.assertEqual(bs.repo_from_urls(["https://litellm.ai",
                                            "https://github.com/BerriAI/litellm/issues"]),
                         "BerriAI/litellm")
        self.assertEqual(bs.repo_from_urls(["git@github.com:vllm-project/vllm.git"]),
                         "vllm-project/vllm")
        self.assertIsNone(bs.repo_from_urls(["https://github.com/sponsors/someone", None, ""]))

    def test_normalize(self):
        self.assertEqual(bs.normalize_name("pip", "Open_WebUI"), "open-webui")
        self.assertEqual(bs.normalize_name("npm", "Flowise"), "flowise")


def adv(ghsa, cve, sev, vulns, summary="s"):
    return {"ghsa_id": ghsa, "cve_id": cve, "severity": sev, "summary": summary,
            "published_at": "2026-08-31T00:00:00Z",
            "html_url": "https://github.com/o/r/security/advisories/" + ghsa,
            "vulnerabilities": vulns}


def vuln(eco, name, rng, fixed):
    return {"package": {"ecosystem": eco, "name": name},
            "vulnerable_version_range": rng, "patched_versions": fixed}


ADVISORIES = {
    "FlowiseAI/Flowise": [
        adv("GHSA-aaaa-aaaa-aaaa", "CVE-2026-1", "critical",
            [vuln("npm", "flowise", "<= 3.1.3", "3.1.4")]),            # blind
        adv("GHSA-bbbb-bbbb-bbbb", None, "high",
            [vuln("npm", "flowise", "<= 3.1.3", "3.1.4")]),            # visible by GHSA
        adv("GHSA-cccc-cccc-cccc", "CVE-2026-3", "medium",
            [vuln("npm", "flowise", "<= 3.1.3", "3.1.4")]),            # visible via CVE alias
        adv("GHSA-dddd-dddd-dddd", None, "high",
            [vuln("npm", "flowise", "< 2.0.0", "2.0.0")]),             # not your version
        adv("GHSA-eeee-eeee-eeee", None, "low",
            [vuln("npm", "flowise-components", "<= 3.1.3", "3.1.4")]),  # other package
    ],
    "langgenius/dify": [
        adv("GHSA-ffff-ffff-ffff", None, "high", [vuln("pip", "dify-api", "< 1.5.0", "1.5.0")]),
        adv("GHSA-gggg-gggg-gggg", None, "medium", []),
        adv("GHSA-hhhh-hhhh-hhhh", None, "low", [vuln("pip", "dify-api", "< 1.0.0", "1.0.0")]),
    ],
}


class TestCheck(unittest.TestCase):
    def run_check(self, deps):
        calls = {"repos": [], "osv": []}

        def get_advisories(repo):
            calls["repos"].append(repo)
            return ADVISORIES.get(repo, [])

        def package_ids(eco, name, version):
            calls["osv"].append((eco, name, version))
            return {"GHSA-bbbb-bbbb-bbbb", "OSV-X", "CVE-2026-3"}

        def id_lookup(vid):
            return {"GHSA-ffff-ffff-ffff"} if vid == "GHSA-ffff-ffff-ffff" else set()

        resolve = lambda eco, name: {"flowise": "FlowiseAI/Flowise"}.get(name.lower())
        return bs.check(deps, resolve, get_advisories, package_ids, id_lookup), calls

    def test_package_mode(self):
        report, calls = self.run_check([("npm", "flowise", "3.1.3"), ("npm", "Flowise", "3.1.3")])
        ids = [(f["ghsa_id"], f["scanner_visible"]) for f in report["findings"]]
        # Same repo listed once; OSV queried once per dependency.
        self.assertEqual(calls["repos"], ["FlowiseAI/Flowise"])
        self.assertEqual(len(calls["osv"]), 2)
        self.assertEqual(len(ids), 6)
        self.assertEqual(set(ids), {("GHSA-aaaa-aaaa-aaaa", False), ("GHSA-bbbb-bbbb-bbbb", True),
                                    ("GHSA-cccc-cccc-cccc", True)})
        # Blind spots sort first.
        self.assertEqual(ids[0], ("GHSA-aaaa-aaaa-aaaa", False))
        self.assertEqual(report["blind_spots"], 2)

    def test_unpinned_is_unknown_not_dropped(self):
        report, _ = self.run_check([("npm", "flowise", None)])
        self.assertEqual(len(report["findings"]), 4)
        self.assertTrue(all(f["affects_your_version"] == "unknown" for f in report["findings"]))

    def test_repo_mode(self):
        report, calls = self.run_check([("repo", "langgenius/dify", "1.4.0")])
        got = {f["ghsa_id"]: f["scanner_visible"] for f in report["findings"]}
        self.assertEqual(got, {"GHSA-ffff-ffff-ffff": True, "GHSA-gggg-gggg-gggg": False})
        self.assertEqual(calls["osv"], [])

    def test_unmapped(self):
        report, _ = self.run_check([("pip", "nothing-here", "1.0")])
        self.assertEqual(report["mapped_to_repo"], 0)
        self.assertEqual(report["unmapped"][0]["package"], "nothing-here")
        self.assertIn("--map", bs.render_text(report))


class TestMain(unittest.TestCase):
    def test_cli_end_to_end_offline(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "package.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"dependencies": {"flowise": "3.1.3"}}, fh)
            with mock.patch.object(bs, "list_repo_advisories",
                                   lambda repo: ADVISORIES.get(repo, [])), \
                 mock.patch.object(bs, "osv_package_ids", lambda e, n, v: {"GHSA-bbbb-bbbb-bbbb"}), \
                 mock.patch.object(bs, "osv_has_id", lambda i: set()), \
                 mock.patch.object(bs, "registry_repo", lambda e, n: None):
                out = io.StringIO()
                with redirect_stdout(out):
                    code = bs.main(["--npm", path, "--json", "--fail-on-blind"])
            report = json.loads(out.getvalue())
            self.assertEqual(code, 1)
            self.assertEqual(report["findings"][0]["repo"], "FlowiseAI/Flowise")
            self.assertEqual(report["findings"][0]["ghsa_id"], "GHSA-aaaa-aaaa-aaaa")


if __name__ == "__main__":
    unittest.main()
