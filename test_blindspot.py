"""Unit tests for blindspot.py. No network: GitHub and OSV are faked."""
import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
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

    def test_pyproject_pep621(self):
        data = {"project": {
            "dependencies": ["vllm==0.10.1", "litellm>=1.0", "requests"],
            "optional-dependencies": {
                "all": ["Open_WebUI[all]==0.6.5 ; python_version >= '3.11'"]}}}
        self.assertEqual(bs.parse_pyproject(data), [
            ("vllm", "0.10.1"), ("litellm", None), ("requests", None),
            ("Open_WebUI", "0.6.5")])

    def test_pyproject_poetry(self):
        data = {"tool": {"poetry": {
            "dependencies": {"python": "^3.9", "requests": "^2.0",
                             "vllm": "==0.10.1", "flowise": {"version": "3.1.3"}},
            "group": {"dev": {"dependencies": {"pytest": "^7.0"}}}}}}
        self.assertEqual(bs.parse_pyproject(data), [
            ("requests", None), ("vllm", "0.10.1"), ("flowise", None),
            ("pytest", None)])

    def test_pyproject_load_toml(self):
        text = "\n".join([
            '[project]',
            'name = "demo"',
            'dependencies = ["vllm==0.10.1", "litellm>=1.0"]',
            '[project.optional-dependencies]',
            'extra = ["requests==2.31.0"]',
        ])
        self.assertEqual(bs.parse_pyproject(bs.load_toml(text)), [
            ("vllm", "0.10.1"), ("litellm", None), ("requests", "2.31.0")])


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


FINGERPRINT_RE = re.compile(r"^[0-9a-f]{16}:1$")


class TestSarif(unittest.TestCase):
    def report(self, deps):
        return TestCheck.run_check(self, deps)[0]

    def test_find_line(self):
        text = "# open-webui pinned below\nflowise-components==1.0\nOpen_WebUI[all]==0.6.5\n"
        self.assertEqual(bs.find_line(text, "pip", "open-webui"), (3, 22))
        self.assertIsNone(bs.find_line("flowise-components==1.0\n", "npm", "flowise"))
        lock = '{\n  "dependencies": {\n    "@scope/x": "1.0.0"\n  }\n}'
        self.assertEqual(bs.find_line(lock, "npm", "@scope/x")[0], 3)
        self.assertIsNone(bs.find_line("", "pip", "vllm"))

    def test_sarif_uri(self):
        self.assertEqual(bs.sarif_uri("./sub\\requirements.txt"), "sub/requirements.txt")
        self.assertEqual(bs.sarif_uri(os.path.join(os.getcwd(), "a", "b.txt")), "a/b.txt")

    def test_blind_spot_becomes_security_result(self):
        report = self.report([("npm", "flowise", "3.1.3")])
        sarif = bs.render_sarif(report, lambda f: ("package.json", 3, 25))
        json.dumps(sarif)  # serialisable
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "advisory-blindspot")
        # Only the blind spot: OSV-visible advisories are already alerted on.
        self.assertEqual([r["ruleId"] for r in run["results"]], ["GHSA-aaaa-aaaa-aaaa"])
        rule = run["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["id"], "GHSA-aaaa-aaaa-aaaa")
        self.assertEqual(rule["properties"]["security-severity"], "9.5")
        self.assertIn("security", rule["properties"]["tags"])
        self.assertTrue(rule["helpUri"].endswith("GHSA-aaaa-aaaa-aaaa"))
        for key in ("shortDescription", "fullDescription", "help"):
            self.assertTrue(rule[key]["text"])
        res = run["results"][0]
        self.assertEqual((res["level"], res["ruleIndex"]), ("error", 0))
        loc = res["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "package.json")
        self.assertEqual((loc["region"]["startLine"], loc["region"]["endColumn"]), (3, 26))
        self.assertIn("CVE-2026-1", res["message"]["text"])
        self.assertIn("fixed in 3.1.4", res["message"]["text"])
        fp = res["partialFingerprints"]["primaryLocationLineHash"]
        self.assertRegex(fp, FINGERPRINT_RE)
        again = bs.render_sarif(report, lambda f: ("package.json", 9, 1))
        # Stable across runs, even if the manifest line moves.
        self.assertEqual(again["runs"][0]["results"][0]["partialFingerprints"]
                         ["primaryLocationLineHash"], fp)

    def test_one_rule_per_advisory(self):
        report = self.report([("npm", "flowise", "3.1.3"), ("npm", "flowise", "3.1.2")])
        run = bs.render_sarif(report, lambda f: ("package-lock.json", 1, 0))["runs"][0]
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)
        self.assertEqual(len(run["results"]), 2)
        fps = {r["partialFingerprints"]["primaryLocationLineHash"] for r in run["results"]}
        self.assertEqual(len(fps), 2)
        self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]["region"]
                         ["endColumn"], 2)

    def test_no_blind_spots_still_writes_a_run(self):
        report = self.report([("pip", "nothing-here", "1.0")])
        run = bs.render_sarif(report, lambda f: ("x", 1, 0))["runs"][0]
        self.assertEqual((run["results"], run["tool"]["driver"]["rules"]), ([], []))

    def test_repo_mode_message(self):
        report = self.report([("repo", "langgenius/dify", "1.4.0")])
        run = bs.render_sarif(report, lambda f: ("ci.yml", 6, 30))["runs"][0]
        self.assertEqual([r["ruleId"] for r in run["results"]], ["GHSA-gggg-gggg-gggg"])
        res = run["results"][0]
        self.assertEqual(res["level"], "warning")
        self.assertIn("OSV.dev does not carry this advisory", res["message"]["text"])
        self.assertIn("no patched version is listed", res["message"]["text"])
        self.assertIn("not pinned", res["message"]["text"])
        self.assertEqual(run["tool"]["driver"]["rules"][0]["properties"]["security-severity"],
                         "5.5")


def offline():
    """Patch every network call of main() with the fake advisories."""
    return [mock.patch.object(bs, "list_repo_advisories", lambda repo: ADVISORIES.get(repo, [])),
            mock.patch.object(bs, "osv_package_ids", lambda e, n, v: {"GHSA-bbbb-bbbb-bbbb"}),
            mock.patch.object(bs, "osv_has_id", lambda i: set()),
            mock.patch.object(bs, "registry_repo", lambda e, n: None)]


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

    def test_cli_pyproject_offline(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "pyproject.toml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('[project]\nname = "demo"\n'
                         'dependencies = ["dify-api==1.4.0"]\n')
            with mock.patch.object(bs, "list_repo_advisories",
                                   lambda repo: ADVISORIES.get(repo, [])), \
                 mock.patch.object(bs, "osv_package_ids",
                                   lambda e, n, v: {"GHSA-bbbb-bbbb-bbbb"}), \
                 mock.patch.object(bs, "osv_has_id", lambda i: set()), \
                 mock.patch.object(bs, "registry_repo",
                                   lambda e, n: "langgenius/dify" if n == "dify-api" else None):
                out = io.StringIO()
                with redirect_stdout(out):
                    code = bs.main(["--pyproject", path, "--json"])
            report = json.loads(out.getvalue())
            self.assertEqual(report["dependencies_checked"], 1)
            self.assertEqual({f["ghsa_id"] for f in report["findings"]},
                             {"GHSA-ffff-ffff-ffff"})

    def run_in(self, d, argv):
        old = os.getcwd()
        patches = offline()
        os.chdir(d)
        try:
            for p in patches:
                p.start()
            with redirect_stdout(io.StringIO()):
                return bs.main(argv)
        finally:
            for p in patches:
                p.stop()
            os.chdir(old)

    def test_cli_sarif_points_at_manifest_line(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "package.json"), "w", encoding="utf-8") as fh:
                json.dump({"dependencies": {"flowise": "3.1.3"}}, fh, indent=2)
            code = self.run_in(d, ["--npm", "package.json", "--sarif", "out.sarif"])
            with open(os.path.join(d, "out.sarif"), encoding="utf-8") as fh:
                run = json.load(fh)["runs"][0]
        self.assertEqual(code, 0)
        # The offline OSV fake reports only GHSA-bbbb, so -cccc (CVE alias) is blind here too.
        self.assertEqual([r["ruleId"] for r in run["results"]],
                         ["GHSA-aaaa-aaaa-aaaa", "GHSA-cccc-cccc-cccc"])
        loc = run["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "package.json")
        self.assertEqual(loc["region"]["startLine"], 3)

    def test_cli_sarif_package_specs_point_at_anchor(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".github", "workflows"))
            with open(os.path.join(d, ".github", "workflows", "ci.yml"), "w",
                      encoding="utf-8") as fh:
                fh.write("jobs:\n  x:\n    steps:\n"
                         "      - uses: munimtechnologies/advisory-import-census@v0.5.0\n"
                         "        with:\n"
                         "          packages: \"npm:flowise@3.1.3\"\n")
            self.run_in(d, ["--package", "npm:flowise@3.1.3", "--sarif", "out.sarif",
                            "--sarif-anchor", ".github/workflows/ci.yml"])
            with open(os.path.join(d, "out.sarif"), encoding="utf-8") as fh:
                run = json.load(fh)["runs"][0]
        loc = run["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], ".github/workflows/ci.yml")
        self.assertEqual(loc["region"]["startLine"], 6)

    def test_cli_sarif_package_specs_need_an_anchor(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            bs.main(["--package", "npm:flowise@3.1.3", "--sarif", "never-written.sarif"])
        self.assertFalse(os.path.exists("never-written.sarif"))


if __name__ == "__main__":
    unittest.main()
