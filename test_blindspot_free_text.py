"""Advisories whose package name is free text (blindspot 0.9.1)."""
import unittest

import blindspot as bs


def adv(ghsa, cve, sev, vulns):
    return {"ghsa_id": ghsa, "cve_id": cve, "severity": sev, "summary": "s",
            "published_at": "2026-08-21T00:00:00Z",
            "html_url": "https://github.com/traefik/traefik/security/advisories/" + ghsa,
            "vulnerabilities": vulns}


def vuln(eco, name, rng, fixed):
    return {"package": {"ecosystem": eco, "name": name},
            "vulnerable_version_range": rng, "patched_versions": fixed}


# Traefik's maintainers name the package "Traefik", not the Go module path
# github.com/traefik/traefik/v3, in their repository advisories (e.g. the
# critical GHSA-5w68-77r2-r64c), so an exact name match dropped them all.
TRAEFIK = {
    "traefik/traefik": [
        adv("GHSA-tr11-1111-1111", None, "critical",
            [vuln("go", "Traefik", "<= 3.5.2", "3.5.3")]),                  # free text, blind
        adv("GHSA-tr22-2222-2222", "CVE-2027-2", "high",
            [vuln("go", "Traefik", "<= 3.5.2", "3.5.3")]),                  # free text, OSV has it
        adv("GHSA-tr33-3333-3333", None, "high",
            [vuln("go", "Traefik", "< 2.11.0", "2.11.0")]),                 # not your version
        adv("GHSA-tr44-4444-4444", None, "high",
            [vuln("go", "github.com/traefik/traefik/v2", "<= 3.5.2", "3.5.3")]),  # another module
        adv("GHSA-tr55-5555-5555", None, "medium",
            [vuln("npm", "Traefik Dashboard", "<= 3.5.2", "3.5.3")]),       # another ecosystem
        adv("GHSA-tr66-6666-6666", None, "low", []),                        # names no package
    ],
}
DEP = ("go", "github.com/traefik/traefik/v3", "v3.5.0")


def run(deps, advisories=TRAEFIK, osv_ids=("CVE-2027-2",)):
    return bs.check(deps, lambda eco, name: bs.go_module_repo(name),
                    lambda repo: advisories.get(repo, []),
                    lambda eco, name, version: set(osv_ids), lambda vid: set())


class TestFreeTextName(unittest.TestCase):
    def test_free_text_package(self):
        for eco, name in (("go", "Traefik"), ("go", "gitea.dev"), ("go", "SAML"),
                          ("go", "The Go Programming Language"), ("pip", "Home Assistant"),
                          ("pip", "bentoml/BentoML"), ("npm", "Traefik Dashboard")):
            self.assertTrue(bs.free_text_package(eco, name), (eco, name))
        for eco, name in (("go", "github.com/traefik/traefik/v3"), ("go", "code.gitea.io/gitea"),
                          ("pip", "Open_WebUI"), ("pip", "zope.interface"), ("npm", "@scope/x"),
                          ("npm", "Flowise"), ("go", ""), ("pip", None)):
            self.assertFalse(bs.free_text_package(eco, name), (eco, name))


class TestFreeTextCheck(unittest.TestCase):
    def test_free_text_advisories_are_reported(self):
        report = run([DEP])
        got = {f["ghsa_id"]: f["scanner_visible"] for f in report["findings"]}
        # tr33 is out of range; tr44 names another module, tr55 another
        # ecosystem and tr66 no package at all, so none of them applies.
        self.assertEqual(got, {"GHSA-tr11-1111-1111": False, "GHSA-tr22-2222-2222": True})
        self.assertEqual(report["blind_spots"], 1)
        first = report["findings"][0]
        self.assertEqual(first["ghsa_id"], "GHSA-tr11-1111-1111")  # blind spots sort first
        self.assertEqual(first["affects_your_version"], "yes")
        self.assertTrue(all(f["package_named"] is False for f in report["findings"]))

    def test_exact_name_wins_over_free_text(self):
        both = {"traefik/traefik": [adv("GHSA-tr77-7777-7777", None, "high", [
            vuln("go", "Traefik", "<= 9.0.0", "9.0.1"),
            vuln("go", "github.com/traefik/traefik/v3", "< 3.0.0", "3.0.0")])]}
        # The exact entry decides: v3.5.0 is outside "< 3.0.0", so nothing applies.
        self.assertEqual(run([DEP], advisories=both)["findings"], [])

    def test_exact_name_is_marked_named(self):
        named = {"traefik/traefik": [adv("GHSA-tr88-8888-8888", None, "high",
                                         [vuln("go", "github.com/traefik/traefik/v3",
                                               "<= 3.5.2", "3.5.3")])]}
        report = run([DEP], advisories=named)
        self.assertIs(report["findings"][0]["package_named"], True)
        self.assertNotIn("free text", bs.render_text(report))

    def test_repo_mode_unchanged(self):
        # repo: mode takes every advisory of the repo, as before.
        report = run([("repo", "traefik/traefik", None)])
        self.assertEqual(len(report["findings"]), 6)
        self.assertTrue(all(f["package_named"] is True for f in report["findings"]))

    def test_text_and_sarif_say_free_text(self):
        report = run([DEP])
        self.assertIn("names its package only in free text", bs.render_text(report))
        run_ = bs.render_sarif(report, lambda f: ("go.mod", 3, 40))["runs"][0]
        self.assertEqual([r["ruleId"] for r in run_["results"]], ["GHSA-tr11-1111-1111"])
        self.assertIn("only in free text", run_["results"][0]["message"]["text"])
        self.assertEqual(run_["tool"]["driver"]["semanticVersion"], bs.__version__)


if __name__ == "__main__":
    unittest.main()
