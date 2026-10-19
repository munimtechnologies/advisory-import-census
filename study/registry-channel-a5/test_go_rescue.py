"""Offline unit tests for registry-channel A5 (no network).

Covers the go-module probe helpers, the OSV-name parser, and the pre-registered
permutation machinery on synthetic data with a known answer. Run:
    python -m unittest -v test_go_rescue
Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import unittest

import go_rescue_census as C
import go_rescue_analysis as A


class TestProbeHelpers(unittest.TestCase):
    def test_proxy_escape(self):
        self.assertEqual(C.go_proxy_escape("github.com/grafana/grafana"),
                         "github.com/grafana/grafana")
        self.assertEqual(C.go_proxy_escape("github.com/TryGhost/Ghost"),
                         "github.com/!try!ghost/!ghost")
        self.assertEqual(C.go_proxy_escape("github.com/ClickHouse/ClickHouse"),
                         "github.com/!click!house/!click!house")

    def test_parse_module_line(self):
        self.assertEqual(C.parse_module_line("module github.com/a/b\n\ngo 1.21\n"),
                         "github.com/a/b")
        self.assertEqual(C.parse_module_line('module "github.com/a/b"\n'),
                         "github.com/a/b")
        self.assertEqual(C.parse_module_line("module github.com/a/b // comment\n"),
                         "github.com/a/b")
        self.assertEqual(C.parse_module_line("module (\n  github.com/a/b\n)\n"),
                         "github.com/a/b")
        self.assertIsNone(C.parse_module_line("go 1.21\nrequire x v1\n"))
        self.assertIsNone(C.parse_module_line(""))

    def test_module_path_is_repo(self):
        self.assertTrue(C.module_path_is_repo("github.com/grafana/grafana",
                                              "grafana/grafana"))
        self.assertTrue(C.module_path_is_repo("github.com/a/b/v2", "a/b"))
        self.assertTrue(C.module_path_is_repo("github.com/A/B", "a/b"))  # case
        # prefix guard: a/b must not match a/b-extra
        self.assertFalse(C.module_path_is_repo("github.com/a/b-extra", "a/b"))
        self.assertFalse(C.module_path_is_repo("gitlab.com/a/b", "a/b"))
        self.assertFalse(C.module_path_is_repo(None, "a/b"))

    def test_decide_go_module(self):
        self.assertTrue(C.decide_go_module(True, False))
        self.assertTrue(C.decide_go_module(False, True))
        self.assertTrue(C.decide_go_module(True, True))
        self.assertFalse(C.decide_go_module(False, False))


class TestOsvNameParser(unittest.TestCase):
    def test_parse_osv_pkgs(self):
        self.assertEqual(A.parse_osv_pkgs("Go:github.com/grafana/grafana"),
                         [("Go", "github.com/grafana/grafana")])
        self.assertEqual(A.parse_osv_pkgs("npm:a;pip:b"),
                         [("npm", "a"), ("pip", "b")])
        self.assertEqual(A.parse_osv_pkgs(""), [])

    def test_names_repo_go_module(self):
        self.assertTrue(A.names_repo_go_module(
            {"repo": "grafana/grafana", "osv_packages": "Go:github.com/grafana/grafana"}))
        self.assertTrue(A.names_repo_go_module(
            {"repo": "a/b", "osv_packages": "Go:github.com/a/b/v2"}))
        # Packagist rescue is NOT a repo-path go module
        self.assertFalse(A.names_repo_go_module(
            {"repo": "grokability/snipe-it", "osv_packages": "Packagist:snipe/snipe-it"}))
        # a Go module that is NOT this repo's path
        self.assertFalse(A.names_repo_go_module(
            {"repo": "a/b", "osv_packages": "Go:github.com/other/thing"}))


def _rows(repo, registry_group, go_module, n, n_visible, osv="Go:github.com/x/y"):
    out = []
    for i in range(n):
        vis = i < n_visible
        out.append({
            "registry_group": registry_group, "repo": repo,
            "ghsa_id": "GHSA-%s-%d" % (repo.replace("/", "-"), i),
            "cve_id": "", "go_module": str(go_module),
            "scanner_class": "scanner_visible" if vis else "scanner_blind",
            "osv_packages": osv if vis else "", "advisory_ecosystems": "",
        })
    return out


class TestAnalysis(unittest.TestCase):
    def test_direction_and_shares_small_frame(self):
        rows = []
        rows += _rows("a/go1", "no_registry", True, 5, 4,
                      "Go:github.com/a/go1")
        rows += _rows("a/go2", "no_registry", True, 3, 3,
                      "Go:github.com/a/go2")
        rows += _rows("b/nogo1", "no_registry", False, 10, 0)
        rows += _rows("b/nogo2", "no_registry", False, 8, 1, "npm:thing")
        rows += _rows("c/reg1", "registry", False, 5, 5, "Packagist:snipe/x")
        out = A.analyse(rows)
        p1 = out["P1_primary_no_registry"]
        self.assertEqual(p1["visible_shares"]["go"]["k"], 7)
        self.assertEqual(p1["visible_shares"]["go"]["n"], 8)
        self.assertEqual(p1["visible_shares"]["not_go"]["k"], 1)
        self.assertEqual(p1["visible_shares"]["not_go"]["n"], 18)
        self.assertGreater(p1["permutation"]["difference_pct_points"], 0)
        self.assertTrue(0 < p1["permutation"]["p_two_sided"] <= 1)
        # registry repo excluded from the no_registry primary
        self.assertEqual(out["counts"]["no_registry_software_typed"], 26)
        # P3: every go-visible advisory names a repo-path Go module; the npm one does not
        self.assertEqual(out["P3_rescue_channel"]["go"]["names_repo_go_module"], 7)
        self.assertEqual(out["P3_rescue_channel"]["not_go"]["names_repo_go_module"], 0)

    def test_significance_large_frame(self):
        rows = []
        for i in range(6):
            rows += _rows("go/r%d" % i, "no_registry", True, 5, 5,
                          "Go:github.com/go/r%d" % i)
        for i in range(6):
            rows += _rows("nogo/r%d" % i, "no_registry", False, 5, 0)
        out = A.analyse(rows)
        pm = out["P1_primary_no_registry"]["permutation"]
        self.assertEqual(pm["repositories"], 12)
        self.assertAlmostEqual(pm["difference_pct_points"], 100.0, places=1)
        self.assertLess(pm["p_two_sided"], 0.05)


if __name__ == "__main__":
    unittest.main()
