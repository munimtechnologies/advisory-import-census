"""Offline unit tests for registry-channel A6 (no network).

Covers the frozen frame (fresh: no overlap with any earlier frame), the repo-metadata
parser, frame hygiene, the join, the language robustness grouping, and the
pre-registered tests on synthetic data with a known answer. Needs the published A5
modules (go_rescue_census.py, go_rescue_analysis.py) beside it. Run:
    python -m unittest -v test_oos_go_rescue
Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import json
import os
import unittest

import oos_go_rescue as O

HERE = os.path.dirname(os.path.abspath(__file__))

# Every application used in an earlier frame: app-vs-library + A2 (27) and A1/A3/A4/A5 (32).
EARLIER_APPS = {
    "n8n-io/n8n", "coder/code-server", "9001/copyparty", "getsentry/sentry",
    "payloadcms/payload", "laurent22/joplin", "DIYgod/RSSHub", "gogs/gogs",
    "syncthing/syncthing", "usememos/memos", "pocketbase/pocketbase",
    "lobehub/lobehub", "immich-app/immich", "Stirling-Tools/Stirling-PDF",
    "hoppscotch/hoppscotch", "dani-garcia/vaultwarden", "pi-hole/pi-hole",
    "penpot/penpot", "makeplane/plane", "twentyhq/twenty", "huginn/huginn",
    "calcom/cal.diy", "siyuan-note/siyuan", "paperless-ngx/paperless-ngx",
    "RocketChat/Rocket.Chat", "LibreChat-AI/LibreChat",
    "reactive-resume/reactive-resume",
    "open-webui/open-webui", "strapi/strapi", "nocodb/nocodb", "go-gitea/gitea",
    "TryGhost/Ghost", "apache/superset", "directus/directus",
    "firefly-iii/firefly-iii", "grokability/snipe-it", "element-hq/synapse",
    "netbox-community/netbox", "louislam/uptime-kuma", "grafana/grafana",
    "coollabsio/coolify", "jellyfin/jellyfin", "appwrite/appwrite",
    "mastodon/mastodon", "ClickHouse/ClickHouse", "metabase/metabase",
    "discourse/discourse", "janhq/jan", "ToolJet/ToolJet", "appsmithorg/appsmith",
    "outline/outline", "mattermost/mattermost", "keycloak/keycloak",
    "nextcloud/server", "goharbor/harbor", "requarks/wiki", "jenkinsci/jenkins",
    "zulip/zulip", "goauthentik/authentik",
}
# Candidates dropped before freezing because they ship a live Packagist app release.
REGISTRY_DROPPED = {"kimai/kimai", "pterodactyl/panel", "thorsten/phpMyFAQ",
                    "librenms/librenms"}


class TestFrame(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(HERE, "frame_apps.json"), encoding="utf-8") as f:
            self.frame = [e["repo"] for e in json.load(f)]

    def test_size_and_unique(self):
        self.assertEqual(len(self.frame), 30)
        self.assertEqual(len({r.lower() for r in self.frame}), 30)

    def test_fresh(self):
        earlier = {r.lower() for r in EARLIER_APPS}
        self.assertEqual(len(EARLIER_APPS), 59)
        self.assertEqual([r for r in self.frame if r.lower() in earlier], [])

    def test_registry_apps_not_in_frame(self):
        dropped = {r.lower() for r in REGISTRY_DROPPED}
        self.assertEqual([r for r in self.frame if r.lower() in dropped], [])


class TestRepoMeta(unittest.TestCase):
    def test_ok(self):
        m = O.parse_repo_meta(200, json.dumps({"archived": False, "language": "Go",
                                               "full_name": "a/B"}), "a/b")
        self.assertIs(m["archived"], False)
        self.assertEqual(m["language"], "Go")
        self.assertFalse(m["renamed"])  # case-only difference is not a rename

    def test_renamed_and_archived(self):
        m = O.parse_repo_meta(200, json.dumps({"archived": True, "language": "PHP",
                                               "full_name": "new/name"}), "old/name")
        self.assertTrue(m["renamed"])
        self.assertFalse(O.included(m))

    def test_failed_lookup_is_unknown_not_archived(self):
        m = O.parse_repo_meta(403, "rate limited", "a/b")
        self.assertIsNone(m["archived"])
        self.assertIsNone(m["language"])
        self.assertTrue(O.included(m))
        self.assertIsNone(O.parse_repo_meta(200, "not json", "a/b")["archived"])


def _census(repo, n, n_vis, ptype, osv, age=200.0, cve="", own="True"):
    out = []
    for i in range(n):
        vis = i < n_vis
        out.append({"repo": repo, "ghsa_id": "GHSA-%s-%s-%d" % (repo, ptype, i),
                    "cve_id": cve, "published_at": "2026-01-01T00:00:00Z",
                    "age_days": str(age), "own_id_in_osv": own if vis else "False",
                    "scanner_class": "scanner_visible" if vis else "scanner_blind",
                    "osv_packages": osv if vis else "",
                    "advisory_product_type": ptype, "advisory_ecosystems": ""})
    return out


def _probe(go):
    return {"go_module": go, "gomod_module": "", "proxy_version": "",
            "gomod_match": go, "proxy_ok": go}


def _meta(lang, archived=False):
    return {"archived": archived, "language": lang, "renamed": False}


class TestJoinAndAnalysis(unittest.TestCase):
    def setUp(self):
        census, probes, metas = [], {}, {}
        for i in range(5):
            repo = "go/r%d" % i
            census += _census(repo, 4, 4, "software", "Go:github.com/%s" % repo)
            census += _census(repo, 2, 2, "package", "Go:github.com/%s" % repo)
            probes[repo], metas[repo] = _probe(True), _meta("Go")
        for i in range(5):
            repo = "py/r%d" % i
            census += _census(repo, 4, 0, "software", "")
            census += _census(repo, 2, 1, "package", "PyPI:x%d" % i)
            probes[repo], metas[repo] = _probe(False), _meta("Python")
        # a Go app whose module lives in a subdirectory: probe says not_go, language Go
        census += _census("sub/go", 3, 3, "software", "Go:github.com/sub/go/api")
        probes["sub/go"], metas["sub/go"] = _probe(False), _meta("Go")
        # an archived repo is dropped from every test
        census += _census("old/arch", 9, 9, "software", "Go:github.com/old/arch")
        probes["old/arch"], metas["old/arch"] = _probe(True), _meta("Go", True)
        self.census, self.probes, self.metas = census, probes, metas
        self.rows = O.build_rows(census, probes, metas)

    def test_join(self):
        self.assertFalse(any(r["repo"] == "old/arch" for r in self.rows))
        self.assertTrue(all(r["registry_group"] == "no_registry" for r in self.rows))
        self.assertEqual({r["go_module"] for r in self.rows}, {"True", "False"})
        self.assertEqual(len(O.software_rows(self.rows)), 5 * 4 + 5 * 4 + 3)

    def test_primary_direction_and_significance(self):
        s = O.analyse_a6(self.rows, self.probes, self.metas)
        p1 = s["software_typed"]["P1_primary_no_registry"]
        self.assertEqual(p1["visible_shares"]["go"]["k"], 20)
        self.assertEqual(p1["visible_shares"]["go"]["n"], 20)
        self.assertEqual(p1["visible_shares"]["not_go"]["k"], 3)  # sub/go
        self.assertEqual(p1["visible_shares"]["not_go"]["n"], 23)
        self.assertGreater(p1["permutation"]["difference_pct_points"], 40)
        self.assertLess(p1["permutation"]["p_two_sided"], 0.05)
        self.assertEqual(p1["permutation"]["repositories"], 11)
        p2 = s["all_advisories"]["P1_primary_no_registry"]
        self.assertEqual(p2["visible_shares"]["go"]["n"], 30)
        # P3: every go-visible software advisory names the repo-path module
        p3 = s["software_typed"]["P3_rescue_channel"]
        self.assertEqual(p3["go"]["names_repo_go_module"], 20)
        # sub/go's OSV name is a SUBPATH of its repo, which P3 counts as repo-path
        self.assertEqual(p3["not_go"]["names_repo_go_module"], 3)

    def test_language_robustness(self):
        s = O.analyse_a6(self.rows, self.probes, self.metas)
        r2 = s["R2_language_software"]["visible_shares"]
        self.assertEqual(r2["go"]["n"], 23)   # sub/go joins by language
        self.assertEqual(r2["go"]["k"], 23)
        self.assertEqual(r2["not_go"]["k"], 0)
        self.assertEqual(s["covariate_disagreements"],
                         [{"repo": "sub/go", "go_module": False, "language": "Go"}])

    def test_confounds_and_rescue_record(self):
        census, probes, metas = [], {}, {}
        # go/a: 2 settled CVE advisories visible via own GHSA, 2 recent no-CVE ones
        # visible only through a CVE alias (e.g. a Go vulndb GO- record)
        census += _census("go/a", 2, 2, "software", "Go:github.com/go/a",
                          age=120, cve="CVE-2026-0001")
        census += _census("go/a", 2, 2, "software", "Go:github.com/go/a",
                          age=20, cve="", own="False")
        census += _census("rb/b", 3, 0, "software", "", age=300, cve="")
        census += _census("rb/b", 1, 0, "software", "", age="", cve="CVE-2026-0002")
        for repo, go, lang in (("go/a", True, "Go"), ("rb/b", False, "Ruby")):
            probes[repo], metas[repo] = _probe(go), _meta(lang)
        rows = O.build_rows(census, probes, metas)
        s = O.analyse_a6(rows, probes, metas)
        c = s["confounds_software"]
        # settled: go/a's 2 old ones + rb/b's 3 (blank age is not settled)
        self.assertEqual(c["R3_settled_ge_90_days"]["visible_shares"]["go"]["n"], 2)
        self.assertEqual(c["R3_settled_ge_90_days"]["visible_shares"]["not_go"]["n"], 3)
        self.assertEqual(c["R4_with_cve"]["visible_shares"]["go"]["n"], 2)
        self.assertEqual(c["R4_with_cve"]["visible_shares"]["not_go"]["n"], 1)
        self.assertEqual(c["R4_without_cve"]["visible_shares"]["go"]["n"], 2)
        self.assertEqual(c["R4_without_cve"]["visible_shares"]["not_go"]["n"], 3)
        d1 = s["D1_rescue_record_software"]
        self.assertEqual(d1["go"], {"visible_n": 4, "own_ghsa_record": 2,
                                    "cve_alias_only": 2})
        self.assertEqual(d1["not_go"]["visible_n"], 0)
        self.assertFalse(O.settled({"age_days": "89.9"}))
        self.assertTrue(O.settled({"age_days": "90"}))

    def test_unknown_language_excluded_from_r2_only(self):
        self.metas["py/r0"] = {"archived": None, "language": None, "renamed": False}
        rows = O.build_rows(self.census, self.probes, self.metas)
        s = O.analyse_a6(rows, self.probes, self.metas)
        self.assertEqual(s["R2_language_software"]["unknown_language_rows"], 4)
        self.assertEqual(
            s["software_typed"]["P1_primary_no_registry"]["visible_shares"]["not_go"]["n"],
            23)


if __name__ == "__main__":
    unittest.main()
