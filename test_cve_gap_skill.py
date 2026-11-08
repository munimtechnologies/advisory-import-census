# SPDX-License-Identifier: Apache-2.0
"""Tests for the github-advisory-cve-gap agent skill (skills/github-advisory-cve-gap/).

Checks that SKILL.md is a valid skill file and that cve_gap.py gives the right verdict for each
pattern. No network: every HTTP answer is a fixture. The fixtures for CVE-2026-47078 (Erlang/OTP),
CVE-2024-38805 (EDK2) and CVE-2026-59194 (pnpm) copy the fields the live APIs returned on
2026-11-08 UTC; the CVE-2099-* cases are made up.
Made with AI agents working in MV2's (Munim, Inc.) name.
"""
import contextlib
import importlib.util
import io
import json
import os
import re
import shlex
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "skills", "github-advisory-cve-gap")
SKILL_MD = os.path.join(SKILL_DIR, "SKILL.md")
SCRIPT = os.path.join(SKILL_DIR, "scripts", "cve_gap.py")
STREET = re.compile(r"\b\d{1,5}\s+[A-Z][a-z]+\s+(Road|Street|Avenue|Lane|Drive|Boulevard)\b")

GH = "https://api.github.com"
CVEORG = "https://cveawg.mitre.org/api/cve/"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="


def load_module():
    spec = importlib.util.spec_from_file_location("cve_gap", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read().replace("\r\n", "\n")


def frontmatter(text):
    lines = text.split("\n")
    assert lines[0] == "---", "SKILL.md must start with ---"
    end = lines.index("---", 1)
    fields = {}
    for line in lines[1:end]:
        key, _, value = line.partition(": ")
        fields[key] = value
    return fields, "\n".join(lines[end + 1:])


def cve_record(cve, state="PUBLISHED", assigner="EEF", published="2026-07-27T15:03:50.929Z",
               refs=(), adp_refs=()):
    rec = {
        "dataType": "CVE_RECORD",
        "cveMetadata": {"cveId": cve, "state": state, "assignerShortName": assigner,
                        "datePublished": published},
        "containers": {"cna": {"references": [{"url": u} for u in refs]}},
    }
    if adp_refs:
        rec["containers"]["adp"] = [{"title": "CISA ADP Vulnrichment",
                                     "references": [{"url": u} for u in adp_refs]}]
    return rec


def nvd(cve, published):
    return {"totalResults": 1, "vulnerabilities": [{"cve": {"id": cve, "published": published}}]}


class Fake:
    """fetch() stand-in: a dict of URL -> (status, json). Unknown URLs give 404 and are logged."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        return self.answers.get(url, (404, None))


ERLANG = {
    GH + "/advisories?cve_id=CVE-2026-47078": (200, []),
    CVEORG + "CVE-2026-47078": (200, cve_record(
        "CVE-2026-47078",
        refs=["https://github.com/erlang/otp/security/advisories/GHSA-rf72-wp7h-jg3x",
              "https://cna.erlef.org/cves/CVE-2026-47078.html",
              "https://github.com/erlang/otp/commit/8d537f51a4262d24f3395c4148323eaca9facbbd"])),
    GH + "/advisories/GHSA-rf72-wp7h-jg3x": (404, None),
    GH + "/repos/erlang/otp/security-advisories/GHSA-rf72-wp7h-jg3x": (200, {
        "ghsa_id": "GHSA-rf72-wp7h-jg3x", "cve_id": "CVE-2026-47078", "state": "published",
        "published_at": "2026-07-27T13:45:04Z"}),
    NVD + "CVE-2026-47078": (200, nvd("CVE-2026-47078", "2026-07-27T16:17:07.643")),
}

EDK2_IN_DB = {
    GH + "/advisories?cve_id=CVE-2024-38805": (200, [{
        "ghsa_id": "GHSA-w8rg-pqpr-83hp", "type": "unreviewed", "github_reviewed_at": None,
        "withdrawn_at": None}]),
}

PNPM = {
    GH + "/advisories?cve_id=CVE-2026-59194": (200, []),
    CVEORG + "CVE-2026-59194": (200, cve_record(
        "CVE-2026-59194", assigner="GitHub_M", published="2026-07-06T18:00:00.000Z",
        refs=["https://github.com/pnpm/pnpm/security/advisories/GHSA-72r4-9c5j-mj57"])),
    GH + "/advisories/GHSA-72r4-9c5j-mj57": (200, {
        "ghsa_id": "GHSA-72r4-9c5j-mj57", "cve_id": None, "type": "reviewed",
        "github_reviewed_at": "2026-06-27T00:00:00Z", "withdrawn_at": None}),
    GH + "/repos/pnpm/pnpm/security-advisories/GHSA-72r4-9c5j-mj57": (200, {
        "ghsa_id": "GHSA-72r4-9c5j-mj57", "cve_id": "CVE-2026-59194",
        "published_at": "2026-06-26T00:00:00Z"}),
}


def made_up(cve, listed, adv_published, nvd_published, global_answer=(404, None), repo_status=200):
    ghsa = "GHSA-2c3f-4g5h-6j7m"
    answers = {
        GH + "/advisories?cve_id=" + cve: (200, []),
        CVEORG + cve: (200, cve_record(cve, assigner="example", published=nvd_published + "T01:00:00Z",
                                        refs=["https://github.com/example/proj/security/advisories/" + ghsa])),
        GH + "/advisories/" + ghsa: global_answer,
        GH + "/repos/example/proj/security-advisories/" + ghsa: (
            (repo_status, {"ghsa_id": ghsa, "cve_id": listed, "published_at": adv_published})
            if repo_status == 200 else (repo_status, None)),
        NVD + cve: (200, nvd(cve, nvd_published + "T12:00:00.000")),
    }
    return answers


class SkillFile(unittest.TestCase):
    def setUp(self):
        self.text = read(SKILL_MD)
        self.fields, self.body = frontmatter(self.text)

    def test_frontmatter(self):
        self.assertEqual(self.fields["name"], "github-advisory-cve-gap")
        self.assertEqual(self.fields["name"], os.path.basename(SKILL_DIR))
        self.assertRegex(self.fields["name"], r"^[a-z0-9]+(-[a-z0-9]+)*$")
        desc = self.fields["description"]
        self.assertTrue(desc.startswith("Use when"))
        self.assertLessEqual(len(desc), 1024)
        self.assertNotIn(": ", desc)
        self.assertNotIn("<", desc)
        self.assertEqual(self.fields["license"], "Apache-2.0")
        self.assertEqual(set(self.fields), {"name", "description", "license"})

    def test_every_verdict_is_documented(self):
        mod = load_module()
        for verdict in mod.VERDICTS:
            self.assertIn("`" + verdict + "`", self.body, verdict)
            self.assertIn(verdict, mod.MESSAGES, verdict)

    def test_documented_commands_parse(self):
        mod = load_module()
        cmds = [ln.strip() for ln in self.body.split("\n")
                if ln.strip().startswith("python scripts/cve_gap.py")]
        self.assertEqual(len(cmds), 3)
        for cmd in cmds:
            args = mod.build_parser().parse_args(shlex.split(cmd)[2:])
            self.assertTrue(args.cves, cmd)
            for cve in args.cves:
                self.assertRegex(cve, mod.CVE_RE.pattern)

    def test_disclosure_licence_and_no_address(self):
        script = read(SCRIPT)
        for text in (self.text, script):
            self.assertIn("Made with AI agents working in MV2's (Munim, Inc.) name", text)
            self.assertNotRegex(text, r"\bMIT\b")
            self.assertIsNone(STREET.search(text))
        self.assertIn("SPDX-License-Identifier: Apache-2.0", script)
        self.assertIn("measured patterns, not", self.text)
        self.assertTrue(self.text.rstrip().endswith("MV2, Munim, Inc., mv2@munimtech.com"))
        self.assertIsNotNone(STREET.search(" ".join(["12", "Example", "Road"])))


class Verdicts(unittest.TestCase):
    def setUp(self):
        self.mod = load_module()

    def test_expected_gap_erlang(self):
        fake = Fake(ERLANG)
        res = self.mod.check("cve-2026-47078", fake)
        self.assertEqual(res["verdict"], "EXPECTED_GAP")
        self.assertEqual(res["cve"], "CVE-2026-47078")
        self.assertEqual(res["assigner"], "EEF")
        self.assertEqual(res["nvd_published"], "2026-07-27")
        self.assertEqual(res["nvd_published_source"], "nvd")
        self.assertEqual(len(res["repo_advisories"]), 1)
        ra = res["repo_advisories"][0]
        self.assertEqual((ra["global"], ra["cve_field"], ra["timing"]), ("NOT_GLOBAL", "LISTS_THIS", "EARLY"))
        self.assertEqual(ra["url"], "https://github.com/erlang/otp/security/advisories/GHSA-rf72-wp7h-jg3x")
        self.assertEqual([u for u in fake.calls if u not in ERLANG], [])

    def test_in_database_stops_after_one_call(self):
        fake = Fake(EDK2_IN_DB)
        res = self.mod.check("CVE-2024-38805", fake)
        self.assertEqual(res["verdict"], "IN_DATABASE")
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(res["in_database"], [{"ghsa_id": "GHSA-w8rg-pqpr-83hp", "type": "unreviewed",
                                               "reviewed": False, "withdrawn": False}])

    def test_alias_missing_pnpm_skips_nvd(self):
        fake = Fake(PNPM)
        res = self.mod.check("CVE-2026-59194", fake)
        self.assertEqual(res["verdict"], "ALIAS_MISSING")
        self.assertEqual(res["repo_advisories"][0]["global"], "GLOBAL")
        self.assertFalse(any(u.startswith(NVD) for u in fake.calls))

    def test_linked_to_other_cve(self):
        answers = made_up("CVE-2099-1001", "CVE-2099-1001", "2099-01-01T00:00:00Z", "2099-01-02",
                          global_answer=(200, {"ghsa_id": "GHSA-2c3f-4g5h-6j7m", "cve_id": "CVE-2099-1000",
                                               "type": "reviewed", "withdrawn_at": None}))
        res = self.mod.check("CVE-2099-1001", Fake(answers))
        self.assertEqual(res["verdict"], "LINKED_TO_OTHER_CVE")

    def test_global_holds_this_cve(self):
        answers = made_up("CVE-2099-1002", "CVE-2099-1002", "2099-01-01T00:00:00Z", "2099-01-02",
                          global_answer=(200, {"ghsa_id": "GHSA-2c3f-4g5h-6j7m", "cve_id": "CVE-2099-1002",
                                               "type": "reviewed", "withdrawn_at": None}))
        res = self.mod.check("CVE-2099-1002", Fake(answers))
        self.assertEqual(res["verdict"], "IN_DATABASE")
        self.assertEqual(len(res["notes"]), 1)

    def test_late_listing_is_other_gap(self):
        res = self.mod.check("CVE-2099-1003", Fake(made_up(
            "CVE-2099-1003", "CVE-2099-1003", "2099-03-05T09:00:00Z", "2099-03-04")))
        self.assertEqual(res["verdict"], "OTHER_GAP")
        self.assertEqual(res["repo_advisories"][0]["timing"], "LATE")

    def test_same_day_is_early(self):
        res = self.mod.check("CVE-2099-1004", Fake(made_up(
            "CVE-2099-1004", "CVE-2099-1004", "2099-03-04T23:59:00Z", "2099-03-04")))
        self.assertEqual(res["verdict"], "EXPECTED_GAP")

    def test_no_known_cve_and_other_cve_and_gone(self):
        res = self.mod.check("CVE-2099-1005", Fake(made_up(
            "CVE-2099-1005", None, "2099-03-01T00:00:00Z", "2099-03-04")))
        self.assertEqual((res["verdict"], res["repo_advisories"][0]["cve_field"]), ("OTHER_GAP", "NO_CVE"))
        res = self.mod.check("CVE-2099-1006", Fake(made_up(
            "CVE-2099-1006", "CVE-2099-0001", "2099-03-01T00:00:00Z", "2099-03-04")))
        self.assertEqual((res["verdict"], res["repo_advisories"][0]["cve_field"]), ("OTHER_GAP", "LISTS_OTHER"))
        res = self.mod.check("CVE-2099-1007", Fake(made_up(
            "CVE-2099-1007", None, None, "2099-03-04", repo_status=404)))
        self.assertEqual((res["verdict"], res["repo_advisories"][0]["cve_field"]), ("OTHER_GAP", "GONE"))

    def test_nvd_fallback_to_cve_org(self):
        answers = dict(ERLANG)
        answers[NVD + "CVE-2026-47078"] = (503, None)
        res = self.mod.check("CVE-2026-47078", Fake(answers))
        self.assertEqual(res["verdict"], "EXPECTED_GAP")
        self.assertEqual(res["nvd_published_source"], "cve.org")
        self.assertEqual(res["nvd_published"], "2026-07-27")

    def test_repo_api_error_is_error(self):
        answers = made_up("CVE-2099-1008", "CVE-2099-1008", "2099-03-01T00:00:00Z", "2099-03-04",
                          repo_status=403)
        res = self.mod.check("CVE-2099-1008", Fake(answers))
        self.assertEqual(res["verdict"], "ERROR")

    def test_simple_verdicts(self):
        self.assertEqual(self.mod.check("not-a-cve", Fake({}))["verdict"], "BAD_ID")
        self.assertEqual(self.mod.check("CVE-2099-2000", Fake({}))["verdict"], "ERROR")
        base = {GH + "/advisories?cve_id=CVE-2099-2001": (200, [])}
        self.assertEqual(self.mod.check("CVE-2099-2001", Fake(base))["verdict"], "NO_CVE_RECORD")
        reserved = dict(base)
        reserved[CVEORG + "CVE-2099-2001"] = (200, cve_record("CVE-2099-2001", state="RESERVED"))
        self.assertEqual(self.mod.check("CVE-2099-2001", Fake(reserved))["verdict"], "NOT_PUBLISHED")
        norefs = dict(base)
        norefs[CVEORG + "CVE-2099-2001"] = (200, cve_record(
            "CVE-2099-2001", refs=["https://example.com/advisory", "https://github.com/o/r/commit/abc"]))
        self.assertEqual(self.mod.check("CVE-2099-2001", Fake(norefs))["verdict"], "NO_REPO_ADVISORY")

    def test_reference_extraction(self):
        rec = cve_record("CVE-2099-3000", refs=[
            "https://github.com/Owner/Repo/security/advisories/GHSA-2C3F-4G5H-6J7M",
            "https://github.com/owner/repo/security/advisories/GHSA-2c3f-4g5h-6j7m",
            "https://github.com/advisories/GHSA-2c3f-4g5h-6j7m",
            "https://github.com/x/y/security/advisories/GHSA-aaaa-bbbb-cccc",
        ], adp_refs=["https://github.com/a/b/security/advisories/GHSA-mmmm-pppp-qqqq"])
        self.assertEqual(self.mod.cited_repo_advisories(rec), [
            ("Owner", "Repo", "GHSA-2c3f-4g5h-6j7m"),
            ("a", "b", "GHSA-mmmm-pppp-qqqq"),
        ])


class Cli(unittest.TestCase):
    def setUp(self):
        self.mod = load_module()

    def run_main(self, argv, answers):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = self.mod.main(argv, fetch=Fake(answers))
        return code, buf.getvalue()

    def test_text_output(self):
        code, out = self.run_main(["CVE-2026-47078"], ERLANG)
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("CVE-2026-47078: EXPECTED_GAP\n"))
        self.assertIn("  CVE record: PUBLISHED, assigned by EEF", out)
        self.assertIn("  NVD published: 2026-07-27 (nvd)", out)
        self.assertIn("Cited repository advisory erlang/otp GHSA-rf72-wp7h-jg3x: global: NOT_GLOBAL; "
                      "CVE field: LISTS_THIS; published 2026-07-27; EARLY", out)
        self.assertIn("cna-gap-s12-listing-timing/RESULTS.md", out)

    def test_json_output_and_exit_codes(self):
        answers = dict(ERLANG)
        answers.update(PNPM)
        code, out = self.run_main(["CVE-2026-47078", "CVE-2026-59194", "--json"], answers)
        self.assertEqual(code, 0)
        rows = json.loads(out)
        self.assertEqual([r["verdict"] for r in rows], ["EXPECTED_GAP", "ALIAS_MISSING"])
        code, _ = self.run_main(["CVE-2026-47078", "bogus"], ERLANG)
        self.assertEqual(code, 2)
        with contextlib.redirect_stderr(io.StringIO()):
            code, _ = self.run_main([], {})
        self.assertEqual(code, 2)

    def test_version_subprocess(self):
        r = subprocess.run([sys.executable, SCRIPT, "--version"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "cve_gap.py 0.1.0")


if __name__ == "__main__":
    unittest.main()
