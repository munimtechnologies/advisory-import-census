# SPDX-License-Identifier: Apache-2.0
"""Offline tests for cve_where.py: every HTTP call is faked."""
import io
import json
import unittest

import cve_where as cw

CVE = "CVE-2026-49481"
GHSA = "GHSA-6mc7-6948-w5h4"
REPO_URL = "https://github.com/seriousm4x/UpSnap/security/advisories/GHSA-6MC7-6948-W5H4"


class FakeClock:
    def __init__(self):
        self.t = 1000.0
        self.sleeps = []

    def clock(self):
        return self.t

    def sleep(self, s):
        self.sleeps.append(round(s, 3))
        self.t += s


class FakeGet:
    """url -> (status, body, headers) or a list of those, served in order."""

    def __init__(self, table):
        self.table = table
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        v = self.table.get(url, (404, None, {}))
        if isinstance(v, list):
            return v.pop(0) if len(v) > 1 else v[0]
        return v


def ok(body):
    return (200, body, {})


def record(assigner="GitHub_M", refs=(), adp_refs=()):
    rec = {"cveMetadata": {"cveId": CVE, "state": "PUBLISHED", "assignerShortName": assigner,
                           "datePublished": "2026-08-12T23:08:45.158Z"},
           "containers": {"cna": {"references": [{"url": u} for u in refs]}}}
    if adp_refs:
        rec["containers"]["adp"] = [{"references": [{"url": u} for u in adp_refs]}]
    return rec


def nvd(status="Deferred", source="security-advisories@github.com", refs=()):
    return {"totalResults": 1, "vulnerabilities": [{"cve": {
        "id": CVE, "vulnStatus": status, "sourceIdentifier": source, "published": "2026-08-12T23:15:00.000",
        "references": [{"url": u} for u in refs]}}]}


def upsnap_table(**over):
    t = {
        cw.CVE_ID_API % CVE: ok({"cve_id": CVE, "state": "PUBLISHED", "owning_cna": "GitHub_M"}),
        cw.CVE_REC_API % CVE: ok(record(refs=[REPO_URL, "https://github.com/seriousm4x/UpSnap/releases/tag/5.4.0"])),
        cw.NVD_API % CVE: ok(nvd(refs=[REPO_URL])),
        cw.GH_BY_CVE % CVE: ok([]),
        cw.GH_REPO % ("seriousm4x", "UpSnap", GHSA): ok({
            "ghsa_id": GHSA, "cve_id": CVE, "state": "published",
            "vulnerabilities": [{"package": {"ecosystem": "", "name": "Upsnap"}}]}),
        cw.GH_GLOBAL % GHSA: (404, None, {}),
        cw.OSV_API % CVE: (404, None, {}),
    }
    t.update(over)
    return t


def client_for(table, wait=True):
    clk = FakeClock()
    get = FakeGet(table)
    return cw.Client(getter=get, sleep=clk.sleep, clock=clk.clock, wait_rate_limit=wait), get, clk


class ParseTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(cw.normalize(" cve-2026-49481 "), CVE)
        self.assertIsNone(cw.normalize("CVE-2026-10"))
        self.assertIsNone(cw.normalize("GHSA-6mc7-6948-w5h4"))
        self.assertIsNone(cw.normalize(None))

    def test_refs_from_record_reads_adp_and_dedups(self):
        rec = record(refs=[REPO_URL], adp_refs=[REPO_URL.lower(),
                                                "https://github.com/o/r/security/advisories/GHSA-2r7f-4h2c-5x73",
                                                "https://github.com/advisories/GHSA-g48f-pgwh-wwxx"])
        self.assertEqual(cw.refs_from_record(rec), [
            {"owner": "seriousm4x", "repo": "UpSnap", "ghsa": GHSA},
            {"owner": "o", "repo": "r", "ghsa": "GHSA-2r7f-4h2c-5x73"}])

    def test_supported(self):
        self.assertFalse(cw.supported([""]))
        self.assertFalse(cw.supported(["other"]))
        self.assertTrue(cw.supported(["", "pip"]))


class CheckTests(unittest.TestCase):
    def test_repo_only_outside_supported_registries(self):
        c, get, _ = client_for(upsnap_table())
        r = cw.check(CVE, c)
        self.assertEqual(r["cve_id_state"], "PUBLISHED")
        self.assertEqual(r["cve_record"]["assigner"], "GitHub_M")
        self.assertEqual(r["nvd"]["status"], "Deferred")
        self.assertEqual(r["github_lookup"], "EMPTY")
        self.assertFalse(r["found_on_github"])
        a = r["repo_advisories"][0]
        self.assertEqual((a["ghsa"], a["repo_state"], a["ecosystems"], a["global_state"]),
                         (GHSA, "published", [""], "NOT_GLOBAL"))
        f = " ".join(r["findings"])
        self.assertTrue(r["findings"][0].startswith("NOT FOUND"))
        self.assertIn("Issued by GitHub's own CNA", f)
        self.assertIn("names no package in a supported registry (ecosystem: (empty))", f)
        self.assertEqual(r["osv"]["id"], "")
        # the same repository advisory cited twice (record + NVD) is read once
        self.assertEqual(sum(1 for u in get.calls if "/security-advisories/" in u), 1)

    def test_found(self):
        c, _, _ = client_for(upsnap_table(**{
            cw.GH_BY_CVE % CVE: ok([{"ghsa_id": "GHSA-6V38-4H7W-RJ9H", "type": "reviewed", "withdrawn_at": None}])}))
        r = cw.check(CVE, c)
        self.assertTrue(r["found_on_github"])
        self.assertEqual(r["findings"][0], "FOUND: GitHub's Advisory Database lists %s on GHSA-6v38-4h7w-rj9h "
                                           "(reviewed)." % CVE)

    def test_only_withdrawn_is_not_found(self):
        c, _, _ = client_for(upsnap_table(**{
            cw.GH_BY_CVE % CVE: ok([{"ghsa_id": "GHSA-6m87-8wg6-hh8w", "type": "reviewed",
                                     "withdrawn_at": "2026-10-27T14:50:09Z"}])}))
        r = cw.check(CVE, c)
        self.assertFalse(r["found_on_github"])
        self.assertIn("only withdrawn: GHSA-6m87-8wg6-hh8w", r["findings"][0])

    def test_reserved_skips_record_and_reports_no_ref(self):
        table = {cw.CVE_ID_API % CVE: ok({"state": "RESERVED", "owning_cna": "[REDACTED]"}),
                 cw.NVD_API % CVE: ok({"totalResults": 0, "vulnerabilities": []}),
                 cw.GH_BY_CVE % CVE: ok([])}
        c, get, _ = client_for(table)
        r = cw.check(CVE, c, osv=False)
        self.assertNotIn(cw.CVE_REC_API % CVE, get.calls)
        self.assertEqual(r["nvd"]["status"], "NOT_IN_NVD")
        self.assertNotIn("osv", r)
        f = " ".join(r["findings"])
        self.assertIn("RESERVED", f)
        self.assertIn("No GitHub repository advisory is cited", f)

    def test_osv_record_is_reported(self):
        c, _, _ = client_for(upsnap_table(**{cw.OSV_API % CVE: ok({"id": CVE, "aliases": [GHSA]})}))
        r = cw.check(CVE, c)
        self.assertEqual(r["osv"], {"id": CVE, "aliases": [GHSA], "related": []})
        self.assertIn("OSV: has a record %s (aliases: %s)." % (CVE, GHSA), r["findings"])

    def test_published_but_not_in_nvd(self):
        c, _, _ = client_for(upsnap_table(**{cw.NVD_API % CVE: ok({"totalResults": 0, "vulnerabilities": []})}))
        r = cw.check(CVE, c)
        self.assertIn("NVD has no entry yet", " ".join(r["findings"]))

    def test_never_allocated(self):
        table = {cw.CVE_ID_API % CVE: (404, None, {}), cw.GH_BY_CVE % CVE: ok([])}
        c, _, _ = client_for(table)
        r = cw.check(CVE, c, osv=False)
        self.assertEqual(r["cve_id_state"], "NOT_FOUND")
        self.assertIn("never allocated", " ".join(r["findings"]))

    def test_global_advisory_without_the_alias(self):
        c, _, _ = client_for(upsnap_table(**{
            cw.GH_GLOBAL % GHSA: ok({"ghsa_id": GHSA, "type": "reviewed", "cve_id": None, "withdrawn_at": None})}))
        r = cw.check(CVE, c)
        self.assertIn("its CVE field is empty, not %s" % CVE, " ".join(r["findings"]))

    def test_supported_registry_but_not_global(self):
        c, _, _ = client_for(upsnap_table(**{
            cw.GH_REPO % ("seriousm4x", "UpSnap", GHSA): ok({
                "state": "published", "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "x"}}]})}))
        r = cw.check(CVE, c)
        self.assertIn("names a package in a supported registry (pip) but is not in the global database",
                      " ".join(r["findings"]))

    def test_github_error_is_unknown(self):
        c, _, _ = client_for(upsnap_table(**{cw.GH_BY_CVE % CVE: (502, None, {})}))
        r = cw.check(CVE, c)
        self.assertEqual(r["github_lookup"], "ERROR:502")
        self.assertTrue(r["findings"][0].startswith("UNKNOWN"))


class ClientTests(unittest.TestCase):
    def test_waits_for_github_rate_limit_reset(self):
        url = cw.GH_BY_CVE % CVE
        limited = (403, None, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1100"})
        c, get, clk = client_for({url: [limited, ok([])]})
        self.assertEqual(c.get(url), (200, []))
        self.assertIn(102.0, clk.sleeps)
        self.assertEqual(len(get.calls), 2)

    def test_no_wait_returns_rate_limited(self):
        url = cw.GH_BY_CVE % CVE
        limited = (403, None, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1100"})
        c, _, clk = client_for({url: [limited, ok([])]}, wait=False)
        self.assertEqual(c.get(url), ("RATE_LIMITED", None))
        self.assertEqual(clk.sleeps, [])

    def test_spaces_nvd_calls(self):
        url = cw.NVD_API % CVE
        c, _, clk = client_for({url: ok({"vulnerabilities": []})})
        c.get(url)
        c.get(url)
        self.assertEqual(clk.sleeps, [6.5])

    def test_retries_5xx_then_gives_up(self):
        url = cw.OSV_API % CVE
        c, get, _ = client_for({url: (503, None, {})})
        self.assertEqual(c.get(url), (503, None))
        self.assertEqual(len(get.calls), 3)

    def test_network_error_is_error(self):
        def boom(url):
            raise OSError("down")
        clk = FakeClock()
        c = cw.Client(getter=boom, sleep=clk.sleep, clock=clk.clock)
        self.assertEqual(c.get(cw.OSV_API % CVE), ("ERROR", None))


class MainTests(unittest.TestCase):
    def test_json_and_fail_if_missing(self):
        c, _, _ = client_for(upsnap_table())
        buf = io.StringIO()
        code = cw.main([CVE, "cve-2026-49481", "CVE-2026-1", "--json", "--fail-if-missing"], client=c, out=buf)
        self.assertEqual(code, 1)
        rows = json.loads(buf.getvalue())
        self.assertEqual([r["cve"] for r in rows], [CVE, "CVE-2026-1"])
        self.assertTrue(rows[1]["invalid"])

    def test_text_output_and_exit_zero_when_found(self):
        c, _, _ = client_for(upsnap_table(**{
            cw.GH_BY_CVE % CVE: ok([{"ghsa_id": GHSA, "type": "unreviewed", "withdrawn_at": None}])}))
        buf = io.StringIO()
        code = cw.main([CVE, "--fail-if-missing"], client=c, out=buf)
        self.assertEqual(code, 0)
        text = buf.getvalue()
        self.assertTrue(text.startswith(CVE + "\n"))
        self.assertIn("  GitHub    ?cve_id= -> %s unreviewed" % GHSA, text)
        self.assertIn("  Repo adv  %s seriousm4x/UpSnap: published; ecosystems (empty); global NOT_GLOBAL" % GHSA,
                      text)
        self.assertIn("    - FOUND:", text)


if __name__ == "__main__":
    unittest.main()
