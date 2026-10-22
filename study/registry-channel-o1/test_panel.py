"""Offline tests for registry-channel O1 (panel_recheck.py, panel_analysis.py).

No network. Verifies the frozen frame-building, A4's verbatim classify as rewired by
O1, the git-blob-sha check, and that panel_analysis scores P1-P5, R1-R4 and the verdict
exactly as PREREGISTRATION-registry-channel-o1.md specifies. Run with:
    python -m unittest -v
Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import datetime as dt
import unittest

import panel_recheck as pr
import panel_analysis as pa


# --------------------------------------------------------------------------- #
# panel_recheck: pure helpers
# --------------------------------------------------------------------------- #
class TestGitBlobSha(unittest.TestCase):
    def test_empty_blob(self):
        self.assertEqual(pr.git_blob_sha(b""),
                         "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")

    def test_hello_blob(self):
        # `printf 'hello\n' | git hash-object --stdin`
        self.assertEqual(pr.git_blob_sha("hello\n"),
                         "ce013625030ba8dba906f756967f9e9ca394464a")


class TestClassification(unittest.TestCase):
    def test_nested(self):
        obj = {"classification": {
            "Open-WebUI/open-webui": {"group": "registry"},
            "louislam/uptime-kuma": {"group": "no_registry"},
            "x/y": {"group": "other"}}}
        c = pr.load_classification_obj(obj)
        self.assertEqual(c["open-webui/open-webui"], "registry")
        self.assertEqual(c["louislam/uptime-kuma"], "no_registry")
        self.assertNotIn("x/y", c)

    def test_flat(self):
        c = pr.load_classification_obj({"a/b": "registry", "c/d": "no_registry"})
        self.assertEqual(c, {"a/b": "registry", "c/d": "no_registry"})


class TestAgeBin(unittest.TestCase):
    def test_bins(self):
        self.assertIsNone(pr.age_bin(13.9))
        self.assertEqual(pr.age_bin(14), "young")
        self.assertEqual(pr.age_bin(89.9), "young")
        self.assertEqual(pr.age_bin(90), "mid")
        self.assertEqual(pr.age_bin(364), "mid")
        self.assertEqual(pr.age_bin(365), "old")


CSV = (
    "group,repo,ghsa_id,cve_id,severity,published_at,age_days,period,own_id_in_osv,"
    "osv_packages,scanner_class,advisory_product_type,advisory_ecosystems,"
    "named_packages,named_pkg_resolution,real_package,url\n"
    # in frame: registry, young, blind, package-typed
    "application,open-webui/open-webui,GHSA-aaaa-aaaa-aaaa,CVE-2026-0001,high,"
    "2026-09-19T00:00:00Z,30,from_2026_05,True,,scanner_blind,package,pypi,,,,u1\n"
    # in frame: no_registry, mid, visible, software-typed (package-less)
    "application,louislam/uptime-kuma,GHSA-bbbb-bbbb-bbbb,,high,"
    "2026-06-01T00:00:00Z,120,from_2026_05,False,,scanner_visible,software,,,,,u2\n"
    # off frame: repo not in classification
    "application,ghost/ghost,GHSA-cccc-cccc-cccc,,high,"
    "2026-09-01T00:00:00Z,45,from_2026_05,False,,scanner_blind,software,,,,,u3\n"
    # below floor: age < 14
    "application,open-webui/open-webui,GHSA-dddd-dddd-dddd,,high,"
    "2026-10-10T00:00:00Z,5,from_2026_05,False,,scanner_blind,other,,,,,u4\n"
    # age missing
    "application,louislam/uptime-kuma,GHSA-eeee-eeee-eeee,,high,"
    "2026-09-01T00:00:00Z,,from_2026_05,False,,scanner_blind,other,,,,,u5\n"
)
CLS = {"open-webui/open-webui": "registry", "louislam/uptime-kuma": "no_registry"}


class TestBuildFrame(unittest.TestCase):
    def setUp(self):
        self.rows, self.counts = pr.build_frame(CSV, CLS)

    def test_counts(self):
        self.assertEqual(self.counts["kept"], 2)
        self.assertEqual(self.counts["off_frame"], 1)
        self.assertEqual(self.counts["age_below_floor"], 1)
        self.assertEqual(self.counts["age_missing"], 1)

    def test_fields(self):
        a = {r["ghsa_id"]: r for r in self.rows}
        r1 = a["GHSA-aaaa-aaaa-aaaa"]
        self.assertEqual(r1["group"], "registry")
        self.assertEqual(r1["bin"], "young")
        self.assertTrue(r1["package_typed"])
        self.assertEqual(r1["a4_state"], "blind")
        self.assertTrue(r1["a4_snapshot"].startswith("2026-10-19"))
        r2 = a["GHSA-bbbb-bbbb-bbbb"]
        self.assertEqual(r2["group"], "no_registry")
        self.assertEqual(r2["bin"], "mid")
        self.assertFalse(r2["package_typed"])
        self.assertEqual(r2["a4_state"], "visible")


class TestClassify(unittest.TestCase):
    def test_ghsa_names_package_visible(self):
        osv = {"GHSA-x": {"affected": [{"package": {"name": "p"}}]}}
        own, pkgs, blind = pr.classify(pr.build_adv("GHSA-x", ""), osv.get)
        self.assertTrue(own)
        self.assertFalse(blind)

    def test_cve_fallback_visible(self):
        osv = {"GHSA-y": None, "CVE-2026-9": {"affected": [{"package": {"name": "p"}}]}}
        own, pkgs, blind = pr.classify(pr.build_adv("GHSA-y", "CVE-2026-9"), osv.get)
        self.assertFalse(own)       # GHSA not in OSV
        self.assertFalse(blind)     # but CVE names a package

    def test_blind(self):
        own, pkgs, blind = pr.classify(pr.build_adv("GHSA-z", "CVE-2026-1"),
                                       lambda vid: None)
        self.assertFalse(own)
        self.assertTrue(blind)


class TestNewPostA4(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 11, 16, tzinfo=dt.timezone.utc)
        self.snap = dt.datetime(2026, 10, 19, tzinfo=dt.timezone.utc)
        self.a4 = {"GHSA-old"}

    def test_new_eligible(self):
        self.assertTrue(pr.is_new_post_a4("GHSA-new", "2026-10-25T00:00:00Z",
                                          self.a4, self.snap, self.now))

    def test_too_young_at_t2(self):
        self.assertFalse(pr.is_new_post_a4("GHSA-new", "2026-11-10T00:00:00Z",
                                           self.a4, self.snap, self.now))

    def test_before_snapshot(self):
        self.assertFalse(pr.is_new_post_a4("GHSA-new", "2026-10-10T00:00:00Z",
                                           self.a4, self.snap, self.now))

    def test_in_a4(self):
        self.assertFalse(pr.is_new_post_a4("GHSA-old", "2026-10-25T00:00:00Z",
                                           self.a4, self.snap, self.now))


# --------------------------------------------------------------------------- #
# panel_analysis: predictions + verdict
# --------------------------------------------------------------------------- #
def row(ghsa, repo, group, bin_, a4_state, t2_state, package_typed,
        withdrawn="", page="200", r1_new="False"):
    return {"ghsa_id": ghsa, "repo": repo, "group": group, "cve_id_a4": "",
            "product_type": "package" if package_typed else "software",
            "package_typed": package_typed, "bin": bin_, "age_days_a4": "30",
            "a4_state": a4_state, "t2_state": t2_state,
            "transition": "%s->%s" % (a4_state, t2_state),
            "own_in_osv_t2": "True", "osv_packages_t2": "",
            "withdrawn_t2": withdrawn, "r1_cve_t2": "", "r1_new_cve": r1_new,
            "page_status": page, "a4_snapshot": "2026-10-19T00:00:00+00:00",
            "t2_snapshot": "2026-11-16T00:00:00+00:00"}


def persists_dataset(p1_caught=2):
    """P1 holds (few package-less no_registry catch up), P3 holds (registry young-blind
    catch up, no_registry young-blind do not), both powered."""
    rows = []
    # P1 set: no_registry, package-less (software), blind, MID bin. 5 repos x 24 = 120.
    n = 0
    for ri in range(5):
        for j in range(24):
            caught = n < p1_caught
            rows.append(row("P1-%d" % n, "nr-mid-%d" % ri, "no_registry", "mid",
                            "blind", "visible" if caught else "blind",
                            package_typed=False))
            n += 1
    # P3 registry young-blind: 5 repos x 8, 7 caught up each (also the P2 set).
    for ri in range(5):
        for j in range(8):
            rows.append(row("RY-%d-%d" % (ri, j), "reg-y-%d" % ri, "registry", "young",
                            "blind", "visible" if j < 7 else "blind",
                            package_typed=True))
    # P3 no_registry young-blind: 5 repos x 8, none caught up.
    for ri in range(5):
        for j in range(8):
            rows.append(row("NY-%d-%d" % (ri, j), "nr-y-%d" % ri, "no_registry", "young",
                            "blind", "blind", package_typed=True))
    # a couple of reversals (P4) and one gone advisory (R4).
    rows.append(row("REV-1", "reg-y-0", "registry", "mid", "visible", "blind",
                    package_typed=True))
    rows.append(row("GONE-1", "nr-mid-0", "no_registry", "mid", "blind", "blind",
                    package_typed=False, page="404"))
    return rows


class TestVerdictPersists(unittest.TestCase):
    def setUp(self):
        self.s = pa.analyse(persists_dataset(), [])

    def test_p1_holds(self):
        p1 = self.s["P1_primary"]
        self.assertFalse(p1["underpowered"])
        self.assertLessEqual(p1["share"]["pct"], pa.P1_MAX_PCT)
        self.assertTrue(p1["holds"])
        # GONE-1 (page 404) is excluded from the primary set by R4.
        self.assertEqual(p1["share"]["n"], 120)

    def test_p2_holds(self):
        p2 = self.s["P2_secondary"]
        self.assertGreaterEqual(p2["share"]["pct"], pa.P2_MIN_PCT)
        self.assertTrue(p2["holds"])

    def test_p3_holds(self):
        p3 = self.s["P3_mechanism"]
        self.assertGreaterEqual(p3["difference_pct_points"], pa.P3_MIN_PTS)
        self.assertLess(p3["p_two_sided"], pa.ALPHA)
        self.assertTrue(p3["holds"])

    def test_verdict(self):
        self.assertEqual(self.s["verdict"], "PERSISTS_LONGITUDINALLY")

    def test_p4_reversals(self):
        self.assertEqual(self.s["P4_reversals"]["count"], 1)

    def test_r4_gone(self):
        self.assertEqual(self.s["robustness"]["R4_gone_advisories"]["count"], 1)


class TestVerdictPackagelessCatchup(unittest.TestCase):
    def test_verdict(self):
        s = pa.analyse(persists_dataset(p1_caught=60), [])  # 50% catch up -> P1 fails
        self.assertFalse(s["P1_primary"]["holds"])
        self.assertFalse(s["P1_primary"]["underpowered"])
        self.assertEqual(s["verdict"], "PACKAGELESS_CATCHUP")


class TestVerdictUnderpowered(unittest.TestCase):
    def test_verdict(self):
        rows = [row("u%d" % i, "nr-0", "no_registry", "mid", "blind", "blind",
                    package_typed=False) for i in range(10)]
        s = pa.analyse(rows, [])
        self.assertTrue(s["P1_primary"]["underpowered"])
        self.assertEqual(s["verdict"], "INCONCLUSIVE_UNDERPOWERED")


class TestVerdictNoDifferential(unittest.TestCase):
    def test_verdict(self):
        rows = []
        n = 0
        for ri in range(5):
            for j in range(24):
                rows.append(row("P1-%d" % n, "nr-mid-%d" % ri, "no_registry", "mid",
                                "blind", "blind", package_typed=False))
                n += 1
        # P3 both groups catch up equally (~12.5%): diff ~ 0 -> P3 fails.
        for ri in range(5):
            for j in range(8):
                rows.append(row("RY-%d-%d" % (ri, j), "reg-y-%d" % ri, "registry",
                                "young", "blind", "visible" if j < 1 else "blind",
                                package_typed=True))
                rows.append(row("NY-%d-%d" % (ri, j), "nr-y-%d" % ri, "no_registry",
                                "young", "blind", "visible" if j < 1 else "blind",
                                package_typed=True))
        s = pa.analyse(rows, [])
        self.assertTrue(s["P1_primary"]["holds"])
        self.assertFalse(s["P3_mechanism"]["holds"])
        self.assertEqual(s["verdict"], "NO_DIFFERENTIAL_MOVEMENT")


class TestRobustnessAndP5(unittest.TestCase):
    def test_r2_excludes_withdrawn(self):
        rows = persists_dataset()
        rows.append(row("W-1", "nr-mid-0", "no_registry", "mid", "blind", "visible",
                        package_typed=False, withdrawn="2026-11-01T00:00:00Z"))
        s = pa.analyse(rows, [])
        self.assertEqual(s["robustness"]["R2_exclude_withdrawn"]["excluded_withdrawn"], 1)
        # withdrawn row is gone -> excluded from primary too, so P1 n stays 120.
        self.assertEqual(s["P1_primary"]["share"]["n"], 120)

    def test_r1_new_cve(self):
        rows = persists_dataset()
        rows.append(row("C-1", "nr-mid-0", "no_registry", "mid", "blind", "visible",
                        package_typed=False, r1_new="True"))
        s = pa.analyse(rows, [])
        r1 = s["robustness"]["R1_new_cves"]
        self.assertEqual(r1["advisories_with_new_cve"], 1)
        self.assertEqual(r1["blind_to_visible_with_new_cve"], 1)

    def test_p5(self):
        new = [{"ghsa_id": "n1", "repo": "reg-y-0", "group": "registry",
                "t2_state": "visible"},
               {"ghsa_id": "n2", "repo": "nr-y-0", "group": "no_registry",
                "t2_state": "blind"}]
        s = pa.analyse(persists_dataset(), new)
        p5 = s["P5_new_advisories"]
        self.assertEqual(p5["registry"]["pct"], 100.0)
        self.assertEqual(p5["no_registry"]["pct"], 0.0)


if __name__ == "__main__":
    unittest.main()
