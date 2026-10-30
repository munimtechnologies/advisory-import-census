"""Offline tests for cve_reuse_check.py. Apache-2.0. Made with AI agents working for MV2 of Munim, Inc."""
import unittest

import cve_reuse_check as c


def adv(ghsa, pkgs, **kw):
    d = {"ghsa_id": ghsa,
         "vulnerabilities": [{"package": {"ecosystem": e, "name": n}} for e, n in pkgs]}
    d.update(kw)
    return d


class TestNextLink(unittest.TestCase):
    def test_next_present(self):
        h = ('<https://api.github.com/x?page=2>; rel="next", '
             '<https://api.github.com/x?page=3>; rel="last"')
        self.assertEqual(c.next_link(h), "https://api.github.com/x?page=2")

    def test_no_next(self):
        self.assertIsNone(c.next_link('<https://api.github.com/x?page=1>; rel="prev"'))
        self.assertIsNone(c.next_link(None))


class TestPackages(unittest.TestCase):
    def test_packages_of(self):
        a = adv("GHSA-a", [("npm", "@wbce-d9/api"), ("npm", "directus")])
        self.assertEqual(c.packages_of(a), {"npm:@wbce-d9/api", "npm:directus"})

    def test_missing_package_ignored(self):
        self.assertEqual(c.packages_of({"vulnerabilities": [{"package": None}]}), set())
        self.assertEqual(c.packages_of({}), set())


class TestClassify(unittest.TestCase):
    own = {"npm:@wbce-d9/api"}
    upstream = adv("GHSA-j8xj-7jff-46mx", [("npm", "directus")])

    def test_in_global_wins(self):
        cat, others, _ = c.classify("GHSA-x", "CVE-1", 200, [self.upstream], self.own)
        self.assertEqual(cat, "in_global")
        self.assertEqual(others, ["GHSA-j8xj-7jff-46mx"])

    def test_missing_no_cve(self):
        self.assertEqual(c.classify("GHSA-x", None, 404, [], self.own)[0], "missing_no_cve")

    def test_missing_cve_already_in_global(self):
        cat, others, listed = c.classify("GHSA-x", "CVE-1", 404, [self.upstream], self.own)
        self.assertEqual(cat, "missing_cve_already_in_global")
        self.assertEqual(others, ["GHSA-j8xj-7jff-46mx"])
        self.assertFalse(listed)

    def test_own_ghsa_in_matches_is_not_other(self):
        cat, others, _ = c.classify("GHSA-x", "CVE-1", 404, [adv("GHSA-x", [])], self.own)
        self.assertEqual(cat, "missing_cve_unclaimed")
        self.assertEqual(others, [])

    def test_package_already_listed(self):
        merged = adv("GHSA-up", [("npm", "directus"), ("npm", "@wbce-d9/api")])
        self.assertTrue(c.classify("GHSA-x", "CVE-1", 404, [merged], self.own)[2])


class TestSummarize(unittest.TestCase):
    def test_counts(self):
        rows = [{"category": "a"}, {"category": "b"}, {"category": "a"}]
        self.assertEqual(c.summarize(rows), {"a": 2, "b": 1})


class TestClientRateLimit(unittest.TestCase):
    def test_waits_once_then_returns(self):
        import urllib.error
        import io
        calls = []

        def fake_urlopen(req, timeout=60):
            calls.append(req.full_url)
            hdrs = {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "0"}
            raise urllib.error.HTTPError(req.full_url, 403, "rate", hdrs, io.BytesIO(b""))

        slept = []
        orig = c.urllib.request.urlopen
        c.urllib.request.urlopen = fake_urlopen
        try:
            status, _, body = c.Client(sleep=slept.append).get("https://api.github.com/x")
        finally:
            c.urllib.request.urlopen = orig
        self.assertEqual(status, 403)
        self.assertIsNone(body)
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(slept), 1)


if __name__ == "__main__":
    unittest.main()
