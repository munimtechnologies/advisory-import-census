# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. Made with AI agents working for MV2 of Munim, Inc.
import io
import json
import os
import shutil
import tempfile
import unittest

import cve_alias_state as m

# Responses shaped like real CVE Services answers read on 2026-11-02/03.
FAKE = {
    "CVE-2013-3364": (200, {"cve_id": "CVE-2013-3364", "cve_year": "2013", "state": "RESERVED",
                            "owning_cna": "[REDACTED]"}),
    "CVE-2024-10039": (200, {"cve_id": "CVE-2024-10039", "state": "REJECTED", "owning_cna": "redhat"}),
    "CVE-2023-45023": (200, {"cve_id": "CVE-2023-45023", "state": "PUBLISHED", "owning_cna": "mitre"}),
    "CVE-2016-1000249": (404, None),
}


def fake_getter(url):
    cve = url.rsplit("/", 1)[1]
    return FAKE.get(cve, (404, None))


def no_sleep(_s):
    pass


class TestNormalize(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(m.normalize(" cve-2016-1000249 "), "CVE-2016-1000249")
        self.assertEqual(m.normalize("CVE-2026-111943"), "CVE-2026-111943")

    def test_invalid(self):
        for bad in ("GHSA-2r7f-4h2c-5x73", "CVE-16-1", "CVE-2016-123", "", None, 5):
            self.assertIsNone(m.normalize(bad))


class TestClassify(unittest.TestCase):
    def test_states(self):
        self.assertEqual(m.classify(404, None), ("NOT_FOUND", ""))
        self.assertEqual(m.classify(200, {"state": "RESERVED", "owning_cna": "[REDACTED]"}),
                         ("RESERVED", "[REDACTED]"))
        self.assertEqual(m.classify(200, {"state": "rejected", "owning_cna": "redhat"}), ("REJECTED", "redhat"))
        self.assertEqual(m.classify(200, {"state": "PUBLISHED", "owning_cna": None}), ("PUBLISHED", ""))

    def test_errors(self):
        self.assertEqual(m.classify(200, None), ("ERROR", ""))
        self.assertEqual(m.classify(200, {"state": "WEIRD"}), ("ERROR", ""))
        self.assertEqual(m.classify(403, {"state": "RESERVED"}), ("ERROR", ""))


class TestLookup(unittest.TestCase):
    def test_known(self):
        self.assertEqual(m.lookup("CVE-2013-3364", getter=fake_getter, sleep=no_sleep), ("RESERVED", "[REDACTED]"))
        self.assertEqual(m.lookup("cve-2016-1000249", getter=fake_getter, sleep=no_sleep), ("NOT_FOUND", ""))

    def test_invalid_id_makes_no_request(self):
        calls = []
        self.assertEqual(m.lookup("not-a-cve", getter=lambda u: calls.append(u), sleep=no_sleep), ("INVALID", ""))
        self.assertEqual(calls, [])

    def test_retries_then_succeeds(self):
        answers = [OSError("down"), (503, None), (200, {"state": "PUBLISHED", "owning_cna": "mitre"})]

        def flaky(_url):
            a = answers.pop(0)
            if isinstance(a, Exception):
                raise a
            return a
        self.assertEqual(m.lookup("CVE-2023-45023", getter=flaky, sleep=no_sleep), ("PUBLISHED", "mitre"))
        self.assertEqual(answers, [])

    def test_gives_up_as_error(self):
        calls = []

        def always_429(url):
            calls.append(url)
            return 429, None
        self.assertEqual(m.lookup("CVE-2013-3364", getter=always_429, tries=3, sleep=no_sleep), ("ERROR", ""))
        self.assertEqual(len(calls), 3)


class TestAdvisoryDir(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        docs = {
            "a/GHSA-93ww-43rr-79v3.json": {"id": "GHSA-93ww-43rr-79v3", "aliases": ["CVE-2024-10039"]},
            "b/GHSA-2r7f-4h2c-5x73.json": {"id": "GHSA-2r7f-4h2c-5x73", "aliases": ["CVE-2016-1000249"]},
            "c/GHSA-xxxx-old.json": {"id": "GHSA-xxxx-old", "aliases": ["CVE-2013-3364"],
                                     "withdrawn": "2024-01-01T00:00:00Z"},
            "d/GHSA-none.json": {"id": "GHSA-none", "aliases": []},
        }
        for rel, doc in docs.items():
            path = os.path.join(self.tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(doc, fh)
        with open(os.path.join(self.tmp, "broken.json"), "w", encoding="utf-8") as fh:
            fh.write("{not json")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_collect_skips_withdrawn_and_broken(self):
        found = m.collect_from_dir(self.tmp)
        self.assertEqual(found, {"CVE-2024-10039": ["GHSA-93ww-43rr-79v3"],
                                 "CVE-2016-1000249": ["GHSA-2r7f-4h2c-5x73"]})

    def test_main_dir_csv_and_fail_on(self):
        out = io.StringIO()
        code = m.main(["--advisory-dir", self.tmp, "--fail-on", "REJECTED,NOT_FOUND", "--pause", "0"],
                      getter=fake_getter, out=out, sleep=no_sleep)
        self.assertEqual(code, 1)
        lines = out.getvalue().strip().splitlines()
        self.assertEqual(lines[0], "cve,state,owning_cna,sources")
        self.assertIn("CVE-2016-1000249,NOT_FOUND,,GHSA-2r7f-4h2c-5x73", lines)
        self.assertIn("CVE-2024-10039,REJECTED,redhat,GHSA-93ww-43rr-79v3", lines)


class TestMain(unittest.TestCase):
    def test_json_and_dedupe(self):
        out = io.StringIO()
        code = m.main(["CVE-2013-3364", "cve-2013-3364", "CVE-2023-45023", "--json", "--pause", "0"],
                      getter=fake_getter, out=out, sleep=no_sleep)
        self.assertEqual(code, 0)
        rows = json.loads(out.getvalue())
        self.assertEqual([r["cve"] for r in rows], ["CVE-2013-3364", "CVE-2023-45023"])
        self.assertEqual(rows[0]["state"], "RESERVED")
        self.assertEqual(rows[0]["sources"], "arg arg")
        self.assertEqual(rows[1]["owning_cna"], "mitre")

    def test_invalid_reported(self):
        out = io.StringIO()
        code = m.main(["GHSA-2r7f-4h2c-5x73", "--fail-on", "invalid", "--pause", "0"],
                      getter=fake_getter, out=out, sleep=no_sleep)
        self.assertEqual(code, 1)
        self.assertIn("GHSA-2r7f-4h2c-5x73,INVALID,,arg", out.getvalue())

    def test_from_file(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "ids.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("# reviewed aliases\nCVE-2024-10039\n\nCVE-2013-3364  # old\n")
            out = io.StringIO()
            code = m.main(["--from-file", path, "--pause", "0"], getter=fake_getter, out=out, sleep=no_sleep)
            self.assertEqual(code, 0)
            self.assertIn("CVE-2024-10039,REJECTED,redhat,file", out.getvalue())
            self.assertIn("CVE-2013-3364,RESERVED,[REDACTED],file", out.getvalue())
        finally:
            shutil.rmtree(tmp)

    def test_bad_fail_on_and_no_input(self):
        with self.assertRaises(SystemExit):
            m.main(["CVE-2013-3364", "--fail-on", "BOGUS"], getter=fake_getter, out=io.StringIO(), sleep=no_sleep)
        with self.assertRaises(SystemExit):
            m.main([], getter=fake_getter, out=io.StringIO(), sleep=no_sleep)


if __name__ == "__main__":
    unittest.main()
