"""Tests for the GitHub Marketplace metadata in action.yml (v0.9.25).

The Marketplace refuses to publish an action whose top-level `description` is
125 characters or longer ("Description must be less than 125 characters.").
Release v0.9.24's description was a three-line folded block well over that, so
it could not be listed. These tests pin the metadata the Marketplace checks:
name, a short single-line description, author, branding icon and color. They
read action.yml as plain text (standard library only, no YAML parser).
"""

import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def top_level(text):
    """Return {key: raw value} for the top-level `key: value` lines."""
    out = {}
    for line in text.splitlines():
        if not line or line[0] in " #" or ":" not in line:
            continue
        key, _, value = line.partition(":")
        out[key.strip()] = value.strip()
    return out


def unquote(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


class ActionMetadataTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(HERE, "action.yml"), encoding="utf-8") as fh:
            self.text = fh.read()
        self.meta = top_level(self.text)

    def test_name(self):
        self.assertEqual(unquote(self.meta["name"]), "Advisory blind-spot check")

    def test_description_is_one_line_and_under_125_characters(self):
        raw = self.meta["description"]
        # A folded (>-) or literal (|) block would continue on the next lines.
        self.assertNotIn(raw[:1], (">", "|"))
        description = unquote(raw)
        self.assertTrue(description)
        self.assertLess(len(description), 125, description)

    def test_description_names_what_it_checks(self):
        description = unquote(self.meta["description"])
        self.assertIn("OSV", description)
        self.assertIn("advisories", description)

    def test_author(self):
        self.assertEqual(unquote(self.meta["author"]), "MV2 of Munim, Inc.")

    def test_branding(self):
        self.assertIn('  icon: "eye-off"', self.text)
        self.assertIn('  color: "purple"', self.text)

    def test_composite_runs_blindspot(self):
        self.assertIn('using: "composite"', self.text)
        self.assertIn("${GITHUB_ACTION_PATH}/blindspot.py", self.text)


if __name__ == "__main__":
    unittest.main()
