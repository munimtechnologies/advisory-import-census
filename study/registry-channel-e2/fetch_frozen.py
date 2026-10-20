"""Fetch the frozen study scripts for the E2 pooled ecosystem-adjusted test.

Downloads, from the public repository's main branch, the exact bytes of the A4
censuser and the E1 analysis (plus the E1 test), writes them next to this file,
and records the sha256 and git-blob-sha of what ran so the code is auditable.
Standard library only. Apache-2.0. Made with AI agents for MV2 of Munim, Inc.
"""
import argparse
import hashlib
import json
import os
import sys
import urllib.request

RAW = (
    "https://raw.githubusercontent.com/munimtechnologies/"
    "advisory-import-census/main/study/"
)
DEPS = {
    "real_package_census.py": "registry-channel-a4/real_package_census.py",
    "ecosystem_adjusted_analysis.py": "registry-channel-e1/ecosystem_adjusted_analysis.py",
    "test_ecosystem_adjusted_analysis.py": "registry-channel-e1/test_ecosystem_adjusted_analysis.py",
}
UA = "mv2-advisory-import-census-e2/1.0 (+github.com/munimtechnologies/advisory-import-census)"


def git_blob_sha1(body):
    """GitHub's blob object id: sha1 of 'blob <len>\\0' + content."""
    h = hashlib.sha1()
    h.update(b"blob " + str(len(body)).encode() + b"\x00")
    h.update(body)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description="Fetch frozen E2 scripts.")
    ap.add_argument("--dest", required=True, help="where to write the scripts")
    ap.add_argument("--out-dir", required=True, help="where to write the audit record")
    args = ap.parse_args()

    os.makedirs(args.dest, exist_ok=True)
    os.makedirs(args.out_dir, exist_ok=True)

    record = {}
    for name, path in DEPS.items():
        url = RAW + path
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read()
        if not body:
            print("empty dependency: %s" % name, file=sys.stderr)
            sys.exit(2)
        with open(os.path.join(args.dest, name), "wb") as fh:
            fh.write(body)
        record[name] = {
            "source": url,
            "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "git_blob_sha1": git_blob_sha1(body),
        }
        print("fetched %s (%d bytes, blob %s)" % (name, len(body), record[name]["git_blob_sha1"]))

    with open(os.path.join(args.out_dir, "frozen_code_sha.json"), "w") as fh:
        json.dump(record, fh, indent=2, sort_keys=True)
    print("wrote frozen_code_sha.json")


if __name__ == "__main__":
    main()
