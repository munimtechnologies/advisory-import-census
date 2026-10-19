"""Fetch A8's frozen inputs and prove they are the committed bytes (registry-channel A8).

A8 re-analyses A6's published census with A5's published statistics. Each input is
downloaded from main and its git blob sha1 is checked against the sha the GitHub
contents API reported for the committed file (2026-10-19). Any mismatch stops the job.
The analysis code that runs beside them is hashed too, so it can be matched to the
commit that froze it. Everything goes to <out-dir>/frozen_code_sha.json.

Stdlib only. Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import hashlib
import json
import os
import sys
import time
import urllib.request

RAW = "https://raw.githubusercontent.com/munimtechnologies/advisory-import-census/main"
TARGETS = [
    ("study/registry-channel-a6/oos_go_rescue_census.csv",
     "oos_go_rescue_census.csv", "89c41a26dd9fb14868f5e4950a0cea19a8bd97cd"),
    ("study/registry-channel-a6/oos_go_rescue_repo_probe.csv",
     "oos_go_rescue_repo_probe.csv", "2d54ff3d79d7f1c335296c9d2a5820dc0be61dec"),
    ("study/registry-channel-a5/go_rescue_analysis.py",
     "go_rescue_analysis.py", "861051715843702a4214006672122eed3bd09fc9"),
]
LOCAL = ["gomod_class_analysis.py", "test_gomod_class.py", "fetch_inputs.py"]


def git_blob_sha1(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def fetch(url, tries=8, pause=20):
    last = None
    for attempt in range(1, tries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "mv2-a8/1.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read()
            if not data:
                raise ValueError("empty body")
            return data
        except Exception as e:  # noqa: BLE001 - report and retry
            last = e
            print("[fetch] attempt %d/%d failed for %s: %s"
                  % (attempt, tries, url, e), flush=True)
            if attempt < tries:
                time.sleep(pause)
    raise SystemExit("[fetch] giving up on %s: %s" % (url, last))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dest", default=".")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)

    record = {"inputs": {}, "analysis_code": {}}
    for path, dest, want in TARGETS:
        data = fetch("%s/%s" % (RAW, path))
        got = git_blob_sha1(data)
        if got != want:
            raise SystemExit("[fetch] %s blob sha %s != frozen %s" % (path, got, want))
        with open(os.path.join(args.dest, dest), "wb") as f:
            f.write(data)
        record["inputs"][path] = {"bytes": len(data), "git_blob_sha1": got,
                                  "sha256": hashlib.sha256(data).hexdigest()}
        print("[fetch] %s OK (%d bytes, blob %s)" % (path, len(data), got), flush=True)
    for name in LOCAL:
        with open(os.path.join(args.dest, name), "rb") as f:
            data = f.read()
        record["analysis_code"][name] = {"bytes": len(data),
                                         "git_blob_sha1": git_blob_sha1(data),
                                         "sha256": hashlib.sha256(data).hexdigest()}
    with open(os.path.join(args.out_dir, "frozen_code_sha.json"), "w",
              encoding="utf-8") as f:
        json.dump(record, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
