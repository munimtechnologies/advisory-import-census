"""Fetch the PUBLISHED A3 collector and A5 probe/analysis modules (registry-channel A6).

A6 reuses three already-public files verbatim rather than re-typing them, so the
out-of-sample test scores advisories and probes Go modules exactly as A3 and A5 do:

  study/registry-channel-a3/attribution_census.py  (visibility + product-type census)
  study/registry-channel-a5/go_rescue_census.py    (go.mod / Go-proxy probe helpers)
  study/registry-channel-a5/go_rescue_analysis.py  (P1-P4 analysis, A1-A4 statistics)

Each is downloaded from the repository's main branch into the working directory and
its sha256 is written to /out/deps_sha256.json so the exact code that ran is auditable.
Stdlib only. Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import hashlib
import json
import os
import sys
import urllib.request

BASE = ("https://raw.githubusercontent.com/munimtechnologies/"
        "advisory-import-census/main/study/")
DEPS = {
    "attribution_census.py": "registry-channel-a3/attribution_census.py",
    "go_rescue_census.py": "registry-channel-a5/go_rescue_census.py",
    "go_rescue_analysis.py": "registry-channel-a5/go_rescue_analysis.py",
}
UA = "mv2-advisory-import-census-a6 (+https://github.com/munimtechnologies)"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dest", default=".")
    ap.add_argument("--out-dir", default=None)
    args = ap.parse_args(argv)
    shas = {}
    for local, remote in DEPS.items():
        url = BASE + remote
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=60) as r:
            body = r.read()
        if not body.strip():
            raise SystemExit("empty dependency: %s" % url)
        with open(os.path.join(args.dest, local), "wb") as f:
            f.write(body)
        shas[local] = {"source": url, "sha256": hashlib.sha256(body).hexdigest(),
                       "bytes": len(body)}
        print("fetched %-24s %s" % (local, shas[local]["sha256"]), flush=True)
    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        with open(os.path.join(args.out_dir, "deps_sha256.json"), "w",
                  encoding="utf-8") as f:
            json.dump(shas, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
