#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. Made by AI agents working for MV2 of Munim, Inc.
"""advisory-range-check: compare a Rust advisory's affected ranges with what crates.io published.

Give it one advisory ID (RUSTSEC-..., GHSA-..., or CVE-...) or an OSV JSON file. For every
crates.io package in it, the script lists the published versions and reports:

  R1 BOUND_UNPUBLISHED     a lower bound or an inclusive upper bound names a version that
                           crates.io never published (e.g. "0.25.0" when only 0.25.0-alpha.*
                           exist). OSV's own linter has a similar check (PKG:002).
  R2 PRERELEASE_GAP        a stable lower bound X leaves out published pre-releases of X
                           (SemVer: 0.26.0-beta.1 < 0.26.0). Only a real gap if the
                           vulnerable code was already in those pre-releases: read the source.
  R3 FIX_UNPUBLISHED       the fixed version is not on crates.io (yet).
  R4 FIX_PRERELEASES       published pre-releases of a stable fixed version Y are counted as
                           affected. Correct only if the fix landed after them (info).
  R5 EMPTY_RANGE           a range matches no published version at all.
  R6 UNPARSED              a free-text range (repository advisories) was not understood.
  R7 NOT_IN_RUSTSEC        no RustSec advisory for the package names this GHSA/CVE (info).

R1, R2, R5 and R6 make the exit code 1, so the script can gate CI. Every finding is a
candidate for a human to check against the released source, never a verdict.

Sources: api.osv.dev (OSV records, RustSec lookup), crates.io API (versions, 1 request per
second), api.github.com (GitHub-reviewed advisories; with --repo, a repository's published
advisory, which is how maintainer-only GHSAs are read). Standard library only.
"""
import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "0.1.0"
UA = "advisory-range-check/%s (MV2 of Munim, Inc.; mv2@munimtech.com)" % __version__
ECO = "crates.io"
_NUM = re.compile(r"^\d+$")
_VER = r"v?\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
FAILING = ("R1", "R2", "R5", "R6")


# ---------------------------------------------------------------- versions
def semver_key(v):
    """Sort key for SemVer versions. Unparsable -> None."""
    s = str(v).strip().lstrip("v").split("+", 1)[0]
    core, _, pre = s.partition("-")
    parts = core.split(".")
    if not parts or len(parts) > 3 or not all(_NUM.match(p) for p in parts):
        return None
    nums = tuple(int(p) for p in parts) + (0,) * (3 - len(parts))
    if not pre:
        return (nums, (1,))
    ids = []
    for x in pre.split("."):
        ids.append((0, int(x), "") if _NUM.match(x) else (1, 0, x))
    return (nums, (0, tuple(ids)))


def is_pre(v):
    return "-" in str(v).split("+", 1)[0]


def norm(v):
    return str(v).strip().lstrip("v")


def synthetic(v):
    """'1.19.0-0' is the conventional 'lowest pre-release of 1.19.0' bound, not a real version."""
    return str(v).split("+", 1)[0].partition("-")[2] == "0"


def versions_in_text(text):
    """Every SemVer-looking version in free text such as '>= 0.24.5, 0.25.3' (in order)."""
    return [norm(x) for x in re.findall(_VER, str(text or "")) if semver_key(x) is not None]


# ---------------------------------------------------------------- intervals
class Interval(object):
    """lo/hi are version strings or None (unbounded)."""

    def __init__(self, lo=None, lo_incl=True, hi=None, hi_incl=False, hi_kind="", text=""):
        self.lo, self.lo_incl, self.hi, self.hi_incl = lo, lo_incl, hi, hi_incl
        self.hi_kind = hi_kind or ("last_affected" if hi_incl else ("fixed" if hi else ""))
        self.text = text

    def contains(self, v):
        k = semver_key(v)
        if k is None:
            return False
        if self.lo is not None:
            lk = semver_key(self.lo)
            if lk is None or k < lk or (k == lk and not self.lo_incl):
                return False
        if self.hi is not None:
            hk = semver_key(self.hi)
            if hk is None or k > hk or (k == hk and not self.hi_incl):
                return False
        return True

    def describe(self):
        if self.text:
            return self.text.strip()
        a = (">= " if self.lo_incl else "> ") + self.lo if self.lo else ""
        b = ("<= " if self.hi_incl else "< ") + self.hi if self.hi else ""
        return ", ".join(x for x in (a, b) if x) or "all versions"


def osv_intervals(affected):
    """Intervals and explicit versions from one OSV `affected` entry."""
    out = []
    for rng in affected.get("ranges", []) or []:
        if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        lo, open_ = None, False
        for ev in rng.get("events", []) or []:
            if "introduced" in ev:
                s = norm(ev["introduced"])
                lo, open_ = (None if s == "0" else s), True
            elif open_ and ("fixed" in ev or "last_affected" in ev or "limit" in ev):
                kind = "fixed" if "fixed" in ev else ("last_affected" if "last_affected" in ev else "limit")
                out.append(Interval(lo, True, norm(ev[kind]), kind == "last_affected", kind))
                open_ = False
        if open_:
            out.append(Interval(lo, True, None, False, ""))
    return out, [norm(x) for x in affected.get("versions", []) or []]


_CLAUSE = re.compile(r"^(>=|<=|==|=|>|<)?\s*(" + _VER + r")$")
_SPAN = re.compile(r"^(" + _VER + r")(?:\s*\.\.=?\s*|\s+-\s+|\s+to\s+|\s+through\s+)(" + _VER + r")$")


def parse_range_text(text):
    """GitHub-style range text -> list of Interval, or None if not understood.

    Handles '>= 1.2.0, < 1.3.0', '< 2.0', '= 1.0.0', '1.0.0', and the free-text spans
    maintainers type into repository advisories ('0.25.0 .. 0.26.1', '1.0 - 1.4', both
    ends taken as inclusive). Several alternatives may be separated by '||' or ';'.
    """
    t = (text or "").strip()
    if not t:
        return None
    out = []
    for alt in re.split(r"\|\||;", t):
        alt = alt.strip()
        if not alt:
            continue
        m = _SPAN.match(alt)
        if m and semver_key(m.group(1)) and semver_key(m.group(2)):
            out.append(Interval(norm(m.group(1)), True, norm(m.group(2)), True, "last_affected", alt))
            continue
        lo, lo_incl, hi, hi_incl = None, True, None, False
        ok = True
        for cl in [c.strip() for c in re.split(r",|\s+(?=[<>=])", alt) if c.strip()]:
            m = _CLAUSE.match(cl)
            if not m or semver_key(m.group(2)) is None:
                ok = False
                break
            op, v = m.group(1) or "=", norm(m.group(2))
            if op in ("=", "=="):
                lo, lo_incl, hi, hi_incl = v, True, v, True
            elif op in (">=", ">"):
                lo, lo_incl = v, op == ">="
            else:
                hi, hi_incl = v, op == "<="
        if not ok:
            return None
        out.append(Interval(lo, lo_incl, hi, hi_incl, "", alt))
    return out or None


# ---------------------------------------------------------------- analysis
def check_package(name, intervals, versions, releases, refs=(), rustsec=None, unparsed=()):
    """releases: list of (version, yanked). rustsec: list of OSV RUSTSEC records for the
    package (None = not looked up). refs: GHSA/CVE ids of the advisory. Returns findings."""
    found = []
    pub_keys = {semver_key(v) for v, _ in releases} - {None}
    live = sorted((norm(v) for v, y in releases if not y and semver_key(v) is not None), key=semver_key)
    vkeys = {semver_key(v) for v in versions} - {None}

    def unpublished(v):
        return semver_key(v) is not None and semver_key(v) not in pub_keys

    def affected(v):
        return semver_key(v) in vkeys or any(i.contains(v) for i in intervals)

    for text in unparsed:
        found.append({"code": "R6", "package": name, "range": text,
                      "detail": "range text not understood; check it by hand"})
    seen_lo = set()
    for iv in intervals:
        if iv.lo and unpublished(iv.lo) and not synthetic(iv.lo):
            pres = [v for v in live if is_pre(v) and semver_key(v)[0] == semver_key(iv.lo)[0]]
            found.append({"code": "R1", "package": name, "range": iv.describe(), "bound": iv.lo,
                          "detail": "lower bound %s was never published on crates.io%s" % (
                              iv.lo, (" (its pre-releases were: %s)" % ", ".join(pres[:6])) if pres else "")})
        if iv.hi and iv.hi_incl and unpublished(iv.hi):
            found.append({"code": "R1", "package": name, "range": iv.describe(), "bound": iv.hi,
                          "detail": "inclusive upper bound %s was never published on crates.io" % iv.hi})
        if iv.lo and iv.lo_incl and not is_pre(iv.lo) and iv.lo not in seen_lo and semver_key(iv.lo):
            seen_lo.add(iv.lo)
            core = semver_key(iv.lo)[0]
            gap = [v for v in live if is_pre(v) and semver_key(v)[0] == core and not affected(v)]
            if gap:
                f = {"code": "R2", "package": name, "range": iv.describe(), "bound": iv.lo,
                     "versions": gap,
                     "detail": "%d published pre-release(s) of %s are outside every range: %s" % (
                         len(gap), iv.lo, ", ".join(gap[:8]) + (" ..." if len(gap) > 8 else ""))}
                if rustsec is not None:
                    f["rustsec_affected"] = [v for v in gap if any(rustsec_covers(r, name, v) for r in rustsec)]
                found.append(f)
        if iv.hi and not iv.hi_incl and iv.hi_kind == "fixed":
            if unpublished(iv.hi):
                found.append({"code": "R3", "package": name, "range": iv.describe(), "bound": iv.hi,
                              "detail": "fixed version %s is not on crates.io" % iv.hi})
            if not is_pre(iv.hi) and semver_key(iv.hi):
                core = semver_key(iv.hi)[0]
                pres = [v for v in live if is_pre(v) and semver_key(v)[0] == core and iv.contains(v)]
                if pres:
                    found.append({"code": "R4", "package": name, "range": iv.describe(), "bound": iv.hi,
                                  "versions": pres,
                                  "detail": "%d pre-release(s) of the fix version %s are counted as affected: %s"
                                            % (len(pres), iv.hi, ", ".join(pres[:6]))})
        if live and semver_key(iv.lo or "0") and not any(iv.contains(v) for v in live):
            found.append({"code": "R5", "package": name, "range": iv.describe(),
                          "detail": "no published, non-yanked version is inside this range"})
    if rustsec is not None and refs:
        refset = set(refs)
        linked = [r for r in rustsec if refset & ({r.get("id")} | set(r.get("aliases", []) or [])
                                                  | set(r.get("related", []) or []))]
        if not linked:
            found.append({"code": "R7", "package": name,
                          "detail": "no RustSec advisory for %s lists %s" % (name, " or ".join(sorted(refset)))})
    return found


def rustsec_covers(rec, name, v):
    for aff in rec.get("affected", []) or []:
        pkg = aff.get("package", {}) or {}
        if pkg.get("ecosystem") == ECO and pkg.get("name") == name:
            ivs, vers = osv_intervals(aff)
            if v in vers or any(i.contains(v) for i in ivs):
                return True
    return False


# ---------------------------------------------------------------- sources
def from_osv(rec):
    """OSV record -> (refs, {package: (intervals, versions, unparsed)})."""
    pk = {}
    for aff in rec.get("affected", []) or []:
        pkg = aff.get("package", {}) or {}
        if pkg.get("ecosystem") != ECO:
            continue
        ivs, vers = osv_intervals(aff)
        cur = pk.setdefault(pkg.get("name", ""), ([], [], []))
        cur[0].extend(ivs)
        cur[1].extend(vers)
    refs = {rec.get("id", "")} | set(rec.get("aliases", []) or [])
    return {r for r in refs if r.startswith(("GHSA-", "CVE-"))}, pk


def from_github(doc):
    """GitHub global or repository advisory JSON -> (refs, packages).

    The patched-version field may be a version, an object with an identifier, or free text
    such as '>= 0.24.5, 0.25.3' (repository advisories). An open-ended range gets the
    lowest patched version above its lower bound as its fix."""
    pk = {}
    for vul in doc.get("vulnerabilities", []) or []:
        pkg = vul.get("package") or {}
        eco = (pkg.get("ecosystem") or vul.get("ecosystem") or "").lower()
        name = pkg.get("name") or vul.get("name") or ""
        if eco not in ("rust", "crates.io", "cargo") or not name:
            continue
        cur = pk.setdefault(name, ([], [], []))
        text = vul.get("vulnerable_version_range") or ""
        ivs = parse_range_text(text)
        fix = vul.get("first_patched_version") or vul.get("patched_versions") or ""
        if isinstance(fix, dict):
            fix = fix.get("identifier") or ""
        fixes = versions_in_text(fix)
        if ivs is None:
            cur[2].append(text)
            continue
        for iv in ivs:
            if iv.hi is None:
                above = [f for f in fixes if iv.lo is None or semver_key(f) > semver_key(iv.lo)]
                if above:
                    iv.hi, iv.hi_incl, iv.hi_kind = min(above, key=semver_key), False, "fixed"
            elif not iv.hi_incl:
                iv.hi_kind = "fixed"
            cur[0].append(iv)
    refs = {doc.get("ghsa_id", ""), doc.get("cve_id") or ""}
    return {r for r in refs if r}, pk


class Net(object):
    def __init__(self, sleep=time.sleep):
        self.sleep = sleep
        self.last_crates = 0.0

    def get(self, url, data=None):
        for i in range(4):
            try:
                req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                             headers={"User-Agent": UA, "Accept": "application/json",
                                                      "Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=60) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return None
                if e.code in (429, 500, 502, 503, 504) and i < 3:
                    self.sleep(3 * (i + 1))
                    continue
                raise
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                if i == 3:
                    raise
                self.sleep(3 * (i + 1))
        return None

    def osv(self, vid):
        return self.get("https://api.osv.dev/v1/vulns/" + urllib.parse.quote(vid))

    def osv_package(self, name):
        out, token = [], None
        while True:
            body = {"package": {"name": name, "ecosystem": ECO}}
            if token:
                body["page_token"] = token
            doc = self.get("https://api.osv.dev/v1/query", body) or {}
            out.extend(doc.get("vulns", []) or [])
            token = doc.get("next_page_token")
            if not token:
                return out

    def github(self, ghsa, repo=None):
        if repo:
            doc = self.get("https://api.github.com/repos/%s/security-advisories/%s" % (repo, ghsa))
            if doc:
                return doc
        return self.get("https://api.github.com/advisories/" + ghsa)

    def releases(self, name):
        out = []
        url = "https://crates.io/api/v1/crates/%s/versions?per_page=100" % urllib.parse.quote(name)
        while url:
            wait = 1.05 - (time.time() - self.last_crates)
            if wait > 0:
                self.sleep(wait)
            doc = self.get(url)
            self.last_crates = time.time()
            if not doc:
                break
            for v in doc.get("versions", []) or []:
                out.append((v.get("num", ""), bool(v.get("yanked"))))
            nxt = (doc.get("meta", {}) or {}).get("next_page")
            url = ("https://crates.io/api/v1/crates/%s/versions%s" % (urllib.parse.quote(name), nxt)) if nxt else None
        return out


def load(advisory, net, repo=None, path=None):
    """Returns (source label, refs, packages)."""
    if path:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        if "vulnerabilities" in doc:
            return ("github-json", ) + from_github(doc)
        return ("osv-json", ) + from_osv(doc)
    def has_crate(r):
        return r and any((a.get("package", {}) or {}).get("ecosystem") == ECO for a in r.get("affected", []) or [])

    if not (advisory.startswith("GHSA-") and repo):
        rec = net.osv(advisory)
        if has_crate(rec):
            return ("osv", ) + from_osv(rec)
        if rec and advisory.startswith("CVE-"):
            # a CVE record rarely names crates; follow its GHSA/RUSTSEC aliases once
            for alt in sorted(set(rec.get("aliases", []) or []) | set(rec.get("related", []) or [])):
                if alt.startswith(("GHSA-", "RUSTSEC-")):
                    r2 = net.osv(alt)
                    if has_crate(r2):
                        refs, pk = from_osv(r2)
                        return ("osv via " + alt, refs | {advisory}, pk)
    if advisory.startswith("GHSA-"):
        doc = net.github(advisory, repo)
        if doc:
            return ("github-repo" if repo and doc.get("state") else "github", ) + from_github(doc)
    raise SystemExit("advisory %s not found with crates.io packages (for a GHSA that only the "
                     "maintainers published, pass --repo owner/name)" % advisory)


def run(advisory, net, repo=None, path=None, rustsec=True):
    source, refs, packages = load(advisory, net, repo, path)
    report = {"advisory": advisory or path, "source": source, "refs": sorted(refs), "packages": {}}
    for name, (ivs, vers, unparsed) in sorted(packages.items()):
        rel = net.releases(name)
        if not rel:
            report["packages"][name] = {"error": "no versions on crates.io (wrong name?)", "findings": []}
            continue
        rs = None
        if rustsec:
            rs = [r for r in net.osv_package(name) if r.get("id", "").startswith("RUSTSEC-")]
        report["packages"][name] = {
            "ranges": [i.describe() for i in ivs] + [("= " + v) for v in vers],
            "published": len(rel),
            "affected_published": sum(1 for v, _ in rel if norm(v) in vers or any(i.contains(norm(v)) for i in ivs)),
            "findings": check_package(name, ivs, vers, rel, refs if source != "osv" or advisory.startswith(("GHSA-", "CVE-")) else (), rs, unparsed),
        }
    return report


def render(report):
    lines = ["%s (%s)%s" % (report["advisory"], report["source"],
                            ("  refs: " + ", ".join(report["refs"])) if report["refs"] else "")]
    for name, p in report["packages"].items():
        if "error" in p:
            lines.append("  %s: %s" % (name, p["error"]))
            continue
        lines.append("  %s: %s  (%d of %d published versions in range)" % (
            name, "; ".join(p["ranges"]) or "-", p["affected_published"], p["published"]))
        for f in p["findings"]:
            extra = ""
            if f.get("rustsec_affected") is not None and f["code"] == "R2":
                extra = "  [RustSec marks %d of them affected]" % len(f["rustsec_affected"])
            lines.append("    %s %s%s" % (f["code"], f["detail"], extra))
        if not p["findings"]:
            lines.append("    ok")
    return "\n".join(lines)


def exit_code(report):
    return 1 if any(f["code"] in FAILING for p in report["packages"].values() for f in p["findings"]) else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("advisory", nargs="*", help="RUSTSEC-, GHSA- or CVE- id(s)")
    ap.add_argument("--repo", help="owner/name, to read a GHSA published only in the project's repository")
    ap.add_argument("--file", help="read an OSV or GitHub advisory JSON file instead")
    ap.add_argument("--json", action="store_true", help="print JSON")
    ap.add_argument("--no-rustsec", action="store_true", help="skip the RustSec cross-check")
    ap.add_argument("--version", action="version", version="%(prog)s " + __version__)
    a = ap.parse_args(argv)
    if not a.advisory and not a.file:
        ap.error("give an advisory id or --file")
    net, reports = Net(), []
    for adv in (a.advisory or [""]):
        reports.append(run(adv, net, a.repo, a.file, not a.no_rustsec))
    if a.json:
        print(json.dumps(reports if len(reports) > 1 else reports[0], indent=1))
    else:
        print("\n\n".join(render(r) for r in reports))
    return max(exit_code(r) for r in reports)


if __name__ == "__main__":
    sys.exit(main())
