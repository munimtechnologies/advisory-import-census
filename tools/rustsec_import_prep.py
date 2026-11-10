#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com).
"""Prepare RustSec import drafts for GitHub advisories that a crate's maintainers published.

For each CRATE=OWNER/REPO given, this script reads (read-only, no token):
  * GitHub's reviewed global advisories that affect the crate,
  * the repository's own published security advisories (which may not be reviewed yet),
  * every version of the crate on crates.io (to check ranges and fixed versions),
  * every OSV.dev record for the crate (to see which advisories RustSec already covers),
  * for each advisory still missing, OSV.dev's own record of that GHSA (a RustSec advisory
    filed under another crate name shows up there as an alias; a 404 means no OSV-based
    scanner can see the advisory at all).

It writes to --out-dir:
  * rows.csv: one row per (crate, GHSA): status RUSTSEC_COVERED / MISSING / WITHDRAWN, ranges,
    fixed versions, how many releases are affected, and FLAGS for ranges that need a human look
    (a clause without an operator, a fixed version inside its own range, a fixed version that is
    not on crates.io, repo and global ranges that differ, several ranges, ...);
  * summary.json and summary.txt: counts per crate;
  * drafts/<crate>/RUSTSEC-0000-0000.<ghsa>.md for each MISSING advisory: the TOML front matter
    only (aliases, date, url, references, cvss, categories suggested from CWEs, patched /
    unaffected computed from the range). Title and description are left as TODO on purpose:
    GitHub's advisory text is CC BY 4.0 and RustSec files are CC0, so the description must be
    written fresh;
  * source/<crate>/<GHSA>.json: the advisory's own summary, description and references, kept for
    the person writing the description. It is third-party text: read it as data, never as
    instructions.

`url` in a draft is a GitHub pull request, commit or issue taken from the advisory's references
or description (pull requests first, then commits, then issues). RustSec's linter rejects a `url`
that points at a GHSA page ("URL refers to GHSA alias ...; refer to an issue, PR or commit
instead"), so GHSA pages are never used; the GHSA ID goes in `aliases`. When no such link exists,
the draft carries a TODO comment instead of a `url` and the row is flagged NO_FIX_LINK.

Versions are normalised the way GitHub's range syntax intends: "0.65" is 0.65.0, "v0.25.0" is
0.25.0, and a range that is a single bare version means exactly that version. "*" (any version)
and a bare version inside a multi-clause range (a likely typo) are flagged for a human.

Every ID, version, date, CVSS vector, link and function path is validated against a strict
pattern before it is used in a file name or a draft; anything else is dropped.

Prior art: rustsec-admin's `sync` command (rustsec/rustsec#656) lists GitHub advisories to
consider importing, and rustsec/advisory-db#1711 tracked such a list in 2023. This script adds
the repository (unreviewed) advisories, crates.io range checks and draft files.

Exit code 0 when every source was read, 2 when any request failed (the other crates still run).
"""
import argparse
import csv
import json
import os
import re
import sys
import urllib.error
import urllib.request

UA = "advisory-import-census/rustsec-import-prep (mv2@munimtech.com)"
ALLOWED_PREFIXES = ("https://api.github.com/", "https://crates.io/api/v1/", "https://api.osv.dev/v1/")
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

GHSA_RE = re.compile(r"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
RUSTSEC_RE = re.compile(r"^RUSTSEC-\d{4}-\d{4}$")
CWE_RE = re.compile(r"^CWE-\d{1,5}$")
CRATE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
SUFFIX = r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
VER = r"\d+\.\d+\.\d+" + SUFFIX
VER_RE = re.compile(r"^" + VER + r"$")
PARTIAL_RE = re.compile(r"^v?(\d{1,9})(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(" + SUFFIX + r")$")
PATCH_TOKEN_RE = re.compile(r"v?\d+(?:\.\d+){1,2}" + SUFFIX)
CLAUSE_RE = re.compile(r"^(>=|<=|>|<|=)?\s*(\S+)$")
CVSS3_RE = re.compile(
    r"^CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")
FUNC_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)+$")
ADV_URL_RE = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/security/advisories/"
    r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}$")
# A GitHub pull request, commit or issue, and nothing else (checked with fullmatch).
FIX_LINK_RE = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}/"
    r"(pull|commit|issues)/([0-9a-f]{7,40}|[0-9]{1,7})")
TEXT_URL_RE = re.compile(r"https://github\.com/[^\s<>()\[\]{}\"'`|\\]+")
LINK_KIND_ORDER = {"pull": 0, "commit": 1, "issues": 2}
NEXT_RE = re.compile(r'<(https://api\.github\.com/[^>\s]+)>;\s*rel="next"')
SEVERITY = {"low": "low", "medium": "medium", "moderate": "medium", "high": "high",
            "critical": "critical"}
SEV_ORDER = ["critical", "high", "medium", "low", ""]

# RustSec categories suggested from CWE IDs. A suggestion only: check each draft by hand.
CWE_CATEGORY = [
    ("code-execution", {"CWE-77", "CWE-78", "CWE-94", "CWE-95"}),
    ("crypto-failure", {"CWE-203", "CWE-208", "CWE-295", "CWE-297", "CWE-310", "CWE-311",
                        "CWE-320", "CWE-322", "CWE-325", "CWE-326", "CWE-327", "CWE-328",
                        "CWE-330", "CWE-347", "CWE-354"}),
    ("denial-of-service", {"CWE-248", "CWE-400", "CWE-401", "CWE-404", "CWE-405", "CWE-407",
                           "CWE-409", "CWE-617", "CWE-674", "CWE-770", "CWE-772", "CWE-789",
                           "CWE-834", "CWE-835", "CWE-1325", "CWE-1333"}),
    ("file-disclosure", {"CWE-22", "CWE-23", "CWE-36", "CWE-59"}),
    ("format-injection", {"CWE-74", "CWE-75", "CWE-93", "CWE-113", "CWE-116", "CWE-117"}),
    ("memory-corruption", {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-415", "CWE-416",
                           "CWE-763", "CWE-787", "CWE-824"}),
    ("memory-exposure", {"CWE-125", "CWE-126", "CWE-226", "CWE-908"}),
    ("privilege-escalation", {"CWE-269", "CWE-284", "CWE-285", "CWE-287", "CWE-288",
                              "CWE-290", "CWE-305", "CWE-306", "CWE-639", "CWE-862",
                              "CWE-863"}),
]

ROW_FIELDS = ["crate", "ghsa", "cve", "severity", "published", "sources", "status",
              "rustsec_ids", "ranges", "patched", "versions_affected", "cwes", "cvss",
              "flags", "draft_file"]


# ---------------------------------------------------------------- versions and ranges

def norm_ver(s):
    """'0.65' -> '0.65.0', 'v0.25.0' -> '0.25.0', '1' -> '1.0.0'; '' when not a version.
    A pre-release or build suffix is only accepted on a full MAJOR.MINOR.PATCH version."""
    if not isinstance(s, str):
        return ""
    m = PARTIAL_RE.match(s.strip())
    if not m:
        return ""
    a, b, c, rest = m.groups()
    if rest and c is None:
        return ""
    return "%d.%d.%d%s" % (int(a), int(b or 0), int(c or 0), rest or "")


def ver_key(v):
    """Sort key for a semver string (pre-releases sort before their release)."""
    v = v.split("+", 1)[0]
    core, _, pre = v.partition("-")
    a, b, c = (int(x) for x in core.split("."))
    if not pre:
        return (a, b, c, 1, ())
    parts = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (a, b, c, 0, parts)


def parse_range(s):
    """'>= 1.0.0, < 1.2' -> ([('>=', '1.0.0'), ('<', '1.2.0')], True).
    A range that is one bare version means '= version'; '*' means any version ([], True).
    ([], False) if any clause is not a valid version, or a clause of a multi-clause range has
    no operator (e.g. '>= 0.34.0-beta.1,0.61.0', which is almost certainly a typo)."""
    if not isinstance(s, str) or not s.strip():
        return [], False
    if s.strip() == "*":
        return [], True
    parts = s.split(",")
    out = []
    for part in parts:
        m = CLAUSE_RE.match(part.strip())
        if not m:
            return [], False
        op = m.group(1)
        if op is None and len(parts) > 1:
            return [], False
        v = norm_ver(m.group(2))
        if not v:
            return [], False
        out.append((op or "=", v))
    return out, True


def render_range(clauses):
    return ", ".join("%s %s" % c for c in clauses)


_OPS = {
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
    ">": lambda a, b: a > b,
    "<": lambda a, b: a < b,
    "=": lambda a, b: a == b,
}


def satisfies(v, clauses):
    k = ver_key(v)
    return all(_OPS[op](k, ver_key(x)) for op, x in clauses)


def norm_range(s):
    return re.sub(r"\s+", "", s or "")


def range_key(s):
    clauses, ok = parse_range(s)
    return "ok:" + repr(clauses) if ok else "raw:" + norm_range(s)


# ---------------------------------------------------------------- advisory records

def _patched_list(raw, source):
    if source == "global":
        n = norm_ver(raw)
        return [n] if n else []
    out = []
    for t in PATCH_TOKEN_RE.findall(raw):
        n = norm_ver(t)
        if n and n not in out:
            out.append(n)
    return out


def _entries(adv, crate, source):
    out = []
    for v in adv.get("vulnerabilities") or []:
        if not isinstance(v, dict):
            continue
        pkg = v.get("package")
        if not isinstance(pkg, dict) or pkg.get("name") != crate:
            continue
        if pkg.get("ecosystem") not in ("rust", "crates.io"):
            continue
        rng = v.get("vulnerable_version_range")
        rng = rng.strip() if isinstance(rng, str) else ""
        if source == "global":
            p = v.get("first_patched_version")
            if isinstance(p, dict):
                p = p.get("identifier")
        else:
            p = v.get("patched_versions")
        raw = p.strip() if isinstance(p, str) else ""
        funcs = [f for f in (v.get("vulnerable_functions") or [])
                 if isinstance(f, str) and FUNC_RE.match(f)]
        out.append({"range": rng, "patched": _patched_list(raw, source), "patched_raw": raw,
                    "functions": funcs})
    return out


def normalize(adv, crate, source):
    """Validated fields of one GitHub advisory (global or repository) for one crate."""
    if not isinstance(adv, dict):
        return None
    gid = adv.get("ghsa_id")
    if not isinstance(gid, str) or not GHSA_RE.match(gid):
        return None
    cve = adv.get("cve_id")
    cve = cve if isinstance(cve, str) and CVE_RE.match(cve) else ""
    sev = adv.get("severity")
    sev = SEVERITY.get(sev.lower(), "") if isinstance(sev, str) else ""
    pub = adv.get("published_at")
    pub = pub[:10] if isinstance(pub, str) and DATE_RE.match(pub) else ""
    cvss = ""
    cs = adv.get("cvss_severities")
    if isinstance(cs, dict) and isinstance(cs.get("cvss_v3"), dict):
        vs = cs["cvss_v3"].get("vector_string")
        if isinstance(vs, str) and CVSS3_RE.match(vs):
            cvss = vs
    if not cvss and isinstance(adv.get("cvss"), dict):
        vs = adv["cvss"].get("vector_string")
        if isinstance(vs, str) and CVSS3_RE.match(vs):
            cvss = vs
    cwes = []
    for c in adv.get("cwes") or []:
        cid = c.get("cwe_id") if isinstance(c, dict) else None
        if isinstance(cid, str) and CWE_RE.match(cid) and cid not in cwes:
            cwes.append(cid)
    for cid in adv.get("cwe_ids") or []:
        if isinstance(cid, str) and CWE_RE.match(cid) and cid not in cwes:
            cwes.append(cid)
    html = adv.get("html_url")
    url = html if isinstance(html, str) and ADV_URL_RE.match(html) else ""
    refs = [r for r in (adv.get("references") or []) if isinstance(r, str)][:50]
    text = {
        "summary": adv.get("summary") if isinstance(adv.get("summary"), str) else "",
        "description": (adv.get("description") or "")[:20000]
        if isinstance(adv.get("description"), str) else "",
        "references": refs,
    }
    return {
        "ghsa": gid, "cve": cve, "severity": sev, "published": pub, "cvss": cvss,
        "cwes": cwes, "url": url, "withdrawn": bool(adv.get("withdrawn_at")),
        "entries": _entries(adv, crate, source), "text": text,
    }


def _clean_link(s):
    """A GitHub pull request, commit or issue URL in canonical form, or ''.
    Query strings and fragments are dropped; anything after the number or SHA is refused."""
    if not isinstance(s, str):
        return ""
    s = s.strip().split("#", 1)[0].split("?", 1)[0].rstrip(".,;:!/")
    m = FIX_LINK_RE.fullmatch(s)
    if not m:
        return ""
    kind, ident = m.group(1), m.group(2)
    if kind in ("pull", "issues") and not ident.isdigit():
        return ""
    if kind == "commit" and not re.fullmatch(r"[0-9a-f]{7,40}", ident):
        return ""
    return s


def fix_links(*recs):
    """Pull request, commit and issue links from the advisories' references, then from their
    descriptions, deduplicated, pull requests first, then commits, then issues (stable order
    within a kind). GHSA pages and any other link are left out."""
    found = []
    for rec in recs:
        if not isinstance(rec, dict) or not isinstance(rec.get("text"), dict):
            continue
        refs = rec["text"].get("references") or []
        for r in refs if isinstance(refs, list) else []:
            found.append(_clean_link(r))
    for rec in recs:
        if not isinstance(rec, dict) or not isinstance(rec.get("text"), dict):
            continue
        desc = rec["text"].get("description")
        if isinstance(desc, str):
            found.extend(_clean_link(u) for u in TEXT_URL_RE.findall(desc))
    out = []
    for link in found:
        if link and link not in out:
            out.append(link)
    out.sort(key=lambda u: LINK_KIND_ORDER[u.split("/")[5]])
    return out


def rustsec_coverage(osv_vulns):
    """Map alias (GHSA or CVE) -> set of RUSTSEC IDs, and the set of RUSTSEC IDs, from OSV."""
    by_alias, ids = {}, set()
    for v in osv_vulns:
        if not isinstance(v, dict):
            continue
        vid = v.get("id")
        aliases = [a for a in (v.get("aliases") or []) if isinstance(a, str)]
        if isinstance(vid, str) and RUSTSEC_RE.match(vid):
            ids.add(vid)
            for a in aliases:
                if GHSA_RE.match(a) or CVE_RE.match(a):
                    by_alias.setdefault(a, set()).add(vid)
        elif isinstance(vid, str) and GHSA_RE.match(vid):
            for a in aliases:
                if RUSTSEC_RE.match(a):
                    by_alias.setdefault(vid, set()).add(a)
                    ids.add(a)
    return by_alias, ids


def osv_ghsa_rustsec(fetch, gid):
    """RUSTSEC IDs that OSV.dev's own record of a GHSA lists as aliases (any crate);
    None when OSV.dev has no record of the GHSA (HTTP 404)."""
    if not GHSA_RE.match(gid):
        raise ValueError("bad GHSA id")
    try:
        obj, _h = fetch(OSV_VULN_URL + gid)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    if not isinstance(obj, dict):
        raise ValueError("expected a JSON object from OSV")
    return {a for a in (obj.get("aliases") or []) if isinstance(a, str) and RUSTSEC_RE.match(a)}


# ---------------------------------------------------------------- checks and drafts

def check_flags(rec, other, versions):
    flags = []
    ents = rec["entries"]
    if not ents:
        return ["NO_ENTRY_FOR_CRATE"]
    if len(ents) > 1:
        flags.append("MULTI_RANGE")
    for e in ents:
        clauses, ok = parse_range(e["range"])
        if not ok:
            flags.append("RANGE_UNPARSED")
        elif not clauses:
            flags.append("RANGE_ANY")
        if not e["patched"]:
            flags.append("NO_PATCHED")
        if len(e["patched"]) > 1:
            flags.append("MULTI_PATCHED")
        for p in e["patched"]:
            if versions and p not in versions:
                flags.append("PATCHED_NOT_ON_CRATES_IO")
            elif versions.get(p):
                flags.append("PATCHED_YANKED")
            if ok and satisfies(p, clauses):
                flags.append("PATCHED_INSIDE_RANGE")
        if ok and versions:
            for op, x in clauses:
                if op in (">=", "<=", "=") and x not in versions:
                    flags.append("BOUND_NOT_ON_CRATES_IO")
            if not any(satisfies(v, clauses) for v in versions):
                flags.append("RANGE_MATCHES_NO_RELEASE")
    if other is not None:
        a = sorted(range_key(e["range"]) for e in ents)
        b = sorted(range_key(e["range"]) for e in other["entries"])
        if a != b:
            flags.append("REPO_GLOBAL_RANGE_DIFFER")
    seen, out = set(), []
    for f in flags:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def versions_affected(rec, versions):
    n = 0
    for v, yanked in versions.items():
        if yanked:
            continue
        for e in rec["entries"]:
            clauses, ok = parse_range(e["range"])
            if ok and satisfies(v, clauses):
                n += 1
                break
    return n


def rustsec_versions(rec, versions):
    """(patched, unaffected) lists for the draft, or (None, None) when it needs a human."""
    ents = rec["entries"]
    if len(ents) != 1:
        return None, None
    e = ents[0]
    clauses, ok = parse_range(e["range"])
    if not ok or not clauses or len(e["patched"]) > 1:
        return None, None
    if e["patched"] and satisfies(e["patched"][0], clauses):
        return None, None
    patched = [">= " + e["patched"][0]] if e["patched"] else []
    unaffected = []
    for op, x in clauses:
        if op == ">=" and (not versions or any(ver_key(v) < ver_key(x) for v in versions)):
            unaffected.append("< " + x)
        elif op == ">" and (not versions or any(ver_key(v) <= ver_key(x) for v in versions)):
            unaffected.append("<= " + x)
    return patched, unaffected


def categories(cwes):
    return [name for name, ids in CWE_CATEGORY if any(c in ids for c in cwes)]


def _toml_list(items):
    return "[" + ", ".join('"%s"' % i for i in items) + "]"


def render_draft(crate, rec, versions, links=None):
    patched, unaffected = rustsec_versions(rec, versions)
    aliases = sorted(x for x in (rec["cve"], rec["ghsa"]) if x)
    if links is None:
        links = fix_links(rec)
    lines = ["```toml", "[advisory]", 'id = "RUSTSEC-0000-0000"', 'package = "%s"' % crate,
             'date = "%s"' % rec["published"]]
    if links:
        lines.append('url = "%s"' % links[0])
        if len(links) > 1:
            lines.append("references = " + _toml_list(links[1:4]))
    else:
        lines.append("# url = TODO: an issue, PR or commit (RustSec's lint rejects GHSA links; "
                     "the GHSA ID is in aliases)")
    lines += ["categories = " + _toml_list(categories(rec["cwes"])),
              "keywords = []", "aliases = " + _toml_list(aliases)]
    if rec["cvss"]:
        lines.append('cvss = "%s"' % rec["cvss"])
    ident = crate.replace("-", "_") + "::"
    if patched is not None:
        e = rec["entries"][0]
        funcs = [f for f in e["functions"] if f.startswith(ident)]
        if funcs:
            rng = render_range(parse_range(e["range"])[0])
            lines += ["", "[affected.functions]"]
            lines += ['"%s" = ["%s"]' % (f, rng) for f in funcs]
    lines += ["", "[versions]"]
    if patched is None:
        lines.append("patched = []  # TODO: ranges need a human (see flags in rows.csv)")
    else:
        lines.append("patched = " + _toml_list(patched))
        if unaffected:
            lines.append("unaffected = " + _toml_list(unaffected))
    lines += ["```", "", "# TODO: title, written fresh", "",
              "TODO: description, written fresh. GitHub's advisory text is CC BY 4.0 and RustSec "
              "files are CC0, so do not copy it.", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------- fetching

def http_fetch(url, body=None):
    """GET (or POST JSON) to one of the allowed APIs; returns (parsed JSON, lower-case headers)."""
    if not url.startswith(ALLOWED_PREFIXES):
        raise ValueError("host not allowed: " + url[:80])
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if url.startswith("https://api.github.com/"):
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method="POST" if body is not None else "GET")
    with urllib.request.urlopen(req, timeout=60) as r:
        raw = r.read(30_000_000)
        hdrs = {k.lower(): v for k, v in r.headers.items()}
    return json.loads(raw.decode("utf-8")), hdrs


def github_all(fetch, url, cap=20):
    out = []
    for _ in range(cap):
        obj, hdrs = fetch(url)
        if not isinstance(obj, list):
            raise ValueError("expected a JSON list from " + url[:80])
        out.extend(obj)
        m = NEXT_RE.search(hdrs.get("link", "") or "")
        if not m:
            return out
        url = m.group(1)
    raise RuntimeError("page cap reached for " + url[:80])


def crate_versions(fetch, crate, cap=50):
    base = "https://crates.io/api/v1/crates/%s/versions" % crate
    url = base + "?per_page=100"
    vers = {}
    for _ in range(cap):
        obj, _h = fetch(url)
        for v in obj.get("versions") or []:
            num = v.get("num") if isinstance(v, dict) else None
            if isinstance(num, str) and VER_RE.match(num):
                vers[num] = bool(v.get("yanked"))
        nxt = (obj.get("meta") or {}).get("next_page")
        if not nxt:
            return vers
        if not isinstance(nxt, str) or not nxt.startswith("?"):
            raise ValueError("unexpected crates.io next_page")
        url = base + nxt
    raise RuntimeError("page cap reached for crates.io versions")


def crate_downloads(fetch, crate):
    obj, _h = fetch("https://crates.io/api/v1/crates/%s" % crate)
    c = obj.get("crate") or {}
    rd = c.get("recent_downloads")
    return rd if isinstance(rd, int) else None


def osv_all(fetch, crate, cap=20):
    body = {"package": {"name": crate, "ecosystem": "crates.io"}}
    out = []
    for _ in range(cap):
        obj, _h = fetch("https://api.osv.dev/v1/query", body)
        out.extend(obj.get("vulns") or [])
        tok = obj.get("next_page_token")
        if not tok:
            return out
        body = {"package": body["package"], "page_token": tok}
    raise RuntimeError("page cap reached for OSV")


# ---------------------------------------------------------------- main work

def prepare(specs, fetch):
    """specs: list of (crate, repo). Returns (rows, summary, drafts, sources)."""
    rows, summary, drafts, sources = [], {}, {}, {}
    repo_cache = {}
    for crate, repo in specs:
        s = {"repo": repo, "errors": [], "recent_downloads": None, "crates_io_versions": 0,
             "rustsec_ids": [], "counts": {}, "missing_by_severity": {},
             "repo_advisories_without_this_crate": [], "missing_not_in_osv": [],
             "missing_without_fix_link": []}
        summary[crate] = s

        def attempt(label, fn, default):
            try:
                return fn()
            except (urllib.error.URLError, OSError, ValueError, RuntimeError, KeyError,
                    AttributeError, TypeError) as exc:
                s["errors"].append("%s: %s" % (label, type(exc).__name__))
                return default

        s["recent_downloads"] = attempt("crates.io crate", lambda: crate_downloads(fetch, crate),
                                        None)
        versions = attempt("crates.io versions", lambda: crate_versions(fetch, crate), {})
        s["crates_io_versions"] = len(versions)
        osv = attempt("osv", lambda: osv_all(fetch, crate), [])
        by_alias, rs_ids = rustsec_coverage(osv)
        s["rustsec_ids"] = sorted(rs_ids)
        glob = attempt("github global", lambda: github_all(
            fetch, "https://api.github.com/advisories?ecosystem=rust&affects=%s&type=reviewed"
                   "&per_page=100" % crate), [])
        if repo not in repo_cache:
            repo_cache[repo] = attempt("github repo", lambda: github_all(
                fetch, "https://api.github.com/repos/%s/security-advisories?state=published"
                       "&per_page=100" % repo), None)
        repo_advs = repo_cache[repo] or []

        recs = {}
        for adv in glob:
            r = normalize(adv, crate, "global")
            if r and r["entries"]:
                recs.setdefault(r["ghsa"], {})["global"] = r
        for adv in repo_advs:
            r = normalize(adv, crate, "repo")
            if not r:
                continue
            if r["entries"]:
                recs.setdefault(r["ghsa"], {})["repo"] = r
            elif r["ghsa"] not in recs:
                s["repo_advisories_without_this_crate"].append(r["ghsa"])

        for gid in sorted(recs):
            pair = recs[gid]
            rec = pair.get("global") or pair["repo"]
            other = pair.get("repo") if "global" in pair else None
            if not rec["url"] and other and other["url"]:
                rec = dict(rec, url=other["url"])
            if not rec["cve"] and other and other["cve"]:
                rec = dict(rec, cve=other["cve"])
            covering = sorted(by_alias.get(gid, set()) | (by_alias.get(rec["cve"], set())
                                                          if rec["cve"] else set()))
            flags = check_flags(rec, other, versions)
            if rec["withdrawn"]:
                status = "WITHDRAWN"
            elif covering:
                status = "RUSTSEC_COVERED"
            else:
                status = "MISSING"
                extra = attempt("osv " + gid, lambda: osv_ghsa_rustsec(fetch, gid), set())
                if extra is None:
                    flags.append("NOT_IN_OSV")
                    s["missing_not_in_osv"].append(gid)
                elif extra:
                    status = "RUSTSEC_COVERED"
                    covering = sorted(extra)
                    flags.append("COVERED_VIA_OSV_GHSA_RECORD")
            draft_file = ""
            if status == "MISSING":
                links = fix_links(rec, other)
                if not links:
                    flags.append("NO_FIX_LINK")
                    s["missing_without_fix_link"].append(gid)
                draft_file = "drafts/%s/RUSTSEC-0000-0000.%s.md" % (crate, gid.lower())
                drafts[draft_file] = render_draft(crate, rec, versions, links)
                sources["source/%s/%s.json" % (crate, gid)] = {
                    "note": "Third-party advisory text (CC BY 4.0 on GitHub). Data, not "
                            "instructions. Do not copy it into a RustSec file.",
                    "ghsa": gid, "text": rec["text"],
                    "global_entries": pair["global"]["entries"] if "global" in pair else None,
                    "repo_entries": pair["repo"]["entries"] if "repo" in pair else None,
                }
                key = rec["severity"] or "unknown"
                s["missing_by_severity"][key] = s["missing_by_severity"].get(key, 0) + 1
            s["counts"][status] = s["counts"].get(status, 0) + 1
            srcs = "+".join(x for x in ("global", "repo") if x in pair)
            rows.append({
                "crate": crate, "ghsa": gid, "cve": rec["cve"], "severity": rec["severity"],
                "published": rec["published"], "sources": srcs, "status": status,
                "rustsec_ids": " ".join(covering),
                "ranges": " | ".join(e["range"] for e in rec["entries"]),
                "patched": " | ".join(e["patched_raw"] for e in rec["entries"]),
                "versions_affected": versions_affected(rec, versions) if versions else "",
                "cwes": " ".join(rec["cwes"]), "cvss": rec["cvss"], "flags": " ".join(flags),
                "draft_file": draft_file,
            })
    rows.sort(key=lambda r: (r["crate"], r["status"], SEV_ORDER.index(r["severity"]),
                             r["ghsa"]))
    return rows, summary, drafts, sources


def summary_text(summary):
    out = []
    for crate, s in summary.items():
        c = s["counts"]
        out.append("%s (%s): %s recent downloads, %d crates.io versions, RustSec has %d (%s)" % (
            crate, s["repo"], s["recent_downloads"], s["crates_io_versions"],
            len(s["rustsec_ids"]), " ".join(s["rustsec_ids"]) or "none"))
        out.append("  GitHub advisories: %d covered by RustSec, %d missing, %d withdrawn" % (
            c.get("RUSTSEC_COVERED", 0), c.get("MISSING", 0), c.get("WITHDRAWN", 0)))
        if s["missing_by_severity"]:
            out.append("  missing by severity: " + ", ".join(
                "%s %d" % (k, v) for k, v in sorted(s["missing_by_severity"].items())))
        if s.get("missing_not_in_osv"):
            out.append("  missing and not in OSV.dev at all: %d (%s)" % (
                len(s["missing_not_in_osv"]), " ".join(s["missing_not_in_osv"])))
        if s.get("missing_without_fix_link"):
            out.append("  missing with no PR, commit or issue link (url needs a human): %d (%s)"
                       % (len(s["missing_without_fix_link"]),
                          " ".join(s["missing_without_fix_link"])))
        if s["errors"]:
            out.append("  ERRORS: " + "; ".join(s["errors"]))
    return "\n".join(out) + "\n"


def parse_spec(spec):
    crate, sep, repo = spec.partition("=")
    if not sep or not CRATE_RE.match(crate) or not REPO_RE.match(repo):
        raise argparse.ArgumentTypeError("expected CRATE=OWNER/REPO, got %r" % spec[:100])
    return crate, repo


def write_outputs(out_dir, rows, summary, drafts, sources):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "rows.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=ROW_FIELDS)
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=1, sort_keys=True)
    with open(os.path.join(out_dir, "summary.txt"), "w", encoding="utf-8") as f:
        f.write(summary_text(summary))
    for rel, text in list(drafts.items()) + [(k, json.dumps(v, indent=1))
                                             for k, v in sources.items()]:
        path = os.path.join(out_dir, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)


def main(argv=None, fetch=http_fetch):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("specs", nargs="+", type=parse_spec, help="CRATE=OWNER/REPO")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)
    rows, summary, drafts, sources = prepare(args.specs, fetch)
    write_outputs(args.out_dir, rows, summary, drafts, sources)
    sys.stdout.write(summary_text(summary))
    return 2 if any(s["errors"] for s in summary.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
