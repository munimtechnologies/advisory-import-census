#!/usr/bin/env python3
"""blindspot.py: which security advisories, published by the maintainers of
your dependencies, can your scanner NOT see?

Maintainers publish GitHub repository security advisories ("GRAs") on their
own repo. Dependabot, npm audit, pip-audit and osv-scanner only see an
advisory once it reaches the global GitHub Advisory Database / OSV.dev, and
the census in this repo found 31.6% of GRAs for self-hosted AI/ML tools never
got there. This tool checks YOUR dependencies for that gap:

  1. map each package to its GitHub repo (registry metadata, a small built-in
     map, or --map name=owner/repo);
  2. list that repo's published security advisories (public REST API);
  3. keep the ones whose affected range covers your version;
  4. ask OSV.dev, with the same package and version a scanner would send,
     whether it reports that advisory (by GHSA ID or its CVE alias).

An advisory that affects you but that OSV does not report is a blind spot.

Usage:
  python blindspot.py -r requirements.txt
  python blindspot.py --npm package-lock.json
  python blindspot.py --pyproject pyproject.toml
  python blindspot.py --package pip:vllm==0.10.1 --package npm:flowise@3.1.3
  python blindspot.py --package repo:langgenius/dify@1.4.0   (apps, not packages)
  add --json for machine-readable output, --fail-on-blind for CI, and
  --sarif blindspot.sarif to write the blind spots as SARIF 2.1.0 for GitHub
  code scanning (they then show as alerts in the repository's Security tab).

Set GITHUB_TOKEN in the environment to raise GitHub's unauthenticated limit of
60 requests an hour (one request per repo); it is only sent to api.github.com.

Public, read-only metadata only. Standard library only (reading a pyproject.toml
needs Python 3.11+ for the standard-library tomllib, or the `tomli` backport).

Made with AI agents working for MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "0.5.0"

UA = "advisory-import-census-blindspot (MV2 of Munim, Inc.; munimversion2@gmail.com)"

# GitHub advisory ecosystem -> OSV ecosystem.
OSV_ECOSYSTEM = {
    "pip": "PyPI", "npm": "npm", "go": "Go", "maven": "Maven",
    "rubygems": "RubyGems", "rust": "crates.io", "composer": "Packagist",
    "nuget": "NuGet", "pub": "Pub", "erlang": "Hex",
}
ECOSYSTEM_ALIASES = {"pypi": "pip", "python": "pip", "node": "npm", "cargo": "rust",
                     "crates.io": "rust", "packagist": "composer", "gem": "rubygems"}

# Packages whose registry entry has no GitHub link (checked 2026-10-14:
# registry.npmjs.org/flowise/latest has no "repository" field).
KNOWN_REPOS = {
    ("npm", "flowise"): "FlowiseAI/Flowise",
    ("npm", "flowise-components"): "FlowiseAI/Flowise",
    ("npm", "flowise-ui"): "FlowiseAI/Flowise",
    ("pip", "comfyui"): "Comfy-Org/ComfyUI",
}

GITHUB_REPO_RE = re.compile(
    r"github\.com[/:]([A-Za-z0-9][A-Za-z0-9-]*)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#?]|$)")
NOT_REPO_OWNERS = {"sponsors", "orgs", "users", "features", "marketplace", "apps"}
PYPI_URL_KEYS = ("source", "source code", "repository", "code", "github", "homepage",
                 "home", "bug tracker", "issues", "tracker")


# ---------------------------------------------------------------- versions

def normalize_name(ecosystem, name):
    name = name.strip()
    if ecosystem == "pip":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in ("npm", "rubygems", "rust", "composer", "nuget", "pub", "erlang"):
        return name.lower()
    return name


def version_key(v):
    """Sortable key for a version string. Handles PEP 440 and semver well
    enough for advisory ranges: release numbers, then pre < final < post.
    Returns None if there is no leading number."""
    s = v.strip().lstrip("vV=").strip()
    m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", s)
    if not m:
        return None
    release = [int(x) for x in m.group(1).split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    rest = m.group(2).lower().split("+", 1)[0].lstrip("-._")
    if not rest:
        phase = 1
    elif rest.startswith("post") or re.match(r"^\d", rest):
        phase = 2
    else:
        phase = 0
    tokens = tuple((0, int(t)) if t.isdigit() else (1, t)
                   for t in re.findall(r"\d+|[a-z]+", rest))
    if phase == 0 and tokens and tokens[0] == (1, "dev"):
        tokens = ((0, -1),) + tokens  # dev sorts before a/b/rc
    return (tuple(release), phase, tokens)


def compare_versions(a, b):
    ka, kb = version_key(a), version_key(b)
    if ka is None or kb is None:
        return None
    return (ka > kb) - (ka < kb)


_OPS = {
    ">=": lambda c: c >= 0, "<=": lambda c: c <= 0, ">": lambda c: c > 0,
    "<": lambda c: c < 0, "==": lambda c: c == 0, "=": lambda c: c == 0,
    "!=": lambda c: c != 0,
}


def in_range(version, range_text):
    """True/False if `version` is inside a GitHub vulnerable_version_range
    such as ">= 1.0, < 1.2.3" (comma = AND, "||" = OR); None if unknown."""
    if not version or not range_text or not range_text.strip():
        return None
    any_unknown = False
    for alternative in range_text.split("||"):
        ok = True
        for part in alternative.split(","):
            part = part.strip()
            if not part:
                continue
            m = re.match(r"^(>=|<=|==|!=|>|<|=)?\s*(\S+)$", part)
            if not m:
                return None
            c = compare_versions(version, m.group(2))
            if c is None:
                any_unknown = True
                ok = False
                break
            if not _OPS[m.group(1) or "="](c):
                ok = False
                break
        if ok:
            return True
    return None if any_unknown else False


# ---------------------------------------------------------------- manifests

def parse_requirements(text):
    """Return [(name, version-or-None)] from a requirements.txt. Only an exact
    `==` pin gives a version; other specifiers check every version."""
    deps = []
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http:", "https:", "file:")):
            continue
        line = line.split(";", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$", line)
        if not m:
            continue
        pin = re.match(r"^===?\s*([^\s,;*]+)$", m.group(2).strip())
        deps.append((m.group(1), pin.group(1) if pin else None))
    return deps


def parse_package_lock(data):
    """Return [(name, version)] from a package-lock.json (v1, v2 or v3)."""
    deps = set()
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, info in packages.items():
            if not path or "node_modules/" not in path or not isinstance(info, dict):
                continue
            name = path.rsplit("node_modules/", 1)[1]
            if info.get("version") and not info.get("link"):
                deps.add((name, info["version"]))
    else:
        def walk(tree):
            for name, info in (tree or {}).items():
                if isinstance(info, dict):
                    if info.get("version"):
                        deps.add((name, info["version"]))
                    walk(info.get("dependencies"))
        walk(data.get("dependencies"))
    return sorted(deps)


def parse_package_json(data):
    """Return [(name, version-or-None)] from a package.json. Only an exact
    version gives a version; ranges like ^1.2.0 check every version."""
    deps = []
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(key) or {}).items():
            spec = str(spec).strip()
            exact = re.match(r"^=?v?(\d+\.\d+\.\d+[^\s]*)$", spec)
            deps.append((name, exact.group(1) if exact else None))
    return deps


def parse_package_arg(text):
    """'pip:vllm==0.10.1', 'npm:flowise@3.1.3', 'npm:@scope/x@1.0.0',
    'repo:owner/name@1.4.0' -> (ecosystem, name, version-or-None)."""
    if ":" not in text:
        raise ValueError("expected ECOSYSTEM:NAME[==VERSION], got %r" % text)
    eco, rest = text.split(":", 1)
    eco = ECOSYSTEM_ALIASES.get(eco.strip().lower(), eco.strip().lower())
    if eco != "repo" and eco not in OSV_ECOSYSTEM:
        raise ValueError("unknown ecosystem %r" % eco)
    rest = rest.strip()
    if "==" in rest:
        name, version = rest.split("==", 1)
    elif "@" in rest[1:]:
        at = rest.rindex("@")
        name, version = rest[:at], rest[at + 1:]
    else:
        name, version = rest, None
    return eco, name.strip(), (version.strip() or None) if version else None


def load_toml(text):
    """Parse TOML text to a dict. Uses the standard-library tomllib on Python
    3.11+, or the `tomli` backport if installed; raises a clear error on older
    Python with neither."""
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib
        except ModuleNotFoundError:
            raise RuntimeError(
                "reading a pyproject.toml needs Python 3.11+ (tomllib) or the "
                "`tomli` package; on older Python use -r requirements.txt instead"
            ) from None
    return tomllib.loads(text)


def parse_pyproject(data):
    """Return [(name, version-or-None)] from a parsed pyproject.toml. Covers
    PEP 621 [project] dependencies / optional-dependencies (PEP 508 strings)
    and legacy Poetry [tool.poetry] dependencies and group dependencies. As in
    requirements.txt, only an exact `==` pin gives a version; any other
    constraint (ranges, carets, markers) checks every version."""
    project = data.get("project") or {}
    lines = [str(x) for x in (project.get("dependencies") or [])]
    for group in (project.get("optional-dependencies") or {}).values():
        lines += [str(x) for x in (group or [])]
    deps = parse_requirements("\n".join(lines))
    poetry = (data.get("tool") or {}).get("poetry") or {}
    tables = [poetry.get("dependencies") or {}]
    for grp in (poetry.get("group") or {}).values():
        tables.append((grp or {}).get("dependencies") or {})
    for table in tables:
        for name, spec in table.items():
            if name.lower() == "python":
                continue
            if isinstance(spec, dict):
                spec = spec.get("version") or ""
            pin = re.match(r"^===?\s*([^\s,;*]+)$", str(spec).strip())
            deps.append((name, pin.group(1) if pin else None))
    return deps


# ---------------------------------------------------------------- network

def http_json(url, data=None, headers=None, timeout=30, retries=4):
    """GET (or POST JSON) and decode. Returns (status, obj); 404 -> (404, None)."""
    hdrs = {"User-Agent": UA, "Accept": "application/json"}
    hdrs.update(headers or {})
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    last = None
    for attempt in range(retries):
        req = urllib.request.Request(url, data=body, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8") or "null")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return 404, None
            if e.code in (403, 429) and e.headers.get("X-RateLimit-Remaining") == "0":
                raise RuntimeError("GitHub API rate limit reached; set GITHUB_TOKEN "
                                   "or wait for the hourly reset") from None
            last = e
            if e.code not in (429, 500, 502, 503, 504):
                break
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = e
        time.sleep(min(30, 2 ** attempt))
    raise RuntimeError("request failed: %s (%s)" % (url, last))


def github_headers():
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        h["Authorization"] = "Bearer " + token
    return h


def repo_from_urls(urls):
    for u in urls:
        m = GITHUB_REPO_RE.search(u or "")
        if m and m.group(1).lower() not in NOT_REPO_OWNERS:
            return "%s/%s" % (m.group(1), m.group(2))
    return None


def registry_repo(ecosystem, name):
    """Find a package's GitHub repo from its registry metadata (PyPI, npm)."""
    if ecosystem == "pip":
        status, obj = http_json("https://pypi.org/pypi/%s/json" % urllib.parse.quote(name))
        if status != 200 or not obj:
            return None
        info = obj.get("info") or {}
        project_urls = info.get("project_urls") or {}
        ranked = sorted(project_urls.items(),
                        key=lambda kv: (PYPI_URL_KEYS.index(kv[0].lower())
                                        if kv[0].lower() in PYPI_URL_KEYS else 99))
        return repo_from_urls([v for _, v in ranked] + [info.get("home_page")])
    if ecosystem == "npm":
        status, obj = http_json("https://registry.npmjs.org/%s/latest"
                                % urllib.parse.quote(name, safe="@/"))
        if status != 200 or not obj:
            return None
        repo = obj.get("repository")
        repo = repo.get("url") if isinstance(repo, dict) else repo
        bugs = obj.get("bugs")
        bugs = bugs.get("url") if isinstance(bugs, dict) else bugs
        return repo_from_urls([repo, obj.get("homepage"), bugs])
    return None


def list_repo_advisories(repo):
    """Every published security advisory of a GitHub repo."""
    out = []
    url = ("https://api.github.com/repos/%s/security-advisories?state=published&per_page=100"
           % repo)
    while url:
        req = urllib.request.Request(url, headers=dict(github_headers(), **{"User-Agent": UA}))
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                page = json.loads(resp.read().decode("utf-8"))
                link = resp.headers.get("Link", "")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return out
            if e.code in (403, 429) and e.headers.get("X-RateLimit-Remaining") == "0":
                raise RuntimeError("GitHub API rate limit reached; set GITHUB_TOKEN "
                                   "or wait for the hourly reset") from None
            raise
        if not isinstance(page, list):
            break
        out.extend(page)
        url = None
        for part in link.split(","):
            seg = part.split(";")
            if len(seg) >= 2 and 'rel="next"' in seg[1]:
                url = seg[0].strip().strip("<>")
    return out


def osv_package_ids(ecosystem, name, version):
    """Every vulnerability ID and alias OSV.dev reports for this package (and
    version, when given): what an OSV-based scanner would be told."""
    query = {"package": {"name": name, "ecosystem": OSV_ECOSYSTEM[ecosystem]}}
    if version:
        query["version"] = version
    ids = set()
    while True:
        _, obj = http_json("https://api.osv.dev/v1/query", data=query)
        for v in (obj or {}).get("vulns", []) or []:
            ids.add(v.get("id"))
            ids.update(v.get("aliases") or [])
        token = (obj or {}).get("next_page_token")
        if not token:
            return ids
        query["page_token"] = token


def osv_has_id(vuln_id):
    status, obj = http_json("https://api.osv.dev/v1/vulns/%s" % vuln_id)
    if status != 200 or not obj:
        return set()
    return {obj.get("id")} | set(obj.get("aliases") or [])


# ---------------------------------------------------------------- core

def check(deps, resolve_repo, get_advisories, package_ids, id_lookup):
    """Classify every advisory that applies to each dependency.

    deps: [(ecosystem, name, version-or-None)]; ecosystem "repo" means name is
    owner/repo and every advisory of that repo applies. The four callables
    are injected so the logic is testable offline. Returns a report dict."""
    findings, unmapped, repos_seen = [], [], {}
    for eco, name, version in deps:
        repo = name if eco == "repo" else resolve_repo(eco, name)
        if not repo:
            unmapped.append({"ecosystem": eco, "package": name, "version": version})
            continue
        if repo not in repos_seen:
            repos_seen[repo] = get_advisories(repo)
        want = normalize_name(eco, name)
        osv_ids = None
        for adv in repos_seen[repo]:
            matches = []
            vulns = adv.get("vulnerabilities") or []
            if eco == "repo" and not vulns:
                vulns = [{}]  # an app advisory naming no package still applies
            for vuln in vulns:
                pkg = vuln.get("package") or {}
                if eco != "repo" and (
                        (pkg.get("ecosystem") or "").lower() != eco
                        or normalize_name(eco, pkg.get("name") or "") != want):
                    continue
                matches.append(vuln)
            if not matches:
                continue
            if version:
                hits = [in_range(version, v.get("vulnerable_version_range")) for v in matches]
                affected = True if True in hits else (None if None in hits else False)
            else:
                affected = None
            if affected is False:
                continue
            ghsa, cve = adv.get("ghsa_id"), adv.get("cve_id")
            if eco == "repo":
                # No package to query by, so ask whether OSV serves this GHSA
                # at all (the census test). A bare NVD CVE record names no
                # package and alerts nobody, so it does not count.
                seen = id_lookup(ghsa)
                cve_hit = False
            else:
                if osv_ids is None:
                    osv_ids = package_ids(eco, name, version)
                seen = osv_ids
                cve_hit = bool(cve and cve in seen)
            visible = ghsa in seen or cve_hit
            findings.append({
                "ecosystem": eco, "package": name, "version": version, "repo": repo,
                "ghsa_id": ghsa, "cve_id": cve or "", "severity": adv.get("severity") or "",
                "summary": adv.get("summary") or "", "published_at": adv.get("published_at") or "",
                "vulnerable_range": "; ".join(v.get("vulnerable_version_range") or "?"
                                              for v in matches),
                "patched": "; ".join(v.get("patched_versions") or "?" for v in matches),
                "affects_your_version": "yes" if affected else "unknown",
                "scanner_visible": visible,
                "url": adv.get("html_url") or "",
            })
    sev = {"critical": 0, "high": 1, "medium": 2, "moderate": 2, "low": 3}
    findings.sort(key=lambda f: (f["scanner_visible"], sev.get(f["severity"], 4),
                                 f["package"], f["ghsa_id"] or ""))
    blind = [f for f in findings if not f["scanner_visible"]]
    return {
        "dependencies_checked": len(deps),
        "mapped_to_repo": len(deps) - len(unmapped),
        "repos_with_advisories": sum(1 for a in repos_seen.values() if a),
        "advisories_that_apply": len(findings),
        "blind_spots": len(blind),
        "findings": findings,
        "unmapped": unmapped,
    }


def render_text(report):
    lines = ["Advisory blind-spot check (advisory-import-census, MV2 of Munim, Inc.)",
             "Dependencies: %d, mapped to a GitHub repo: %d, repos with published advisories: %d"
             % (report["dependencies_checked"], report["mapped_to_repo"],
                report["repos_with_advisories"]), ""]
    groups = [("BLIND SPOTS: published by the maintainers, not reported by OSV for this package",
               [f for f in report["findings"] if not f["scanner_visible"]]),
              ("Also apply, and OSV reports them",
               [f for f in report["findings"] if f["scanner_visible"]])]
    for title, items in groups:
        lines.append("%s (%d)" % (title, len(items)))
        for f in items:
            ver = f["version"] or "any version"
            lines.append("  %-8s %s %s  %s %s  affected: %s  fixed: %s%s" % (
                f["severity"] or "?", f["package"], ver, f["ghsa_id"], f["cve_id"],
                f["vulnerable_range"], f["patched"],
                "" if f["affects_your_version"] == "yes" else "  (version not pinned or range unclear)"))
            lines.append("           %s" % f["url"])
        lines.append("")
    if report["unmapped"]:
        lines.append("No GitHub repo found for %d package(s); add --map NAME=OWNER/REPO to check them:"
                     % len(report["unmapped"]))
        lines.append("  " + ", ".join(u["package"] for u in report["unmapped"]))
    return "\n".join(lines)


# ---------------------------------------------------------------- SARIF

# GitHub code scanning reads properties.security-severity (0.1-10.0) and maps
# it to its own levels: > 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, < 4 low.
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "moderate": "5.5",
                     "medium": "5.5", "low": "2.0"}
SARIF_LEVEL = {"critical": "error", "high": "error", "moderate": "warning",
               "medium": "warning", "low": "note"}
SCANNERS = "Dependabot, pip-audit, osv-scanner, npm audit"


def name_pattern(ecosystem, name):
    """Regex that finds a dependency name as a whole token in a manifest line
    (for pip, '-', '_' and '.' are interchangeable, as in PEP 503)."""
    if ecosystem == "pip":
        body = r"[-_.]+".join(re.escape(p) for p in normalize_name("pip", name).split("-"))
    else:
        body = re.escape(name)
    return re.compile(r"(?<![A-Za-z0-9_.-])%s(?![A-Za-z0-9_-])" % body, re.IGNORECASE)


def find_line(text, ecosystem, name):
    """(1-based line number, line length) of the first non-comment line of
    `text` that names the dependency, or None."""
    pattern = name_pattern(ecosystem, name)
    for number, line in enumerate((text or "").splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        if pattern.search(line):
            return number, len(line)
    return None


def sarif_uri(path):
    """A repository-relative URI with forward slashes; paths outside the
    current directory become file:// URIs."""
    if os.path.isabs(path):
        try:
            rel = os.path.relpath(path)
        except ValueError:  # another drive on Windows
            rel = ".."
        if rel.startswith(".."):
            return pathlib.Path(path).as_uri()
        path = rel
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def _fixed_text(patched):
    parts = [p.strip() for p in (patched or "").split(";")]
    if all(p in ("", "?") for p in parts):
        return "no patched version is listed"
    return "fixed in " + "; ".join(p for p in parts if p not in ("", "?"))


def render_sarif(report, locate):
    """SARIF 2.1.0 log of the blind spots, for GitHub code scanning
    (github/codeql-action/upload-sarif). One rule per advisory, one result per
    affected dependency. locate(finding) -> (uri, line, line_length) says where
    the dependency is declared. Advisories OSV does report are left out: an
    OSV-based scanner already alerts on them. An empty result list is still
    written, so code scanning closes alerts once an advisory is imported."""
    rules, rule_index, results = [], {}, []
    for f in report.get("findings", []):
        if f.get("scanner_visible"):
            continue
        sev = (f.get("severity") or "").lower()
        rule_id = f.get("ghsa_id") or f.get("cve_id") or "advisory-blindspot/unknown"
        ident = rule_id + (" / " + f["cve_id"] if f.get("cve_id") and f["cve_id"] != rule_id else "")
        summary = f.get("summary") or ident
        if rule_id not in rule_index:
            help_text = (
                "%s was published by the maintainers of %s as a GitHub repository security "
                "advisory, but OSV.dev does not report it for the affected package, so "
                "OSV-based scanners (%s) cannot alert on it. Affected: %s; %s. Advisory: %s"
                % (ident, f.get("repo"), SCANNERS, f.get("vulnerable_range") or "?",
                   _fixed_text(f.get("patched")), f.get("url") or "(no URL)"))
            properties = {"tags": ["security", "dependency", "advisory-blindspot"],
                          "precision": "high"}
            if sev in SECURITY_SEVERITY:
                properties["security-severity"] = SECURITY_SEVERITY[sev]
            rule = {
                "id": rule_id,
                "shortDescription": {"text": "%s: %s" % (rule_id, summary)},
                "fullDescription": {"text": summary},
                "help": {"text": help_text},
                "defaultConfiguration": {"level": SARIF_LEVEL.get(sev, "warning")},
                "properties": properties,
            }
            if f.get("url"):
                rule["helpUri"] = f["url"]
            rule_index[rule_id] = len(rules)
            rules.append(rule)
        uri, line, length = locate(f)
        version = f.get("version")
        if f.get("ecosystem") == "repo":
            where = "OSV.dev does not carry this advisory"
        else:
            where = "OSV.dev does not report it for this package and version"
        message = ("%s %s is affected by %s (%s severity), published by the maintainers of "
                   "%s, but %s, so OSV-based scanners (%s) cannot alert on it. Affected: %s; "
                   "%s.%s" % (
                       f.get("package"), version or "(any version)", ident, sev or "unknown",
                       f.get("repo"), where, SCANNERS, f.get("vulnerable_range") or "?",
                       _fixed_text(f.get("patched")),
                       "" if f.get("affects_your_version") == "yes"
                       else " The version is not pinned or the range is unclear, so check "
                            "which version you install."))
        key = "|".join([rule_id, f.get("ecosystem") or "",
                        normalize_name(f.get("ecosystem") or "", f.get("package") or ""),
                        version or "", uri])
        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": SARIF_LEVEL.get(sev, "warning"),
            "message": {"text": message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line, "startColumn": 1, "endLine": line,
                           "endColumn": max(2, length + 1)},
            }}],
            "partialFingerprints": {
                "primaryLocationLineHash": hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
                + ":1"},
            "properties": {"ecosystem": f.get("ecosystem"), "package": f.get("package"),
                           "version": version, "repo": f.get("repo"),
                           "cve": f.get("cve_id") or None},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "advisory-blindspot",
                "semanticVersion": __version__,
                "informationUri": "https://github.com/munimtechnologies/advisory-import-census",
                "rules": rules,
            }},
            "results": results,
        }],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="List security advisories your dependencies' maintainers published "
                    "that OSV-based scanners do not report.")
    ap.add_argument("-r", "--requirements", action="append", default=[],
                    help="a pip requirements.txt")
    ap.add_argument("--npm", action="append", default=[],
                    help="a package-lock.json or package.json")
    ap.add_argument("--pyproject", action="append", default=[],
                    help="a pyproject.toml (PEP 621 or Poetry dependencies)")
    ap.add_argument("--package", action="append", default=[],
                    help="ECOSYSTEM:NAME[==VERSION], e.g. pip:vllm==0.10.1, "
                         "npm:flowise@3.1.3, repo:langgenius/dify@1.4.0")
    ap.add_argument("--map", action="append", default=[],
                    help="NAME=OWNER/REPO for packages whose registry has no GitHub link")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    ap.add_argument("--fail-on-blind", action="store_true",
                    help="exit 1 if any blind spot is found (for CI)")
    ap.add_argument("--sarif", metavar="PATH",
                    help="also write the blind spots as SARIF 2.1.0 to PATH, for GitHub "
                         "code scanning (github/codeql-action/upload-sarif)")
    ap.add_argument("--sarif-anchor", metavar="FILE",
                    help="repository file that SARIF results for --package specs point "
                         "at, e.g. the workflow that lists them (default: the first "
                         "manifest given)")
    args = ap.parse_args(argv)

    deps, sources, texts = [], {}, {}

    def add(eco, parsed, path):
        for n, v in parsed:
            deps.append((eco, n, v))
            if path:
                sources.setdefault((eco, normalize_name(eco, n)), path)

    for path in args.requirements:
        with open(path, encoding="utf-8") as fh:
            texts[path] = fh.read()
        add("pip", parse_requirements(texts[path]), path)
    for path in args.npm:
        with open(path, encoding="utf-8") as fh:
            texts[path] = fh.read()
        data = json.loads(texts[path])
        parsed = (parse_package_lock(data) if ("packages" in data or "lockfileVersion" in data)
                  else parse_package_json(data))
        add("npm", parsed, path)
    for path in args.pyproject:
        with open(path, encoding="utf-8") as fh:
            texts[path] = fh.read()
        add("pip", parse_pyproject(load_toml(texts[path])), path)
    for text in args.package:
        eco, name, version = parse_package_arg(text)
        add(eco, [(name, version)], None)
    if not deps:
        ap.error("give at least one of -r, --npm, --pyproject or --package")
    anchor = args.sarif_anchor or next(iter(texts), None)
    if args.sarif and args.package and not anchor:
        ap.error("--sarif with only --package specs needs --sarif-anchor FILE "
                 "(e.g. the workflow file that lists them)")
    seen, unique = set(), []
    for d in deps:
        key = (d[0], normalize_name(d[0], d[1]), d[2])
        if key not in seen:
            seen.add(key)
            unique.append(d)

    overrides = {}
    for m in args.map:
        name, _, repo = m.partition("=")
        overrides[name.strip().lower()] = repo.strip()

    def resolve(eco, name):
        key = normalize_name(eco, name)
        known = overrides.get(name.lower()) or overrides.get(key) or KNOWN_REPOS.get((eco, key))
        if known:
            return known
        try:
            return registry_repo(eco, name)
        except RuntimeError as e:
            print("  could not look up %s:%s (%s)" % (eco, name, e), file=sys.stderr)
            return None

    report = check(unique, resolve, list_repo_advisories, osv_package_ids, osv_has_id)
    print(json.dumps(report, indent=2) if args.json else render_text(report))

    if args.sarif:
        def locate(f):
            eco = f["ecosystem"]
            path = sources.get((eco, normalize_name(eco, f["package"]))) or anchor
            if path not in texts:
                try:
                    with open(path, encoding="utf-8") as fh:
                        texts[path] = fh.read()
                except OSError:
                    texts[path] = ""
            line, length = find_line(texts[path], eco, f["package"]) or (1, 0)
            return sarif_uri(path), line, length

        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(render_sarif(report, locate), fh, indent=2)
            fh.write("\n")
    return 1 if (args.fail_on_blind and report["blind_spots"]) else 0


if __name__ == "__main__":
    sys.exit(main())
