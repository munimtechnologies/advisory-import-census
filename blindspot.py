#!/usr/bin/env python3
"""blindspot.py: which security advisories, published by the maintainers of
your dependencies, can your scanner NOT see?

Maintainers publish GitHub repository security advisories ("GRAs") on their
own repo. Dependabot, npm audit, pip-audit and osv-scanner only see an
advisory once it reaches the global GitHub Advisory Database / OSV.dev, and
the census in this repo found 31.6% of GRAs for self-hosted AI/ML tools never
got there. This tool checks YOUR dependencies for that gap:

  1. map each package to its GitHub repo (registry metadata, a small built-in
     map, --map name=owner/repo, or, for a Go module, its path -- github.com
     modules, gopkg.in by its documented redirect rule, the Kubernetes vanity
     hosts k8s.io and sigs.k8s.io, the Go sub-repositories under golang.org/x
     and Istio (istio.io) by owner-prefix, the Google Cloud
     (cloud.google.com/go), etcd (go.etcd.io/etcd), OpenTelemetry
     (go.opentelemetry.io/{otel,collector,contrib,proto,auto,ebpf-profiler}) and
     Tailscale (tailscale.com) monorepos by monorepo-prefix, and a small map of
     known vanity modules such as Gitea, GORM, gocloud.dev, gRPC, Protobuf,
     Helm, CUE, ORAS, Connect, the go.uber.org libraries, OpenCensus, CEL, the
     etcd raft and bbolt libraries, the MongoDB Go driver and the Google
     API/genproto/App Engine client modules, each verified from its go.mod);
  2. list that repo's published security advisories (public REST API);
  3. keep the ones whose affected range covers your version;
  4. ask OSV.dev, with the same package and version a scanner would send,
     whether it reports that advisory (by GHSA ID or its CVE alias).

An advisory that affects you but that OSV does not report is a blind spot.
Maintainers type the advisory's package name by hand; when it is free text
that no package can have (Go "Traefik" rather than
github.com/traefik/traefik/v3), the advisory is still reported for a
dependency from that repo, marked as naming its package only in free text.

Usage:
  python blindspot.py -r requirements.txt
  python blindspot.py --npm package-lock.json
  python blindspot.py --pyproject pyproject.toml
  python blindspot.py --lock uv.lock      (also poetry.lock, pylock.toml,
                      Pipfile.lock, yarn.lock, pnpm-lock.yaml, go.mod, go.sum:
                      exact versions of every direct and transitive dependency)
  python blindspot.py --package pip:vllm==0.10.1 --package npm:flowise@3.1.3
  python blindspot.py --package go:github.com/gin-gonic/gin@v1.9.1
  python blindspot.py --package repo:langgenius/dify@1.4.0   (apps, not packages)
  add --json for machine-readable output, --fail-on-blind for CI, and
  --sarif blindspot.sarif to write the blind spots as SARIF 2.1.0 for GitHub
  code scanning (they then show as alerts in the repository's Security tab).
  Accept a known blind spot without turning the gate off with
  --ignore GHSA-... (repeatable) or --ignore-file blindspot-ignore.txt.

Set GITHUB_TOKEN in the environment to raise GitHub's unauthenticated limit of
60 requests an hour (one request per repo); it is only sent to api.github.com.
If the limit is reached anyway, the repos left are reported as not checked
(and --fail-on-blind fails), rather than silently passing.

Public, read-only metadata only. Standard library only (reading a pyproject.toml
or a TOML lock file needs Python 3.11+ for the standard-library tomllib, or the
`tomli` backport).

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

__version__ = "0.9.14"

UA = "advisory-import-census-blindspot (MV2 of Munim, Inc.; munimversion2@gmail.com)"

# GitHub advisory ecosystem -> OSV ecosystem.
OSV_ECOSYSTEM = {
    "pip": "PyPI", "npm": "npm", "go": "Go", "maven": "Maven",
    "rubygems": "RubyGems", "rust": "crates.io", "composer": "Packagist",
    "nuget": "NuGet", "pub": "Pub", "erlang": "Hex",
}
ECOSYSTEM_ALIASES = {"pypi": "pip", "python": "pip", "node": "npm", "cargo": "rust",
                     "crates.io": "rust", "packagist": "composer", "gem": "rubygems",
                     "golang": "go"}

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


class RateLimited(RuntimeError):
    """GitHub's API rate limit was reached."""


# ---------------------------------------------------------------- versions

def normalize_name(ecosystem, name):
    name = name.strip()
    if ecosystem == "pip":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in ("npm", "rubygems", "rust", "composer", "nuget", "pub", "erlang"):
        return name.lower()
    return name


# A PEP 508 project name; anything else in a pip advisory's package field is free text.
PIP_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")


def free_text_package(ecosystem, name):
    """True if an advisory's package name is free text that no package in
    `ecosystem` can have: Go "Traefik" or "gitea.dev" (a Go module path has a
    '/'), pip "Home Assistant" or "bentoml/BentoML" (not a PEP 508 name), or
    any name with a space. Maintainers type this field by hand, and matching
    it exactly would silently drop the advisory."""
    name = (name or "").strip()
    if not name:
        return False
    if re.search(r"\s", name):
        return True
    if ecosystem == "go":
        return "/" not in name
    if ecosystem == "pip":
        return not PIP_NAME_RE.match(name)
    return False


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
    `==` pin gives a version; other specifiers check every version. Reads the
    hashed output of `pip-compile --generate-hashes` / `uv pip compile` too:
    `\\` line continuations are joined and per-requirement options such as
    --hash are dropped, so the pin is kept."""
    deps = []
    for raw in re.sub(r"\\[ \t]*\r?\n", " ", text or "").splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http:", "https:", "file:")):
            continue
        line = re.split(r"\s--", line, maxsplit=1)[0]
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
    'go:github.com/gin-gonic/gin@v1.9.1', 'repo:owner/name@1.4.0' ->
    (ecosystem, name, version-or-None)."""
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


def parse_ignore_file(text):
    """Return the advisory IDs listed in an ignore file: one GHSA or CVE ID per
    line, with blank lines and `#` comments skipped (an inline `# ...` after an
    ID is stripped too, so you can note why an ID is accepted)."""
    ids = []
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            ids.append(line)
    return ids


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


# ---------------------------------------------------------------- lock files

LOCK_FILES = ("uv.lock", "poetry.lock", "pylock.toml", "Pipfile.lock", "package-lock.json",
              "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "go.mod", "go.sum")
# A uv/poetry/PEP 751 package from one of these sources is the project's own code.
LOCAL_SOURCE_KEYS = ("editable", "virtual", "directory", "path")
# yarn ranges that point at local code or patch another entry, not a registry release.
YARN_LOCAL = ("workspace:", "link:", "portal:", "file:", "patch:", "exec:")
# A go.mod require line: a module path, then its selected version (vX.Y.Z or a
# vX.Y.Z-pseudo.version). An inline `// indirect` comment is stripped first.
GOMOD_REQUIRE_RE = re.compile(r"^(\S+)\s+(v\S+)")


def parse_toml_lock(data):
    """Return [(name, version)] from a parsed uv.lock, poetry.lock or PEP 751
    pylock.toml: every locked package that has a version, leaving out the
    project itself and other local-directory packages."""
    deps = set()
    for key in ("package", "packages"):
        entries = data.get(key)
        for pkg in (entries if isinstance(entries, list) else []):
            if not isinstance(pkg, dict) or not pkg.get("name") or not pkg.get("version"):
                continue
            source = pkg.get("source") if isinstance(pkg.get("source"), dict) else {}
            if (any(k in source for k in LOCAL_SOURCE_KEYS) or "directory" in pkg
                    or source.get("type") in ("directory", "file")):
                continue
            deps.add((str(pkg["name"]), str(pkg["version"])))
    return sorted(deps)


def parse_pipfile_lock(data):
    """Return [(name, version)] from a Pipfile.lock (default and develop).
    Entries with no `==` version (local paths, VCS) are left out."""
    deps = set()
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            if not isinstance(info, dict):
                continue
            pin = re.match(r"^===?\s*([^\s,;*]+)$", str(info.get("version") or "").strip())
            if pin:
                deps.add((name, pin.group(1)))
    return sorted(deps)


def _split_spec(spec):
    """'name@range' or '@scope/name@range' -> (name, range); (None, None) if
    there is no '@' after the first character."""
    at = spec.find("@", 1)
    if at <= 0:
        return None, None
    return spec[:at], spec[at + 1:]


def parse_yarn_lock(text):
    """Return [(name, version)] from a yarn.lock, classic (v1) or Berry (v2+).
    Each entry is a header line (`name@range, name@range2:`) followed by an
    indented `version "x"` (v1) or `version: x` (Berry). npm aliases
    (`alias@npm:real@^1`) count as the real package; workspace, link, file and
    patch entries are left out."""
    deps, name = set(), None
    for line in (text or "").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            name = None
            first = line.rstrip().rstrip(":").split(",")[0].strip().strip('"')
            spec_name, rng = _split_spec(first)
            if spec_name and not rng.startswith(YARN_LOCAL):
                if rng.startswith("npm:"):
                    spec_name = _split_spec(rng[4:])[0] or spec_name
                name = spec_name
            continue
        m = re.match(r'^  version:?\s+"?([^"\s]+)"?\s*$', line)
        if name and m and re.match(r"^\d", m.group(1)):
            deps.add((name, m.group(1)))
            name = None
    return sorted(deps)


def parse_pnpm_lock(text):
    """Return [(name, version)] from a pnpm-lock.yaml (lockfile v5, v6 or v9):
    the keys of its top-level `packages:` map, e.g. `/flowise/3.1.3` (v5),
    `/flowise@3.1.3` (v6) or `flowise@3.1.3` (v9). Peer-dependency suffixes
    (`(react@18.2.0)`, `_react@18.2.0`) are dropped. Read line by line, so no
    YAML library is needed."""
    deps, inside = set(), False
    for line in (text or "").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            inside = line.rstrip() == "packages:"
            continue
        m = re.match(r"^  (\S.*?):\s*$", line)
        if not inside or not m:
            continue
        key = m.group(1).strip("'\"").lstrip("/").split("(", 1)[0]
        v5 = re.match(r"^(@[^/@]+/[^/@]+|[^@/][^/@]*)/(\d[^/]*)$", key)
        if v5:
            name, version = v5.group(1), v5.group(2).split("_", 1)[0]
        else:
            name, version = _split_spec(key)
        if name and version and re.match(r"^\d", version):
            deps.add((name, version))
    return sorted(deps)


def parse_gomod(text):
    """Return [(module, version)] from a go.mod: the require directives, direct
    and `// indirect`, at their selected versions. Both the single-line
    `require M V` form and the `require ( ... )` block are read; the module,
    go, toolchain, exclude and replace directives are left out (a `replace` is
    not followed, so a replaced module is reported at its required version).
    The module path is the OSV/GitHub Go package name; github.com/* modules map
    to a repo by their path, others are reported as unmapped."""
    deps, in_require = set(), False
    for raw in (text or "").splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if in_require:
            if line.startswith(")"):
                in_require = False
                continue
            m = GOMOD_REQUIRE_RE.match(line)
            if m:
                deps.add((m.group(1), m.group(2)))
            continue
        if line.startswith("require"):
            rest = line[len("require"):].strip()
            if rest.startswith("("):
                in_require = True
                continue
            m = GOMOD_REQUIRE_RE.match(rest)
            if m:
                deps.add((m.group(1), m.group(2)))
    return sorted(deps)


def parse_gosum(text):
    """Return [(module, version)] from a go.sum. go.sum records a hash for
    every module version in the build graph, so a module can appear at more
    than one version and the `/go.mod` hash line repeats it; each distinct
    (module, version) is returned, with the `/go.mod` suffix stripped from the
    version. go.mod lists one selected version per module, so prefer it when a
    project has both."""
    deps = set()
    for raw in (text or "").splitlines():
        parts = raw.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            deps.add((parts[0], parts[1].split("/", 1)[0]))
    return sorted(deps)


def parse_lock(path, text):
    """(ecosystem, [(name, version)]) from a lock file, chosen by its file name.
    Raises ValueError for a file name it does not know."""
    base = os.path.basename(path).lower()
    if base in ("uv.lock", "poetry.lock") or re.match(r"^pylock\.([^.]+\.)?toml$", base):
        return "pip", parse_toml_lock(load_toml(text))
    if base == "pipfile.lock":
        return "pip", parse_pipfile_lock(json.loads(text))
    if base in ("package-lock.json", "npm-shrinkwrap.json"):
        return "npm", parse_package_lock(json.loads(text))
    if base == "yarn.lock":
        return "npm", parse_yarn_lock(text)
    if base == "pnpm-lock.yaml":
        return "npm", parse_pnpm_lock(text)
    if base == "go.mod":
        return "go", parse_gomod(text)
    if base == "go.sum":
        return "go", parse_gosum(text)
    raise ValueError("not a supported lock file name (supported: %s, pylock.NAME.toml)"
                     % ", ".join(LOCK_FILES))


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
                raise RateLimited("GitHub API rate limit reached; set GITHUB_TOKEN "
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


# Vanity hosts whose <prefix>/<repo> import path maps to one fixed GitHub owner
# by prefix substitution: the repo is the first path element after the prefix,
# and any /vN major version or deeper sub-package path that follows does not
# change it. A prefix may be one path element (k8s.io) or two (golang.org/x).
# Verified from each project's go.mod `module` line (2026-10-17):
#   k8s.io/api, k8s.io/apimachinery, k8s.io/client-go, k8s.io/klog/v2,
#     k8s.io/apiserver          -> kubernetes/<repo>
#   sigs.k8s.io/yaml, sigs.k8s.io/controller-runtime,
#     sigs.k8s.io/structured-merge-diff/v7 -> kubernetes-sigs/<repo>
#   golang.org/x/<repo> (the Go project's own sub-repositories: crypto, net,
#     sys, text, oauth2, tools, sync, ...) -> golang/<repo> (new in 0.9.6; a
#     two-element prefix, so the repo is the element after golang.org/x).
#     Verified from the go.mod `module` line of golang/{net,crypto,sys,text,
#     oauth2} (each reads `module golang.org/x/<repo>`), 2026-10-17. Only the
#     golang.org/x namespace is treated as a prefix; other golang.org/* paths
#     stay unmapped.
#   istio.io/<repo> -> istio/<repo> (new in 0.9.11). Verified from the go.mod
#     `module` line of istio/{istio,api,client-go,pkg} (each reads
#     `module istio.io/<repo>`), 2026-10-18. The element after istio.io names a
#     separate repo (istio.io/api and istio.io/client-go are their own repos,
#     required by istio/istio), so this is an owner prefix, not a monorepo.
# NB go.uber.org is NOT a prefix host: most of its libraries live under
# github.com/uber-go/<repo>, but go.uber.org/yarpc lives at yarpc/yarpc-go
# (verified 2026-10-17), so its modules are mapped by exact entries below.
GO_VANITY_OWNER_PREFIX = {
    "k8s.io": "kubernetes",
    "sigs.k8s.io": "kubernetes-sigs",
    "golang.org/x": "golang",
    "istio.io": "istio",
}

# Vanity-host prefixes whose ENTIRE subtree lives in one GitHub monorepo: a
# module whose path is the prefix itself or begins with "<prefix>/" maps to the
# SAME repo, whatever follows. This differs from GO_VANITY_OWNER_PREFIX, where
# the repo is the path element after the prefix; here every sub-module shares one
# repo. The longest matching prefix wins and a trailing /vN major version makes
# no difference. Verified from the go.mod `module` line of the root and several
# sub-modules (2026-10-17):
#   cloud.google.com/go -> googleapis/google-cloud-go (the Google Cloud Go
#     client monorepo). The bare root plus cloud.google.com/go/{storage,pubsub,
#     bigquery} and the deeper cloud.google.com/go/compute/metadata each read
#     `module cloud.google.com/go/<sub>`. These GCP client sub-modules are among
#     the most common Go dependencies, and only the bare root was mapped before.
#   go.etcd.io/etcd -> etcd-io/etcd (the etcd monorepo). Verified from
#     go.etcd.io/etcd/{etcdctl,etcdutl}/v3 (both `module go.etcd.io/etcd/<sub>
#     /v3`), on top of the api/client/server/pkg sub-modules checked for 0.9.5.
#     go.etcd.io/bbolt and go.etcd.io/raft are DIFFERENT repos (etcd-io/bbolt,
#     etcd-io/raft) and are NOT under the go.etcd.io/etcd/ prefix, so they are
#     unaffected by this prefix and stay exact entries below (raft added 0.9.10).
#   go.opentelemetry.io/contrib -> open-telemetry/opentelemetry-go-contrib (the
#     OpenTelemetry Go contrib monorepo; new in 0.9.8). Every instrumentation,
#     exporter and detector module lives in this one repo. Verified from the
#     go.mod `module` line of the root (go.opentelemetry.io/contrib) and four
#     sub-modules across three subtrees -- instrumentation
#     .../net/http/otelhttp and .../google.golang.org/grpc/otelgrpc, exporter
#     .../exporters/autoexport and detector .../detectors/gcp -- each reading
#     `module go.opentelemetry.io/contrib/<sub>` (2026-10-17).
#   The other go.opentelemetry.io subtrees (new in 0.9.9). OpenTelemetry's own
#     vanity-URL config (open-telemetry/opentelemetry-go-vanityurls,
#     go.opentelemetry.io/vanity.yaml, read 2026-10-17) maps each top-level path
#     to ONE repo and no deeper path to any other repo, so each subtree is a
#     monorepo. Before 0.9.9 the core and the collector had only a few exact
#     entries, so common modules such as go.opentelemetry.io/otel/sdk/metric,
#     the OTLP exporters and go.opentelemetry.io/collector/pdata were unmapped.
#     Each verified from its go.mod `module` line (2026-10-17):
#     go.opentelemetry.io/otel{,/sdk/metric,/log,/exporters/prometheus,
#       /exporters/otlp/otlptrace/otlptracegrpc} -> open-telemetry/opentelemetry-go
#     go.opentelemetry.io/collector{,/pdata,/component,/confmap}
#       -> open-telemetry/opentelemetry-collector
#     go.opentelemetry.io/proto/otlp -> open-telemetry/opentelemetry-proto-go
#     go.opentelemetry.io/auto -> open-telemetry/opentelemetry-go-instrumentation
#     go.opentelemetry.io/ebpf-profiler -> open-telemetry/opentelemetry-ebpf-profiler
#   The Collector's contrib repo (opentelemetry-collector-contrib) declares
#     github.com/open-telemetry/opentelemetry-collector-contrib/... module paths
#     (root and receiver/prometheusreceiver checked), so it is NOT under
#     go.opentelemetry.io/collector and maps as a direct GitHub module. The
#     match is path-boundary anchored, so go.opentelemetry.io/otelc (a different
#     repo) does not fall under go.opentelemetry.io/otel.
#   tailscale.com -> tailscale/tailscale (new in 0.9.10). Tailscale ships as a
#     single Go module whose path is the bare host tailscale.com, so every
#     import path under it (tailscale.com/cmd/tailscale, tailscale.com/ipn,
#     tailscale.com/tsnet, ...) is one package in the one repo. Verified from
#     the go.mod `module` line of tailscale/tailscale (`module tailscale.com`),
#     2026-10-17. A monorepo prefix, not an owner prefix: the element after the
#     host is a sub-package, not a separate repo.
GO_VANITY_MONOREPO_PREFIX = {
    "cloud.google.com/go": "googleapis/google-cloud-go",
    "go.etcd.io/etcd": "etcd-io/etcd",
    "go.opentelemetry.io/contrib": "open-telemetry/opentelemetry-go-contrib",
    "go.opentelemetry.io/otel": "open-telemetry/opentelemetry-go",
    "go.opentelemetry.io/collector": "open-telemetry/opentelemetry-collector",
    "go.opentelemetry.io/proto": "open-telemetry/opentelemetry-proto-go",
    "go.opentelemetry.io/auto": "open-telemetry/opentelemetry-go-instrumentation",
    "go.opentelemetry.io/ebpf-profiler": "open-telemetry/opentelemetry-ebpf-profiler",
    "tailscale.com": "tailscale/tailscale",
}

# Well-known Go vanity module hosts whose code lives on GitHub. gopkg.in follows
# a documented redirect rule (handled by gopkg_in_repo) and the Kubernetes hosts
# and golang.org/x a prefix rule (GO_VANITY_OWNER_PREFIX); these exact entries
# are verified from each project's go.mod `module` line (checked 2026-10-17):
#   code.gitea.io/gitea (releases) and gitea.dev (current main) -> go-gitea/gitea
#   gorm.io/gorm -> go-gorm/gorm; gorm.io/driver/{mysql,postgres,sqlite,
#     sqlserver} -> go-gorm/{mysql,...}; gorm.io/datatypes -> go-gorm/datatypes
#   gocloud.dev -> google/go-cloud
#   google.golang.org/grpc -> grpc/grpc-go; google.golang.org/protobuf ->
#     protocolbuffers/protobuf-go
#   go.uber.org/{zap,multierr,atomic} -> uber-go/{...}; go.uber.org/yarpc ->
#     yarpc/yarpc-go (a different owner, so it is an exact entry, not a prefix)
#   go.mongodb.org/mongo-driver -> mongodb/mongo-go-driver (its master module
#     path is go.mongodb.org/mongo-driver/v2; the /vN is stripped before lookup)
# From 0.9.5, each verified from its go.mod `module` line (2026-10-17):
#   google.golang.org is NOT a prefix host (grpc, protobuf, api and genproto all
#     live in different repos): google.golang.org/api -> googleapis/
#     google-api-go-client; google.golang.org/genproto and its common
#     sub-modules .../googleapis/{api,rpc} -> googleapis/go-genproto
#   cloud.google.com/go: moved to GO_VANITY_MONOREPO_PREFIX in 0.9.7 (the whole
#     subtree is one monorepo, googleapis/google-cloud-go)
#   go.opentelemetry.io has no single owner: its core, collector and contrib
#     subtrees live in different repos. Each subtree is one monorepo, so all
#     of them moved to GO_VANITY_MONOREPO_PREFIX (contrib in 0.9.8; the otel
#     core, which had exact entries for otel{,/trace,/metric,/sdk}, in 0.9.9).
#   go.etcd.io/etcd: moved to GO_VANITY_MONOREPO_PREFIX in 0.9.7 (one monorepo,
#     etcd-io/etcd); go.etcd.io/bbolt -> etcd-io/bbolt stays an exact entry
#     because it is a different repo outside the go.etcd.io/etcd/ prefix
# New in 0.9.6, each verified from its go.mod `module` line (2026-10-17):
#   google.golang.org/appengine -> golang/appengine (its v2 module path is
#     google.golang.org/appengine/v2; the /vN is stripped before lookup)
#   go.opentelemetry.io/collector (moved to GO_VANITY_MONOREPO_PREFIX in 0.9.9)
# (go.opentelemetry.io/contrib/... had a single exact entry for the net/http
# otelhttp module in 0.9.6; 0.9.8 replaced it with the go.opentelemetry.io/
# contrib monorepo prefix above, which covers every contrib sub-module.)
# New in 0.9.10, each verified from its go.mod `module` line (2026-10-17):
#   helm.sh/helm -> helm/helm. Helm is a single module with a major-version
#     path element: main reads `module helm.sh/helm/v4`, the dev-v3 branch
#     reads `module helm.sh/helm/v3`; both live in helm/helm. The trailing /vN
#     is stripped before this exact lookup, so the base path is the key.
#   go.etcd.io/raft -> etcd-io/raft. Its go.mod reads `module go.etcd.io/raft/v3`
#     (the /v3 is stripped before the lookup). raft lives OUTSIDE the
#     go.etcd.io/etcd/ monorepo prefix, so it needs this exact entry, like bbolt.
# New in 0.9.11, each verified from its go.mod `module` line (2026-10-18):
#   cuelang.org/go -> cue-lang/cue (`module cuelang.org/go` on master; one
#     module, so cuelang.org/go/cue/... are packages inside it).
#   oras.land/oras-go -> oras-project/oras-go. The v2 line (tag v2.6.0) reads
#     `module oras.land/oras-go/v2`; the /v2 is stripped before the lookup. main
#     has since moved to `module github.com/oras-project/oras-go/v3`, which the
#     github.com rule already maps to the same repo.
#   connectrpc.com/{connect,otelconnect,grpcreflect} ->
#     connectrpc/{connect-go,otelconnect-go,grpcreflect-go}. connect reads
#     `module connectrpc.com/connect` at v1.18.1 and `.../connect/v2` on main;
#     grpcreflect reads `.../grpcreflect/v2` on main. The repo names carry a -go
#     suffix the import path lacks, so connectrpc.com is NOT a prefix host and
#     only these three verified paths are mapped.
# New in 0.9.12, each verified from its go.mod `module` line (2026-10-18). These
# are all widely-used transitive dependencies whose vanity host is neither a
# prefix host nor a monorepo (their siblings, if any, live under other owners),
# so each is an exact entry:
#   dario.cat/mergo -> darccio/mergo (`module dario.cat/mergo` on master; the
#     very common struct-merging library, pulled in transitively by Docker,
#     Helm, containerd and many others; its old import.cat path imdario/mergo
#     moved owner, so only the current dario.cat path is mapped here).
#   filippo.io/age -> FiloSottile/age; filippo.io/edwards25519 ->
#     FiloSottile/edwards25519 (each `module filippo.io/<name>`). edwards25519 is
#     a common low-level crypto dependency. filippo.io is NOT treated as an owner
#     prefix (not every filippo.io module is FiloSottile/<same-name>), so these
#     two verified paths are exact entries.
#   honnef.co/go/tools -> dominikh/go-tools (`module honnef.co/go/tools`; the
#     staticcheck toolchain, a common dev/CI dependency).
#   gotest.tools -> gotestyourself/gotest.tools. The current module path is
#     `gotest.tools/v3` (the /v3 is stripped before the lookup, so the key is the
#     base path); the v1/v2 line was the bare `gotest.tools`. A very common test
#     helper dependency.
#   go.starlark.net -> google/starlark-go (`module go.starlark.net`; the Go
#     implementation of Starlark, used by Tilt, Buildkite and others).
#   mvdan.cc/sh -> mvdan/sh. The current module path is `mvdan.cc/sh/v3` (the /v3
#     is stripped before the lookup); the shell parser/formatter behind shfmt.
# New in 0.9.13, each verified from its go.mod `module` line (2026-10-18). Like
# the 0.9.12 batch, each vanity host is neither a prefix host nor a monorepo (its
# repo name differs from the import path, or it is the host's only module), so
# each is an exact entry; a trailing /vN is stripped before the lookup:
#   entgo.io/ent -> ent/ent (`module entgo.io/ent` on master; the Ent ORM /
#     entity framework, a very common data-layer dependency).
#   go.temporal.io/sdk -> temporalio/sdk-go; go.temporal.io/api ->
#     temporalio/api-go (each `module go.temporal.io/<name>`). The Temporal Go
#     SDK and its generated API types; the SDK requires the API module, so both
#     appear together in a Temporal user's go.sum. go.temporal.io is NOT treated
#     as a prefix host: the repo names carry a -go suffix the import path lacks
#     (sdk -> sdk-go, api -> api-go), so only these two verified paths are mapped.
#   gvisor.dev/gvisor -> google/gvisor (`module gvisor.dev/gvisor` on master; the
#     gVisor application kernel, used by runsc/gVisor-based container sandboxes;
#     one module whose sub-packages all live in the one repo).
#   buf.build/go/protovalidate -> bufbuild/protovalidate-go (`module
#     buf.build/go/protovalidate`; protobuf message validation, a common gRPC/
#     Connect dependency). buf.build/go is NOT a prefix host (the repo name
#     carries a -go suffix the path lacks), so only this verified path is mapped.
#   go.yaml.in/yaml -> yaml/go-yaml. The canonical go-yaml module moved to this
#     vanity host: the v3 branch reads `module go.yaml.in/yaml/v3` and main reads
#     `module go.yaml.in/yaml/v4`, both in yaml/go-yaml; the /vN is stripped
#     before the lookup, so the base path is the key. go.yaml.in is NOT a prefix
#     host (the element after it is "yaml" but the repo is "go-yaml"). The older
#     gopkg.in/yaml.vN path still maps to go-yaml/yaml by the gopkg.in rule.
# New in 0.9.14, each verified from its go.mod `module` line (2026-10-18). All are
# very common direct or transitive dependencies, and each is an exact entry:
#   go.uber.org/{mock,goleak,automaxprocs,dig,fx} -> uber-go/{same name} (each
#     `module go.uber.org/<name>`). mock is the maintained gomock fork (the old
#     github.com/golang/mock path is a different, archived repo and keeps mapping
#     there by the github.com rule). go.uber.org stays an exact-entry host, not a
#     prefix, because go.uber.org/yarpc lives under a different owner (see above).
#   go.opencensus.io -> census-instrumentation/opencensus-go (`module
#     go.opencensus.io`; one module, still pulled in transitively by many Google
#     Cloud and gRPC clients).
#   cel.dev/expr -> google/cel-spec (`module cel.dev/expr` at the root of
#     cel-spec; the CEL protobuf types, required by grpc-go and cel-go). cel.dev is
#     NOT a prefix host: only this verified path is mapped.
GO_VANITY_REPOS = {
    "code.gitea.io/gitea": "go-gitea/gitea",
    "gitea.dev": "go-gitea/gitea",
    "gorm.io/gorm": "go-gorm/gorm",
    "gorm.io/driver/mysql": "go-gorm/mysql",
    "gorm.io/driver/postgres": "go-gorm/postgres",
    "gorm.io/driver/sqlite": "go-gorm/sqlite",
    "gorm.io/driver/sqlserver": "go-gorm/sqlserver",
    "gorm.io/datatypes": "go-gorm/datatypes",
    "gocloud.dev": "google/go-cloud",
    "google.golang.org/grpc": "grpc/grpc-go",
    "google.golang.org/protobuf": "protocolbuffers/protobuf-go",
    "google.golang.org/api": "googleapis/google-api-go-client",
    "google.golang.org/genproto": "googleapis/go-genproto",
    "google.golang.org/genproto/googleapis/api": "googleapis/go-genproto",
    "google.golang.org/genproto/googleapis/rpc": "googleapis/go-genproto",
    "google.golang.org/appengine": "golang/appengine",
    "go.uber.org/zap": "uber-go/zap",
    "go.uber.org/multierr": "uber-go/multierr",
    "go.uber.org/atomic": "uber-go/atomic",
    "go.uber.org/yarpc": "yarpc/yarpc-go",
    "go.mongodb.org/mongo-driver": "mongodb/mongo-go-driver",
    "go.etcd.io/bbolt": "etcd-io/bbolt",
    "helm.sh/helm": "helm/helm",
    "go.etcd.io/raft": "etcd-io/raft",
    "cuelang.org/go": "cue-lang/cue",
    "oras.land/oras-go": "oras-project/oras-go",
    "connectrpc.com/connect": "connectrpc/connect-go",
    "connectrpc.com/otelconnect": "connectrpc/otelconnect-go",
    "connectrpc.com/grpcreflect": "connectrpc/grpcreflect-go",
    "dario.cat/mergo": "darccio/mergo",
    "filippo.io/age": "FiloSottile/age",
    "filippo.io/edwards25519": "FiloSottile/edwards25519",
    "honnef.co/go/tools": "dominikh/go-tools",
    "gotest.tools": "gotestyourself/gotest.tools",
    "go.starlark.net": "google/starlark-go",
    "mvdan.cc/sh": "mvdan/sh",
    "entgo.io/ent": "ent/ent",
    "go.temporal.io/sdk": "temporalio/sdk-go",
    "go.temporal.io/api": "temporalio/api-go",
    "gvisor.dev/gvisor": "google/gvisor",
    "buf.build/go/protovalidate": "bufbuild/protovalidate-go",
    "go.yaml.in/yaml": "yaml/go-yaml",
    "go.uber.org/mock": "uber-go/mock",
    "go.uber.org/goleak": "uber-go/goleak",
    "go.uber.org/automaxprocs": "uber-go/automaxprocs",
    "go.uber.org/dig": "uber-go/dig",
    "go.uber.org/fx": "uber-go/fx",
    "go.opencensus.io": "census-instrumentation/opencensus-go",
    "cel.dev/expr": "google/cel-spec",
}

# A gopkg.in package element carries a major-version selector, e.g. "yaml.v3".
_GOPKG_VERSIONED = re.compile(r"^(.+)\.v\d+$")


def gopkg_in_repo(module):
    """The GitHub owner/repo for a gopkg.in module path, or None, by gopkg.in's
    own documented redirect rule: gopkg.in/pkg.vN lives at github.com/go-pkg/pkg
    and gopkg.in/user/pkg.vN at github.com/user/pkg. A deeper sub-package path
    may follow and does not change the repo. No network request."""
    parts = (module or "").split("/")
    if len(parts) < 2 or parts[0].lower() != "gopkg.in":
        return None
    short = _GOPKG_VERSIONED.match(parts[1])
    if short:
        pkg = short.group(1)
        return "go-%s/%s" % (pkg, pkg) if pkg else None
    if len(parts) >= 3:
        pkg_m = _GOPKG_VERSIONED.match(parts[2])
        if parts[1] and pkg_m:
            return "%s/%s" % (parts[1], pkg_m.group(1))
    return None


def go_vanity_prefix_repo(module):
    """The GitHub owner/repo for a Go module on a vanity host that maps every
    <prefix>/<repo> path to one fixed GitHub owner by prefix substitution (the
    entries in GO_VANITY_OWNER_PREFIX: k8s.io -> kubernetes, sigs.k8s.io ->
    kubernetes-sigs, golang.org/x -> golang, istio.io -> istio). A prefix may be one path element
    (k8s.io) or two (golang.org/x); the longest matching prefix wins. The repo
    is the first path element after the prefix; a /vN major version or a deeper
    sub-package path follows it and does not change the repo (k8s.io/klog/v2 ->
    kubernetes/klog, golang.org/x/net/http2 -> golang/net). None for any other
    host. No network request."""
    parts = (module or "").split("/")
    for n in (2, 1):          # try the longer (two-element) prefix first
        if len(parts) <= n:
            continue
        owner = GO_VANITY_OWNER_PREFIX.get("/".join(parts[:n]).lower())
        repo = parts[n]
        if owner and repo and not re.match(r"^v\d+$", repo):
            return "%s/%s" % (owner, repo)
    return None


def go_vanity_monorepo_repo(module):
    """The GitHub owner/repo for a Go module whose whole vanity subtree lives in
    one monorepo (the entries in GO_VANITY_MONOREPO_PREFIX: cloud.google.com/go
    -> googleapis/google-cloud-go, go.etcd.io/etcd -> etcd-io/etcd, the
    go.opentelemetry.io subtrees -> their open-telemetry repos, tailscale.com ->
    tailscale/tailscale). The module
    path equals a prefix or begins with "<prefix>/", and the entire subtree maps
    to the same repo, whatever follows (cloud.google.com/go/storage,
    go.etcd.io/etcd/api/v3, ...). The longest matching prefix wins. Unlike
    go_vanity_prefix_repo, the repo does not depend on the element after the
    prefix. None for any other host. No network request."""
    module = (module or "").strip().lower()
    best = None
    for prefix, repo in GO_VANITY_MONOREPO_PREFIX.items():
        if module == prefix or module.startswith(prefix + "/"):
            if best is None or len(prefix) > len(best[0]):
                best = (prefix, repo)
    return best[1] if best else None


def go_module_repo(module):
    """The GitHub owner/repo for a Go module path, or None. For
    github.com/OWNER/REPO (optionally with a /vN major-version suffix or a
    deeper sub-package path) the repo is OWNER/REPO. gopkg.in paths follow
    gopkg.in's documented redirect rule, the Kubernetes vanity hosts k8s.io and
    sigs.k8s.io, the golang.org/x sub-repositories and istio.io an owner-prefix
    rule, the
    Google Cloud (cloud.google.com/go), etcd (go.etcd.io/etcd), OpenTelemetry
    (go.opentelemetry.io/{otel,collector,contrib,proto,auto,ebpf-profiler}) and
    Tailscale (tailscale.com) monorepos a monorepo-prefix rule (the whole subtree
    is one repo), and a small map of well-known vanity hosts (Gitea, GORM,
    gocloud.dev, gRPC, Protobuf, Helm, CUE, ORAS, Connect, the go.uber.org
    libraries, the etcd raft
    and bbolt libraries, the MongoDB Go driver and the Google
    API/genproto/App Engine client modules) verified from their go.mod is
    applied, with a trailing /vN major version stripped before the exact lookup.
    Other hosts (other golang.org paths, gopkg.in without a version, a private
    host) are not mapped, so they are reported as unmapped rather than guessed.
    No network request."""
    module = (module or "").strip()
    parts = module.split("/")
    if len(parts) >= 3 and parts[0].lower() == "github.com":
        owner, repo = parts[1], parts[2]
        if owner and repo and owner.lower() not in NOT_REPO_OWNERS:
            return "%s/%s" % (owner, repo)
    if parts and parts[0].lower() == "gopkg.in":
        return gopkg_in_repo(module)
    prefixed = go_vanity_prefix_repo(module)
    if prefixed:
        return prefixed
    monorepo = go_vanity_monorepo_repo(module)
    if monorepo:
        return monorepo
    if module in GO_VANITY_REPOS:
        return GO_VANITY_REPOS[module]
    return GO_VANITY_REPOS.get(re.sub(r"/v\d+$", "", module))


def registry_repo(ecosystem, name):
    """Find a package's GitHub repo from its registry metadata (PyPI, npm) or,
    for a Go module, from its own path (no network request)."""
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
    if ecosystem == "go":
        return go_module_repo(name)
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
                raise RateLimited("GitHub API rate limit reached; set GITHUB_TOKEN "
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


def osv_query_version(ecosystem, version):
    """The version string to send to OSV for a package query. A Go module
    version carries a leading 'v' (v1.9.1) in go.mod/go.sum, but OSV's Go
    ranges are plain semver, so the 'v' is dropped for the query; every other
    ecosystem is sent unchanged."""
    if version and ecosystem == "go" and version[:1] in ("v", "V"):
        return version[1:]
    return version


def osv_package_ids(ecosystem, name, version):
    """Every vulnerability ID and alias OSV.dev reports for this package (and
    version, when given): what an OSV-based scanner would be told."""
    version = osv_query_version(ecosystem, version)
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

def check(deps, resolve_repo, get_advisories, package_ids, id_lookup, ignore=None):
    """Classify every advisory that applies to each dependency.

    deps: [(ecosystem, name, version-or-None)]; ecosystem "repo" means name is
    owner/repo and every advisory of that repo applies. The four callables
    are injected so the logic is testable offline. `ignore` is an iterable of
    advisory IDs (GHSA or CVE, matched case-insensitively) to accept: those
    findings are marked "ignored" and left out of blind_spots, so a known gap
    does not fail --fail-on-blind. If get_advisories raises RateLimited, that
    repo and every repo not yet listed are recorded in unchecked_repos
    (without further GitHub requests) instead of failing the whole run. An
    advisory that names the dependency's ecosystem but gives its package in
    free text (see free_text_package) is kept, with package_named False,
    unless another of its entries names the package exactly.
    Returns a report dict."""
    ignore_ids = {i.upper() for i in (ignore or [])}
    findings, unmapped, repos_seen, unchecked = [], [], {}, []
    limited = False
    for eco, name, version in deps:
        repo = name if eco == "repo" else resolve_repo(eco, name)
        if not repo:
            unmapped.append({"ecosystem": eco, "package": name, "version": version})
            continue
        if repo not in repos_seen:
            repos_seen[repo] = None
            if not limited:
                try:
                    repos_seen[repo] = get_advisories(repo)
                except RateLimited:
                    limited = True
            if repos_seen[repo] is None:
                unchecked.append(repo)
        want = normalize_name(eco, name)
        osv_ids = None
        for adv in repos_seen[repo] or []:
            matches, free_text = [], []
            vulns = adv.get("vulnerabilities") or []
            if eco == "repo" and not vulns:
                vulns = [{}]  # an app advisory naming no package still applies
            for vuln in vulns:
                pkg = vuln.get("package") or {}
                pkg_eco = (pkg.get("ecosystem") or "").lower()
                if eco != "repo" and (
                        pkg_eco != eco or normalize_name(eco, pkg.get("name") or "") != want):
                    if pkg_eco == eco and free_text_package(eco, pkg.get("name")):
                        free_text.append(vuln)
                    continue
                matches.append(vuln)
            # The maintainers named the package in free text ("Traefik"), so it
            # can't be matched by name; the dependency comes from their repo,
            # so report the advisory, marked, rather than drop it.
            named = bool(matches)
            matches = matches or free_text
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
            ignored = bool((ghsa and ghsa.upper() in ignore_ids)
                           or (cve and cve.upper() in ignore_ids))
            findings.append({
                "ecosystem": eco, "package": name, "version": version, "repo": repo,
                "ghsa_id": ghsa, "cve_id": cve or "", "severity": adv.get("severity") or "",
                "summary": adv.get("summary") or "", "published_at": adv.get("published_at") or "",
                "vulnerable_range": "; ".join(v.get("vulnerable_version_range") or "?"
                                              for v in matches),
                "patched": "; ".join(v.get("patched_versions") or "?" for v in matches),
                "affects_your_version": "yes" if affected else "unknown",
                "package_named": named,
                "scanner_visible": visible,
                "ignored": ignored,
                "url": adv.get("html_url") or "",
            })
    sev = {"critical": 0, "high": 1, "medium": 2, "moderate": 2, "low": 3}
    findings.sort(key=lambda f: (f["scanner_visible"], sev.get(f["severity"], 4),
                                 f["package"], f["ghsa_id"] or ""))
    blind = [f for f in findings if not f["scanner_visible"] and not f["ignored"]]
    accepted = [f for f in findings if not f["scanner_visible"] and f["ignored"]]
    return {
        "dependencies_checked": len(deps),
        "mapped_to_repo": len(deps) - len(unmapped),
        "repos_with_advisories": sum(1 for a in repos_seen.values() if a),
        "advisories_that_apply": len(findings),
        "blind_spots": len(blind),
        "ignored_blind_spots": len(accepted),
        "unchecked_repos": unchecked,
        "findings": findings,
        "unmapped": unmapped,
    }


def render_text(report):
    lines = ["Advisory blind-spot check (advisory-import-census, MV2 of Munim, Inc.)",
             "Dependencies: %d, mapped to a GitHub repo: %d, repos with published advisories: %d"
             % (report["dependencies_checked"], report["mapped_to_repo"],
                report["repos_with_advisories"]), ""]
    unchecked = report.get("unchecked_repos") or []
    if unchecked:
        lines.append("INCOMPLETE: GitHub's API rate limit was reached, so %d repo(s) were NOT "
                     "checked. Set GITHUB_TOKEN (or wait for the hourly reset) and re-run:"
                     % len(unchecked))
        lines.append("  " + ", ".join(unchecked))
        lines.append("")
    findings = report["findings"]
    groups = [("BLIND SPOTS: published by the maintainers, not reported by OSV for this package",
               [f for f in findings if not f["scanner_visible"] and not f.get("ignored")]),
              ("Also apply, and OSV reports them",
               [f for f in findings if f["scanner_visible"]])]
    accepted = [f for f in findings if not f["scanner_visible"] and f.get("ignored")]
    if accepted:
        groups.append(("Accepted blind spots (--ignore: not counted, do not fail CI)", accepted))
    for title, items in groups:
        lines.append("%s (%d)" % (title, len(items)))
        for f in items:
            ver = f["version"] or "any version"
            lines.append("  %-8s %s %s  %s %s  affected: %s  fixed: %s%s%s" % (
                f["severity"] or "?", f["package"], ver, f["ghsa_id"], f["cve_id"],
                f["vulnerable_range"], f["patched"],
                "" if f["affects_your_version"] == "yes" else "  (version not pinned or range unclear)",
                "" if f.get("package_named", True)
                else "  (the advisory names its package only in free text)"))
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
    OSV-based scanner already alerts on them. Advisories accepted with --ignore
    are left out too, so no alert is raised for a gap you have chosen to accept.
    An empty result list is still written, so code scanning closes alerts once
    an advisory is imported (or accepted)."""
    rules, rule_index, results = [], {}, []
    for f in report.get("findings", []):
        if f.get("scanner_visible") or f.get("ignored"):
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
                   "%s.%s%s" % (
                       f.get("package"), version or "(any version)", ident, sev or "unknown",
                       f.get("repo"), where, SCANNERS, f.get("vulnerable_range") or "?",
                       _fixed_text(f.get("patched")),
                       "" if f.get("affects_your_version") == "yes"
                       else " The version is not pinned or the range is unclear, so check "
                            "which version you install.",
                       "" if f.get("package_named", True)
                       else " The advisory names its package only in free text, so check "
                            "that it means this one."))
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
                    help="a pip requirements.txt (hashed pip-compile output is fine)")
    ap.add_argument("--npm", action="append", default=[],
                    help="a package-lock.json or package.json")
    ap.add_argument("--pyproject", action="append", default=[],
                    help="a pyproject.toml (PEP 621 or Poetry dependencies)")
    ap.add_argument("--lock", action="append", default=[],
                    help="a lock file, recognised by name: " + ", ".join(LOCK_FILES)
                         + " (every locked package, at its exact version)")
    ap.add_argument("--package", action="append", default=[],
                    help="ECOSYSTEM:NAME[==VERSION], e.g. pip:vllm==0.10.1, "
                         "npm:flowise@3.1.3, go:github.com/gin-gonic/gin@v1.9.1, "
                         "repo:langgenius/dify@1.4.0")
    ap.add_argument("--map", action="append", default=[],
                    help="NAME=OWNER/REPO for packages whose registry has no GitHub link")
    ap.add_argument("--ignore", action="append", default=[], metavar="ID",
                    help="accept a known blind spot by its GHSA or CVE id (case-insensitive): "
                         "it is still listed, as accepted, but is not counted and does not "
                         "fail --fail-on-blind. Repeatable.")
    ap.add_argument("--ignore-file", action="append", default=[], metavar="PATH",
                    help="a file of advisory ids to accept, one per line (# comments allowed)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    ap.add_argument("--fail-on-blind", action="store_true",
                    help="exit 1 if any blind spot is found, or if the GitHub rate limit "
                         "left repos unchecked (for CI)")
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
    for path in args.lock:
        with open(path, encoding="utf-8") as fh:
            texts[path] = fh.read()
        try:
            eco, parsed = parse_lock(path, texts[path])
        except ValueError as e:
            ap.error("--lock %s: %s" % (path, e))
        add(eco, parsed, path)
    for text in args.package:
        eco, name, version = parse_package_arg(text)
        add(eco, [(name, version)], None)
    if not deps:
        ap.error("give at least one of -r, --npm, --pyproject, --lock or --package")
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

    ignore = list(args.ignore)
    for path in args.ignore_file:
        with open(path, encoding="utf-8") as fh:
            ignore += parse_ignore_file(fh.read())

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

    report = check(unique, resolve, list_repo_advisories, osv_package_ids, osv_has_id,
                   ignore=ignore)
    print(json.dumps(report, indent=2) if args.json else render_text(report))
    if report["unchecked_repos"]:
        print("blindspot: GitHub rate limit reached; %d repo(s) not checked (see "
              "unchecked_repos)" % len(report["unchecked_repos"]), file=sys.stderr)

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
    failed = report["blind_spots"] or report["unchecked_repos"]
    return 1 if (args.fail_on_blind and failed) else 0


if __name__ == "__main__":
    sys.exit(main())
