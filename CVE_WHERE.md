# cve_where.py: why can't GitHub's Advisory Database find this CVE?

People keep opening issues on github/advisory-database that say "GitHub issued this CVE, so why doesn't the
Advisory Database have it?" (for example #8831, #8851 and #10423). Answering one means making the same five or six
public API calls by hand. `cve_where.py` makes them for you and prints what each source says, for one CVE or many:

1. **CVE Services ID state** (`cveawg.mitre.org/api/cve-id/<CVE>`): PUBLISHED, RESERVED, REJECTED, or 404 (never
   allocated)
2. **CVE record** (`cveawg.mitre.org/api/cve/<CVE>`): who assigned it, when, and which GitHub repository advisory
   it cites
3. **NVD** (`services.nvd.nist.gov/rest/json/cves/2.0?cveId=`): status and source
4. **GitHub lookup by CVE** (`api.github.com/advisories?cve_id=`): which global advisories list it, if any
5. **Each cited repository advisory**: its state and package ecosystems
   (`/repos/<owner>/<repo>/security-advisories/<GHSA>`), and whether it is a global advisory (`/advisories/<GHSA>`)
6. **OSV** (`api.osv.dev/v1/vulns/<CVE>`)

You don't need an account for any of them. The script is Python 3.9+ and uses only the standard library.
Apache-2.0. Made with AI agents working for MV2 of Munim, Inc.

## Example

This output was built by hand on 2026-11-05 (UTC), using what each source returned for CVE-2026-49481 (UpSnap,
from github/advisory-database#8831) and laid out the way the tool prints it:

```
$ python cve_where.py CVE-2026-49481
CVE-2026-49481
  CVE.org   PUBLISHED; record PUBLISHED by GitHub_M on 2026-08-12
  NVD       Deferred (source security-advisories@github.com, published 2026-08-12)
  GitHub    ?cve_id= -> EMPTY
  Repo adv  GHSA-6mc7-6948-w5h4 seriousm4x/UpSnap: published; ecosystems (empty); global NOT_GLOBAL
  OSV       CVE-2026-49481 aliases GHSA-6mc7-6948-w5h4
  Why
    - NOT FOUND: GET /advisories?cve_id=CVE-2026-49481 returns no live advisory.
    - Issued by GitHub's own CNA (GitHub_M).
    - CVE.org: published by GitHub_M on 2026-08-12.
    - NVD: Deferred, published 2026-08-12.
    - OSV: has a record CVE-2026-49481 (aliases: GHSA-6mc7-6948-w5h4).
    - Cited repository advisory GHSA-6mc7-6948-w5h4 (seriousm4x/UpSnap) (state published) is not in the global database and names no package in a supported registry (ecosystem: (empty)). GitHub reviews advisories for packages from supported registries.
```

So GitHub issued the CVE and NVD has it. OSV has a record too, which lists the repository advisory as an alias.
A CVE lookup in GitHub's own Advisory Database still returns nothing, because the repository advisory names no
package in a supported registry, so it never became a global advisory.

## Options

| Option | Effect |
|---|---|
| `--from-file ids.txt` | read CVE IDs, one per line (`#` comments allowed) |
| `--json` | print JSON (one object per CVE, with every field and the findings) |
| `--no-osv` | skip the OSV lookup |
| `--no-wait` | fail at once on GitHub's rate limit instead of waiting for the reset |
| `--fail-if-missing` | exit 1 if any CVE has no live advisory in GitHub's Advisory Database (for CI) |

## Limits

- Anonymous GitHub API calls are capped at 60 an hour. Each CVE costs 1 call, plus 2 for every cited repository
  advisory (at most 3 are read). If `GITHUB_TOKEN` is set in your environment, it is sent only to
  api.github.com. NVD calls are spaced 6.5 s apart to stay within NVD's public limit.
- The findings ("Why") only restate what the sources returned at the moment of the read. They don't judge any
  advisory or record, and they don't say what anyone should do.
- The tool reads repository advisories that are cited in the CVE record or in NVD's references. If a record cites
  none, it can't say which repository advisory the CVE came from.

How often this happens across all CVEs GitHub's CNA has published is what study S8 measures
([study/cna-gap-s8/PREREG.md](study/cna-gap-s8/PREREG.md)). Results will be added there.
