# Will scanners see your app's security advisories? A maintainer's checklist

You publish a GitHub security advisory for your self-hosted app. Will the people
running your app find out from their vulnerability scanner? Dependency scanners
(OSV-Scanner and the tools built on OSV) match **installed packages** against
advisory records. If no record ties your advisory to a package, your users' scanner
will never show it, however severe it is.

This checklist turns the findings of the [pre-registered study chain](../study/README.md)
into steps. Each step says which result it rests on and how strong that evidence is.
All of it is observational: the studies compare apps, they do not change one app and
watch what happens. Apache-2.0 / CC BY 4.0.

## 1. Check whether your existing advisories are visible (2 minutes)

For each advisory ID (`GHSA-xxxx-xxxx-xxxx`) on your repository's Security tab:

```
curl -s https://api.osv.dev/v1/vulns/GHSA-xxxx-xxxx-xxxx
```

If OSV returns HTTP 404 (*not found*), or the record has no `affected[].package`, a
package-matching scanner can't report it. (If the advisory has a CVE, try the CVE ID
too; the studies count either.) Or check every advisory for a release at once:

```
python blindspot.py --package repo:<owner>/<repo>@<version>
```

[blindspot](../README.md) lists your repository's own advisories covering that version
that OSV can't match to a package.

**How common is "blind"?** Among self-hosted applications, very common. Applications
were 53 points more often blind than libraries ([H1](../study/app-vs-library/RESULTS.md)).
Among 30 Docker/binary-only apps, *non-Go* apps' package-less advisories reached
scanners 1 time in 638 ([A6](../study/registry-channel-a6/RESULTS.md)). And an old
advisory is not a safe one: among no-registry apps, advisories over a year old that
name **no package** are still only 22% visible, because the gap is not just import lag
([L1](../study/registry-channel-l1/RESULTS.md)).

## 2. Find out which group your app is in

| Your app ships as… | What the studies saw | Evidence |
|---|---|---|
| A release on an OSV-indexed registry (e.g. npm, PyPI, Packagist, Maven) under a name that matches the project | About 51–58 points *more* visible than apps without one; replicated on a fresh sample. Still +41.7 points when apps are compared within the same OSV ecosystem, so it is not just OSV covering npm or PyPI better | [A2](../study/registry-channel/RESULTS.md), [A1](../study/registry-channel-a1/RESULTS.md), [E2](../study/registry-channel-e2/RESULTS.md) (p = 0.0077, p = 0.0017, p < 0.0001) |
| A Go module (`go.mod` at the repository root) | Package-less advisories 74.8% visible (83 of 111), almost always as `Go: github.com/<owner>/<repo>`, attached by GitHub's advisory reviewers | [A6](../study/registry-channel-a6/RESULTS.md) (p = 0.0001) |
| A Go module with a vanity path (`go.example.org/...`) | Only one app in the sample; both its package-less advisories were visible. Too rare to test | [A8](../study/registry-channel-a8/RESULTS.md) |
| Docker images, binaries or install scripts only, not Go | Almost always blind: 0 of 190 (GLPI), 0 of 126 (OpenEMR), 0 of 86 (OpenProject), 0 of 49 (Zammad) | [A6](../study/registry-channel-a6/RESULTS.md) |

Releasing more often does **not** explain the difference: registry apps actually
release slightly *less* often (40.3 vs 44.5 releases a year), and the gap is large in
every release-cadence third, widest among the most frequent releasers (+50.6 / +58.4 /
+75.1 points from least to most frequent) ([A7](../study/registry-channel-a7/RESULTS.md)).

## 3. When you file the next advisory

- **Fill in the package fields** (ecosystem + package name) on the advisory form when
  your app has a real package. Use the exact name your users install. This matters even
  for advisories that take a while to be reviewed: among no-registry apps, advisories
  that *do* name a package reached 93% visibility once they were over a year old, while
  advisories naming no package stayed blind at every age
  ([L1](../study/registry-channel-l1/RESULTS.md)).
- **Don't name a package that doesn't exist.** Coolify named
  `composer:coollabsio/coolify` on 33 advisories, a name with no Packagist release, and
  0 of 33 reached scanners ([E1](../study/registry-channel-e1/RESULTS.md)). Frappe
  named `pip:frappe`, which is only a placeholder on PyPI: 4 of 62 reached scanners
  ([A6](../study/registry-channel-a6/RESULTS.md)). Naming a package explained only
  about a third of the registry effect
  ([A3](../study/registry-channel-a3/RESULTS.md)).
- **Go apps:** name the `Go` ecosystem and your module path exactly as written in
  `go.mod`. In the studies GitHub's reviewers usually attached it anyway; naming it
  yourself is our suggestion to save that step, not something the studies tested.
- **Say in the advisory text which image tags or release versions are affected and
  fixed.** That doesn't help scanners, but it is what a blind advisory's readers
  need to act.

## 4. If your app is Docker-only and not Go

**Why this group is blind is documented, not just observed.** GitHub's own
documentation says that "GitHub-reviewed advisories are mapped to packages in
ecosystems we support", and lists twelve supported ecosystems: Composer, Erlang (Hex),
GitHub Actions, Go, Maven, npm, NuGet, pip, Pub, RubyGems, Rust and Swift
([About the GitHub Advisory Database](https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database),
[github/advisory-database README](https://github.com/github/advisory-database#supported-ecosystems),
both checked 2026-10-19). No container-image, binary or install-script "ecosystem" is
on that list, so a Docker-only app's advisory has nothing GitHub's reviewers can map
it to, and OSV-based scanners match on exactly those mappings. The 0-of-451 result in
the table above is what that policy looks like in the data.

This is a known, open question upstream. Before opening a new issue, read these:

- [github/advisory-database#7268](https://github.com/github/advisory-database/issues/7268)
  (open since 2026-03) asks for maintainer-verified advisories outside any ecosystem
  to enter the global database. A GitHub staff member replied that such advisories
  "are valuable" but need "a curation step" because any GitHub user can create a
  repository advisory, and that GitHub is "looking into alternative solutions".
- [github/advisory-database#10118](https://github.com/github/advisory-database/issues/10118)
  (open since 2026-10) proposes recognising GitHub repository URLs in advisories as a
  generic binding, the way Go module paths already work.
- [github/advisory-database#9400](https://github.com/github/advisory-database/issues/9400)
  (open since 2026-09) is a worked example: a Docker-image-only app with a high-severity
  RCE and no matchable record anywhere.

GitHub's README says new-ecosystem suggestions should be raised "as an issue for
discussion" there. Adding your app as a concrete case to an existing issue is more
useful to the maintainers than a duplicate.

The studies found **no free route** for this group today. What the evidence suggests,
from strongest to weakest:

1. Apps that publish a real registry release under a matching name are far more often
   visible (A1/A2, and within the same ecosystem in E2). That is a comparison between
   apps, not a test of what happens when one app starts publishing, so treat it as
   likely but unproven.
2. Tell your users directly. Put a line in your README and install docs pointing to
   your repository's Security → Advisories page and saying that dependency scanners
   will not report these advisories. Mention each fix in your release notes.
3. Users can check your repository in CI with blindspot's GitHub Action, which lists
   advisories that OSV can't match.

## 5. If your advisory names a package but is not in the database yet

GitHub's page
[About repository security advisories](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/about-repository-security-advisories)
says GitHub "will review each published security advisory" and add it to the GitHub
Advisory Database, and that "This process can take up to 72 hours". Advisories that
name a package in a supported ecosystem usually do get added, but often later than
that. Until then, Dependabot, `npm audit`, OSV and the tools built on OSV don't report
them.

- **Check where it stands.** This prints `404` until the advisory is in the global
  database:

  ```
  curl -s -o /dev/null -w "%{http_code}\n" https://api.github.com/advisories/GHSA-xxxx-xxxx-xxxx
  ```

  Once it is in, that global record's `published_at` is the day GitHub added it, not
  the day you published it on your repository. Compare the two dates to see how long
  review took.
- **What the wait looks like (all checked 2026-10-30).** go-jose published
  GHSA-mgcc-cww5-fp2q (Go) on its repository on 2026-10-14, and it entered the global
  database on 2026-10-27, 13 days later. GHSA-vvm8-gf78-28g4 from the same project
  took 9 days (2026-10-19 to 2026-10-28). GHSA-44f3-xgp9-pvp2 (npm `hackmyagent`),
  published on its repository on 2026-08-09, still returned 404. Across 2,486
  repository advisories from 45 projects published in 2026, Safeguard measured a
  median of 5.4 days for those that arrived, and found 30.7% not in the database or
  OSV at all on 2026-10-18
  ([report](https://safeguard.sh/resources/blog/github-repository-advisories-missing-from-advisory-database-2026-data)).
- **Rule out your own side first.** The ecosystem and package name must match what
  your users install (section 3). If your repository is a fork, the same GitHub page
  says Dependabot alerts are sent only when the fork has its own uniquely named
  package on a public registry.
- **Where to ask.** The place is the
  [github/advisory-database issue tracker](https://github.com/github/advisory-database/issues).
  Search it for your GHSA ID before opening an issue. Expect to wait there too: on
  2026-10-30,
  [#10342](https://github.com/github/advisory-database/issues/10342) (opened
  2026-10-13, eight advisories),
  [#10688](https://github.com/github/advisory-database/issues/10688) and
  [#10746](https://github.com/github/advisory-database/issues/10746) (21 advisories)
  had no replies, and the go-jose reporter closed
  [#10687](https://github.com/github/advisory-database/issues/10687) themselves once
  the advisory appeared.
- **Meanwhile, tell your users directly** (section 4, step 2): a line in the release
  notes reaches them while scanners are still silent.

## What this checklist doesn't know

- Every number comes from public GitHub advisory pages and the OSV API at the time of
  each study (October 2026), with frames of about 30–60 self-hosted apps each. OSV and
  GitHub's review practice can change.
- Re-checked 2026-10-19: `coollabsio/coolify` is still absent from Packagist
  (`repo.packagist.org/p2/coollabsio/coolify.json` returns 404) and `frappe` on PyPI is
  still the 0.0.1 placeholder from 2023 whose own description says to install via bench
  or Docker instead. Re-checked 2026-10-20 and again 2026-10-30: all three upstream
  issues in section 4 are still open, with no new reply from GitHub staff.
- Section 5's examples are single advisories, picked because their maintainers or
  users asked about them in public. They show that long waits happen, not how often.
  For rates, see Safeguard's report.
- Both pre-registered follow-ups have now landed. The pooled ecosystem test: the
  registry gap survives holding the OSV ecosystem fixed, +41.7 points across 6
  ecosystems and 52 apps ([E2](../study/registry-channel-e2/RESULTS.md)). The review-lag
  test ([L1](../study/registry-channel-l1/RESULTS.md)): within the same no-registry
  repos, old (≥ 1 year) advisories are more visible than young ones (+22.4 points,
  p = 0.0001), so part of the blind spot is import lag — but a +74-point registry gap
  remains even among year-old advisories (p = 0.0063), and the catch-up happens only for
  advisories that name a package. Apps that name no package stay blind at every age.
- No result has been reviewed by a human. Corrections are welcome as issues.

Made with AI agents working for MV2 of Munim, Inc.
