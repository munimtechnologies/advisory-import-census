# advisory-range-check (v0.1.0)

Compares a Rust security advisory's affected-version ranges with the versions crates.io has
actually published. Apache-2.0. Python 3.8+ standard library only. Made by AI agents working
for MV2 of Munim, Inc. (mv2@munimtech.com).

```
python advisory_range_check.py RUSTSEC-2026-0514
python advisory_range_check.py GHSA-29q9-p769-j8gq --repo hickory-dns/hickory-dns
python advisory_range_check.py CVE-2026-41678 --json
python advisory_range_check.py --file my-draft.json      # OSV or GitHub advisory JSON
python -m unittest -v test_advisory_range_check          # offline tests
```

`--repo owner/name` reads a GHSA that only the project's maintainers have published (a
repository advisory). GitHub's global API and OSV don't serve those until GitHub reviews them,
and their ranges are free text such as `0.25.0 .. 0.26.1`. Free-text patched versions such as
`>= 0.24.5, 0.25.3` are read too: an open-ended range gets the lowest patched version above
its lower bound.

## What it reports

| Code | Meaning | Exit 1? |
|---|---|---|
| R1 | A lower bound or an inclusive upper bound names a version crates.io never published (`introduced: 0.25.0` when only `0.25.0-alpha.*` exist). OSV's linter has the same idea as PKG:002. Synthetic `X.Y.Z-0` bounds are fine. | yes |
| R2 | A stable lower bound `X` leaves out published pre-releases of `X`. Under SemVer `0.26.0-beta.1 < 0.26.0`, so a range starting at `0.26.0` treats them as safe. We found no other tool that checks this (OSV's osv-linter checks that versions exist, not how ranges treat pre-releases; checked 2026-11-13). | yes |
| R3 | The fixed version isn't on crates.io (yet). | no |
| R4 | Published pre-releases of a stable fixed version are counted as affected. That's correct only if the fix landed after them. | no |
| R5 | A range matches no published version. | yes |
| R6 | A free-text range wasn't understood. | yes |
| R7 | No RustSec advisory for the package lists this GHSA or CVE, so it may still need importing. | no |

For R2 it also reports which of the left-out pre-releases a linked RustSec advisory already
marks as affected.

**Every finding is a candidate, not a verdict.** A left-out pre-release only matters if the
vulnerable code was already in it, so read the fix commit and the pre-release's source
(docs.rs or the tag) before you file a correction. This is how the hickory-dns range notes in
`docs/notes/hickory-range-checks-2026-11-13.md` were checked.

A range that matches crates.io can still be wrong if the "patched" release does not contain
the whole fix. The tool cannot see that; read the vulnerable lines at the patched tag. For an
example, see `docs/notes/uutils-preserve-root-records-2026-11-15.md`.

## Live run (2026-11-15)

The offline tests passed and seven live examples ran in a clean `python:3.12` container on
2026-11-15 (about five minutes, network on). The full output is in
[`examples-2026-11-15.txt`](examples-2026-11-15.txt). Highlights:

- `GHSA-29q9-p769-j8gq --repo hickory-dns/hickory-dns`: the maintainers' range for
  `hickory-recursor` starts at `0.25.0`, which was never published (R1); its five
  `0.25.0-alpha.*` releases fall outside every range (R2).
- `GHSA-3w89-7rx5-hpwx`: ranges starting at `0.26.0` (`hickory-net`) and `0.25.0`
  (`hickory-proto`) leave out four betas and five alphas (R2).
- `RUSTSEC-2026-0487`: the lower bound `0.20.1` names a version the `hickory-proto` crate
  never published (R1). The range still covers the intended releases, so this one is cosmetic.
- `RUSTSEC-2026-0514` and `CVE-2026-41678` (openssl): no findings.
- `GHSA-jh2m-fhpj-3vr7` without `--repo`: not found, with the hint to pass `--repo`, as designed.

## Agent skill

The same script ships as an agent skill in
`skills/rust-advisory-range-check/` (a `SKILL.md` plus `scripts/advisory_range_check.py`, an
identical copy), so coding agents such as Claude Code, Codex or Cursor can find and run it
when they review or write a Rust advisory. To add it to a project with Vercel's skills CLI:

```
npx skills add munimtechnologies/advisory-import-census --skill rust-advisory-range-check
```

It is listed with this repository's other skills on skills.sh:
<https://skills.sh/munimtechnologies/advisory-import-census>

## Sources and limits

It uses api.osv.dev (records and the RustSec lookup), crates.io's API (one request per second,
per its crawler policy) and api.github.com (60 unauthenticated requests per hour). It covers
crates.io only and uses today's version lists, so yanked versions count as not live. Free-text
spans like `a .. b` are read with both ends inclusive.
