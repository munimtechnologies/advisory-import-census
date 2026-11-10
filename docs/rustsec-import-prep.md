# rustsec_import_prep.py: from "GitHub has it, RustSec doesn't" to a draft RustSec file

`tools/rustsec_import_prep.py` prepares imports into the RustSec advisory database
([rustsec/advisory-db](https://github.com/rustsec/advisory-db)) for advisories that a crate's own
maintainers published on GitHub. Advisories that never reach RustSec are not reported by `cargo audit` or
`cargo deny`; study [S14](../study/rust-ghsa-only-s14/RESULTS.md) counted 620 such GitHub-reviewed Rust
advisories.

Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com). Apache-2.0. Python 3.8+, standard
library only, read-only requests, no token.

## Use

```
python tools/rustsec_import_prep.py russh=Eugeny/russh pageant=Eugeny/russh --out-dir out/prep
```

Each argument is `CRATE=OWNER/REPO`. For each crate the script reads:

1. GitHub's reviewed advisories that affect the crate.
2. The repository's own published security advisories. These include ones GitHub has not reviewed yet,
   which therefore never reach Dependabot or OSV.dev.
3. Every crates.io release of the crate.
4. OSV.dev's records for the crate.
5. For each advisory still missing, OSV.dev's record of that GHSA. A RustSec advisory filed under a
   different crate name shows up there, and a 404 means no OSV-based scanner can see the advisory at all.

It writes:

- `rows.csv`: one row per advisory, with status `RUSTSEC_COVERED`, `MISSING` or `WITHDRAWN`, the ranges,
  the fixed versions, how many releases are affected, and flags for anything a person should check.
- `summary.txt` and `summary.json`: counts per crate.
- `drafts/<crate>/RUSTSEC-0000-0000.<ghsa>.md`: the TOML part of a RustSec file. `aliases`, `date`, `url`,
  `references`, `cvss`, suggested `categories` and `patched` / `unaffected` are filled in. The title and
  description are left as TODO on purpose: GitHub's advisory text is CC BY 4.0 and RustSec is CC0, so they
  have to be written fresh, from the fix commits.
- `source/<crate>/<GHSA>.json`: the advisory's own text, for the person writing the description. It is
  third-party text; treat it as data.

Exit code 0 when every source was read, 2 when any request failed (the other crates still run).

## The `url` field

RustSec's linter rejects a `url` that points at a GitHub advisory page:

```
invalid value `"https://github.com/<owner>/<repo>/security/advisories/GHSA-..."` for key `url` in
[advisory]: URL refers to GHSA alias GHSA-...; refer to an issue, PR or commit instead
```

So the draft's `url` is a GitHub pull request, commit or issue taken from the advisory's references, then
from links in its description: pull requests first, then commits, then issues. Up to three more go in
`references`. Each link must be exactly `https://github.com/OWNER/REPO/pull/N`, `.../issues/N` or
`.../commit/<7-40 hex>`; query strings and fragments are dropped and anything else is refused. The GHSA ID
stays in `aliases`. If the advisory has no such link, the draft has a `# url = TODO` comment instead and
the row gets the `NO_FIX_LINK` flag: find the fix commit (often a "Merge commit from fork" from a private
security fork) in the release's compare view.

Check every link by hand before you send a draft: a link in the description can be to a related issue
rather than the fix.

## Flags

| Flag | Meaning |
|---|---|
| `RANGE_UNPARSED` | A range clause the script cannot read, such as free text (`0.25.0 .. 0.25.2`) or a clause without an operator inside a longer range (`>= 0.34.0-beta.1,0.61.0`, almost always a typo) |
| `RANGE_ANY` | The range is `*` |
| `NO_PATCHED` / `MULTI_PATCHED` | No fixed version, or more than one |
| `PATCHED_NOT_ON_CRATES_IO` / `PATCHED_YANKED` | The fixed version was never published, or it was yanked |
| `PATCHED_INSIDE_RANGE` | The fixed version falls inside its own vulnerable range |
| `BOUND_NOT_ON_CRATES_IO` / `RANGE_MATCHES_NO_RELEASE` | A bound names a version that does not exist, or the range matches no release |
| `MULTI_RANGE` | More than one range for the crate |
| `REPO_GLOBAL_RANGE_DIFFER` | The repository advisory and GitHub's reviewed copy give different ranges |
| `NOT_IN_OSV` | OSV.dev has no record of this GHSA |
| `COVERED_VIA_OSV_GHSA_RECORD` | RustSec covers it, found through OSV's record of the GHSA (for example under another crate) |
| `NO_FIX_LINK` | Missing advisory with no pull request, commit or issue link, so the draft has no `url` yet |

Versions follow GitHub's range syntax: `0.65` means 0.65.0, `v0.25.0` means 0.25.0, and a range that is one
bare version means exactly that version.

## Check the description against the released code

The GitHub advisory describes the fix the reporter proposed or tested, and that can differ from what was
released. In the russh batch (rustsec/advisory-db#3538), two of six advisories differed:

- GHSA-wwx6-x28x-8259: 0.61.1 caps decompressed packets at the normal maximum packet length (256 KiB
  plus 33 bytes, `MAXIMUM_DECOMPRESSED_PACKET_LEN = MAXIMUM_PACKET_LEN` in `cipher/mod.rs` at v0.61.1).
  The advisory gives the intended ceiling as 128 MiB, following OpenSSH, and the first draft copied that
  figure.
- GHSA-4r3c-5hpg-58qr: the advisory names `take_str` / `take_bytes` / `take_name_list` helpers. In the
  released 0.61.0 the fix is a bounded name-list decoder (`MAX_NAME_LIST_BYTES = 16 * 1024`,
  `MAX_NAME_LIST_ENTRIES = 1024` in `helpers.rs`), and those helper names do not appear in `parsing.rs`,
  `helpers.rs` or `negotiation.rs` at that tag.

Read the fixed version's source at its tag (`raw.githubusercontent.com/OWNER/REPO/vX.Y.Z/...`) before
describing the fix.

## Prior art

`rustsec-admin sync` ([rustsec/rustsec#656](https://github.com/rustsec/rustsec/pull/656)) updates aliases
from OSV and lists GitHub advisories to consider importing, and
[rustsec/advisory-db#1711](https://github.com/rustsec/advisory-db/issues/1711) tracked such a list in 2023.
This script adds four things: unreviewed repository advisories, checks of each range against crates.io,
the OSV lookup of each GHSA, and draft files.

## Results so far

- 2026-11-10, first version on six crates: russh 28 missing (7 high), pageant 2, tough 9,
  hickory-recursor 8 (7 of them repository advisories that are not in GitHub's reviewed database),
  gix-fs 3 (2 repository-only), pingora-core 0. That run showed the two-part version (`< 0.65`) and
  free-text range shapes that the tool now handles.
- The openssl advisories that went through this workflow were merged into RustSec:
  [#3531](https://github.com/rustsec/advisory-db/pull/3531) (RUSTSEC-2026-0463) and
  [#3533](https://github.com/rustsec/advisory-db/pull/3533) (RUSTSEC-2026-0473 to RUSTSEC-2026-0479).
- [#3538](https://github.com/rustsec/advisory-db/pull/3538) (six high-severity russh advisories) failed
  RustSec's lint because every `url` was a GHSA page. That is why drafts now take `url` from a fix link.

## Tests

```
python -m unittest -v tools/test_rustsec_import_prep.py
```

The tests use fixtures only. They include hostile text in every remote field, real range shapes seen in
GitHub advisories on 2026-11-10, and the link shapes the `url` picker must accept or refuse.
