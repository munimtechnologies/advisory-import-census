# tauri, cedar-policy and openmls: maintainer-published advisories missing from scanner databases (checked 2026-11-11)

Checked by AI agents working for MV2 of Munim, Inc., on 2026-11-11 (about 21:00-22:00 UTC). Licence: CC BY 4.0.

"In RustSec" means the advisory has a file in rustsec/advisory-db, which is what cargo-audit and cargo-deny read.
"GitHub-reviewed" means github.com/advisories/<GHSA> resolves; that page 404s when GitHub hasn't reviewed the advisory, and then
Dependabot and osv-scanner (which reads GitHub's reviewed advisories through OSV) don't report it either.

| Crate (90-day downloads) | Advisory | Severity | Published | Patched | In RustSec | GitHub-reviewed |
|---|---|---|---|---|---|---|
| tauri (18.1M) | GHSA-w28w-mhc8-qvjv (any webview could take another webview's queued channel data) | high | 2026-09-26 | 2.11.6, 3.0.0-alpha.2 | no | no |
| tauri | GHSA-7gmj-67g7-phm9 / CVE-2026-42184 (remote origin treated as local on Windows/Android) | moderate | 2026-05-06 | 2.11.1 | no | yes |
| cedar-policy (4.1M) | GHSA-m84h-6f26-p3p7 (memory exhaustion parsing nested extended `has`) | high | 2026-10-22 | 4.13.0 | no | no |
| openmls (0.74M) | GHSA-gc79-23g3-8g52 (unbounded recursion decoding nested extensions) | high | 2026-10-08 | 0.8.2, 0.9.1 | no | no |
| openmls | GHSA-8x3w-qj7j-gqhf (tag length not checked) | high | 2026-02-04 | 0.7.2 | no | yes |

rustsec.org has no package page at all for cedar-policy or openmls, and lists only the two 2022 advisories for tauri. No
rustsec/advisory-db pull request adds advisories for cedar-policy or openmls (the only "openmls" match is about hpke-rs and
libcrux-psq), and none from 2026 adds one for the tauri crate (one bot PR names the separate tauri-winrt-notification crate).

## A range detail in tauri GHSA-w28w

Upstream gives `>= 2.0.0, <= 2.11.5`, patched 2.11.6. But tauri 3.0.0-alpha.0 (2026-09-13) and 3.0.0-alpha.1 (2026-09-15)
were published before 2.11.6 (2026-09-19). Their `src/ipc/channel.rs` (read on docs.rs) still has the single app-wide
`HashMap<u32, InvokeResponseBody>` and a `fetch` command that never checks the calling webview. 3.0.0-alpha.2 (2026-09-21)
has the per-webview queue. A database that copies `patched >= 2.11.6` therefore reports the two vulnerable 3.0 alphas as
fixed. The draft RustSec entry uses `patched = [">= 2.11.6, < 3.0.0-alpha.0", ">= 3.0.0-alpha.2"]`.

The advisory text also says the fix uses random IDs. The merged commit (e901f1de) switched to per-webview ID sequences
after review, so the draft describes the merged code.

## Sources

- Repository advisory lists: github.com/tauri-apps/tauri/security/advisories, github.com/cedar-policy/cedar/security/advisories,
  github.com/openmls/openmls/security/advisories.
- Fixes: tauri e901f1de9ee4dee9d0d2e1942808679a14f1f610 (2.11.6) and ba025588f3559858f43547e8c04424c47a3c445b (2.11.1);
  cedar-policy/cedar#2560 (merged 2026-09-10, released in 4.13.0 on 2026-09-15).
- Download counts and release dates: crates.io API, 2026-11-11.

## What happens next

MV2 has single-crate RustSec pull requests drafted for comrak, tauri and cedar-policy. They will be sent one at a time as his
open RustSec pull requests are reviewed (he keeps no more than three open). openmls comes after that, once its fix commits
are mapped. Nothing here has been reported to the projects. All five advisories were published by the projects themselves,
so this is about database coverage, not new vulnerabilities.
