# russh 0.65.0 / pageant 0.2.5 advisories: range checks (2026-11-14)

On 2026-10-25 the russh maintainer published five advisories, all fixed in the russh 0.65.0 and pageant 0.2.5
releases of that day. On 2026-11-14 none of them had a RustSec entry, so `cargo audit` and `cargo deny` users got no
alert. Before drafting RustSec entries, AI agents working in MV2's name checked each advisory's version range against
the fix commits and the released source. Two of the five ranges don't match the code.

Licence: CC BY 4.0. Made with AI agents working in MV2's name (MV2, Munim, Inc., mv2@munimtech.com).

| Advisory | Crate | Upstream range | What the code shows | Range we propose |
|---|---|---|---|---|
| GHSA-3hm4-p7h4-rvwp (high, no CVE, not GitHub-reviewed) | russh | header `< 0.65`; text says 0.61.0 to 0.64.1 | 0.60.3 depends on `internal-russh-forked-ssh-key =0.6.18`; 0.61.0 pins `ssh-key =0.7.0-rc.10` (the recursion is in the 0.7.0 release candidates); fix 730d663 in v0.65.0 | `>= 0.61.0, < 0.65.0` (header too wide) |
| GHSA-fw5c-8223-6h42 (moderate) | russh | `>= 0.60.0, < 0.65` | The advisory says 0.60.0 is only the oldest release checked and that all releases with `channels::io::ChannelTx` are likely affected; fix 39cb9db | `< 0.65.0` (no lower bound) |
| GHSA-4p9f-7p9m-5vfg (moderate) | russh | `< 0.65` | fix b33e93b (at most two EXT_INFO per session) | `< 0.65.0` (matches) |
| GHSA-9wfm-jcj8-jfv9 (low) | russh | `< 0.65.0` | fix 23aa5d2 (confirm constraint stored once) | `< 0.65.0` (matches) |
| GHSA-662x-8wvj-2276 (low) | pageant | `>= 0.2.0, < 0.2.5` | The same unchecked length-prefixed buffering loop is in 0.0.4 and 0.1.0 (`src/pageant_impl.rs`); 0.0.1-0.0.3 forward each read without framing; fix 69e4b55 | `>= 0.0.4, < 0.2.5` (upstream misses 0.0.4 and 0.1.0) |

## How it was checked

- Version lists and dependency pins from the crates.io API (`/api/v1/crates/russh/<version>/dependencies`, `/api/v1/crates/pageant/versions`).
- Fix commits read in full (`Eugeny/russh` commits 730d663, 39cb9db, b33e93b, 23aa5d2, 69e4b55); all five are in `v0.64.1...v0.65.0`.
- pageant source read on docs.rs at 0.0.1, 0.0.2, 0.0.3, 0.0.4, 0.1.0 and 0.2.0 (`PageantStream::new`: `read_u32` length prefix, then `if buf.len() < len + 4 { continue; }` with no maximum).

## Limits

- We read the source at boundary releases and did not run any code.
- pageant 0.0.4 and 0.1.0 only run on Windows, and the attack needs agent forwarding to a malicious server, as upstream describes for 0.2.x.
- The GHSA-3hm4 root cause is in `ssh-key`, whose own advisory was still pending upstream on 2026-11-14. We propose no `ssh-key` entry.
- The 2026-11-03 russh advisories (GHSA-9264-jvgf-6w2f and GHSA-736f-c93q-9fwx) and the older moderate and low ones are not covered here.

Earlier notes in this series: [hickory range checks](hickory-range-checks-2026-11-13.md), [zip advisories](zip-advisories-2026-11-14.md).
