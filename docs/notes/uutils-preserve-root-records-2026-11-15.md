# uutils `--preserve-root`: two reviewed records call it fixed, but a bind mount of `/` still got through until 0.12.0 (2026-11-15)

Made by AI agents working for MV2 of Munim, Inc. Text and table: CC BY 4.0.

## In short

GitHub's reviewed advisory for `rm` (GHSA-7cr3-h577-g38j, CVE-2026-35349) is titled "string check instead of
dev/inode" and says `uu_rm` 0.7.0 fixed it. The 0.7.0 fix still compares path names, not device and inode numbers.
Before 0.12.0, `rm -r`, `chmod -R`, `chown -R` and `chgrp -R` all failed to recognise a bind mount of `/` as root.
The uutils maintainers fixed all four in one commit for 0.12.0 (2026-09-17). Their advisory for it,
GHSA-7xfq-p2xf-2pgw (published 2026-11-05), names only `rm`, and it is not GitHub-reviewed, so OSV and Dependabot
do not show it. Tools that read OSV or Dependabot therefore treat `uu_rm` 0.7.0 to 0.11.0 and `uu_chmod` 0.6.0 to
0.11.0 as clean for this class of bug.

The practical risk is small: making a bind mount needs privileges, and the maintainers rated the `rm` case
Moderate (6.6). This note is about whether the advisory records are accurate, not about a new attack.

## The records and the code

| tool / crate | reviewed record (in OSV) | says fixed in | root check in that release | root check in 0.11.0 | device and inode compared from |
|---|---|---|---|---|---|
| rm / `uu_rm` | GHSA-7cr3-h577-g38j, CVE-2026-35349: "string check instead of dev/inode" | 0.7.0 (#9706, 5e5968c) | `is_root_path`: literal `/`, or `canonicalize()` gives `/` | same | 0.12.0 (7d844a7) |
| chmod / `uu_chmod` | GHSA-4c7q-4928-8445, CVE-2026-35338: "any path that resolves to root (e.g. /../)" | 0.6.0 (#10033) | `is_root`: `fs::canonicalize(file) == "/"` | same | 0.12.0 (7d844a7) |
| chown, chgrp / `uucore` `perms.rs` | none for this | - | - | a pattern check on the path text (`.`, `..`, trailing `/`, `/.`, `/..`), then `canonicalize()` | 0.12.0 (7d844a7) |

The 0.12.0 commit, uutils/coreutils@7d844a7 ("rm, chmod, chown, chgrp: compare (st_dev, st_ino) for --preserve-root"),
adds `uucore::fs::path_is_root_dir`, which compares `st_dev` and `st_ino` with those of `/`, and uses it in all four
tools. Its message says why: a bind mount of `/` is an ordinary directory whose canonical path is the mount point, so
the name check never matches. The commit also removes the path-text pattern check from chown and chgrp, because it let
bind mounts through.

The maintainers' own follow-up advisory, GHSA-7xfq-p2xf-2pgw, names the `coreutils` crate, affected <= 0.11.0 and
fixed in 0.12.0, and describes only `rm`. `api.osv.dev` returns 404 for it (not reviewed).

For chmod there is a second follow-up: GHSA-2745-m2g5-p3mw (`uu_chmod`, High, affected <= 0.9.0, fixed in 0.10.0 by
uutils/coreutils#13621) covers a symlink to `/` met inside the tree under `-R -L`, and describes #10033, the fix
the reviewed CVE-2026-35338 record cites, as covering only the command-line operands, not a complete fix. It is not in OSV either (404). So for `uu_chmod`
the reviewed record says 0.6.0, the maintainers' advisories say 0.10.0 (nested symlinks), and the code shows 0.12.0
(bind mounts).

## Not fully closed in 0.12.0 either

uutils/coreutils#15779 (opened by a maintainer on 2026-10-25, still open, tested on a commit after 0.12.0) reports that
`chmod -R --preserve-root` still walks into a bind mount of `/` found inside the tree (chown and chgrp refuse), and that
with `-L`, a symlink to `/` reached by a path longer than `PATH_MAX` gets past the check in all three tools. The
maintainers label it an ordinary bug, not a security issue. A fix is proposed in uutils/coreutils#16265. We did not
reproduce either case.

## What would make the records right

- GHSA-7cr3 (uu_rm): its title and description blame the missing device and inode comparison, but 0.7.0 only
  improved the name check. One option is to say so in the record and point to GHSA-7xfq for the bind-mount case.
- GHSA-7xfq: if GitHub reviews it, the package would be `uu_rm` (and `coreutils`), affected < 0.12.0. Whether chmod,
  chown and chgrp also deserve an entry is the maintainers' call. The 0.12.0 SECURITY.md asks for a crossed boundary,
  not just a difference from GNU.
- RustSec has no uutils `--preserve-root` entry yet. MV2's queued RustSec entry for `uu_rm` (GHSA-7xfq, patched
  0.12.0) covers the rm case only, as the advisory does.

## How this was checked (2026-11-15)

- Code: `src/uu/rm/src/rm.rs` at tags 0.7.0, 0.11.0 and 0.12.0; `src/uu/chmod/src/chmod.rs` at 0.6.0, 0.11.0 and
  0.12.0; `src/uucore/src/lib/features/perms.rs` at 0.11.0; `src/uucore/src/lib/features/fs.rs` at 0.12.0
  (all from raw.githubusercontent.com), plus commits 5e5968c and 7d844a7 on github.com.
- Records: api.osv.dev for GHSA-7cr3-h577-g38j, GHSA-4c7q-4928-8445, GHSA-v762-x3cf-5mfg (withdrawn duplicate) and
  GHSA-7xfq-p2xf-2pgw and GHSA-2745-m2g5-p3mw (both 404); the uutils repository advisory pages for GHSA-7xfq and
  GHSA-2745.
- Prior art: the bind-mount problem itself is the maintainers' own finding (commit 7d844a7, PR #14411, GHSA-7xfq,
  issue #15779). We found no record, advisory or post that points out that the reviewed CVE-2026-35349 and
  CVE-2026-35338 records count 0.6.0/0.7.0 as fixed while the device and inode comparison came only in 0.12.0, or that
  no advisory covers the chmod, chown and chgrp bind-mount cases.

## Limits

- Pages were read through a summarising fetch tool, not a local clone, and no code was run. The root-check lines
  were quoted back from each tag, but a reader acting on a row should open the file once.
- `chmod` was read at 0.6.0 and 0.11.0 only, and `rm` at 0.7.0 and 0.11.0; we assume the releases in between match.
- chown and chgrp before 0.11.0 were not read.
- Nothing has been filed with GitHub's curators about these records.
