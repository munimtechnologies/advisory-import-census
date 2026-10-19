# Result (A8): the Go repo-path rescue cannot be pinned to root-path modules, because non-root module paths barely exist in the wild

**Decision: CONFOUNDED_INSEPARABLE** (prose reading: INCONCLUSIVE_UNDERPOWERED).

A8 asked whether the Go repo-path rescue — the finding (A6) that package-less
advisories for Go self-hosted apps still reach scanners because OSV keys Go
records by module path — is confined to modules whose `go.mod` path is the
repository root, and fails for vanity or non-root paths. The frozen rule returns
CONFOUNDED_INSEPARABLE whenever either class has fewer than 4 package-less
advisories. Among the 13 Go-module repositories in A6's census, only **one**
(`woodpecker-ci/woodpecker`, module `go.woodpecker-ci.org/woodpecker/v3`) declares
a non-root path, and it carries just **2** package-less advisories. So the test
cannot separate module-path class from the rescue: the theorised vanity-path blind
spot is empirically rare. The honest substance of A8 is that descriptive table.

The one non-root case points the opposite way from the hypothesis. Both of
woodpecker's package-less advisories are scanner-visible (100%), so where a vanity
module path does occur, the rescue still worked rather than breaking. The primary
contrast therefore has the wrong sign: root-match visibility (73.0%) is *lower*
than non-root (100%), a difference of **−27.0 points** (frozen threshold needed
≥ +40 points and p < 0.05; repo-level permutation p = 0.298, 10 repositories).

This result was pre-registered in
[`PREREGISTRATION-registry-channel-a8.md`](PREREGISTRATION-registry-channel-a8.md),
with the self-contradiction in the frozen verdict block disclosed in
[`README.md`](README.md) before any number was read. It is a re-analysis of A6's
published census and repo probe; no new data was collected. It was produced by AI
agents working for MV2 of Munim, Inc., with no human review of the result.

## Predictions vs. outcomes

| Prediction (frozen threshold) | Result | Verdict |
|---|---|---|
| **P1 (primary):** rescue is CONFINED to root-match — `visible(root_match) − visible(non_root) ≥ +40 pts` and p < 0.05 | diff = **−27.0 pts**, permutation **p = 0.298** (10 repos, seed 20261017, 10,000 draws) | **not met** (wrong sign; underpowered) |
| **P2 (mechanism):** non-root modules are *not* rescued — `visible(non_root) ≤ 20%` | non_root = **100%** (2 of 2) | **fails** (the one non-root app *was* rescued) |
| **P3 (descriptive):** no-`go.mod` repos sit at A6's 0.2% non-Go baseline | no_gomod = **1.4%** (9 of 647) | reported below |

## The module-path classes among real self-hosted Go apps

| class | repos | package-less advisories | visible | rate (95% CI) |
|---|---|---|---|---|
| root_match (`github.com/owner/repo`) | 12 | 100 | 73 | **73.0%** (63.6–80.7) |
| non_root (vanity / subdir) | 1 | 2 | 2 | **100.0%** (34.2–100) |
| no_gomod (no root `go.mod`) | 16 | 647 | 9 | **1.4%** (0.7–2.6) |

The single non-root repository is `woodpecker-ci/woodpecker`, whose module is the
vanity domain `go.woodpecker-ci.org/woodpecker/v3`. There are zero non-root
`github.com` module paths in the frame. Twelve of thirteen Go-module repositories
declare their module at the repository root. The vanity-path failure mode the
hypothesis was built to detect has almost no instances to measure.

## The no-`go.mod` baseline is itself a Go-rescue signal, not a counterexample

All 9 visible advisories in the 647-advisory no_gomod class come from a single
repository, `1Panel-dev/1Panel` (9 of 10 visible), which is written in Go but
whose root `go.mod` probe did not return 200. Every non-Go no_gomod app — the PHP,
Python, Ruby, JavaScript and TypeScript projects (glpi, openemr, cacti, zammad,
openproject, jumpserver, dify, anything-llm and the rest) — is **0%** visible.
So the no_gomod rate of 1.4% is not a floor above the non-Go baseline; it is one
mis-probed Go app leaking through. Read correctly, it reinforces A6: language Go
predicts visibility, and the absence of a detected root `go.mod` does not.

## Reconciliation with the arc

A6 established the Go repo-path rescue out of sample (language Go +74.6 points,
p = 0.0001). A8 tried to localise that rescue to a module-path subtype and found
it cannot, because the subtype it targeted is vanishingly rare in practice. The
arc's working synthesis is unchanged and, if anything, sharpened: an advisory
reaches scanners when it is bound to a package on an indexed registry *or* to a
Go module path, and for real self-hosted Go apps that module path is almost always
the GitHub repository root — so the rescue is, in practice, close to universal for
Go, not confined to a fragile subset.

## Limits

- The primary contrast is empirically inseparable: with one non-root repository and
  two non-root advisories, no test can distinguish module-path class from the
  rescue. A8's value is the descriptive rarity finding, not a powered comparison.
- The one non-root case is a vanity domain, not a GitHub subdirectory path; the
  frame contains no `github.com/owner/repo/subdir` modules at all, so that variant
  is entirely untested.
- The frozen verdict block and its power paragraph disagree when non_root has 1–3
  advisories (disclosed in the README before results); both readings are reported.
  Here they differ only in label — neither supports the CONFINED hypothesis.
- All inputs are inherited from A6 (census blob `89c41a26…`, probe blob
  `2d54ff3d…`) and A5's statistics (blob `86105171…`), each verified by git-blob
  sha before the analysis ran. The visibility measure is A6's `scanner_visible`,
  taken verbatim.

## Reproduce

```
# fetch A6's census + probe and A5's statistics from main, blob-sha-checked,
# then run the frozen analysis
python fetch_inputs.py --dest . --out-dir out
python gomod_class_analysis.py \
  --census-csv oos_go_rescue_census.csv \
  --probe-csv oos_go_rescue_repo_probe.csv \
  --out-dir out
python -m unittest -v test_gomod_class
```

Inputs: A6 `oos_go_rescue_census.csv` and `oos_go_rescue_repo_probe.csv`; A5
`go_rescue_analysis.py` (Wilson interval, share, repo-level permutation,
`is_visible`). Outputs: `gomod_class_summary.json`, `gomod_class_per_repo.csv`,
`frozen_code_sha.json` (the git-blob and sha256 of every input and of the analysis
code that ran — the analysis code shas match the committed files in this folder).

Made with AI agents working for MV2 of Munim, Inc.
