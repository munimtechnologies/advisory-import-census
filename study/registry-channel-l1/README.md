# L1 — review lag vs a permanent gap

Re-analysis of A4's real-package census. The arc finds that a self-hosted app's own
security advisories reach scanners far less often when the app does not ship through a
package registry. L1 asks whether that blind spot is just **import lag** — GitHub has
not yet imported the *recent* advisories, and old ones catch up — or a **permanent**
structural gap. Plan: [`PREREGISTRATION-registry-channel-l1.md`](PREREGISTRATION-registry-channel-l1.md).

| file | what it is |
|---|---|
| `fetch_inputs.py` | downloads A4's census + classification and A5's statistics module from `main`, checks each git blob sha against the committed one, and hashes the analysis code that runs beside them |
| `age_lag_analysis.py` | the pre-registered analysis: age bins, the within-repo permutation for P1, the old-bin registry gap for P2 (A5's repo-level permutation), per-cell Wilson CIs, and the verdict |
| `test_age_lag.py` | offline unit tests of L1's own code (binning, within-repo permutation, verdict, loaders, per-repo table); they do not need A5's module |

The within-repo permutation for P1 shuffles each repository's own young/old labels among
that repository's young and old advisories, so the null holds every repo's bin sizes and
visible counts fixed and asks only whether old advisories are more visible than young
ones *within the same project*. A repository with advisories in only one bin keeps its
rows in the pooled rates but contributes nothing to the null spread.

Reproduce: `python fetch_inputs.py --dest . --out-dir out && python age_lag_analysis.py --census-csv real_package_census.csv --classification registry_classification.json --out-dir out`

Verdict rule (frozen): INCONCLUSIVE_UNDERPOWERED if the no_registry young or old bin has
fewer than 20 advisories or fewer than 3 repos have both bins; else LAG if
`visible(old) − visible(young) ≥ +15 pts` within no_registry and the within-repo
permutation `p < 0.05`; else PERMANENT if that difference is `< +15 pts` and the old-bin
registry gap holds (`≥ +25 pts`, repo-level `p < 0.05`); else MIXED. LAG would falsify
the arc's "structural blind spot" reading; PERMANENT supports it.

Apache-2.0 (code) / CC BY 4.0 (text & data). Made with AI agents working for MV2 of
Munim, Inc. No result here has been reviewed by a human.
