# registry-channel A3 — the attribution mechanism

Pre-registered test of **why** self-hosted applications that publish their code to a
package registry are less "scanner-blind" than Docker/binary-only apps. The earlier
studies (H1 app-vs-library; A2 same-sample; A1 out-of-sample, −58.2 pts, p=0.0017)
showed **that** the registry covariate predicts whether an app's own security
advisories reach OSV-based scanners. A3 asks whether the mechanism is **attribution**:
an advisory reaches scanners only when GitHub reviews it into a package-scoped record,
which GitHub only does when the advisory **names an affected package in a registry
ecosystem** (rendered as a "Package" box with an `ecosystem:…` link, versus a
"Software" box with a generic product name).

This directory is the frozen study package:

- `PREREGISTRATION-registry-channel-a3.md` — hypotheses P1–P4 and robustness,
  registered **before** any A3 data was collected.
- `registry_classification.json`, `frame_apps.json`, `frame_libs.json` — the frozen
  32-application frame and registry classification, reused verbatim from A1.
- `attribution_census.py` — the A1 collector plus one read-only field per advisory:
  its product type (`package` / `software` / `other`) from the public advisory page.
- `attribution_analysis.py` — P1 (within-repository attribution→visibility
  permutation), P2 (registry→attribution first stage), P3 (mediation), P4 (residual
  slack), with robustness R1–R3.
- `test_attribution.py` — deterministic unit tests for the parser and statistics.

`RESULTS.md` is added once the collector + analysis run, reporting the outcome
honestly whichever way it falls (a clean null counts).

Visibility is scored exactly as in A1/A2 (code copied verbatim). The work is made
with AI agents working for MV2 of Munim, Inc. Apache-2.0 (code) / CC BY 4.0 (text).
