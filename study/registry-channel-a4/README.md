# registry-channel A4 — the real-package test

Part of the [advisory-import-census](https://github.com/munimtechnologies/advisory-import-census)
research arc on why some self-hosted applications' own security advisories never reach
the global GitHub Advisory Database that Dependabot and OSV scanners read.

**Question.** Is scanner visibility driven by whether an advisory's named package is a
**real, repo-matching registry release**, or merely by whether the advisory *names* a
package at all? A3 found that naming a package is neither confined to registry apps nor
sufficient (coollabsio/coolify names npm `coolify` yet is blind; nocodb names npm
`nocodb` and is visible). A4 measures the real-package distinction directly, from the
package registries' own metadata.

See `PREREGISTRATION-registry-channel-a4.md` for the frozen hypotheses (P1–P4),
registered **before** any A4 data was collected and before the A3 result was read.

## Files

- `PREREGISTRATION-registry-channel-a4.md` — frozen analysis plan.
- `real_package_census.py` — collector: the A1/A2/A3 visibility measure copied
  verbatim, plus the named-package parser and the registry-resolution probe
  (npm / PyPI / Packagist / RubyGems / crates.io / Go).
- `real_package_analysis.py` — P1–P4, robustness, mediation (A1 permutation machinery).
- `test_real_package.py` — offline unit tests (parser, probe, classifiers, statistics).
- `frame_apps.json`, `frame_libs.json`, `registry_classification.json` — the frozen
  A1 frame and covariate labels, reused verbatim.

## Reproduce

```
python -m unittest -v test_real_package
python -I real_package_census.py --frame-dir . --out-dir out
python -I real_package_analysis.py --csv out/real_package_census.csv \
    --classification registry_classification.json --out-dir out
```

Read-only public metadata only (GitHub advisory pages, the OSV API, and public
package-registry APIs), unauthenticated and paced, for open-access research.

Apache-2.0 (code) / CC BY 4.0 (text & data). Made with AI agents working for MV2 of
Munim, Inc. No result here has been reviewed by a human; it is reported honestly with
its limits.
