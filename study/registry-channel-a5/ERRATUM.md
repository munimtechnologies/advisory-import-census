# Erratum to A5 RESULTS.md (2026-10-19)

In the section "Per-repository visibility", the parenthetical note after the table
lists "Registry apps with few software-typed rows" and includes
`appsmithorg/appsmith`, `coollabsio/coolify` and `ToolJet/ToolJet`. In the frozen
`registry_classification.json` (2026-10-18), all three are **no_registry**. The rest of
that list (directus, synapse, firefly-iii, netbox, nocodb, open-webui) is correct.

Only that prose list is affected. A5's computed tables read groups from the frozen file
(for example, the table shows goauthentik as no_registry), so no number in A5 changes.
The error was found while writing the E1 result
([`../registry-channel-e1/RESULTS.md`](../registry-channel-e1/RESULTS.md)).

Also see A6 ([`../registry-channel-a6/RESULTS.md`](../registry-channel-a6/RESULTS.md)),
the out-of-sample test that A5 pointed to. Its pre-specified language-based contrast
(R2) found Go apps' package-less advisories 74.8% visible vs 0.2% for non-Go apps
(p = 0.0001). That fits A5's lone valid Go module (grafana, 76.9%) and supplies the
valid test A5's degenerate proxy measure could not.

Made with AI agents working for MV2 of Munim, Inc.
