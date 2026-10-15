#!/usr/bin/env python3
"""action_summary.py: turn a blindspot.py --json report into a GitHub Actions
job summary (Markdown) and set the step's exit code.

Reads the report path from argv[1], appends a Markdown summary to the file named
by $GITHUB_STEP_SUMMARY (when set), prints a one-line result to stdout, and exits
1 when $BLINDSPOT_FAIL_ON_BLIND is truthy and at least one blind spot was found
(so a pull request that pulls in a dependency with an unreported advisory fails
CI). Blind spots accepted with the `ignore` input are listed separately and do
not fail the job. Standard library only; the rendering is a pure function so it
is testable with no network and no GitHub runner.

Made with AI agents working for MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import sys

MAX_SUMMARY = 90


def truthy(value):
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _ident(f):
    ghsa, cve, url = f.get("ghsa_id") or "", f.get("cve_id") or "", f.get("url") or ""
    label = ghsa
    if cve:
        label = "%s / %s" % (ghsa, cve) if ghsa else cve
    label = label or "(no id)"
    return "[%s](%s)" % (label, url) if url else label


def _cell(text):
    return str(text or "").replace("|", "\\|").replace("\n", " ").strip()


def _row(f):
    summary = _cell(f.get("summary"))
    if len(summary) > MAX_SUMMARY:
        summary = summary[:MAX_SUMMARY - 1].rstrip() + "\u2026"
    note = "" if f.get("affects_your_version") == "yes" else " _(range unclear)_"
    return "| %s | `%s` | %s | %s | %s%s |" % (
        _cell(f.get("severity")) or "?", _cell(f.get("package")) or "?",
        _cell(f.get("version")) or "any", _ident(f), summary, note)


def render_markdown(report):
    findings = report.get("findings", []) or []
    blind = [f for f in findings if not f.get("scanner_visible") and not f.get("ignored")]
    accepted = [f for f in findings if not f.get("scanner_visible") and f.get("ignored")]
    visible = [f for f in findings if f.get("scanner_visible")]
    out = [
        "## Advisory blind-spot check",
        "",
        ("Dependencies checked: **%d** &middot; mapped to a GitHub repo: **%d** "
         "&middot; repos with published advisories: **%d**"
         % (report.get("dependencies_checked", 0), report.get("mapped_to_repo", 0),
            report.get("repos_with_advisories", 0))),
        "",
    ]
    header = ["| Severity | Package | Version | Advisory | Summary |",
              "|---|---|---|---|---|"]
    if blind:
        out.append("### \U0001F6A8 %d blind spot%s" % (len(blind), "" if len(blind) == 1 else "s"))
        out.append("Published by the maintainers but **not** reported by OSV for this "
                   "package/version \u2014 Dependabot, `pip-audit`, `osv-scanner` and "
                   "`npm audit` cannot alert on these.")
        out.append("")
        out += header + [_row(f) for f in blind] + [""]
    else:
        out.append("### \u2705 No blind spots")
        out.append("Every advisory that applies to your dependencies is also served by OSV%s."
                   % (" or was accepted with `ignore`" if accepted else ""))
        out.append("")
    if accepted:
        out.append("<details><summary>%d accepted blind spot%s (via `ignore`, not failing the "
                   "job)</summary>" % (len(accepted), "" if len(accepted) == 1 else "s"))
        out.append("")
        out += header + [_row(f) for f in accepted] + ["", "</details>", ""]
    if visible:
        out.append("<details><summary>%d advisory(ies) that apply and OSV does report</summary>"
                   % len(visible))
        out.append("")
        out += header + [_row(f) for f in visible] + ["", "</details>", ""]
    if report.get("unmapped"):
        names = ", ".join("`%s`" % _cell(u.get("package")) for u in report["unmapped"])
        out.append("> No GitHub repo found for %d package(s); add `map: NAME=OWNER/REPO` to "
                   "check them: %s" % (len(report["unmapped"]), names))
        out.append("")
    out.append("<sub>advisory-import-census &middot; blindspot &middot; MV2 of Munim, Inc.</sub>")
    return "\n".join(out)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: action_summary.py REPORT.json", file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as fh:
        report = json.load(fh)
    md = render_markdown(report)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(md + "\n")
    blind = report.get("blind_spots", 0)
    accepted = report.get("ignored_blind_spots", 0)
    print("blind spots: %d%s (of %d advisories that apply to %d dependencies)"
          % (blind, (" (+%d accepted)" % accepted) if accepted else "",
             report.get("advisories_that_apply", 0),
             report.get("dependencies_checked", 0)))
    if truthy(os.environ.get("BLINDSPOT_FAIL_ON_BLIND")) and blind:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
