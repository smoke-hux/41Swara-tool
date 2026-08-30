#!/usr/bin/env python3
"""Accuracy-regression comparison for the 41Swara scanner benchmark harness.

Invoked by ``scripts/benchmark.sh``; not intended to be run directly.

Reads the raw JSON the scanner emitted for each corpus, aggregates per-category
and per-file finding counts, compares them against the committed baseline, and
decides whether the run is a regression.

Exit codes
----------
0   no regression
1   regression detected (false-positive drift, or a lost detection)
2   usage / input error

Only the Python standard library is used -- the harness must not add a
dependency to the project.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = 1

# ``// EXPECT: Category`` or ``// EXPECT: CatA, CatB`` in a vuln-corpus file.
EXPECT_RE = re.compile(r"^\s*//\s*EXPECT:\s*(.+?)\s*$")


# ---------------------------------------------------------------------------
# Parsing the scanner's output
# ---------------------------------------------------------------------------


def extract_json_object(raw: str) -> dict[str, Any]:
    """Pull the first complete JSON object out of the scanner's stdout.

    The scanner prints its JSON report to stdout, but banners or warnings may
    precede it depending on flags, so we locate the first ``{`` that begins a
    decodable object rather than assuming the stream is pure JSON.
    """
    decoder = json.JSONDecoder()
    for index, char in enumerate(raw):
        if char != "{":
            continue
        try:
            obj, _ = decoder.raw_decode(raw[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    raise ValueError("no JSON object found in scanner output")


def summarise(raw_path: str, corpus_dir: str) -> dict[str, Any]:
    """Aggregate one scanner JSON report into category / per-file counts."""
    with open(raw_path, "r", encoding="utf-8") as handle:
        report = extract_json_object(handle.read())

    categories: dict[str, int] = {}
    per_file: dict[str, int] = {}
    per_file_categories: dict[str, list[str]] = {}
    severities: dict[str, int] = {}
    total = 0

    for entry in report.get("results", []):
        rel = os.path.relpath(entry.get("file", ""), corpus_dir)
        vulns = entry.get("vulnerabilities") or []
        per_file[rel] = len(vulns)
        seen: set[str] = set()
        for vuln in vulns:
            category = category_name(vuln.get("category"))
            categories[category] = categories.get(category, 0) + 1
            severity = str(vuln.get("severity", "Unknown"))
            severities[severity] = severities.get(severity, 0) + 1
            seen.add(category)
            total += 1
        per_file_categories[rel] = sorted(seen)

    # A file the scanner skipped entirely still belongs in the summary at 0, so
    # that deleting a detection and deleting a file look different.
    for name in sorted(os.listdir(corpus_dir)):
        if name.endswith(".sol"):
            per_file.setdefault(name, 0)
            per_file_categories.setdefault(name, [])

    return {
        "files": len(per_file),
        "total": total,
        "categories": dict(sorted(categories.items())),
        "severities": dict(sorted(severities.items())),
        "per_file": dict(sorted(per_file.items())),
        "per_file_categories": dict(sorted(per_file_categories.items())),
    }


def category_name(category: Any) -> str:
    """Normalise a serialised ``VulnerabilityCategory`` to a plain string.

    Unit-like variants serialise as a bare string; if a variant ever gains
    fields it would serialise as a single-key object, so handle that too rather
    than silently bucketing everything under ``Unknown``.
    """
    if isinstance(category, str):
        return category
    if isinstance(category, dict) and len(category) == 1:
        return next(iter(category))
    return "Unknown"


def read_expectations(corpus_dir: str) -> dict[str, list[str]]:
    """Read the ``// EXPECT: <Category>`` declarations from a vuln corpus.

    The marker must appear in the file's leading comment block (the first 15
    lines), so that a stray ``EXPECT`` deeper in a contract body cannot
    accidentally become a test expectation.
    """
    expectations: dict[str, list[str]] = {}
    for name in sorted(os.listdir(corpus_dir)):
        if not name.endswith(".sol"):
            continue
        found: list[str] = []
        with open(os.path.join(corpus_dir, name), "r", encoding="utf-8") as handle:
            for lineno, line in enumerate(handle):
                if lineno >= 15:
                    break
                match = EXPECT_RE.match(line)
                if match:
                    found.extend(
                        part.strip() for part in match.group(1).split(",") if part.strip()
                    )
        expectations[name] = found
    return expectations


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def diff_rows(baseline: dict[str, int], current: dict[str, int]) -> list[tuple[str, int, int, int]]:
    rows = []
    for key in sorted(set(baseline) | set(current)):
        before = baseline.get(key, 0)
        after = current.get(key, 0)
        rows.append((key, before, after, after - before))
    return rows


def render_table(title: str, rows: list[tuple[str, int, int, int]], stream) -> None:
    print(f"\n{title}", file=stream)
    if not rows:
        print("  (no findings on either side)", file=stream)
        return
    width = max(len("CATEGORY"), max(len(r[0]) for r in rows))
    print(
        f"  {'CATEGORY'.ljust(width)}  {'BASE':>6}  {'CURRENT':>7}  {'DELTA':>6}",
        file=stream,
    )
    print(f"  {'-' * width}  {'-' * 6}  {'-' * 7}  {'-' * 6}", file=stream)
    for name, before, after, delta in rows:
        if delta == 0:
            marker = "   "
            shown = "0"
        elif delta > 0:
            marker = " ^ "
            shown = f"+{delta}"
        else:
            marker = " v "
            shown = str(delta)
        print(
            f"  {name.ljust(width)}  {before:>6}  {after:>7}  {shown:>6}{marker}",
            file=stream,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clean-raw", required=True, help="scanner JSON for the clean corpus")
    parser.add_argument("--vuln-raw", required=True, help="scanner JSON for the vuln corpus")
    parser.add_argument("--clean-dir", required=True)
    parser.add_argument("--vuln-dir", required=True)
    parser.add_argument("--baseline", required=True, help="path to baseline.json")
    parser.add_argument("--scanner-version", default="unknown")
    parser.add_argument("--min-severity", default="low")
    parser.add_argument("--tolerance", type=int, default=None,
                        help="allowed increase in total clean-corpus findings")
    parser.add_argument("--update-baseline", action="store_true")
    parser.add_argument("--json", action="store_true", help="machine-readable output on stdout")
    args = parser.parse_args()

    # Human-readable narration goes to stderr in --json mode so that stdout
    # stays a single parseable document.
    out = sys.stderr if args.json else sys.stdout

    try:
        clean = summarise(args.clean_raw, args.clean_dir)
        vuln = summarise(args.vuln_raw, args.vuln_dir)
    except (OSError, ValueError) as exc:
        print(f"error: could not read scanner output: {exc}", file=sys.stderr)
        return 2

    expectations = read_expectations(args.vuln_dir)

    # --- false negatives: an expected category vanished from its file --------
    false_negatives = []
    for name, expected in sorted(expectations.items()):
        if not expected:
            false_negatives.append({"file": name, "missing": ["<no EXPECT declared>"]})
            continue
        observed = set(vuln["per_file_categories"].get(name, []))
        missing = [category for category in expected if category not in observed]
        if missing:
            false_negatives.append({"file": name, "missing": missing})

    current = {
        "schema_version": SCHEMA_VERSION,
        "generated_by": "scripts/benchmark.sh",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scanner_version": args.scanner_version,
        "scan_options": {"min_severity": args.min_severity},
        "tolerance": {"clean_total_increase": args.tolerance if args.tolerance is not None else 0},
        "clean": clean,
        "vuln": vuln,
    }

    if args.update_baseline:
        if false_negatives:
            print(
                "refusing to write a baseline while the vuln corpus has unmet "
                "expectations -- fix the EXPECT declarations or the detection first:",
                file=sys.stderr,
            )
            for item in false_negatives:
                print(f"  {item['file']}: missing {', '.join(item['missing'])}", file=sys.stderr)
            return 2
        os.makedirs(os.path.dirname(os.path.abspath(args.baseline)), exist_ok=True)
        with open(args.baseline, "w", encoding="utf-8") as handle:
            json.dump(current, handle, indent=2, sort_keys=False)
            handle.write("\n")
        print(f"baseline written: {args.baseline}", file=out)
        print(
            f"  clean: {clean['total']} findings over {clean['files']} files\n"
            f"  vuln:  {vuln['total']} findings over {vuln['files']} files",
            file=out,
        )
        if args.json:
            json.dump({"status": "baseline-updated", "baseline": current}, sys.stdout, indent=2)
            sys.stdout.write("\n")
        return 0

    try:
        with open(args.baseline, "r", encoding="utf-8") as handle:
            baseline = json.load(handle)
    except OSError as exc:
        print(
            f"error: baseline not found at {args.baseline} ({exc}).\n"
            f"       Generate it deliberately with: scripts/benchmark.sh --update-baseline",
            file=sys.stderr,
        )
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: baseline is not valid JSON: {exc}", file=sys.stderr)
        return 2

    base_clean = baseline.get("clean", {})
    base_vuln = baseline.get("vuln", {})
    tolerance = args.tolerance
    if tolerance is None:
        tolerance = int(baseline.get("tolerance", {}).get("clean_total_increase", 0))

    failures: list[str] = []
    warnings: list[str] = []

    base_options = baseline.get("scan_options", {})
    if base_options.get("min_severity", args.min_severity) != args.min_severity:
        failures.append(
            f"scan options differ from the baseline: baseline was recorded at "
            f"--min-severity {base_options.get('min_severity')}, this run used "
            f"--min-severity {args.min_severity}. Counts are not comparable."
        )
    if baseline.get("scanner_version") != args.scanner_version:
        warnings.append(
            f"scanner version changed since the baseline "
            f"({baseline.get('scanner_version')} -> {args.scanner_version})"
        )

    # --- rule 1: false-positive drift on the clean corpus ---------------------
    clean_base_total = int(base_clean.get("total", 0))
    clean_delta = clean["total"] - clean_base_total
    if clean_delta > tolerance:
        failures.append(
            f"FALSE POSITIVE DRIFT: clean corpus went from {clean_base_total} to "
            f"{clean['total']} findings (+{clean_delta}, tolerance +{tolerance}). "
            f"Every finding on the clean corpus is a suspected false positive."
        )
    elif clean_delta > 0:
        warnings.append(
            f"clean corpus findings rose by {clean_delta} (within the +{tolerance} tolerance)"
        )
    elif clean_delta < 0:
        warnings.append(
            f"clean corpus findings FELL by {-clean_delta} -- a false-positive fix. "
            f"Re-run with --update-baseline to lock the improvement in."
        )

    # --- rule 2: a planted vulnerability stopped being detected --------------
    for item in false_negatives:
        failures.append(
            f"FALSE NEGATIVE: {item['file']} expects {', '.join(item['missing'])} "
            f"but the scanner did not report it"
        )

    # --- rule 3: a category the baseline detected went to zero ---------------
    for category, count in sorted(base_vuln.get("categories", {}).items()):
        if count > 0 and vuln["categories"].get(category, 0) == 0:
            failures.append(
                f"LOST DETECTION: category {category} had {count} findings on the "
                f"vuln corpus in the baseline and now has 0"
            )

    vuln_delta = vuln["total"] - int(base_vuln.get("total", 0))
    if vuln_delta < 0:
        warnings.append(
            f"vuln corpus findings fell by {-vuln_delta} -- check this is intentional"
        )

    # --- report --------------------------------------------------------------
    print("=" * 72, file=out)
    print("41Swara accuracy regression report", file=out)
    print("=" * 72, file=out)
    print(f"scanner version : {args.scanner_version}", file=out)
    print(f"baseline        : {args.baseline}", file=out)
    print(f"baseline taken  : {baseline.get('generated_at', 'unknown')}", file=out)
    print(f"min-severity    : {args.min_severity}", file=out)
    print(f"clean tolerance : +{tolerance} total findings", file=out)

    render_table(
        f"CLEAN CORPUS  (every finding is a suspected FALSE POSITIVE)   "
        f"total {clean_base_total} -> {clean['total']}",
        diff_rows(base_clean.get("categories", {}), clean["categories"]),
        out,
    )
    render_table(
        f"VULN CORPUS   (a missing finding is a FALSE NEGATIVE)         "
        f"total {base_vuln.get('total', 0)} -> {vuln['total']}",
        diff_rows(base_vuln.get("categories", {}), vuln["categories"]),
        out,
    )

    clean_file_rows = [
        row
        for row in diff_rows(base_clean.get("per_file", {}), clean["per_file"])
        if row[3] != 0
    ]
    if clean_file_rows:
        render_table("CLEAN CORPUS -- files whose count changed", clean_file_rows, out)

    if warnings:
        print("\nWARNINGS", file=out)
        for warning in warnings:
            print(f"  ! {warning}", file=out)

    if failures:
        print("\nREGRESSIONS", file=out)
        for failure in failures:
            print(f"  x {failure}", file=out)
        print(
            "\nRESULT: FAIL\n"
            "  Fix the rule that caused the drift. Updating the baseline is a\n"
            "  deliberate, reviewed act -- never a way to silence a regression.\n"
            "  See docs/BENCHMARKING.md.",
            file=out,
        )
    else:
        print("\nRESULT: PASS -- no accuracy regression against the baseline.", file=out)

    if args.json:
        json.dump(
            {
                "status": "fail" if failures else "pass",
                "scanner_version": args.scanner_version,
                "min_severity": args.min_severity,
                "tolerance": tolerance,
                "failures": failures,
                "warnings": warnings,
                "false_negatives": false_negatives,
                "clean": {
                    "baseline_total": clean_base_total,
                    "current_total": clean["total"],
                    "delta": clean_delta,
                    "categories": clean["categories"],
                    "per_file": clean["per_file"],
                },
                "vuln": {
                    "baseline_total": base_vuln.get("total", 0),
                    "current_total": vuln["total"],
                    "delta": vuln_delta,
                    "categories": vuln["categories"],
                    "per_file": vuln["per_file"],
                },
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
