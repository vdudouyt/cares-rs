#!/usr/bin/env python3
"""Check that the cares-rs gtest port still tracks the c-ares 1.34.6 oracle.

The upstream c-ares test tree is the oracle.  This script parses the test
bodies out of both trees, compares them after removing comments, preprocessor
lines and insignificant whitespace, and fails if a test was changed, removed or
added without an explicit entry in tools/test_provenance_manifest.json.

Usage:
    python3 tools/check_test_provenance.py
    python3 tools/check_test_provenance.py --upstream /path/to/c-ares/test
    python3 tools/check_test_provenance.py --quiet

Exit status is 0 when every difference is approved, 1 otherwise.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from pathlib import Path

DEFAULT_MANIFEST = Path(__file__).with_name("test_provenance_manifest.json")
REPO_ROOT = Path(__file__).resolve().parent.parent

# Test macros used by the upstream suite.  The first two arguments are always
# the suite and test name (CONTAINED_TEST_F adds hostname/domain/files after).
TEST_MACRO_RE = re.compile(
    r"\b(TEST|TEST_F|TEST_P|CONTAINED_TEST_F|CONTAINED_TEST_P|"
    r"VIRT_NONVIRT_TEST_F)\s*\("
)


def strip_comments(source: str) -> str:
    """Remove C/C++ comments while preserving string and character literals."""
    out: list[str] = []
    i = 0
    n = len(source)
    state: str | None = None
    while i < n:
        c = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if state is None:
            if c == "/" and nxt == "/":
                i += 2
                while i < n and source[i] != "\n":
                    i += 1
                continue
            if c == "/" and nxt == "*":
                i += 2
                while i + 1 < n and not (source[i] == "*" and source[i + 1] == "/"):
                    i += 1
                i += 2
                continue
            if c in "\"'":
                state = c
                out.append(c)
                i += 1
                continue
            out.append(c)
            i += 1
        else:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(source[i + 1])
                i += 2
                continue
            if c == state:
                state = None
            i += 1
    return "".join(out)


def split_args(argstr: str) -> list[str]:
    args: list[str] = []
    cur = ""
    depth = 0
    for c in argstr:
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        if c == "," and depth == 0:
            args.append(cur.strip())
            cur = ""
        else:
            cur += c
    args.append(cur.strip())
    return args


def find_matching(source: str, start: int, open_ch: str, close_ch: str) -> int:
    depth = 1
    i = start
    while i < len(source) and depth:
        if source[i] == open_ch:
            depth += 1
        elif source[i] == close_ch:
            depth -= 1
        i += 1
    return i - 1 if depth == 0 else -1


def parse_tests(path: Path) -> dict[str, dict[str, str]]:
    """Return {suite::test: {'raw': body, 'norm': normalized body}}."""
    source = strip_comments(path.read_text(encoding="utf-8"))
    tests: dict[str, dict[str, str]] = {}
    pos = 0
    while True:
        m = TEST_MACRO_RE.search(source, pos)
        if not m:
            break
        paren_start = m.end() - 1
        paren_end = find_matching(source, paren_start + 1, "(", ")")
        if paren_end < 0:
            raise ValueError(f"unbalanced test macro in {path}")
        args = split_args(source[paren_start + 1 : paren_end])
        pos = paren_end + 1
        if len(args) < 2:
            continue
        name = f"{args[0]}::{args[1]}"
        brace_start = source.find("{", paren_end)
        if brace_start < 0:
            continue
        brace_end = find_matching(source, brace_start + 1, "{", "}")
        if brace_end < 0:
            raise ValueError(f"unbalanced test body for {name} in {path}")
        body = source[brace_start + 1 : brace_end]
        raw_lines = [
            line.strip()
            for line in body.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        normalized = re.sub(r"\s+", " ", "\n".join(raw_lines)).strip()
        tests[name] = {"raw": "\n".join(raw_lines), "norm": normalized}
        pos = brace_end + 1
    return tests


def apply_normalizations(name: str, text: str, normalizations: dict) -> str:
    for old, new in normalizations:
        text = text.replace(old, new)
    return text


def first_diff(upstream: dict[str, str], ported: dict[str, str], limit: int = 8) -> str:
    diff = list(
        difflib.unified_diff(
            upstream["raw"].splitlines(),
            ported["raw"].splitlines(),
            fromfile="upstream",
            tofile="cares-rs",
            lineterm="",
            n=1,
        )
    )
    if not diff:
        return "  (normalized bodies differ only in whitespace)"
    return "\n".join(f"    {line}" for line in diff[:limit])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="path to the approved-adaptation manifest",
    )
    parser.add_argument(
        "--upstream",
        type=Path,
        default=None,
        help="upstream c-ares test directory (overrides the manifest)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="only print failures and the final summary",
    )
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    upstream_root = args.upstream or Path(manifest["upstream_root"])
    ported_root = REPO_ROOT / manifest["ported_root"]

    if not upstream_root.is_dir():
        print(f"ERROR: upstream test tree not found: {upstream_root}", file=sys.stderr)
        return 1
    if not ported_root.is_dir():
        print(f"ERROR: ported test tree not found: {ported_root}", file=sys.stderr)
        return 1

    harness = {entry["file"]: entry["reason"] for entry in manifest["harness_files"]}
    protected = list(manifest["protected_files"])
    verbatim = set(manifest["verbatim_files"])
    excluded_files = {entry["file"]: entry for entry in manifest["excluded_upstream_files"]}
    excluded_tests = manifest["excluded_tests"]
    added_tests = manifest["added_tests"]
    body_normalizations = manifest.get("body_normalizations", {})

    failures: list[str] = []
    warnings: list[str] = []
    compared = 0
    skipped = 0
    added = 0
    checked_files = 0

    # Every upstream test source must be classified, otherwise an upstream file
    # could be dropped silently.
    for upstream_file in sorted(upstream_root.glob("*.cc")):
        name = upstream_file.name
        if not name.startswith(("ares-test", "dns-proto-test")):
            continue
        if name in harness or name in protected or name in excluded_files:
            continue
        failures.append(
            f"unclassified upstream test file: {name} (add it to protected_files, "
            "harness_files or excluded_upstream_files)"
        )

    for name in protected:
        upstream_path = upstream_root / name
        ported_path = ported_root / name
        checked_files += 1
        if not upstream_path.is_file():
            failures.append(f"{name}: missing from upstream oracle tree")
            continue
        if not ported_path.is_file():
            failures.append(f"{name}: missing from ported test tree")
            continue
        try:
            upstream_tests = parse_tests(upstream_path)
            ported_tests = parse_tests(ported_path)
        except ValueError as exc:
            failures.append(str(exc))
            continue

        if name in verbatim:
            up_text = re.sub(r"\s+", " ", strip_comments(upstream_path.read_text())).strip()
            po_text = re.sub(r"\s+", " ", strip_comments(ported_path.read_text())).strip()
            if up_text != po_text:
                failures.append(f"{name}: file is marked verbatim but differs from upstream")
            continue

        file_excludes = {
            entry["name"]: entry for entry in excluded_tests.get(name, [])
        }
        file_added = {entry["name"]: entry for entry in added_tests.get(name, [])}
        normalizations = body_normalizations.get(name, [])

        for test_name, upstream_body in sorted(upstream_tests.items()):
            if test_name not in ported_tests:
                entry = file_excludes.get(test_name)
                if entry is None:
                    failures.append(
                        f"{name}: upstream test missing without approval: {test_name}"
                    )
                else:
                    skipped += 1
                    if not args.quiet:
                        print(
                            f"  approved skip  {name}: {test_name} "
                            f"[{entry['category']}, phase {entry['phase']}]"
                        )
                continue

            compared += 1
            expected = apply_normalizations(
                test_name, upstream_body["norm"], normalizations
            )
            actual = apply_normalizations(
                test_name, ported_tests[test_name]["norm"], normalizations
            )
            if expected != actual:
                failures.append(
                    f"{name}: test body differs from upstream: {test_name}\n"
                    + first_diff(upstream_body, ported_tests[test_name])
                )

        for test_name, ported_body in sorted(ported_tests.items()):
            if test_name in upstream_tests:
                continue
            entry = file_added.get(test_name)
            if entry is None:
                failures.append(
                    f"{name}: port-only test without approval: {test_name}"
                )
            else:
                added += 1
                if not args.quiet:
                    print(
                        f"  approved add   {name}: {test_name} "
                        f"[phase {entry['phase']}]"
                    )

        for test_name in sorted(set(file_excludes) - set(upstream_tests)):
            failures.append(
                f"{name}: stale excluded_tests entry (not in upstream): {test_name}"
            )
        for test_name in sorted(set(file_added) - set(ported_tests)):
            failures.append(
                f"{name}: stale added_tests entry (test no longer ported): {test_name}"
            )

    for name, reason in sorted(harness.items()):
        checked_files += 1
        if not (ported_root / name).is_file():
            failures.append(f"{name}: approved harness file is missing ({reason})")

    for name in sorted(excluded_files):
        checked_files += 1
        if not (upstream_root / name).is_file():
            warnings.append(f"excluded upstream file does not exist upstream: {name}")

    print()
    if failures:
        print(f"PROVENANCE FAILED: {len(failures)} unapproved difference(s)")
        for failure in failures:
            print(f"  FAIL {failure}")
        print()
        print(
            f"checked {checked_files} files, {compared} test bodies, "
            f"{skipped} approved skips, {added} approved additions, "
            f"{len(failures)} failures"
        )
        return 1

    for warning in warnings:
        print(f"  warning: {warning}")
    print(
        f"PROVENANCE OK: checked {checked_files} files, {compared} test bodies, "
        f"{skipped} approved skips, {added} approved additions, "
        f"{len(harness)} approved harness files, "
        f"{len(excluded_files)} excluded upstream files"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
