#!/usr/bin/env python3
"""Count code lines inside unsafe contexts across src/.

A line is "unsafe-context" if any part of it lies inside an `unsafe fn` /
`unsafe extern "C" fn` / `unsafe impl` item (signature included) or an
`unsafe { .. }` block. Comment-only and blank lines count nowhere; string
literal contents are ignored so braces/keywords inside them can't skew the
scan. Fn-pointer *types* (`Option<unsafe extern "C" fn(..)>`) are not regions.

The number this reports is the refactoring ratchet: logic belongs in
`#![forbid(unsafe_code)]` kernels, wrappers stay thin, and CI fails if the
total ever grows past tools/unsafe_baseline.json.

Usage:
  unsafe_lines.py [--src src]                 human-readable report
  unsafe_lines.py --check tools/unsafe_baseline.json
  unsafe_lines.py --update tools/unsafe_baseline.json
"""

import argparse
import json
import re
import sys
from pathlib import Path

REGION_START = re.compile(
    r'\bunsafe\s+(?:extern\s*"[^"]*"\s*)?(?:fn|impl)\b|\bunsafe\s*\{'
)


def strip_noncode(src: str) -> str:
    """Blank out comments and string/char-literal contents, preserving newlines
    and byte-for-byte length (so offsets keep mapping to the same lines)."""
    out = []
    i, n = 0, len(src)
    mode = "code"
    depth = 0  # block-comment nesting
    hashes = 0  # raw-string fence size
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if mode == "code":
            if c == "/" and nxt == "/":
                mode = "line"
                out.append("  ")
                i += 2
                continue
            if c == "/" and nxt == "*":
                mode = "block"
                depth = 1
                out.append("  ")
                i += 2
                continue
            if c == '"':
                mode = "str"
                out.append('"')
                i += 1
                continue
            # raw strings: r"..", r#".."#, br"..", br#".."# (guard against
            # identifiers ending in b/r by requiring a non-ident predecessor)
            if c in "br" and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
                j = i + 1 if (c == "b" and nxt == "r") else i
                if j < n and src[j] == "r":
                    k = j + 1
                    h = 0
                    while k < n and src[k] == "#":
                        h += 1
                        k += 1
                    if k < n and src[k] == '"':
                        mode = "raw"
                        hashes = h
                        out.append(" " * (k - i + 1))
                        i = k + 1
                        continue
            if c == "'":
                # char literal vs lifetime: escaped form '\..' always closes,
                # plain form is exactly 'x'; anything else is a lifetime.
                if nxt == "\\":
                    k = i + 2
                    while k < n and src[k] != "'":
                        k += 1
                    out.append(" " * (min(k, n - 1) - i + 1))
                    i = k + 1
                    continue
                if i + 2 < n and src[i + 2] == "'":
                    out.append("   ")
                    i += 3
                    continue
            out.append(c)
            i += 1
            continue
        if mode == "line":
            out.append(c if c == "\n" else " ")
            if c == "\n":
                mode = "code"
            i += 1
            continue
        if mode == "block":
            if c == "/" and nxt == "*":
                depth += 1
                out.append("  ")
                i += 2
                continue
            if c == "*" and nxt == "/":
                depth -= 1
                out.append("  ")
                i += 2
                if depth == 0:
                    mode = "code"
                continue
            out.append(c if c == "\n" else " ")
            i += 1
            continue
        if mode == "str":
            if c == "\\":
                out.append("  ")
                i += 2
                continue
            if c == '"':
                mode = "code"
                out.append('"')
            else:
                out.append(c if c == "\n" else " ")
            i += 1
            continue
        # mode == "raw"
        if c == '"':
            k = i + 1
            h = 0
            while k < n and src[k] == "#" and h < hashes:
                h += 1
                k += 1
            if h == hashes:
                mode = "code"
                out.append(" " * (k - i))
                i = k
                continue
        out.append(c if c == "\n" else " ")
        i += 1
    return "".join(out)


def body_brace(text: str, pos: int):
    """From the end of an `unsafe fn`/`unsafe impl` match, find the opening
    brace of its body. Returns None for bodyless forms (trait decls) and for
    fn-pointer types (terminated by `;`/`,`/a closing bracket at depth 0)."""
    depth = 0
    i, n = pos, len(text)
    while i < n:
        c = text[i]
        if c in "(<[":
            depth += 1
        elif c == ">" and i > 0 and text[i - 1] == "-":
            pass  # `->` return arrow, not a bracket
        elif c in ")>]":
            depth -= 1
            if depth < 0:
                return None  # escaped an enclosing construct: type position
        elif c == "{" and depth == 0:
            return i
        elif c in ";," and depth <= 0:
            return None
        elif c == "}":
            return None
        i += 1
    return None


def find_regions(text: str):
    """Return [(start, end)] character ranges of unsafe contexts (outermost
    only — nested `unsafe {}` inside an unsafe fn is already covered)."""
    regions = []
    i = 0
    n = len(text)
    while True:
        m = REGION_START.search(text, i)
        if not m:
            return regions
        if m.group().endswith("{"):
            open_idx = m.end() - 1
        else:
            open_idx = body_brace(text, m.end())
            if open_idx is None:
                i = m.end()
                continue
        depth = 0
        j = open_idx
        while j < n:
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        regions.append((m.start(), j))
        i = j + 1


def measure_file(path: Path):
    src = path.read_text()
    cleaned = strip_noncode(src)
    lines = cleaned.split("\n")
    starts = []  # char offset of each line start
    off = 0
    for ln in lines:
        starts.append(off)
        off += len(ln) + 1
    flagged = [False] * len(lines)
    for a, b in find_regions(cleaned):
        first = next(k for k in range(len(starts)) if starts[k] + len(lines[k]) >= a)
        for k in range(first, len(lines)):
            if starts[k] > b:
                break
            flagged[k] = True
    code = sum(1 for ln in lines if ln.strip())
    unsafe = sum(1 for k, ln in enumerate(lines) if ln.strip() and flagged[k])
    return code, unsafe


def measure_tree(src_dir: Path):
    per_file = {}
    for path in sorted(src_dir.rglob("*.rs")):
        code, unsafe = measure_file(path)
        per_file[str(path)] = {"code": code, "unsafe": unsafe}
    total_code = sum(v["code"] for v in per_file.values())
    total_unsafe = sum(v["unsafe"] for v in per_file.values())
    return per_file, total_code, total_unsafe


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="src")
    ap.add_argument("--check", metavar="BASELINE")
    ap.add_argument("--update", metavar="BASELINE")
    args = ap.parse_args()

    per_file, total_code, total_unsafe = measure_tree(Path(args.src))

    if args.update:
        Path(args.update).write_text(
            json.dumps(
                {"total_code_lines": total_code, "unsafe_context_lines": total_unsafe},
                indent=2,
            )
            + "\n"
        )
        print(f"baseline updated: {total_unsafe} unsafe-context / {total_code} code lines")
        return 0

    if args.check:
        baseline = json.loads(Path(args.check).read_text())
        limit = baseline["unsafe_context_lines"]
        if total_unsafe > limit:
            print(
                f"unsafe ratchet FAILED: {total_unsafe} unsafe-context lines "
                f"exceeds baseline {limit} — move the logic into a "
                f"forbid(unsafe_code) kernel, or (if the marshal layer truly "
                f"grew) update tools/unsafe_baseline.json in the same commit",
                file=sys.stderr,
            )
            return 1
        print(f"unsafe ratchet OK: {total_unsafe} <= baseline {limit}")
        return 0

    width = max(len(p) for p in per_file)
    for p, v in per_file.items():
        pct = 100.0 * v["unsafe"] / v["code"] if v["code"] else 0.0
        print(f"{p:<{width}}  {v['unsafe']:>5} / {v['code']:>5}  ({pct:5.1f}%)")
    pct = 100.0 * total_unsafe / total_code if total_code else 0.0
    print(f"{'TOTAL':<{width}}  {total_unsafe:>5} / {total_code:>5}  ({pct:5.1f}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
