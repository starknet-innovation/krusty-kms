#!/usr/bin/env python3
"""Ratchet oversized Rust function spans against a committed baseline."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from lib.rust_scanner import RustBraceScanner


SOFT_LIMIT = 80
FUNCTION = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:const\s+)?(?:unsafe\s+)?(?:extern(?:\s+\"[^\"]+\")?\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path(".github/guardrails/function-size-baseline.json"),
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--base-ref",
        help="Git revision whose source function spans form the ratchet baseline",
    )
    parser.add_argument("--write-baseline", action="store_true")
    return parser.parse_args()


def is_rust_source(relative: str) -> bool:
    return relative.startswith("crates/") and relative.endswith(".rs") and not relative.startswith(
        "crates/experimental/"
    )


def function_spans_from_sources(sources: list[tuple[str, str]]) -> dict[str, int]:
    spans: dict[str, int] = {}
    names: defaultdict[tuple[str, str], int] = defaultdict(int)
    for relative, source in sources:
        lines = source.splitlines()
        for start, line in enumerate(lines):
            match = FUNCTION.match(line)
            if not match:
                continue
            name = match.group(1)
            names[(relative, name)] += 1
            key = f"{relative}::{name}#{names[(relative, name)]}"
            balance = 0
            saw_body = False
            saw_parameters = False
            parentheses = 0
            brackets = 0
            angles = 0
            const_argument_braces = 0
            scanner = RustBraceScanner()
            end = start
            for end in range(start, len(lines)):
                delta, structural_tokens = scanner.scan_line(lines[end])
                for token in structural_tokens:
                    if token == "(":
                        saw_parameters = True
                        parentheses += 1
                    elif token == ")" and parentheses:
                        parentheses -= 1
                    elif token == "[":
                        brackets += 1
                    elif token == "]" and brackets:
                        brackets -= 1
                    elif token == "<":
                        angles += 1
                    elif token == ">" and angles and not const_argument_braces:
                        angles -= 1
                    elif token == "{" and angles:
                        const_argument_braces += 1
                    elif token == "}" and const_argument_braces:
                        const_argument_braces -= 1
                    elif (
                        token == "{"
                        and saw_parameters
                        and not parentheses
                        and not brackets
                        and not angles
                    ):
                        saw_body = True
                balance += delta
                if saw_body and balance <= 0:
                    break
            spans[key] = end - start + 1
    return spans


def function_spans(root: Path) -> dict[str, int]:
    sources = [
        (path.relative_to(root).as_posix(), path.read_text())
        for path in sorted(root.glob("crates/**/*.rs"))
        if is_rust_source(path.relative_to(root).as_posix())
    ]
    return function_spans_from_sources(sources)


def git_output(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "git command failed")
    return result.stdout


def function_spans_at_ref(root: Path, ref: str) -> dict[str, int]:
    paths = git_output(root, "ls-tree", "-r", "--name-only", ref, "--", "crates").splitlines()
    sources = [
        (relative, git_output(root, "show", f"{ref}:{relative}"))
        for relative in paths
        if is_rust_source(relative)
    ]
    return function_spans_from_sources(sources)


def write_baseline(path: Path, spans: dict[str, int], soft_limit: int) -> None:
    tracked = {key: span for key, span in spans.items() if span > soft_limit}
    baseline = {
        "version": 1,
        "soft_limit": soft_limit,
        "notes": "Existing functions over the soft limit. They cannot grow; new functions must stay at or below the limit.",
        "functions": dict(sorted(tracked.items())),
    }
    path.write_text(json.dumps(baseline, indent=2) + "\n")
    print(f"updated {path} ({len(tracked)} oversized functions)")


def main() -> int:
    args = parse_args()
    spans = function_spans(args.root)
    if args.write_baseline:
        write_baseline(args.baseline, spans, SOFT_LIMIT)
        return 0

    baseline = json.loads(args.baseline.read_text())
    if baseline["soft_limit"] != SOFT_LIMIT:
        print(f"::error::expected function soft limit {SOFT_LIMIT}")
        return 1

    try:
        allowed = (
            function_spans_at_ref(args.root, args.base_ref)
            if args.base_ref
            else baseline["functions"]
        )
    except RuntimeError as error:
        print(f"::error::could not load base revision {args.base_ref}: {error}")
        return 1

    failures = []
    for key, span in sorted(spans.items()):
        if span <= SOFT_LIMIT:
            continue
        previous = allowed.get(key)
        if previous is None:
            failures.append(f"new oversized function {key} is {span} lines (limit {SOFT_LIMIT})")
        elif previous <= SOFT_LIMIT:
            failures.append(f"{key} crossed the {SOFT_LIMIT}-line limit ({previous} to {span})")
        elif span > previous:
            failures.append(f"{key} grew from {previous} to {span} lines")
    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1
    source = f"{args.base_ref} source" if args.base_ref else "committed baseline"
    print(f"function-size ratchet passed against {source}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
