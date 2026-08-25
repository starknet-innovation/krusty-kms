#!/usr/bin/env python3
"""Ratchet oversized Rust function spans against a committed baseline."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path


FUNCTION = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern(?:\s+\"[^\"]+\")?\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path(".github/guardrails/function-size-baseline.json"),
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--write-baseline", action="store_true")
    return parser.parse_args()


def brace_delta(line: str) -> int:
    code = line.split("//", 1)[0]
    return code.count("{") - code.count("}")


def function_spans(root: Path) -> dict[str, int]:
    spans: dict[str, int] = {}
    names: defaultdict[tuple[str, str], int] = defaultdict(int)
    for path in sorted(root.glob("crates/**/src/**/*.rs")):
        if "/experimental/" in path.as_posix():
            continue
        lines = path.read_text().splitlines()
        relative = path.relative_to(root).as_posix()
        for start, line in enumerate(lines):
            match = FUNCTION.match(line)
            if not match:
                continue
            name = match.group(1)
            names[(relative, name)] += 1
            key = f"{relative}::{name}#{names[(relative, name)]}"
            balance = 0
            saw_body = False
            end = start
            for end in range(start, len(lines)):
                code = lines[end].split("//", 1)[0]
                balance += brace_delta(code)
                saw_body = saw_body or "{" in code
                if saw_body and balance <= 0:
                    break
            spans[key] = end - start + 1
    return spans


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
        write_baseline(args.baseline, spans, 80)
        return 0

    baseline = json.loads(args.baseline.read_text())
    soft_limit = baseline["soft_limit"]
    allowed = baseline["functions"]
    failures = []
    for key, span in sorted(spans.items()):
        if span <= soft_limit:
            continue
        previous = allowed.get(key)
        if previous is None:
            failures.append(f"new oversized function {key} is {span} lines (limit {soft_limit})")
        elif span > previous:
            failures.append(f"{key} grew from {previous} to {span} lines")
    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1
    print(f"function-size ratchet passed ({len(allowed)} tracked functions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
