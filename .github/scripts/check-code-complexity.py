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


SOFT_LIMIT = 80
FUNCTION = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:const\s+)?(?:unsafe\s+)?(?:extern(?:\s+\"[^\"]+\")?\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)
RAW_STRING_START = re.compile(r'(?:br|rb|r)(?P<hashes>#{0,})"')
CHAR_LITERAL = re.compile(
    r"'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|.)|[^\\'\r\n])'"
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


class RustBraceScanner:
    """Count structural braces while preserving lexical state across source lines."""

    def __init__(self) -> None:
        self.block_comment_depth = 0
        self.in_string = False
        self.string_escape = False
        self.raw_string_hashes: int | None = None

    def scan_line(self, line: str) -> tuple[int, int]:
        delta = 0
        opens = 0
        index = 0
        while index < len(line):
            if self.block_comment_depth:
                if line.startswith("/*", index):
                    self.block_comment_depth += 1
                    index += 2
                elif line.startswith("*/", index):
                    self.block_comment_depth -= 1
                    index += 2
                else:
                    index += 1
                continue

            if self.raw_string_hashes is not None:
                terminator = '"' + "#" * self.raw_string_hashes
                if line.startswith(terminator, index):
                    self.raw_string_hashes = None
                    index += len(terminator)
                else:
                    index += 1
                continue

            if self.in_string:
                char = line[index]
                if self.string_escape:
                    self.string_escape = False
                elif char == "\\":
                    self.string_escape = True
                elif char == '"':
                    self.in_string = False
                index += 1
                continue

            if line.startswith("//", index):
                break
            if line.startswith("/*", index):
                self.block_comment_depth = 1
                index += 2
                continue

            raw_string = RAW_STRING_START.match(line, index)
            if raw_string:
                self.raw_string_hashes = len(raw_string.group("hashes"))
                index = raw_string.end()
                continue

            char = line[index]
            if char == '"':
                self.in_string = True
                index += 1
                continue
            if char == "'":
                char_literal = CHAR_LITERAL.match(line, index)
                if char_literal:
                    index = char_literal.end()
                    continue
            if char == "{":
                delta += 1
                opens += 1
            elif char == "}":
                delta -= 1
            index += 1
        return delta, opens


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
            scanner = RustBraceScanner()
            end = start
            for end in range(start, len(lines)):
                delta, opens = scanner.scan_line(lines[end])
                balance += delta
                saw_body = saw_body or opens > 0
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
