#!/usr/bin/env python3
"""Check line-coverage floors for named crates and source directories."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--floors", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    return parser.parse_args()


def includes(path: str, scope: str) -> bool:
    return path == scope or path.startswith(f"{scope}/")


def main() -> int:
    args = parse_args()
    report = json.loads(args.report.read_text())
    floors = json.loads(args.floors.read_text())
    if floors.get("metric") != "lines":
        print("coverage floors must use the lines metric", file=sys.stderr)
        return 2

    files = report["data"][0]["files"]
    relative_files = []
    for entry in files:
        filename = Path(entry["filename"])
        try:
            relative = filename.relative_to(args.root).as_posix()
        except ValueError:
            continue
        lines = entry["summary"]["lines"]
        relative_files.append((relative, lines["covered"], lines["count"]))

    failures = []
    for scope, floor in floors["floors"].items():
        covered = total = 0
        for path, file_covered, file_total in relative_files:
            if includes(path, scope):
                covered += file_covered
                total += file_total
        if not total:
            failures.append(f"{scope}: no instrumented source files")
            continue
        percent = covered * 100 / total
        print(f"{scope}: {percent:.2f}% ({covered}/{total}), floor {floor:.2f}%")
        if percent + 1e-9 < floor:
            failures.append(f"{scope}: {percent:.2f}% is below {floor:.2f}%")

    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
