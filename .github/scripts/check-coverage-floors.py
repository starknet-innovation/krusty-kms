#!/usr/bin/env python3
"""Check line-coverage floors for named crates and source directories."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--floors", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument(
        "--base-ref",
        help="Git revision whose coverage-floor map must not be reduced",
    )
    return parser.parse_args()


def includes(path: str, scope: str) -> bool:
    return path == scope or path.startswith(f"{scope}/")


def base_floors(root: Path, floors: Path, ref: str) -> dict | None:
    try:
        relative = floors.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise RuntimeError(f"coverage floors are outside the repository: {floors}") from error

    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{ref}:{relative}"],
        cwd=root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if exists.returncode:
        return None

    result = subprocess.run(
        ["git", "show", f"{ref}:{relative}"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "could not read base coverage floors")
    return json.loads(result.stdout)


def floor_ratchet_failures(floors: dict, previous: dict) -> list[str]:
    if previous.get("metric") != "lines":
        return ["base coverage floors must use the lines metric"]

    failures = []
    for scope, previous_floor in previous["floors"].items():
        current_floor = floors["floors"].get(scope)
        if current_floor is None:
            failures.append(f"{scope}: committed coverage floor was removed")
        elif current_floor + 1e-9 < previous_floor:
            failures.append(
                f"{scope}: committed coverage floor decreased "
                f"from {previous_floor:.2f}% to {current_floor:.2f}%"
            )
    return failures


def main() -> int:
    args = parse_args()
    report = json.loads(args.report.read_text())
    floors = json.loads(args.floors.read_text())
    if floors.get("metric") != "lines":
        print("coverage floors must use the lines metric", file=sys.stderr)
        return 2

    failures = []
    if args.base_ref:
        try:
            previous_floors = base_floors(args.root, args.floors, args.base_ref)
        except RuntimeError as error:
            print(f"::error::could not load base coverage floors: {error}")
            return 1
        if previous_floors is None:
            print(f"no coverage-floor map at {args.base_ref}; establishing initial floors")
        else:
            failures.extend(floor_ratchet_failures(floors, previous_floors))

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
