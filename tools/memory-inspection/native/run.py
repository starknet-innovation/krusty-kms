#!/usr/bin/env python3
"""Build and inspect one source snapshot; the parent runner owns control mutation."""
import argparse
import json
import os
import platform
from pathlib import Path
import re
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--mode", required=True, choices=("clean", "control"))
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--target-dir", type=Path)
    parser.add_argument("--toolchain", default=os.environ.get("RUSTUP_TOOLCHAIN", "stable"))
    args = parser.parse_args()
    report = {"backend": "native", "status": "failed", "mode": args.mode,
              "platform": platform.system(), "architecture": platform.machine(),
              "toolchain": args.toolchain, "profile": "release", "opt_level": 3,
              "snapshot_bytes": 65536, "protected_scrub_bytes": 32768,
              "iterations": 4, "operations": ["encode", "validate", "seed"],
              "records": []}
    try:
        if platform.system() not in ("Darwin", "Linux") or platform.machine() not in (
                "arm64", "aarch64", "x86_64", "AMD64"):
            raise RuntimeError("unsupported OS/architecture; inspection was not run")
        root = args.source_root.resolve(strict=True)
        manifest = root / "tools/memory-inspection/native/Cargo.toml"
        target = (args.target_dir or manifest.parent / "target").resolve()
        report["rustc"] = subprocess.check_output(
            ["rustup", "run", args.toolchain, "rustc", "-vV"], text=True).strip()
        report["cc"] = subprocess.check_output(["cc", "--version"], text=True).splitlines()[0]
        subprocess.run(["rustup", "run", args.toolchain, "cargo", "build", "--release",
                        "--locked", "--manifest-path", str(manifest),
                        "--target-dir", str(target)], check=True, timeout=900)
        run = subprocess.run([str(target / "release/krusty-native-memory-inspection"), args.mode],
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        expression = re.compile(r"native operation=(\d) iteration=(\d) entropy_bytes=(\d+) "
                                r"pattern=(\w+) hits=(\d+)")
        for line in run.stdout.splitlines():
            match = expression.fullmatch(line)
            if match:
                operation, iteration, entropy_bytes, pattern, hits = match.groups()
                report["records"].append({"operation": report["operations"][int(operation)],
                    "iteration": int(iteration), "entropy_bytes": int(entropy_bytes),
                    "pattern": pattern, "hits": int(hits)})
        if run.returncode != 0:
            # All harness assertions use static messages and never format secrets.
            raise RuntimeError(f"inspection exited {run.returncode}: {run.stderr.strip()}")
        expected = { (op, iteration, pattern)
            for op in report["operations"] for iteration in range(4)
            for pattern in ("entropy", "entropy_bits", "word_indices", "seed", "hmac_ipad") }
        actual = {(row["operation"], row["iteration"], row["pattern"]) for row in report["records"]}
        if len(report["records"]) != len(expected) or actual != expected:
            raise RuntimeError("incomplete or duplicate inspection records")
        if not run.stdout.rstrip().endswith(
                f"native result=pass mode={args.mode} iterations=4 scanned_bytes=65536"):
            raise RuntimeError("missing successful inspection terminator")
        report["status"] = "passed"
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("backend", "status", "mode")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
