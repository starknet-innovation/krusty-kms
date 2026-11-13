#!/usr/bin/env python3
"""Run optimized memory probes against isolated clean and no-scrub sources."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


SCRUB_CALL = "    let out = run_nested(f);\n    scrub_stack();\n    out\n"
CONTROL_CALL = "    let out = run_nested(f);\n    // Inspection control only: omit the stack scrub.\n    out\n"
SCRYPT_WIPED_V = "    let mut v = Zeroizing::new(vec![0u8; nr128]);\n"
SCRYPT_CONTROL_V = "    let mut v = vec![0u8; nr128];\n"


def snapshot(source, destination, files):
    digest = hashlib.sha256()
    for name in files:
        original = source / name
        if not original.is_file():
            raise RuntimeError(f"tracked source file is missing: {name}")
        if original.is_symlink():
            raise RuntimeError(f"source snapshots do not support symlinks: {name}")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, target)
        digest.update(os.fsencode(name) + b"\0" + target.read_bytes() + b"\0")
    return digest.hexdigest()


def disable_scrub(root):
    path = root / "crates/kms/src/mnemonic.rs"
    text = path.read_text()
    if text.count(SCRUB_CALL) != 1:
        raise RuntimeError("scrubbed() changed; review the control mutation before running")
    path.write_text(text.replace(SCRUB_CALL, CONTROL_CALL, 1))


def disable_scrypt_wipe(root):
    path = root / "crates/kms/src/scrypt_wiping.rs"
    text = path.read_text()
    if text.count(SCRYPT_WIPED_V) != 1:
        raise RuntimeError("ROMix V allocation changed; review the control mutation")
    path.write_text(text.replace(SCRYPT_WIPED_V, SCRYPT_CONTROL_V, 1))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--backend", choices=["all", "native", "wasm"], default="all")
    parser.add_argument("--toolchain", default="stable")
    parser.add_argument("--report-dir", type=Path)
    args = parser.parse_args()
    source = args.source_root.resolve()
    reports = (args.report_dir or source / "target/memory-inspection").resolve()
    reports.mkdir(parents=True, exist_ok=True)
    backends = ["native", "wasm"] if args.backend == "all" else [args.backend]
    files = subprocess.check_output(["git", "-C", str(source), "ls-files", "-z"])
    files = sorted(os.fsdecode(name) for name in files.split(b"\0") if name)
    summary = {"schema_version": 1, "status": "failed", "toolchain": args.toolchain, "runs": []}
    environment = dict(os.environ)
    overrides = [
        name for name in environment
        if name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR")
        or name.startswith("CARGO_PROFILE_")
        or (name.startswith("CARGO_TARGET_") and name.endswith("_RUSTFLAGS"))
    ]
    for name in overrides:
        environment.pop(name)
    summary["cleared_build_overrides"] = sorted(overrides)
    summary["commit"] = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    try:
        with tempfile.TemporaryDirectory(prefix="krusty-memory-") as temporary:
            base = Path(temporary)
            clean = base / "clean"
            control = base / "control"
            # Copy current tracked-file contents, including staged additions. No ignored
            # credentials, user worktrees, build products, or raw memory dumps enter it.
            summary["source_sha256"] = snapshot(source, clean, files)
            if snapshot(source, control, files) != summary["source_sha256"]:
                raise RuntimeError("source changed while snapshots were being made")
            disable_scrub(control)
            disable_scrypt_wipe(control)
            for backend in backends:
                for mode, root in [("control", control), ("clean", clean)]:
                    report = reports / f"{backend}-{mode}.json"
                    report.unlink(missing_ok=True)
                    probe = root / f"tools/memory-inspection/{backend}/run.py"
                    command = [
                        sys.executable, str(probe), "--source-root", str(root),
                        "--mode", mode, "--report", str(report),
                        "--toolchain", args.toolchain,
                        "--target-dir", str(reports / "build" / backend),
                    ]
                    subprocess.run(command, check=True, env=environment)
                    result = json.loads(report.read_text())
                    if result.get("status") != "passed" or result.get("mode") != mode:
                        raise RuntimeError(f"{backend} {mode} did not report a passing probe")
                    summary["runs"].append({"backend": backend, **result})
            summary["status"] = "passed"
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        summary["error"] = str(error)
        print(f"memory inspection failed: {error}", file=sys.stderr)
    finally:
        (reports / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
