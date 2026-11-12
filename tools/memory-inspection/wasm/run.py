#!/usr/bin/env python3
"""Build one caller-supplied source variant and scan optimized WASM memory."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--mode", required=True, choices=("clean", "control"))
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--toolchain", default="1.100.0")
    parser.add_argument("--target-dir", type=Path)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    source = args.source_root.resolve()
    report = args.report.resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    report.unlink(missing_ok=True)
    bindgen_version = subprocess.check_output(["wasm-bindgen", "--version"], text=True).strip()
    if bindgen_version != "wasm-bindgen 0.2.127":
        raise SystemExit("inspection probe requires wasm-bindgen 0.2.127 (its locked version)")
    env = os.environ.copy()
    env["RUSTUP_TOOLCHAIN"] = args.toolchain
    env["RUSTFLAGS"] = '--cfg getrandom_backend="wasm_js"'
    with tempfile.TemporaryDirectory(prefix="krusty-wasm-inspection-") as work:
        work = Path(work)
        probe = work / "probe"
        shutil.copytree(here / "probe", probe, ignore=shutil.ignore_patterns("target"))
        manifest = probe / "Cargo.toml"
        manifest.write_text(manifest.read_text().replace(
            '"../../../../crates/kms"', json.dumps(str(source / "crates/kms"))).replace(
            '"../../../../crates/common"', json.dumps(str(source / "crates/common"))))
        target = args.target_dir.resolve() if args.target_dir else work / "target"
        env["CARGO_TARGET_DIR"] = str(target)
        subprocess.run(["cargo", "build", "--manifest-path", str(manifest),
                        "--release", "--target", "wasm32-unknown-unknown", "--locked"],
                       check=True, env=env)
        artifact = target / "wasm32-unknown-unknown/release/krusty_memory_wasm_probe.wasm"
        glue = work / "glue"
        subprocess.run(["wasm-bindgen", "--target", "nodejs", "--keep-lld-exports",
                        "--out-dir", str(glue), str(artifact)], check=True)
        script = glue / "krusty_memory_wasm_probe.js"
        with script.open("a") as out:
            out.write("\nmodule.exports.__inspection_wasm = wasm;\n")
        result = subprocess.run(["node", str(here / "scan.cjs"), str(script),
                                 args.mode, str(report)], check=False)
        if report.exists():
            data = json.loads(report.read_text())
            data["build"] = {
                "rustc": subprocess.check_output(["rustc", "--version"], env=env, text=True).strip(),
                "node": subprocess.check_output(["node", "--version"], text=True).strip(),
                "wasm_bindgen": bindgen_version,
                "target": "wasm32-unknown-unknown", "profile": "release",
                "opt_level": 3, "codegen_units": 1, "lto": False,
                "memory_scope": "whole linear memory including freed heap and dead stack",
                "exclusions": "exact host input, returned phrase, or 64-byte caller seed return slot only",
            }
            report.write_text(json.dumps(data, indent=2) + "\n")
        if result.returncode:
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
