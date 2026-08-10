"""Shared helpers for guardrail surface extraction and file-size scans."""

from __future__ import annotations

import json
import re
from pathlib import Path

SOFT_LIMIT_DEFAULT = 350
HARD_NEW_DEFAULT = 500


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_baseline(path: Path | None = None) -> dict:
    baseline_path = path or (repo_root() / ".github/guardrails/file-size-baseline.json")
    return json.loads(baseline_path.read_text())


def soft_limit(baseline: dict | None = None) -> int:
    data = baseline if baseline is not None else load_baseline()
    return int(data.get("soft_limit", SOFT_LIMIT_DEFAULT))


def hard_new_limit(baseline: dict | None = None) -> int:
    data = baseline if baseline is not None else load_baseline()
    return int(data.get("hard_limit_new_files", HARD_NEW_DEFAULT))


def oversized_rust_files(root: Path | None = None, min_lines: int | None = None) -> list[dict]:
    root = root or repo_root()
    threshold = soft_limit() if min_lines is None else min_lines
    rows: list[dict] = []
    for path in sorted((root / "crates").rglob("*.rs")):
        if "target" in path.parts:
            continue
        n = sum(1 for _ in path.open("rb"))
        if n >= threshold:
            rows.append({"path": str(path.relative_to(root)), "lines": n})
    return rows


def extract_wasm_exports(root: Path | None = None) -> list[str]:
    root = root or repo_root()
    exports: list[str] = []
    for path in sorted((root / "crates/wasm/src").rglob("*.rs")):
        lines = path.read_text().splitlines()
        i = 0
        while i < len(lines):
            if "#[wasm_bindgen" in lines[i] and "wasm_bindgen_test" not in lines[i]:
                j = i
                while j < len(lines) and not re.match(
                    r"^\s*(pub\s+)?(async\s+)?(unsafe\s+)?(fn|struct|enum|type|const|static)\b",
                    lines[j],
                ) and not re.match(r"^\s*impl\b", lines[j]):
                    j += 1
                if j < len(lines):
                    attrs = "\n".join(lines[i : j + 1])
                    m = re.search(r'js_name\s*=\s*"([^"]+)"', attrs)
                    name = m.group(1) if m else lines[j].strip()
                    exports.append(f"{path.relative_to(root)}: {name}")
                i = j + 1
            else:
                i += 1
    return exports


_KRUSTY_DEP = re.compile(r"^(krusty-kms(?:-[a-z0-9-]+)?)\s*=")
_KRUSTY_TABLE = re.compile(r"^\[(?:.*\.)?dependencies\.(krusty-kms(?:-[a-z0-9-]+)?)\]")


def krusty_deps_from_cargo_toml(text: str) -> set[str]:
    """Collect krusty-* deps from [dependencies] / target.*.dependencies (not dev/build)."""
    deps: set[str] = set()
    sections = re.split(r"\n(?=\[)", text)
    for section in sections:
        header = section.split("\n", 1)[0].strip()
        if "dev-dependencies" in header or "build-dependencies" in header:
            continue
        table = _KRUSTY_TABLE.match(header)
        if table:
            deps.add(table.group(1))
            continue
        if not (
            header == "[dependencies]"
            or header.startswith("[dependencies.")
            or ".dependencies]" in header
            or re.match(r"^\[target\..+\.dependencies\]$", header)
        ):
            continue
        for line in section.splitlines()[1:]:
            stripped = line.strip()
            m = _KRUSTY_DEP.match(stripped)
            if m:
                deps.add(m.group(1))
    return deps
