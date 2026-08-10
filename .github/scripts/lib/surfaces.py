"""Shared helpers for guardrail surface extraction and file-size scans."""

from __future__ import annotations

import json
import re
from pathlib import Path

SOFT_LIMIT_DEFAULT = 350
HARD_NEW_DEFAULT = 500


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


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


_DECL_RE = re.compile(
    r"^\s*(pub\s+)?(async\s+)?(unsafe\s+)?(fn|struct|enum|type|const|static)\b"
)
_IMPL_RE = re.compile(r"^\s*impl\b")


def _normalize_ws(text: str) -> str:
    text = re.sub(r"\s+", " ", text.strip())
    text = re.sub(r"\(\s+", "(", text)
    text = re.sub(r"\s+\)", ")", text)
    text = re.sub(r"\s+,", ",", text)
    text = re.sub(r",\s+", ", ", text)
    text = re.sub(r",\s*\)", ")", text)
    return text


def _paren_depth(text: str) -> int:
    return text.count("(") - text.count(")")


def _collect_rust_signature(lines: list[str], start: int) -> str:
    """Collect a single-line normalized Rust declaration (fn/struct/enum/impl)."""
    first = lines[start]

    if _IMPL_RE.match(first):
        text = first.split("{", 1)[0].strip()
        return _normalize_ws(f"{text} {{")

    if re.match(r"^\s*(pub\s+)?(struct|enum)\b", first):
        parts: list[str] = []
        for j in range(start, len(lines)):
            parts.append(lines[j].strip())
            if "{" in lines[j]:
                before = " ".join(parts).split("{", 1)[0].strip()
                return _normalize_ws(f"{before} {{")
        return _normalize_ws(" ".join(parts))

    parts: list[str] = []
    for j in range(start, len(lines)):
        line = lines[j].strip()
        if "{" in line:
            before = line.split("{", 1)[0].strip()
            if parts:
                return _normalize_ws(" ".join(parts) + (" " + before if before else ""))
            return _normalize_ws(before)
        parts.append(line)
        combined = " ".join(parts)
        if "(" in combined and _paren_depth(combined) == 0:
            if "->" in combined:
                return _normalize_ws(combined)
            if j + 1 < len(lines) and lines[j + 1].strip().startswith("->"):
                parts.append(lines[j + 1].strip())
                return _normalize_ws(" ".join(parts))
            return _normalize_ws(combined)
    return _normalize_ws(" ".join(parts))


def _format_wasm_export(rel_path: str, attrs: str, signature: str) -> str:
    m = re.search(r'js_name\s*=\s*"([^"]+)"', attrs)
    if m:
        return f"{rel_path}: js_name={m.group(1)} | {signature}"
    return f"{rel_path}: {signature}"


def extract_wasm_exports(root: Path | None = None) -> list[str]:
    root = root or repo_root()
    exports: list[str] = []
    for path in sorted((root / "crates/wasm/src").rglob("*.rs")):
        lines = path.read_text().splitlines()
        rel = str(path.relative_to(root))
        i = 0
        while i < len(lines):
            if "#[wasm_bindgen" in lines[i] and "wasm_bindgen_test" not in lines[i]:
                j = i
                while j < len(lines) and not _DECL_RE.match(lines[j]) and not _IMPL_RE.match(lines[j]):
                    j += 1
                if j < len(lines):
                    attrs = "\n".join(lines[i:j])
                    signature = _collect_rust_signature(lines, j)
                    exports.append(_format_wasm_export(rel, attrs, signature))
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
