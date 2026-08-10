"""Shared helpers for guardrail surface extraction and file-size scans."""

from __future__ import annotations

import json
import re
from pathlib import Path

SOFT_LIMIT_DEFAULT = 350
HARD_NEW_DEFAULT = 500


def _is_repo_root(path: Path) -> bool:
    return (path / "Cargo.toml").is_file() and (path / ".github/guardrails").is_dir()


def repo_root() -> Path:
    here = Path(__file__).resolve()
    for candidate in here.parents:
        if _is_repo_root(candidate):
            return candidate
    try:
        fallback = here.parents[3]
    except IndexError as exc:
        raise RuntimeError(
            f"Could not locate repo root from {here}: "
            "no ancestor contains both Cargo.toml and .github/guardrails/"
        ) from exc
    if _is_repo_root(fallback):
        return fallback
    raise RuntimeError(
        f"Could not locate repo root from {here}: "
        f"walk-up found no markers and fallback {fallback} is not a valid repo root"
    )


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
        if n > threshold:
            rows.append({"path": str(path.relative_to(root)), "lines": n})
    return rows


_DECL_RE = re.compile(
    r"^\s*(pub\s+)?(async\s+)?(unsafe\s+)?(fn|struct|enum|type|const|static)\b"
)
_IMPL_RE = re.compile(r"^\s*impl\b")
_PUB_FN_RE = re.compile(
    r"^\s*pub\s+(?!(?:\(crate\)|\(super\)|\(in\b))(?:async\s+)?(?:unsafe\s+)?fn\b"
)
_FIELD_DECL_RE = re.compile(
    r"^\s*pub\s+(?!(?:\(crate\)|\(super\)|\(in\b))([\w]+)\s*:\s*(.+?)\s*,?\s*$"
)
_ENUM_VARIANT_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*(=\s*[^,{]+)?\s*,?\s*$")


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


def _brace_delta(text: str) -> int:
    return text.count("{") - text.count("}")


def _is_field_declaration(line: str) -> bool:
    return bool(_FIELD_DECL_RE.match(line))


def _is_pub_fn_declaration(line: str) -> bool:
    return bool(_PUB_FN_RE.match(line))


def _find_impl_block_end(lines: list[str], impl_line: int) -> int:
    """Return the line index of the closing ``}`` for an ``impl`` block."""
    depth = 0
    started = False
    for j in range(impl_line, len(lines)):
        if not started:
            if "{" not in lines[j]:
                continue
            started = True
        depth += _brace_delta(lines[j])
        if started and depth <= 0:
            return j
    return len(lines) - 1


def _collect_impl_pub_fns(
    lines: list[str], impl_line: int, end_line: int
) -> list[tuple[int, str, str]]:
    """Collect ``pub fn`` exports from a ``#[wasm_bindgen] impl`` body."""
    methods: list[tuple[int, str, str]] = []
    depth = 0
    started = False
    pending_attrs: list[str] = []

    for j in range(impl_line, end_line + 1):
        line = lines[j]
        stripped = line.strip()

        if not started:
            if "{" not in line:
                continue
            depth += _brace_delta(line)
            started = True
            if depth <= 0:
                break
            continue

        if depth == 1:
            if stripped.startswith("#["):
                pending_attrs.append(stripped)
                continue
            if not stripped or stripped.startswith("//"):
                continue
            if _is_pub_fn_declaration(line):
                attrs = "\n".join(pending_attrs)
                signature = _collect_rust_signature(lines, j)
                methods.append((j, attrs, signature))
                pending_attrs = []
            else:
                pending_attrs = []

        depth += _brace_delta(line)

    return methods


def _format_field(attrs: str, signature: str) -> str:
    bindgen = _format_bindgen_attrs(attrs)
    if bindgen:
        return f"{bindgen} | {signature}"
    return signature


def _collect_type_fields(lines: list[str], open_line: int, kind: str) -> list[str]:
    """Collect normalized pub struct fields or enum variants from a type body."""
    fields: list[str] = []
    depth = 0
    pending_attrs: list[str] = []

    for j in range(open_line, len(lines)):
        line = lines[j]
        stripped = line.strip()

        if depth == 0:
            if "{" not in line:
                continue
            depth += _brace_delta(line)
            if depth <= 0:
                break
            continue

        if stripped.startswith("#["):
            pending_attrs.append(stripped)
            continue

        if not stripped or stripped.startswith("//"):
            continue

        depth += _brace_delta(line)
        if depth <= 0:
            break

        if kind == "struct":
            m = _FIELD_DECL_RE.match(line)
            if not m:
                pending_attrs = []
                continue
            name, typ = m.group(1), m.group(2).rstrip(",").strip()
            field_sig = f"pub {name}: {typ}"
            fields.append(_format_field("\n".join(pending_attrs), field_sig))
            pending_attrs = []
            continue

        m = _ENUM_VARIANT_RE.match(line)
        if m and not stripped.startswith("pub"):
            variant = m.group(1)
            value = (m.group(2) or "").strip()
            fields.append(_normalize_ws(f"{variant}{(' ' + value) if value else ''}"))
            pending_attrs = []

    return fields


def _collect_rust_signature(lines: list[str], start: int) -> str:
    """Collect a single-line normalized Rust declaration (fn/struct/enum/impl)."""
    first = lines[start]

    if _IMPL_RE.match(first):
        text = first.split("{", 1)[0].strip()
        return _normalize_ws(f"{text} {{")

    struct_enum = re.match(r"^\s*(pub\s+)?(struct|enum)\b", first)
    if struct_enum:
        kind = struct_enum.group(2)
        parts: list[str] = []
        for j in range(start, len(lines)):
            parts.append(lines[j].strip())
            if "{" in lines[j]:
                before = " ".join(parts).split("{", 1)[0].strip()
                header = _normalize_ws(f"{before} {{")
                body_fields = _collect_type_fields(lines, j, kind)
                if body_fields:
                    return _normalize_ws(f"{header} {'; '.join(body_fields)} }}")
                return header
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


_WASM_BINDGEN_ATTR_RE = re.compile(r"#\[wasm_bindgen(?:\((.*?)\))?\]", re.DOTALL)


def _split_bindgen_args(text: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    in_string = False
    quote = ""

    for ch in text:
        if in_string:
            current.append(ch)
            if ch == quote:
                in_string = False
            continue
        if ch in ('"', "'"):
            in_string = True
            quote = ch
            current.append(ch)
            continue
        if ch == "(":
            depth += 1
            current.append(ch)
            continue
        if ch == ")":
            depth -= 1
            current.append(ch)
            continue
        if ch == "," and depth == 0:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(ch)

    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _normalize_bindgen_option(option: str) -> str:
    option = _normalize_ws(option)
    if "=" not in option:
        return option
    key, _, value = option.partition("=")
    value = value.strip().strip('"').strip("'")
    return f"{key.strip()}={value}"


def _parse_wasm_bindgen_options(attrs: str) -> list[str]:
    raw: list[str] = []
    for match in _WASM_BINDGEN_ATTR_RE.finditer(attrs):
        inner = (match.group(1) or "").strip()
        if inner:
            raw.extend(_split_bindgen_args(inner))
    flags: list[str] = []
    keyed: list[str] = []
    for option in raw:
        normalized = _normalize_bindgen_option(option)
        if "=" in normalized:
            keyed.append(normalized)
        else:
            flags.append(normalized)
    flags.sort()
    keyed.sort()
    return flags + keyed


def _format_bindgen_attrs(attrs: str) -> str:
    options = _parse_wasm_bindgen_options(attrs)
    if not options:
        return ""
    return f"wasm_bindgen({', '.join(options)})"


def _format_wasm_export(rel_path: str, attrs: str, signature: str) -> str:
    bindgen = _format_bindgen_attrs(attrs)
    if bindgen:
        return f"{rel_path}: {bindgen} | {signature}"
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
                j = i + 1
                while j < len(lines) and not _DECL_RE.match(lines[j]) and not _IMPL_RE.match(lines[j]):
                    if _is_field_declaration(lines[j]):
                        j = len(lines)
                        break
                    j += 1
                if j < len(lines):
                    attrs = "\n".join(lines[i:j])
                    if _IMPL_RE.match(lines[j]):
                        signature = _collect_rust_signature(lines, j)
                        exports.append(_format_wasm_export(rel, attrs, signature))
                        end = _find_impl_block_end(lines, j)
                        for _, method_attrs, method_sig in _collect_impl_pub_fns(
                            lines, j, end
                        ):
                            exports.append(
                                _format_wasm_export(rel, method_attrs, method_sig)
                            )
                        i = end + 1
                    else:
                        signature = _collect_rust_signature(lines, j)
                        exports.append(_format_wasm_export(rel, attrs, signature))
                        i = j + 1
                else:
                    i += 1
            else:
                i += 1
    return exports


_KRUSTY_NAME = r"krusty-kms(?:-[a-z0-9-]+)?"
_KRUSTY_NAME_RE = re.compile(rf"^{_KRUSTY_NAME}$")
_KRUSTY_PACKAGE = re.compile(rf'package\s*=\s*"({_KRUSTY_NAME})"')
_DEP_KEY = re.compile(r"^([a-zA-Z0-9_.-]+)\s*=")
_DEP_WS_INLINE = re.compile(r"^([a-zA-Z0-9_-]+)\.workspace\s*=\s*true\b")
_DEP_TABLE = re.compile(r"^\[(?:.*\.)?dependencies\.([a-zA-Z0-9_-]+)\]")


def _is_krusty_dependency_section(header: str) -> bool:
    return (
        header == "[dependencies]"
        or header.startswith("[dependencies.")
        or ".dependencies]" in header
        or re.match(r"^\[target\..+\.dependencies\]$", header) is not None
    )


def _add_krusty_dep_from_entry(deps: set[str], name: str, body: str) -> None:
    pkg = _KRUSTY_PACKAGE.search(body)
    if pkg:
        deps.add(pkg.group(1))
    elif _KRUSTY_NAME_RE.match(name):
        deps.add(name)


def krusty_deps_from_cargo_toml(text: str) -> set[str]:
    """Collect krusty-* deps from [dependencies] / target.*.dependencies (not dev/build)."""
    deps: set[str] = set()
    sections = re.split(r"\n(?=\[)", text)
    for section in sections:
        header = section.split("\n", 1)[0].strip()
        if "dev-dependencies" in header or "build-dependencies" in header:
            continue
        table = _DEP_TABLE.match(header)
        if table:
            body = section.split("\n", 1)[1] if "\n" in section else ""
            _add_krusty_dep_from_entry(deps, table.group(1), body)
            continue
        if not _is_krusty_dependency_section(header):
            continue
        for line in section.splitlines()[1:]:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            ws_match = _DEP_WS_INLINE.match(stripped)
            if ws_match:
                _add_krusty_dep_from_entry(deps, ws_match.group(1), stripped)
                continue
            key_match = _DEP_KEY.match(stripped)
            if not key_match:
                continue
            _add_krusty_dep_from_entry(deps, key_match.group(1), stripped)
    return deps


def _assert_surfaces_self_checks() -> None:
    assert (
        _format_field('#[wasm_bindgen(skip)]', "pub foo: String")
        == "wasm_bindgen(skip) | pub foo: String"
    )
    assert (
        _format_field(
            '#[wasm_bindgen(js_name = "encryptedKey")]',
            "pub encrypted_key: String",
        )
        == "wasm_bindgen(js_name=encryptedKey) | pub encrypted_key: String"
    )
    assert krusty_deps_from_cargo_toml(
        "[dependencies]\nkrusty-kms-common.workspace = true\n"
    ) == {"krusty-kms-common"}
    assert krusty_deps_from_cargo_toml(
        '[dependencies]\nfoo = { package = "krusty-kms-sdk", path = "../sdk" }\n'
    ) == {"krusty-kms-sdk"}
    assert krusty_deps_from_cargo_toml(
        "[dependencies]\nserde.workspace = true\n"
    ) == set()
    assert krusty_deps_from_cargo_toml(
        "[dependencies.krusty-kms-common]\nworkspace = true\n"
    ) == {"krusty-kms-common"}


if __name__ == "__main__":
    _assert_surfaces_self_checks()
