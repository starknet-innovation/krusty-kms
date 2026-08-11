"""Shared helpers for guardrail surface extraction and file-size scans."""

from __future__ import annotations

import json
import re
import subprocess
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


def baseline_paths(data: dict) -> dict[str, int]:
    return {entry["path"]: int(entry["lines"]) for entry in data["files"]}


def count_file_lines(path: Path) -> int:
    return sum(1 for _ in path.open("rb"))


def load_git_baseline_paths(base_ref: str, root: Path) -> dict[str, int] | None:
    rel = ".github/guardrails/file-size-baseline.json"
    try:
        text = subprocess.check_output(
            ["git", "show", f"{base_ref}:{rel}"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return None
    return baseline_paths(json.loads(text))


def path_exists_on_ref(base_ref: str | None, rel: str, root: Path) -> bool:
    """Return True when ``rel`` exists on ``base_ref`` (or when no ref is given)."""
    if not base_ref:
        return True
    try:
        subprocess.check_output(
            ["git", "cat-file", "-e", f"{base_ref}:{rel}"],
            cwd=root,
            stderr=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def check_file_size_ratchet(
    head_baseline: dict,
    root: Path,
    *,
    base_known: dict[str, int] | None = None,
    base_ref: str | None = None,
) -> tuple[int, list[str]]:
    """Return ``(exit_code, lines)`` for the file-size ratchet fitness check."""
    soft = soft_limit(head_baseline)
    hard_new = hard_new_limit(head_baseline)
    known = baseline_paths(head_baseline)

    failed = 0
    out: list[str] = []
    grown: list[tuple[str, int, int]] = []
    new_oversized: list[tuple[str, int, int]] = []
    missing: list[str] = []

    for rel, baseline_lines in sorted(known.items()):
        path = root / rel
        if not path.is_file():
            missing.append(rel)
            continue
        lines = count_file_lines(path)
        if lines > baseline_lines:
            grown.append((rel, baseline_lines, lines))

    for path in sorted((root / "crates").rglob("*.rs")):
        if "target" in path.parts:
            continue
        rel = str(path.relative_to(root))
        lines = count_file_lines(path)
        existed_on_base = path_exists_on_ref(base_ref, rel, root)

        # Hard cap always applies to files that did not exist on the base ref,
        # even if the PR also adds them to file-size-baseline.json.
        if not existed_on_base:
            if lines > hard_new:
                new_oversized.append((rel, lines, hard_new))
            elif lines > soft:
                out.append(
                    f"::warning file={rel}::{rel} is {lines} lines "
                    f"(soft limit {soft}); prefer splitting before it hits {hard_new}"
                )
            continue

        if rel in known:
            # Grandfathered / already-tracked on base: growth handled above.
            # Also reject newly baselined existing files that jump over hard_new
            # when the base baseline is available and did not list them.
            if (
                base_known is not None
                and rel not in base_known
                and lines > hard_new
            ):
                new_oversized.append((rel, lines, hard_new))
            continue

        if lines > hard_new:
            new_oversized.append((rel, lines, hard_new))
        elif lines > soft:
            out.append(
                f"::warning file={rel}::{rel} is {lines} lines "
                f"(soft limit {soft}); prefer splitting before it hits {hard_new}"
            )

    if missing:
        out.append(
            "::error::baseline entries missing on disk "
            "(update baseline if intentional removals/renames):"
        )
        for rel in missing:
            out.append(f"  - {rel}")
        failed = 1

    if grown:
        out.append("::error::oversized files grew past their ratchet baseline:")
        for rel, before, after in grown:
            out.append(f"  - {rel}: {before} -> {after} (+{after - before})")
            out.append(
                "    Split the file or bump the baseline with justification in the PR."
            )
        failed = 1

    if new_oversized:
        # Deduplicate while preserving order.
        seen: set[str] = set()
        unique: list[tuple[str, int, int]] = []
        for item in new_oversized:
            if item[0] in seen:
                continue
            seen.add(item[0])
            unique.append(item)
        out.append(
            "::error::new files exceed the hard size limit for new sources "
            "(baselining does not waive this cap):"
        )
        for rel, lines, limit in unique:
            out.append(f"  - {rel}: {lines} lines (limit {limit})")
        failed = 1

    if failed:
        return failed, out

    out.append(
        f"file-size ratchet ok ({len(known)} baselined files, "
        f"soft={soft}, hard_new={hard_new})"
    )
    return 0, out


def run_file_size_ratchet_check(
    baseline_path: Path,
    root: Path,
    *,
    base_ref: str | None = None,
) -> int:
    head_baseline = json.loads(baseline_path.read_text())
    base_known: dict[str, int] | None = None
    if base_ref:
        base_known = load_git_baseline_paths(base_ref, root)
    code, lines = check_file_size_ratchet(
        head_baseline, root, base_known=base_known, base_ref=base_ref
    )
    for line in lines:
        print(line)
    return code


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
_ENUM_VARIANT_START_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*(.*)$")
_UNRESTRICTED_PUB_ITEM_RE = re.compile(
    r"^\s*pub\s+(?!(?:\(crate\)|\(super\)|\(in\b))"
    r"(?:async\s+)?(?:unsafe\s+)?(?:extern\s+(?:\"[^\"]*\"|'[^']*')\s+)?(?:const\s+)?"
    r"(fn|struct|enum|trait|type|const|static|use|mod|impl)\b"
)
_TRAIT_METHOD_RE = re.compile(
    r"^\s*(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?fn\b"
)
_TRAIT_ASSOC_ITEM_RE = re.compile(r"^\s*(?:type|const)\b")
_UNRESTRICTED_PUB_DIFF_RE = re.compile(
    r"^[+-]\s*pub\s+(?!(?:\(crate\)|\(super\)|\(in\b))"
    r"(?:async\s+)?(?:unsafe\s+)?(?:extern\s+(?:\"[^\"]*\"|'[^']*')\s+)?"
)
_CFG_ATTR_RE = re.compile(r"^#\[cfg\b")


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


def _attr_is_complete(attr: str) -> bool:
    return attr.count("[") <= attr.count("]")


def _append_pending_attr(pending_attrs: list[str], stripped: str) -> bool:
    """Consume an attribute line, including multiline ``#[...]`` continuations."""
    if pending_attrs and not _attr_is_complete(pending_attrs[-1]):
        pending_attrs[-1] = f"{pending_attrs[-1]} {stripped}"
        return True
    if stripped.startswith("#["):
        pending_attrs.append(stripped)
        return True
    return False


def _collect_enum_variant_signature(
    lines: list[str], line_idx: int
) -> tuple[str, int]:
    """Parse one enum variant; return ``(normalized fingerprint, last line index)``."""
    stripped = lines[line_idx].strip()
    m = _ENUM_VARIANT_START_RE.match(stripped)
    if not m:
        return "", line_idx

    name = m.group(1)
    rest = m.group(2).strip().rstrip(",")

    if not rest:
        return name, line_idx

    if rest.startswith("="):
        return _normalize_ws(f"{name} {rest}"), line_idx

    if rest.startswith("("):
        parts = [rest]
        depth = _paren_depth(rest)
        j = line_idx
        while depth > 0 and j + 1 < len(lines):
            j += 1
            nxt = lines[j].strip()
            parts.append(nxt)
            depth += _paren_depth(nxt)
        payload = _normalize_ws(" ".join(parts)).rstrip(",")
        return _normalize_ws(f"{name}{payload}"), j

    if rest.startswith("{"):
        parts = [rest]
        depth = _brace_delta(rest)
        j = line_idx
        while depth > 0 and j + 1 < len(lines):
            j += 1
            nxt = lines[j].strip()
            parts.append(nxt)
            depth += _brace_delta(nxt)
        payload = _normalize_ws(" ".join(parts)).rstrip(",")
        return _normalize_ws(f"{name} {payload}"), j

    return name, line_idx


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
            if not stripped or stripped.startswith("//"):
                continue
            if _append_pending_attr(pending_attrs, stripped):
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
    j = open_line

    while j < len(lines):
        line = lines[j]
        stripped = line.strip()

        if depth == 0:
            if "{" not in line:
                j += 1
                continue
            depth += _brace_delta(line)
            if depth <= 0:
                break
            j += 1
            continue

        if not stripped or stripped.startswith("//"):
            j += 1
            continue

        if _append_pending_attr(pending_attrs, stripped):
            j += 1
            continue

        if kind == "struct":
            depth += _brace_delta(line)
            if depth <= 0:
                break
            m = _FIELD_DECL_RE.match(line)
            if not m:
                pending_attrs = []
                j += 1
                continue
            name, typ = m.group(1), m.group(2).rstrip(",").strip()
            field_sig = f"pub {name}: {typ}"
            fields.append(_format_field("\n".join(pending_attrs), field_sig))
            pending_attrs = []
            j += 1
            continue

        if stripped.startswith("pub"):
            pending_attrs = []
            depth += _brace_delta(line)
            if depth <= 0:
                break
            j += 1
            continue

        variant_sig, end_j = _collect_enum_variant_signature(lines, j)
        if variant_sig:
            fields.append(variant_sig)
            pending_attrs = []
            for k in range(j, end_j + 1):
                depth += _brace_delta(lines[k])
                if depth <= 0:
                    j = end_j + 1
                    break
            else:
                j = end_j + 1
            if depth <= 0:
                break
            continue

        pending_attrs = []
        depth += _brace_delta(line)
        if depth <= 0:
            break
        j += 1

    return fields


def _collect_trait_items(lines: list[str], open_line: int) -> list[str]:
    """Collect normalized method and associated item signatures from a trait body."""
    items: list[str] = []
    depth = 0

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

        if depth == 1:
            if stripped.startswith("#["):
                continue
            if not stripped or stripped.startswith("//"):
                depth += _brace_delta(line)
                if depth <= 0:
                    break
                continue
            if _TRAIT_METHOD_RE.match(line) or _TRAIT_ASSOC_ITEM_RE.match(line):
                items.append(_collect_rust_signature(lines, j))

        depth += _brace_delta(line)
        if depth <= 0:
            break

    return items


def _collect_rust_signature(lines: list[str], start: int) -> str:
    """Collect a single-line normalized Rust declaration (fn/struct/enum/impl)."""
    first = lines[start]

    if _IMPL_RE.match(first):
        text = first.split("{", 1)[0].strip()
        return _normalize_ws(f"{text} {{")

    trait_match = re.match(r"^\s*(pub\s+)?trait\b", first)
    if trait_match:
        parts: list[str] = []
        for j in range(start, len(lines)):
            parts.append(lines[j].strip())
            if "{" in lines[j]:
                before = " ".join(parts).split("{", 1)[0].strip()
                header = _normalize_ws(f"{before} {{")
                body_items = _collect_trait_items(lines, j)
                if body_items:
                    return _normalize_ws(f"{header} {'; '.join(body_items)} }}")
                return header
        return _normalize_ws(" ".join(parts))

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

    if re.match(r"^\s*(pub\s+)?use\b", first):
        parts: list[str] = []
        depth = 0
        for j in range(start, len(lines)):
            line = lines[j].strip()
            parts.append(line)
            depth += _brace_delta(line)
            if "{" in " ".join(parts):
                if depth <= 0:
                    return _normalize_ws(" ".join(parts))
            elif ";" in line:
                return _normalize_ws(" ".join(parts))
        return _normalize_ws(" ".join(parts))

    if re.match(r"^\s*(pub\s+)?(?:mod|type|static)\b", first) or re.match(
        r"^\s*(pub\s+)?const\s+(?!fn\b)", first
    ):
        parts: list[str] = []
        for j in range(start, len(lines)):
            line = lines[j].strip()
            parts.append(line)
            if ";" in line:
                return _normalize_ws(" ".join(parts))
        return _normalize_ws(" ".join(parts))

    parts: list[str] = []
    for j in range(start, len(lines)):
        line = lines[j].strip()
        if not line:
            continue
        if "{" in line:
            before = line.split("{", 1)[0].strip()
            if before:
                parts.append(before)
            return _normalize_ws(" ".join(parts))
        parts.append(line)
        combined = " ".join(parts)
        if ";" in line and _paren_depth(combined) == 0:
            return _normalize_ws(combined)
        if "(" in combined and _paren_depth(combined) == 0:
            nxt = lines[j + 1].strip() if j + 1 < len(lines) else ""
            if nxt.startswith("->") or nxt.startswith("where"):
                continue
            if re.search(r"\bwhere\b", combined) and (
                line == "where" or line.endswith(",") or line.endswith(":")
            ):
                continue
            return _normalize_ws(combined)
    return _normalize_ws(" ".join(parts))


def _collect_preceding_cfg_attrs(lines: list[str], start: int) -> str:
    """Return contiguous ``#[cfg(...)]`` attribute lines immediately above ``start``."""
    attrs: list[str] = []
    i = start - 1
    while i >= 0:
        stripped = lines[i].strip()
        if not stripped:
            i -= 1
            continue
        if _CFG_ATTR_RE.match(stripped):
            attrs.insert(0, stripped)
            i -= 1
            continue
        if stripped.startswith("#["):
            break
        break
    return "\n".join(attrs)


def extract_public_surface(text: str) -> frozenset[str]:
    """Canonical fingerprint of unrestricted ``pub`` API items in Rust source."""
    lines = text.splitlines()
    surface: set[str] = set()
    for i, line in enumerate(lines):
        if not _UNRESTRICTED_PUB_ITEM_RE.match(line):
            continue
        sig = _collect_rust_signature(lines, i)
        if not sig:
            continue
        cfg_attrs = _collect_preceding_cfg_attrs(lines, i)
        if cfg_attrs:
            sig = f"{cfg_attrs} {sig}"
        surface.add(sig)
    return frozenset(surface)


_CRATE_SRC_PATH_RE = re.compile(r"^crates/([^/]+)/src/(.+)\.rs$")
_PUB_MOD_DECL_RE = re.compile(
    r"^\s*(?:#\[[^\]]*\]\s*)*pub\s+(?!(?:\(crate\)|\(super\)|\(in\b))mod\s+(\w+)"
)
_MOD_DECL_RE = re.compile(r"^\s*(?:#\[[^\]]*\]\s*)*mod\s+(\w+)")
_PUB_USE_START_RE = re.compile(
    r"^\s*(?:#\[[^\]]*\]\s*)*pub\s+(?!(?:\(crate\)|\(super\)|\(in\b))use\s+"
)


def _module_path_from_rel(rel_path: str) -> str | None:
    match = _CRATE_SRC_PATH_RE.match(rel_path)
    if not match:
        return None
    rest = match.group(2)
    if rest in ("lib", "main"):
        return ""
    if rest.endswith("/mod"):
        return rest[: -len("/mod")]
    return rest


def _crate_src_dir_from_rel(rel_path: str, root: Path) -> Path | None:
    match = _CRATE_SRC_PATH_RE.match(rel_path)
    if not match:
        return None
    return root / "crates" / match.group(1) / "src"


def _resolve_mod_file(src_dir: Path, parent_path: str, mod_name: str) -> Path | None:
    if parent_path:
        parent_dir = src_dir / parent_path
        candidates = (parent_dir / f"{mod_name}.rs", parent_dir / mod_name / "mod.rs")
    else:
        candidates = (src_dir / f"{mod_name}.rs", src_dir / mod_name / "mod.rs")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _parse_mod_declarations(text: str) -> list[tuple[str, bool, bool]]:
    """Return ``(name, is_public, has_external_file)`` for each ``mod`` declaration."""
    decls: list[tuple[str, bool, bool]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        pub_match = _PUB_MOD_DECL_RE.match(line)
        if pub_match:
            external = ";" in stripped.split("{", 1)[0]
            decls.append((pub_match.group(1), True, external))
            continue
        mod_match = _MOD_DECL_RE.match(line)
        if mod_match and not pub_match:
            external = ";" in stripped.split("{", 1)[0]
            decls.append((mod_match.group(1), False, external))
    return decls


def _resolve_qualified_path(segments: list[str], module_path: str) -> list[str]:
    if not segments:
        return []
    if segments[0] == "crate":
        return _resolve_qualified_path(segments[1:], "")
    if segments[0] == "self":
        base = module_path.split("/") if module_path else []
        return base + _resolve_qualified_path(segments[1:], module_path)
    if segments[0] == "super":
        base = module_path.split("/") if module_path else []
        if base:
            base = base[:-1]
        return base + _resolve_qualified_path(segments[1:], module_path)
    base = module_path.split("/") if module_path else []
    return base + segments


def _use_statement_module_paths(use_stmt: str, module_path: str) -> set[str]:
    body = re.sub(r"^\s*(?:#\[[^\]]*\]\s*)*pub\s+(?!(?:\(crate\)|\(super\)|\(in\b))use\s+", "", use_stmt)
    body = body.strip().rstrip(";").strip()
    if not body:
        return set()

    brace_idx = body.find("{")
    if brace_idx >= 0:
        path_part = body[:brace_idx].rstrip()
    else:
        path_part = re.sub(r"\s+as\s+\w+\s*$", "", body).strip()

    segments = [part.strip() for part in path_part.split("::") if part.strip()]
    if not segments:
        return set()

    resolved = _resolve_qualified_path(segments, module_path)
    if brace_idx < 0 and len(resolved) >= 2 and resolved[-1][0].isupper():
        resolved = resolved[:-1]
    if not resolved:
        return set()

    paths: set[str] = set()
    for i in range(1, len(resolved) + 1):
        paths.add("/".join(resolved[:i]))
    return paths


def _collect_pub_use_module_paths(text: str, module_path: str) -> set[str]:
    lines = text.splitlines()
    paths: set[str] = set()
    idx = 0
    while idx < len(lines):
        if not _PUB_USE_START_RE.match(lines[idx]):
            idx += 1
            continue
        parts = [lines[idx].strip()]
        while idx + 1 < len(lines) and ";" not in parts[-1]:
            idx += 1
            parts.append(lines[idx].strip())
        stmt = " ".join(parts)
        paths.update(_use_statement_module_paths(stmt, module_path))
        idx += 1
    return paths


class _CrateExportIndex:
    """Module reachability and ``pub use`` export map for one crate ``src/`` tree."""

    def __init__(self, src_dir: Path) -> None:
        self.src_dir = src_dir
        self._public_reachable: set[str] = set()
        self._export_touched: set[str] = set()
        root_rs = src_dir / "lib.rs"
        if not root_rs.is_file():
            root_rs = src_dir / "main.rs"
        if root_rs.is_file():
            self._walk_module("", root_rs, is_public=True)

    def is_exported_file(self, rel_path: str) -> bool:
        module_path = _module_path_from_rel(rel_path)
        if module_path is None:
            return False
        if module_path == "":
            return True
        if module_path in self._public_reachable:
            return True
        return module_path in self._export_touched

    def _walk_module(self, module_path: str, file_path: Path, *, is_public: bool) -> None:
        if is_public:
            self._public_reachable.add(module_path)
        text = file_path.read_text()
        if is_public:
            self._export_touched.update(_collect_pub_use_module_paths(text, module_path))
        for name, child_public, external in _parse_mod_declarations(text):
            child_path = f"{module_path}/{name}" if module_path else name
            if not external:
                continue
            child_file = _resolve_mod_file(self.src_dir, module_path, name)
            if child_file is None:
                continue
            self._walk_module(
                child_path,
                child_file,
                is_public=is_public and child_public,
            )


_export_index_cache: dict[str, _CrateExportIndex] = {}


def _export_index_for_file(rel_path: str, root: Path) -> _CrateExportIndex | None:
    src_dir = _crate_src_dir_from_rel(rel_path, root)
    if src_dir is None:
        return None
    key = str(src_dir.resolve())
    if key not in _export_index_cache:
        _export_index_cache[key] = _CrateExportIndex(src_dir)
    return _export_index_cache[key]


def is_exported_crate_source(rel_path: str, root: Path | None = None) -> bool:
    """Return True when ``rel_path`` is part of the crate's exported module surface."""
    repo = root or repo_root()
    index = _export_index_for_file(rel_path, repo)
    if index is None:
        return False
    return index.is_exported_file(rel_path)


def public_api_change_reasons(
    base_ref: str,
    files: list[str],
    *,
    root: Path | None = None,
) -> list[str]:
    """Return design-note trigger reasons for changed production ``src/**/*.rs`` files."""
    repo = root or repo_root()
    _export_index_cache.clear()
    reasons: list[str] = []
    for rel in files:
        if not is_exported_crate_source(rel, repo):
            continue
        try:
            base_text = subprocess.check_output(
                ["git", "show", f"{base_ref}:{rel}"],
                cwd=repo,
                text=True,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            base_text = ""
        head_path = repo / rel
        head_text = head_path.read_text() if head_path.is_file() else ""
        if extract_public_surface(base_text) != extract_public_surface(head_text):
            reasons.append(f"public API surface changed in {rel}")
            continue
        try:
            diff = subprocess.check_output(
                ["git", "diff", f"{base_ref}...HEAD", "--", rel],
                cwd=repo,
                text=True,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            diff = ""
        if _UNRESTRICTED_PUB_DIFF_RE.search(diff):
            reasons.append(f"new/changed/removed pub items in {rel}")
    return reasons


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
_DEP_DOTTED_FIELD_RE = re.compile(r"^([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)\s*=")
_DEP_KNOWN_FIELDS = frozenset(
    {
        "branch",
        "default-features",
        "features",
        "git",
        "optional",
        "package",
        "path",
        "registry",
        "rename",
        "rev",
        "tag",
        "version",
        "workspace",
    }
)
_DEP_WS_INLINE = re.compile(r"^([a-zA-Z0-9_-]+)\.workspace\s*=\s*true\b")
_DEP_TABLE = re.compile(r"^\[(?:.*\.)?dependencies\.([a-zA-Z0-9_-]+)\]")
_WS_DEP_TABLE = re.compile(r"^\[workspace\.dependencies\.([a-zA-Z0-9_.-]+)\]")
_WS_TRUE = re.compile(r"\bworkspace\s*=\s*true\b")
_ENTRY_SEP = "\x1e"


def _is_krusty_dependency_section(header: str) -> bool:
    return (
        header == "[dependencies]"
        or header.startswith("[dependencies.")
        or ".dependencies]" in header
        or re.match(r"^\[target\..+\.dependencies\]$", header) is not None
    )


def _workspace_dep_package_name(key: str, body: str) -> str:
    pkg = _KRUSTY_PACKAGE.search(body)
    if pkg:
        return pkg.group(1)
    return key


def parse_workspace_dependencies(cargo_text: str) -> dict[str, str]:
    """Map ``[workspace.dependencies]`` keys to resolved crate package names."""
    mapping: dict[str, str] = {}
    sections = re.split(r"\n(?=\[)", cargo_text)
    for section in sections:
        if not section.strip():
            continue
        header = section.split("\n", 1)[0].strip()
        body = section.split("\n", 1)[1] if "\n" in section else ""
        if header == "[workspace.dependencies]":
            inline_lines = [
                line.strip()
                for line in section.splitlines()[1:]
                if line.strip() and not line.strip().startswith("#")
            ]
            for name, body in _group_inline_dep_lines(inline_lines):
                mapping[name] = _workspace_dep_package_name(name, body)
            continue
        table = _WS_DEP_TABLE.match(header)
        if table:
            key = table.group(1)
            mapping[key] = _workspace_dep_package_name(key, body)
    return mapping


def _uses_workspace(body: str) -> bool:
    return bool(_WS_TRUE.search(body))


def _group_inline_dep_lines(lines: list[str]) -> list[tuple[str, str]]:
    """Group dotted fields and multiline inline dependency tables into entries."""
    pending: dict[str, list[str]] = {}
    entries: list[tuple[str, str]] = []
    i = 0

    def flush() -> None:
        for name in sorted(pending):
            entries.append((name, "\n".join(pending[name])))
        pending.clear()

    while i < len(lines):
        stripped = lines[i]
        dotted = _DEP_DOTTED_FIELD_RE.match(stripped)
        if dotted:
            name, field = dotted.group(1), dotted.group(2)
            if field in _DEP_KNOWN_FIELDS:
                _, _, value = stripped.partition("=")
                pending.setdefault(name, []).append(f"{field} = {value.strip()}")
                i += 1
                continue
        key_match = _DEP_KEY.match(stripped)
        if not key_match:
            i += 1
            continue
        key = key_match.group(1)
        if "." in key:
            i += 1
            continue
        flush()
        parts = [stripped]
        brace_depth = stripped.count("{") - stripped.count("}")
        i += 1
        while brace_depth > 0 and i < len(lines):
            parts.append(lines[i])
            brace_depth += lines[i].count("{") - lines[i].count("}")
            i += 1
        entries.append((key, "\n".join(parts)))
    flush()
    return entries


def _normalize_dep_body(body: str) -> str:
    lines: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return _ENTRY_SEP.join(lines)


def _format_dep_entry(name: str, body: str) -> str:
    norm = _normalize_dep_body(body)
    return f"{name}{_ENTRY_SEP}{norm}" if norm else name


def _group_feature_lines(lines: list[str]) -> list[tuple[str, str]]:
    """Group ``[features]`` assignments, including multiline arrays."""
    entries: list[tuple[str, str]] = []
    i = 0
    while i < len(lines):
        stripped = lines[i]
        key_match = _DEP_KEY.match(stripped)
        if not key_match or "." in key_match.group(1):
            i += 1
            continue
        name = key_match.group(1)
        parts = [stripped]
        depth = stripped.count("[") - stripped.count("]")
        i += 1
        while depth > 0 and i < len(lines):
            parts.append(lines[i])
            depth += lines[i].count("[") - lines[i].count("]")
            i += 1
        entries.append((name, "\n".join(parts)))
    return entries


def production_dep_entries(cargo_text: str) -> list[str]:
    """Sorted atomic production dependency/feature records for manifest diffing."""
    entries: list[str] = []
    for section in re.split(r"\n(?=\[)", cargo_text):
        if not section.strip():
            continue
        header = section.split("\n", 1)[0].strip()
        if "dev-dependencies" in header or "build-dependencies" in header:
            continue
        if header == "[features]":
            inline_lines = [
                line.strip()
                for line in section.splitlines()[1:]
                if line.strip() and not line.strip().startswith("#")
            ]
            for name, body in _group_feature_lines(inline_lines):
                entries.append(_format_dep_entry(f"[features].{name}", body))
            continue
        table = _DEP_TABLE.match(header)
        if table:
            body = section.split("\n", 1)[1] if "\n" in section else ""
            norm = _normalize_dep_body(body)
            entries.append(f"{header}{_ENTRY_SEP}{norm}" if norm else header)
            continue
        if not _is_krusty_dependency_section(header):
            continue
        inline_lines = [
            line.strip()
            for line in section.splitlines()[1:]
            if line.strip() and not line.strip().startswith("#")
        ]
        for name, body in _group_inline_dep_lines(inline_lines):
            entries.append(_format_dep_entry(name, body))
    return sorted(entries)


def workspace_dep_entries(cargo_text: str) -> list[str]:
    """Sorted atomic workspace dependency records for manifest diffing."""
    entries: list[str] = []
    for section in re.split(r"\n(?=\[)", cargo_text):
        if not section.strip():
            continue
        header = section.split("\n", 1)[0].strip()
        if header == "[workspace.dependencies]":
            inline_lines = [
                line.strip()
                for line in section.splitlines()[1:]
                if line.strip() and not line.strip().startswith("#")
            ]
            for name, body in _group_inline_dep_lines(inline_lines):
                entries.append(_format_dep_entry(name, body))
            continue
        table = _WS_DEP_TABLE.match(header)
        if table:
            body = section.split("\n", 1)[1] if "\n" in section else ""
            norm = _normalize_dep_body(body)
            entries.append(f"{header}{_ENTRY_SEP}{norm}" if norm else header)
    return entries


def _add_krusty_dep_from_entry(
    deps: set[str],
    name: str,
    body: str,
    workspace_deps: dict[str, str],
) -> None:
    pkg = _KRUSTY_PACKAGE.search(body)
    if pkg and _KRUSTY_NAME_RE.match(pkg.group(1)):
        deps.add(pkg.group(1))
        return

    resolved = name
    if _uses_workspace(body) or _DEP_WS_INLINE.match(body):
        resolved = workspace_deps.get(name, name)

    if _KRUSTY_NAME_RE.match(resolved):
        deps.add(resolved)


def krusty_deps_from_cargo_toml(
    text: str,
    workspace_deps: dict[str, str] | None = None,
) -> set[str]:
    """Collect krusty-* deps from [dependencies] / target.*.dependencies (not dev/build)."""
    if workspace_deps is None:
        root_cargo = repo_root() / "Cargo.toml"
        workspace_deps = (
            parse_workspace_dependencies(root_cargo.read_text())
            if root_cargo.is_file()
            else {}
        )

    deps: set[str] = set()
    sections = re.split(r"\n(?=\[)", text)
    for section in sections:
        header = section.split("\n", 1)[0].strip()
        if "dev-dependencies" in header or "build-dependencies" in header:
            continue
        table = _DEP_TABLE.match(header)
        if table:
            body = section.split("\n", 1)[1] if "\n" in section else ""
            _add_krusty_dep_from_entry(deps, table.group(1), body, workspace_deps)
            continue
        if not _is_krusty_dependency_section(header):
            continue
        inline_lines = [
            line.strip()
            for line in section.splitlines()[1:]
            if line.strip() and not line.strip().startswith("#")
        ]
        for name, body in _group_inline_dep_lines(inline_lines):
            _add_krusty_dep_from_entry(deps, name, body, workspace_deps)
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
    ws_map = {"kms": "krusty-kms"}
    assert krusty_deps_from_cargo_toml(
        "[dependencies]\nkms.workspace = true\n",
        workspace_deps=ws_map,
    ) == {"krusty-kms"}
    assert krusty_deps_from_cargo_toml(
        "[dependencies]\nkms = { workspace = true }\n",
        workspace_deps=ws_map,
    ) == {"krusty-kms"}
    assert krusty_deps_from_cargo_toml(
        "[dependencies]\nkms.workspace = true\n",
        workspace_deps={},
    ) == set()
    assert krusty_deps_from_cargo_toml(
        "[dependencies]\nkms = { workspace = true }\n",
        workspace_deps={},
    ) == set()
    assert parse_workspace_dependencies(
        '[workspace.dependencies]\nkms = { package = "krusty-kms", path = "crates/kms" }\n'
    ) == {"kms": "krusty-kms"}
    assert parse_workspace_dependencies(
        '[workspace.dependencies]\nkms.package = "krusty-kms"\nkms.path = "crates/kms"\n'
    ) == {"kms": "krusty-kms"}
    ws_map_multiline = parse_workspace_dependencies(
        "[workspace.dependencies]\n"
        "kms = {\n"
        '  package = "krusty-kms",\n'
        '  path = "crates/kms",\n'
        "}\n"
    )
    assert ws_map_multiline == {"kms": "krusty-kms"}
    assert krusty_deps_from_cargo_toml(
        "[dependencies]\nkms.workspace = true\n",
        workspace_deps=ws_map_multiline,
    ) == {"krusty-kms"}
    ws_map_dotted = parse_workspace_dependencies(
        '[workspace.dependencies]\nkms.package = "krusty-kms"\nkms.path = "crates/kms"\n'
    )
    assert krusty_deps_from_cargo_toml(
        "[dependencies]\nkms.workspace = true\n",
        workspace_deps=ws_map_dotted,
    ) == {"krusty-kms"}
    assert krusty_deps_from_cargo_toml(
        '[dependencies]\nkms.package = "krusty-kms"\nkms.path = "../kms"\n'
    ) == {"krusty-kms"}
    forbidden = krusty_deps_from_cargo_toml(
        '[dependencies]\nclient.package = "krusty-kms-client"\nclient.path = "../client"\n'
    )
    assert "krusty-kms-client" in forbidden
    assert production_dep_entries(
        '[dependencies]\nkms.package = "krusty-kms"\nkms.path = "../kms"\n'
    ) == [
        f"kms{_ENTRY_SEP}package = \"krusty-kms\"{_ENTRY_SEP}path = \"../kms\""
    ]
    assert production_dep_entries(
        '[dependencies]\nkms.package = "krusty-kms"\nkms.path = "../kms"\n'
    ) != production_dep_entries(
        '[dependencies]\nkms.package = "krusty-kms"\nkms.path = "../kms-v2"\n'
    )
    feats_a = """
[features]
default = []
nats = ["dep:async-nats"]
[dependencies]
async-nats = { version = "1", optional = true }
""".strip()
    feats_b = feats_a.replace("default = []", 'default = ["nats"]')
    assert any(e.startswith("[features].default") for e in production_dep_entries(feats_a))
    assert production_dep_entries(feats_a) != production_dep_entries(feats_b)
    feats_multiline = """
[features]
default = [
  "nats",
]
""".strip()
    assert production_dep_entries(feats_a) != production_dep_entries(feats_multiline)

    multiline_impl = """
impl Foo {
    #[wasm_bindgen(
        js_name = "doThing"
    )]
    pub fn do_thing(&self) {}
}
""".strip().splitlines()
    methods = _collect_impl_pub_fns(multiline_impl, 0, len(multiline_impl) - 1)
    assert len(methods) == 1
    assert "js_name=doThing" in _format_bindgen_attrs(methods[0][1])
    changed_impl = """
impl Foo {
    #[wasm_bindgen(
        js_name = "doThingV2"
    )]
    pub fn do_thing(&self) {}
}
""".strip().splitlines()
    changed_methods = _collect_impl_pub_fns(changed_impl, 0, len(changed_impl) - 1)
    assert _format_bindgen_attrs(methods[0][1]) != _format_bindgen_attrs(
        changed_methods[0][1]
    )

    extern_fn = (
        'pub unsafe extern "C" fn kms_stark_sign(\n'
        "  sk: *const u8,\n"
        ") -> i32"
    )
    extern_surface = extract_public_surface(extern_fn)
    assert extern_surface
    assert "kms_stark_sign" in next(iter(extern_surface))
    assert extract_public_surface(extern_fn) != extract_public_surface(
        extern_fn.replace("*const u8", "*const i32")
    )
    assert is_exported_crate_source("crates/ffi/src/signing.rs", repo_root())

    fn_where = """
pub fn serialize_cairo_some<F>(f: F) -> Vec<Felt>
where
    F: FnOnce() -> Vec<Felt>,
{
    f()
}
""".strip()
    assert any("where" in s and "FnOnce" in s for s in extract_public_surface(fn_where))
    assert extract_public_surface(fn_where) != extract_public_surface(
        fn_where.replace("FnOnce", "FnMut")
    )

    trait_src = """
pub trait WalletExecutor: Send + Sync {
    async fn execute(&self, calls: Vec<Call>) -> Result<Tx>;
    async fn estimate_fee(&self, calls: Vec<Call>) -> Result<FeeEstimate>;
}
""".strip()
    changed_trait = trait_src.replace("estimate_fee", "estimate_fee_v2")
    assert extract_public_surface(trait_src) != extract_public_surface(changed_trait)

    trait_assoc = """
pub trait Provider {
    type Error;
    const ID: u8;
    fn get(&self) -> Result<(), Self::Error>;
}
""".strip()
    assert extract_public_surface(trait_assoc) != extract_public_surface(
        trait_assoc.replace("type Error;", "type Error: Debug;")
    )
    assert extract_public_surface(trait_assoc) != extract_public_surface(
        trait_assoc.replace("const ID: u8;", "const ID: u16;")
    )
    assert any("type Error;" in s for s in extract_public_surface(trait_assoc))
    assert any("const ID: u8;" in s for s in extract_public_surface(trait_assoc))

    use_a = """
pub use operations::{
    fund, transfer,
};
""".strip()
    use_b = """
pub use operations::{
    fund, transfer, withdraw,
};
""".strip()
    assert extract_public_surface(use_a) != extract_public_surface(use_b)

    cfg_use = """
#[cfg(feature = "nats")]
pub use multisig::NatsMultisigCoordinator;
""".strip()
    no_cfg_use = "pub use multisig::NatsMultisigCoordinator;"
    assert extract_public_surface(cfg_use) != extract_public_surface(no_cfg_use)
    assert any('#[cfg(feature = "nats")]' in s for s in extract_public_surface(cfg_use))

    mod_a = """
pub mod secret_felt;
pub mod other;
""".strip()
    mod_b = """
pub mod secret_felt;
#[allow(unsafe_code)]
pub mod other;
""".strip()
    mod_c = """
#[allow(unsafe_code)]
pub mod secret_felt;
pub mod other;
""".strip()
    surface_a = extract_public_surface(mod_a)
    surface_b = extract_public_surface(mod_b)
    surface_c = extract_public_surface(mod_c)
    assert surface_a == surface_b
    assert "pub mod secret_felt;" in surface_a
    assert "pub mod other;" in surface_a
    assert surface_a == surface_c

    enum_unit_and_tuple = """
pub enum KmsError {
    Other,
    InvalidPublicKey(String),
}
""".strip()
    enum_tuple_felt = enum_unit_and_tuple.replace("InvalidPublicKey(String)", "InvalidPublicKey(Felt)")
    enum_surface_string = extract_public_surface(enum_unit_and_tuple)
    enum_surface_felt = extract_public_surface(enum_tuple_felt)
    assert enum_surface_string != enum_surface_felt
    assert "InvalidPublicKey(String)" in next(
        s for s in enum_surface_string if s.startswith("pub enum KmsError")
    )
    assert "InvalidPublicKey(Felt)" in next(
        s for s in enum_surface_felt if s.startswith("pub enum KmsError")
    )
    assert "Other" in next(s for s in enum_surface_string if s.startswith("pub enum KmsError"))

    enum_struct = """
pub enum KmsError {
    Other,
    Detailed {
        code: u32,
        message: String,
    },
}
""".strip()
    enum_struct_changed = enum_struct.replace("message: String", "message: Felt")
    assert extract_public_surface(enum_struct) != extract_public_surface(enum_struct_changed)

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src = root / "crates/synthetic/src"
        src.mkdir(parents=True)
        (src / "lib.rs").write_text(
            "\n".join(
                [
                    "mod wallet;",
                    "pub use wallet::Wallet;",
                    "pub mod discovery;",
                ]
            )
            + "\n"
        )
        wallet_dir = src / "wallet"
        wallet_dir.mkdir()
        (wallet_dir / "mod.rs").write_text(
            "\n".join(
                [
                    "pub mod utils;",
                    "pub struct Wallet;",
                ]
            )
            + "\n"
        )
        (wallet_dir / "utils.rs").write_text("pub fn foo() {}\n")
        (src / "discovery.rs").write_text("pub fn discover() {}\n")

        rel_utils = "crates/synthetic/src/wallet/utils.rs"
        rel_wallet_mod = "crates/synthetic/src/wallet/mod.rs"
        rel_discovery = "crates/synthetic/src/discovery.rs"
        rel_lib = "crates/synthetic/src/lib.rs"

        assert not is_exported_crate_source(rel_utils, root)
        assert is_exported_crate_source(rel_wallet_mod, root)
        assert is_exported_crate_source(rel_discovery, root)
        assert is_exported_crate_source(rel_lib, root)

        utils_text = (wallet_dir / "utils.rs").read_text()
        wallet_text = (wallet_dir / "mod.rs").read_text()
        wallet_changed = wallet_text.replace("pub struct Wallet;", "pub struct WalletV2;")
        assert extract_public_surface("") != extract_public_surface(utils_text)
        assert not is_exported_crate_source(rel_utils, root)
        assert is_exported_crate_source(rel_wallet_mod, root)
        assert extract_public_surface(wallet_text) != extract_public_surface(wallet_changed)

        client_utils = "crates/client/src/wallet/utils.rs"
        client_wallet_mod = "crates/client/src/wallet/mod.rs"
        client_discovery = "crates/client/src/discovery.rs"
        assert not is_exported_crate_source(client_utils, repo_root())
        assert is_exported_crate_source(client_wallet_mod, repo_root())
        assert is_exported_crate_source(client_discovery, repo_root())


def _assert_file_size_ratchet_checks() -> None:
    import tempfile

    head = {
        "soft_limit": 350,
        "hard_limit_new_files": 500,
        "files": [
            {"path": "crates/old/src/lib.rs", "lines": 400},
            {"path": "crates/new/src/huge.rs", "lines": 600},
        ],
    }
    base_known = {"crates/old/src/lib.rs": 400}
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        old = root / "crates/old/src"
        new = root / "crates/new/src"
        old.mkdir(parents=True)
        new.mkdir(parents=True)
        (old / "lib.rs").write_text("\n" * 400)
        (new / "huge.rs").write_text("\n" * 600)

        # Existing-on-base but newly baselined over hard_new → fail.
        code, lines = check_file_size_ratchet(head, root, base_known=base_known)
        assert code == 1
        assert any("hard size limit" in line for line in lines)
        assert any("crates/new/src/huge.rs" in line for line in lines)

        # Without base baseline/ref, grandfathered known files are not re-checked.
        code, lines = check_file_size_ratchet(head, root, base_known=None, base_ref=None)
        assert code == 0
        assert any(line.startswith("file-size ratchet ok") for line in lines)

        unbaselined = root / "crates/fresh/src"
        unbaselined.mkdir(parents=True)
        (unbaselined / "big.rs").write_text("\n" * 501)
        code, lines = check_file_size_ratchet(head, root, base_known=base_known)
        assert code == 1
        assert any("hard size limit" in line for line in lines)

        # Brand-new file over hard_new is rejected even when baselined, when
        # base_ref reports the path as absent (simulate with a bogus ref and
        # direct path_exists override via missing base_ref semantics: use a
        # base_ref that makes cat-file fail for the new path).
        # Here we call with base_ref set to an empty tree-ish that won't have
        # the path: use HEAD with a synthetic relative path check by temporarily
        # pointing base_ref at a commit that lacks crates/new.
        # Simpler: monkey-check via path_exists_on_ref returning False when
        # base_ref is "__missing__" (git cat-file fails).
        code, lines = check_file_size_ratchet(
            head, root, base_known=None, base_ref="__missing_ref__"
        )
        assert code == 1
        assert any("crates/new/src/huge.rs" in line for line in lines)
        assert any("baselining does not waive" in line for line in lines)


if __name__ == "__main__":
    _assert_surfaces_self_checks()
    _assert_file_size_ratchet_checks()
