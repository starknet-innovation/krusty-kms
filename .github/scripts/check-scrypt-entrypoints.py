#!/usr/bin/env python3
"""Reject production references to the non-wiping upstream scrypt function."""

from pathlib import Path
import re
import sys


DIRECT = re.compile(r"\bscrypt::scrypt\b")
IMPORT = re.compile(r"\buse\s+(?:::)?scrypt\s*(?:as\b|::(?:\*|\{))")
TEST_ALIASES = {
    "crates/kms/src/keystore.rs",
    "crates/kms/src/scrypt_wiping.rs",
}
ALLOWED_TEST_IMPORT = "use ::scrypt::scrypt as upstream_scrypt;"


def forbidden(source: str, relative_path: str) -> list[int]:
    lines = source.splitlines()
    test_marker = source.find("#[cfg(test)]\nmod tests {")
    failures = []
    offset = 0
    for number, line in enumerate(lines, 1):
        match = DIRECT.search(line) or IMPORT.search(line)
        if match and not line.lstrip().startswith(("//", "*")):
            allowed = (
                relative_path in TEST_ALIASES
                and test_marker >= 0
                and offset > test_marker
                and line.strip() == ALLOWED_TEST_IMPORT
            )
            if not allowed:
                failures.append(number)
        offset += len(line) + 1
    return failures


def self_test() -> None:
    production = "crates/kms/src/encryption.rs"
    for source in (
        "use scrypt::scrypt;",
        "use scrypt::scrypt as derive;",
        "use scrypt as upstream;",
        "use scrypt::{scrypt, Params};",
        "scrypt::scrypt(password, salt, params, out);",
    ):
        assert forbidden(source, production) == [1], source
    assert forbidden("use scrypt::Params;", production) == []
    test_source = "#[cfg(test)]\nmod tests {\n    use ::scrypt::scrypt as upstream_scrypt;\n}\n"
    assert forbidden(test_source, "crates/kms/src/scrypt_wiping.rs") == []


def main() -> int:
    self_test()
    root = Path(sys.argv[1]).resolve()
    base = root / "crates/kms/src"
    failures = []
    for path in sorted(base.rglob("*.rs")):
        relative = path.relative_to(root).as_posix()
        for number in forbidden(path.read_text(), relative):
            failures.append(f"{relative}:{number}")
    for location in failures:
        print(f"::error file={location}::upstream scrypt bypasses scratch wiping")
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
