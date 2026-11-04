"""Lexical scanner for Rust source shared by the guardrail scripts.

The scanner tracks nested block comments, line comments, string literals,
raw string literals and char literals across lines, so callers can separate
code from text without regex stripping. Regex stripping is order-dependent:
a `'"'` char literal reads as a string opener and a `"/*"` string literal as
a comment opener, and either hides whatever follows (audit 2026-11-04, M-5).
"""

from __future__ import annotations

import re

RAW_STRING_START = re.compile(r'(?:br|rb|r)(?P<hashes>#{0,})"')
CHAR_LITERAL = re.compile(
    r"'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|.)|[^\\'\r\n])'"
)
STRUCTURAL = "{}()[]<>"


class RustBraceScanner:
    """Separate Rust code from comments and literals, one line at a time.

    Lexical state (an open block comment, string or raw string) carries across
    calls, so feed a file's lines in order through one scanner instance.
    """

    def __init__(self) -> None:
        self.block_comment_depth = 0
        self.in_string = False
        self.string_escape = False
        self.raw_string_hashes: int | None = None

    def strip_line(self, line: str) -> str:
        """Return `line` with comments and literals replaced by spaces.

        Columns are preserved so callers can report positions in the original.
        """
        code: list[str] = []
        index = 0
        while index < len(line):
            consumed = self._consume_text(line, index)
            if consumed:
                code.append(" " * consumed)
                index += consumed
                continue
            if line.startswith("//", index):
                code.append(" " * (len(line) - index))
                break
            char = line[index]
            code.append(char)
            index += 1
        return "".join(code)

    def scan_line(self, line: str) -> tuple[int, list[str]]:
        """Return the brace-depth delta and structural tokens of `line`."""
        code = self.strip_line(line)
        structural_tokens = [char for char in code if char in STRUCTURAL]
        return code.count("{") - code.count("}"), structural_tokens

    def _consume_text(self, line: str, index: int) -> int:
        """Consume non-code text at `index`; return how many chars it spans (0 if code)."""
        if self.block_comment_depth:
            if line.startswith("/*", index):
                self.block_comment_depth += 1
                return 2
            if line.startswith("*/", index):
                self.block_comment_depth -= 1
                return 2
            return 1

        if self.raw_string_hashes is not None:
            terminator = '"' + "#" * self.raw_string_hashes
            if line.startswith(terminator, index):
                self.raw_string_hashes = None
                return len(terminator)
            return 1

        if self.in_string:
            char = line[index]
            if self.string_escape:
                self.string_escape = False
            elif char == "\\":
                self.string_escape = True
            elif char == '"':
                self.in_string = False
            return 1

        if line.startswith("/*", index):
            self.block_comment_depth = 1
            return 2

        raw_string = RAW_STRING_START.match(line, index)
        if raw_string:
            self.raw_string_hashes = len(raw_string.group("hashes"))
            return raw_string.end() - index

        char = line[index]
        if char == '"':
            self.in_string = True
            return 1
        if char == "'":
            char_literal = CHAR_LITERAL.match(line, index)
            if char_literal:
                return char_literal.end() - index
        return 0


def _self_test() -> None:
    scanner = RustBraceScanner()
    assert scanner.strip_line('let c = \'"\'; unsafe {') == "let c =    ; unsafe {"
    assert scanner.strip_line('let s = "/*"; unsafe {') == "let s =     ; unsafe {"
    assert scanner.strip_line("let s = r#\"a\"b\"#; {") == "let s = " + " " * 8 + "; {"
    assert scanner.strip_line("x /* unsafe { */ y").strip() == "x                y".strip()
    assert scanner.scan_line("fn f() { // }") == (1, ["(", ")", "{"])
    scanner.strip_line("/* open")
    assert scanner.strip_line("unsafe */ }").strip() == "}"
    scanner.strip_line('let s = "open')
    assert scanner.strip_line('unsafe" }').strip() == "}"
    assert scanner.strip_line("fn f<'a>(x: &'a str) -> &'a str {") == (
        "fn f<'a>(x: &'a str) -> &'a str {"
    )
    print("rust_scanner self-test ok")


if __name__ == "__main__":
    _self_test()
