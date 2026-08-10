/* Regression tests for the JNI UTF-16 → standard UTF-8 conversion.
 *
 * Standalone: links nothing, needs no JVM and no libkms, so CI can actually
 * execute it (the Gradle build only compiles Java, and kms_jni.c is built
 * out-of-band against the Rust cdylib).
 *
 * Build and run:
 *   cc -Wall -Wextra -Werror -o /tmp/utf16_test \
 *      packages/kms-jvm/src/test/c/utf16_to_utf8_test.c && /tmp/utf16_test
 */

#include <stdio.h>
#include <string.h>

#include "../../main/c/utf16_to_utf8.h"

static int failures = 0;

static void check(int condition, const char *what) {
    if (!condition) {
        printf("FAIL: %s\n", what);
        failures++;
    } else {
        printf("ok: %s\n", what);
    }
}

/* Convert and compare against an expected byte sequence. */
static void expect_encodes(const uint16_t *utf16, size_t len16, const char *expected,
                           size_t expected_len, const char *what) {
    size_t len8 = 0;
    KmsUtf16Status status = kms_utf16_to_utf8_size(utf16, len16, &len8);
    if (status != KMS_UTF16_OK) {
        printf("FAIL: %s (size returned %d)\n", what, (int)status);
        failures++;
        return;
    }
    if (len8 != expected_len) {
        printf("FAIL: %s (len %zu, expected %zu)\n", what, len8, expected_len);
        failures++;
        return;
    }
    char buf[64];
    kms_utf16_to_utf8_write(utf16, len16, buf);
    check(memcmp(buf, expected, expected_len) == 0, what);
}

static void expect_rejects(const uint16_t *utf16, size_t len16, KmsUtf16Status expected,
                           const char *what) {
    size_t len8 = 12345;
    KmsUtf16Status status = kms_utf16_to_utf8_size(utf16, len16, &len8);
    if (status != expected) {
        printf("FAIL: %s (got %d, expected %d)\n", what, (int)status, (int)expected);
        failures++;
        return;
    }
    /* The out-param must be left untouched on rejection. */
    check(len8 == 12345, what);
}

int main(void) {
    /* ASCII. */
    {
        const uint16_t s[] = {'a', 'b', 'c'};
        expect_encodes(s, 3, "abc", 3, "ASCII passes through");
    }

    /* 2-byte: U+00E9 é → C3 A9. */
    {
        const uint16_t s[] = {0x00E9};
        expect_encodes(s, 1, "\xC3\xA9", 2, "U+00E9 encodes as 2 bytes");
    }

    /* 3-byte: U+20AC € → E2 82 AC. */
    {
        const uint16_t s[] = {0x20AC};
        expect_encodes(s, 1, "\xE2\x82\xAC", 3, "U+20AC encodes as 3 bytes");
    }

    /* 4-byte non-BMP: U+1F600 😀 as a surrogate pair → F0 9F 98 80.
     * This is the M-22 case: JNI modified UTF-8 would emit 6 bytes
     * (ED A0 BD ED B8 80) and derive a different key than Swift/Dart/Rust. */
    {
        const uint16_t s[] = {0xD83D, 0xDE00};
        expect_encodes(s, 2, "\xF0\x9F\x98\x80", 4, "non-BMP emoji encodes as 4-byte UTF-8");
    }

    /* Mixed, to catch index-advance bugs around the surrogate pair. */
    {
        const uint16_t s[] = {'x', 0xD83D, 0xDE00, 'y'};
        expect_encodes(s, 4, "x\xF0\x9F\x98\x80y", 6, "surrogate pair mid-string");
    }

    /* Embedded U+0000 must be rejected, not encoded as a real NUL: the Rust
     * side of this ABI reads these buffers with `CStr::from_ptr`, which
     * truncates there, so accepting it would derive the key for the
     * passphrase's prefix and silently discard the suffix. */
    {
        const uint16_t s[] = {'a', 0x0000, 'b'};
        expect_rejects(s, 3, KMS_UTF16_ERR_EMBEDDED_NUL, "embedded U+0000 rejected");
    }
    {
        const uint16_t s[] = {0x0000};
        expect_rejects(s, 1, KMS_UTF16_ERR_EMBEDDED_NUL, "lone U+0000 rejected");
    }
    {
        const uint16_t s[] = {'a', 'b', 0x0000};
        expect_rejects(s, 3, KMS_UTF16_ERR_EMBEDDED_NUL, "trailing U+0000 rejected");
    }

    /* Unpaired surrogates must be rejected rather than substituted with
     * U+FFFD, which would derive a key no other platform produces. */
    {
        const uint16_t s[] = {0xD83D};
        expect_rejects(s, 1, KMS_UTF16_ERR_UNPAIRED_SURROGATE, "lone high surrogate rejected");
    }
    {
        const uint16_t s[] = {0xDE00};
        expect_rejects(s, 1, KMS_UTF16_ERR_UNPAIRED_SURROGATE, "lone low surrogate rejected");
    }
    {
        const uint16_t s[] = {0xD83D, 'a'};
        expect_rejects(s, 2, KMS_UTF16_ERR_UNPAIRED_SURROGATE, "high surrogate + non-surrogate");
    }

    /* Empty input is valid and produces zero bytes. */
    {
        size_t len8 = 99;
        check(kms_utf16_to_utf8_size(NULL, 0, &len8) == KMS_UTF16_OK && len8 == 0,
              "empty input yields zero length");
    }

    if (failures != 0) {
        printf("\n%d test(s) failed\n", failures);
        return 1;
    }
    printf("\nall tests passed\n");
    return 0;
}
