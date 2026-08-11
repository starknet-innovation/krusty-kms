/* UTF-16 → standard UTF-8 conversion for the JNI boundary.
 *
 * Why this exists: JNI's GetStringUTFChars returns *modified* UTF-8 (CESU-8),
 * which encodes non-BMP code points as 6-byte surrogate pairs and U+0000 as
 * the overlong sequence 0xC0 0x80. Rust, Swift, and Dart all hand the KMS core
 * standard UTF-8, so a JVM caller using modified UTF-8 derives DIFFERENT keys
 * from the same passphrase — a cross-platform funds-availability divergence.
 *
 * Header-only and deliberately free of any JNI or KMS dependency so it can be
 * compiled and executed by a standalone regression test (see
 * ../../test/c/utf16_to_utf8_test.c). kms_jni.c passes `const jchar *` here,
 * which is `unsigned short` on every JNI platform.
 */

#ifndef KMS_UTF16_TO_UTF8_H
#define KMS_UTF16_TO_UTF8_H

#include <stddef.h>
#include <stdint.h>

/* Conversion outcomes. Callers map these onto their own error codes. */
typedef enum {
    KMS_UTF16_OK = 0,
    /* A high surrogate without a following low surrogate, or a lone low
     * surrogate. Rejected rather than substituted with U+FFFD, because a
     * replacement character would derive a key no other platform produces. */
    KMS_UTF16_ERR_UNPAIRED_SURROGATE = -1,
    /* An embedded U+0000. These strings cross the C ABI as NUL-terminated
     * `char *` and every downstream Rust parser uses `CStr::from_ptr`, which
     * truncates at the first NUL. Accepting one would silently derive the key
     * for the passphrase's *prefix* and discard the suffix, leaving funds
     * unreachable with no error. Reject instead. */
    KMS_UTF16_ERR_EMBEDDED_NUL = -2
} KmsUtf16Status;

/* Compute the standard UTF-8 byte length of a UTF-16 sequence (excluding the
 * NUL terminator the caller must allocate room for). On success writes the
 * length to *out and returns KMS_UTF16_OK; otherwise *out is untouched. */
static KmsUtf16Status kms_utf16_to_utf8_size(const uint16_t *chars, size_t len, size_t *out) {
    size_t total = 0;
    for (size_t i = 0; i < len; i++) {
        uint16_t c = chars[i];
        if (c == 0) {
            return KMS_UTF16_ERR_EMBEDDED_NUL;
        } else if (c < 0x80) {
            total += 1;
        } else if (c < 0x800) {
            total += 2;
        } else if (c >= 0xD800 && c <= 0xDBFF) {
            if (i + 1 >= len || chars[i + 1] < 0xDC00 || chars[i + 1] > 0xDFFF) {
                return KMS_UTF16_ERR_UNPAIRED_SURROGATE;
            }
            total += 4;
            i++;
        } else if (c >= 0xDC00 && c <= 0xDFFF) {
            return KMS_UTF16_ERR_UNPAIRED_SURROGATE;
        } else {
            total += 3;
        }
    }
    *out = total;
    return KMS_UTF16_OK;
}

/* Encode a UTF-16 sequence as standard UTF-8. `out` must have room for the
 * length reported by kms_utf16_to_utf8_size, which MUST have returned
 * KMS_UTF16_OK for this input first — this function assumes valid, NUL-free
 * input and performs no validation. Does not NUL-terminate. */
static void kms_utf16_to_utf8_write(const uint16_t *chars, size_t len, char *out) {
    unsigned char *p = (unsigned char *)out;
    for (size_t i = 0; i < len; i++) {
        uint32_t cp = chars[i];
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            uint32_t low = chars[++i];
            cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
        }
        if (cp < 0x80) {
            *p++ = (unsigned char)cp;
        } else if (cp < 0x800) {
            *p++ = (unsigned char)(0xC0 | (cp >> 6));
            *p++ = (unsigned char)(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            *p++ = (unsigned char)(0xE0 | (cp >> 12));
            *p++ = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
            *p++ = (unsigned char)(0x80 | (cp & 0x3F));
        } else {
            *p++ = (unsigned char)(0xF0 | (cp >> 18));
            *p++ = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
            *p++ = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
            *p++ = (unsigned char)(0x80 | (cp & 0x3F));
        }
    }
}

#endif /* KMS_UTF16_TO_UTF8_H */
