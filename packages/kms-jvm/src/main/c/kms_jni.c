/* Request C11 Annex K (memset_s) before any system header pulls in string.h. */
#define __STDC_WANT_LIB_EXT1__ 1

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <strings.h>
#endif

#include "kms.h"

/* ====================================================================== */
/* Helpers                                                                  */
/* ====================================================================== */

/* Best-effort wipe of secret buffers before free / scope exit. */
static void secure_wipe(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }
#if defined(__APPLE__)
    /* macOS has no explicit_bzero; memset_s is the non-optimizable equivalent. */
    memset_s(ptr, len, 0, len);
#elif defined(__linux__)
    explicit_bzero(ptr, len);
#else
    {
        volatile unsigned char *p = (volatile unsigned char *)ptr;
        while (len--) {
            *p++ = 0;
        }
    }
#endif
}

static void secure_free(void *ptr, size_t len) {
    secure_wipe(ptr, len);
    free(ptr);
}

static void throw_kms_error(JNIEnv *env, int32_t code) {
    const char *msg = kms_error_message(code);
    jclass ex = (*env)->FindClass(env, "io/krustykms/KmsException");
    if (ex == NULL) {
        ex = (*env)->FindClass(env, "java/lang/RuntimeException");
    }
    if (ex != NULL) {
        char buf[256];
        snprintf(buf, sizeof(buf), "kms error %d: %s", code, msg ? msg : "unknown");
        (*env)->ThrowNew(env, ex, buf);
    }
}

/* GetStringUTFChars with NULL checks. Returns NULL and throws on failure. */
static const char *require_utf_chars(JNIEnv *env, jstring s) {
    if (s == NULL) {
        throw_kms_error(env, KMS_ERR_NULL_POINTER);
        return NULL;
    }
    const char *p = (*env)->GetStringUTFChars(env, s, NULL);
    if (p == NULL) {
        if (!(*env)->ExceptionCheck(env)) {
            throw_kms_error(env, KMS_ERR_INTERNAL);
        }
        return NULL;
    }
    return p;
}

/* Optional UTF chars: NULL jstring → empty C string (static). */
static const char *optional_utf_chars(JNIEnv *env, jstring s, int *is_empty_literal) {
    *is_empty_literal = 0;
    if (s == NULL) {
        *is_empty_literal = 1;
        return "";
    }
    return require_utf_chars(env, s);
}

static jbyteArray felt_to_jbytearray(JNIEnv *env, const KmsFelt *felt) {
    jbyteArray arr = (*env)->NewByteArray(env, 32);
    if (arr == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, arr, 0, 32, (const jbyte *)felt->bytes);
    return arr;
}

/* Read exactly 32 bytes from a Java byte array into a felt.
 * Returns 0 on success; on NULL, wrong length, or a pending JNI exception it
 * throws and returns non-zero. Callers MUST check the return value:
 * GetByteArrayRegion on a NULL/short array crashes the JVM, and continuing
 * after a pending exception is undefined behavior. */
static int jbytearray_to_felt(JNIEnv *env, jbyteArray arr, KmsFelt *out) {
    if (arr == NULL) {
        throw_kms_error(env, KMS_ERR_NULL_POINTER);
        return -1;
    }
    if ((*env)->GetArrayLength(env, arr) != 32) {
        throw_kms_error(env, KMS_ERR_INVALID_INPUT);
        return -1;
    }
    (*env)->GetByteArrayRegion(env, arr, 0, 32, (jbyte *)out->bytes);
    if ((*env)->ExceptionCheck(env)) {
        return -1;
    }
    return 0;
}

/* Returns a concatenated byte array of N*32 bytes for a projective point (x,y,z) */
static jbyteArray projective_to_jbytearray(JNIEnv *env, const KmsProjectivePoint *pt) {
    jbyteArray arr = (*env)->NewByteArray(env, 96);
    if (arr == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, arr, 0, 32, (const jbyte *)pt->x.bytes);
    (*env)->SetByteArrayRegion(env, arr, 32, 32, (const jbyte *)pt->y.bytes);
    (*env)->SetByteArrayRegion(env, arr, 64, 32, (const jbyte *)pt->z.bytes);
    return arr;
}

static int jbytearrays_to_projective(JNIEnv *env, jbyteArray x, jbyteArray y, jbyteArray z, KmsProjectivePoint *out) {
    if (jbytearray_to_felt(env, x, &out->x)) return -1;
    if (jbytearray_to_felt(env, y, &out->y)) return -1;
    if (jbytearray_to_felt(env, z, &out->z)) return -1;
    return 0;
}

/* Two-call dynamic string pattern: returns a newly allocated Java String */
static jstring string_dynamic(JNIEnv *env,
    int32_t (*fn)(const char*, char*, size_t, size_t*),
    const char *input) {
    size_t needed = 0;
    int32_t rc = fn(input, NULL, 0, &needed);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }

    size_t capacity = needed + 1;
    char *buf = (char *)malloc(capacity);
    if (buf == NULL) {
        throw_kms_error(env, KMS_ERR_INTERNAL);
        return NULL;
    }

    size_t written = 0;
    rc = fn(input, buf, capacity, &written);
    if (rc != KMS_OK) { secure_free(buf, capacity); throw_kms_error(env, rc); return NULL; }

    buf[written] = '\0';
    jstring result = (*env)->NewStringUTF(env, buf);
    secure_free(buf, capacity);
    return result;
}

/* Two-call dynamic string pattern for handle-based proof functions */
static jstring string_dynamic_handle(JNIEnv *env,
    int32_t (*fn)(KmsAccountHandle, const char*, char*, size_t, size_t*),
    KmsAccountHandle handle, const char *input) {
    size_t needed = 0;
    int32_t rc = fn(handle, input, NULL, 0, &needed);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }

    size_t capacity = needed + 1;
    char *buf = (char *)malloc(capacity);
    if (buf == NULL) {
        throw_kms_error(env, KMS_ERR_INTERNAL);
        return NULL;
    }

    size_t written = 0;
    rc = fn(handle, input, buf, capacity, &written);
    if (rc != KMS_OK) { secure_free(buf, capacity); throw_kms_error(env, rc); return NULL; }

    buf[written] = '\0';
    jstring result = (*env)->NewStringUTF(env, buf);
    secure_free(buf, capacity);
    return result;
}

/* Two-call dynamic string for parameterless functions */
static jstring string_dynamic_noarg(JNIEnv *env,
    int32_t (*fn)(char*, size_t, size_t*)) {
    size_t needed = 0;
    int32_t rc = fn(NULL, 0, &needed);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }

    size_t capacity = needed + 1;
    char *buf = (char *)malloc(capacity);
    if (buf == NULL) {
        throw_kms_error(env, KMS_ERR_INTERNAL);
        return NULL;
    }

    size_t written = 0;
    rc = fn(buf, capacity, &written);
    if (rc != KMS_OK) { secure_free(buf, capacity); throw_kms_error(env, rc); return NULL; }

    buf[written] = '\0';
    jstring result = (*env)->NewStringUTF(env, buf);
    secure_free(buf, capacity);
    return result;
}

/* ====================================================================== */
/* Version / ABI                                                           */
/* ====================================================================== */

JNIEXPORT jintArray JNICALL Java_io_krustykms_KmsNative_getAbiVersion(
    JNIEnv *env, jclass cls) {
    (void)cls;
    uint32_t major = 0, minor = 0;
    int32_t rc = kms_get_abi_version(&major, &minor);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }

    jintArray arr = (*env)->NewIntArray(env, 2);
    if (arr == NULL) return NULL;
    jint vals[2] = { (jint)major, (jint)minor };
    (*env)->SetIntArrayRegion(env, arr, 0, 2, vals);
    return arr;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_getVersionString(
    JNIEnv *env, jclass cls) {
    (void)cls;
    return string_dynamic_noarg(env, kms_get_version_string);
}

/* ====================================================================== */
/* Felt ops                                                                */
/* ====================================================================== */

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_feltFromHex(
    JNIEnv *env, jclass cls, jstring hex) {
    (void)cls;
    const char *h = require_utf_chars(env, hex);
    if (h == NULL) return NULL;
    KmsFelt out;
    int32_t rc = kms_felt_from_hex(h, &out);
    (*env)->ReleaseStringUTFChars(env, hex, h);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }
    return felt_to_jbytearray(env, &out);
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_feltToHex(
    JNIEnv *env, jclass cls, jbyteArray value) {
    (void)cls;
    KmsFelt felt;
    if (jbytearray_to_felt(env, value, &felt)) return NULL;

    size_t written = 0;
    int32_t rc = kms_felt_to_hex(&felt, NULL, 0, &written);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }

    char *buf = (char *)malloc(written + 1);
    if (buf == NULL) { throw_kms_error(env, KMS_ERR_INTERNAL); return NULL; }

    rc = kms_felt_to_hex(&felt, buf, written + 1, &written);
    if (rc != KMS_OK) { free(buf); throw_kms_error(env, rc); return NULL; }

    buf[written] = '\0';
    jstring result = (*env)->NewStringUTF(env, buf);
    free(buf);
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_feltFromBytesBe(
    JNIEnv *env, jclass cls, jbyteArray bytes) {
    (void)cls;
    if (bytes == NULL) {
        throw_kms_error(env, KMS_ERR_NULL_POINTER);
        return NULL;
    }
    jsize len = (*env)->GetArrayLength(env, bytes);
    jbyte *data = (*env)->GetByteArrayElements(env, bytes, NULL);
    if (data == NULL) {
        /* Preserve a pending JVM exception (e.g. OOM) from GetByteArrayElements. */
        if (!(*env)->ExceptionCheck(env)) {
            throw_kms_error(env, KMS_ERR_INTERNAL);
        }
        return NULL;
    }
    KmsFelt out;
    int32_t rc = kms_felt_from_bytes_be((const uint8_t *)data, (size_t)len, &out);
    (*env)->ReleaseByteArrayElements(env, bytes, data, JNI_ABORT);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }
    return felt_to_jbytearray(env, &out);
}

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_feltToBytesBe(
    JNIEnv *env, jclass cls, jbyteArray value) {
    (void)cls;
    KmsFelt felt;
    if (jbytearray_to_felt(env, value, &felt)) return NULL;
    uint8_t out[32];
    size_t written = 0;
    int32_t rc = kms_felt_to_bytes_be(&felt, out, 32, &written);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }
    jbyteArray arr = (*env)->NewByteArray(env, (jsize)written);
    if (arr == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, arr, 0, (jsize)written, (const jbyte *)out);
    return arr;
}

/* ====================================================================== */
/* Point ops                                                               */
/* ====================================================================== */

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_projectiveFromAffine(
    JNIEnv *env, jclass cls, jbyteArray affineX, jbyteArray affineY) {
    (void)cls;
    KmsAffinePoint affine;
    if (jbytearray_to_felt(env, affineX, &affine.x)) return NULL;
    if (jbytearray_to_felt(env, affineY, &affine.y)) return NULL;
    KmsProjectivePoint out;
    int32_t rc = kms_projective_from_affine(&affine, &out);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }
    return projective_to_jbytearray(env, &out);
}

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_projectiveToAffine(
    JNIEnv *env, jclass cls, jbyteArray pointX, jbyteArray pointY, jbyteArray pointZ) {
    (void)cls;
    KmsProjectivePoint pt;
    if (jbytearrays_to_projective(env, pointX, pointY, pointZ, &pt)) return NULL;
    KmsAffinePoint out;
    int32_t rc = kms_projective_to_affine(&pt, &out);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }
    jbyteArray arr = (*env)->NewByteArray(env, 64);
    if (arr == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, arr, 0, 32, (const jbyte *)out.x.bytes);
    (*env)->SetByteArrayRegion(env, arr, 32, 32, (const jbyte *)out.y.bytes);
    return arr;
}

/* ====================================================================== */
/* Hash                                                                    */
/* ====================================================================== */

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_pedersenHash(
    JNIEnv *env, jclass cls, jbyteArray left, jbyteArray right) {
    (void)cls;
    KmsFelt l, r, out;
    if (jbytearray_to_felt(env, left, &l)) return NULL;
    if (jbytearray_to_felt(env, right, &r)) return NULL;
    int32_t rc = kms_pedersen_hash(&l, &r, &out);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }
    return felt_to_jbytearray(env, &out);
}

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_poseidonHashMany(
    JNIEnv *env, jclass cls, jobjectArray values) {
    (void)cls;
    if (values == NULL) { throw_kms_error(env, KMS_ERR_NULL_POINTER); return NULL; }
    jsize count = (*env)->GetArrayLength(env, values);
    KmsFelt *felts = NULL;
    if (count > 0) {
        /* On 32-bit targets count * sizeof(KmsFelt) can wrap, undersizing the
           allocation while the loop below writes count elements. */
        if ((size_t)count > SIZE_MAX / sizeof(KmsFelt)) {
            throw_kms_error(env, KMS_ERR_INVALID_INPUT);
            return NULL;
        }
        felts = (KmsFelt *)calloc((size_t)count, sizeof(KmsFelt));
        if (felts == NULL) { throw_kms_error(env, KMS_ERR_INTERNAL); return NULL; }
        for (jsize i = 0; i < count; i++) {
            jbyteArray elem = (jbyteArray)(*env)->GetObjectArrayElement(env, values, i);
            if (elem == NULL || jbytearray_to_felt(env, elem, &felts[i])) {
                if (elem != NULL) (*env)->DeleteLocalRef(env, elem);
                free(felts);
                if (!(*env)->ExceptionCheck(env)) {
                    throw_kms_error(env, KMS_ERR_NULL_POINTER);
                }
                return NULL;
            }
            (*env)->DeleteLocalRef(env, elem);
        }
    }
    KmsFelt out;
    int32_t rc = kms_poseidon_hash_many(felts, (size_t)count, &out);
    free(felts);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }
    return felt_to_jbytearray(env, &out);
}

/* ====================================================================== */
/* Mnemonic                                                                */
/* ====================================================================== */

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_generateMnemonic(
    JNIEnv *env, jclass cls, jint wordCount) {
    (void)cls;
    /* Random each call: do not size from a probe phrase. Use a fixed
     * capacity with grow-on-BUFFER_TOO_SMALL, and always wipe `capacity`. */
    size_t capacity = 512;
    for (int attempt = 0; attempt < 4; attempt++) {
        char *buf = (char *)malloc(capacity);
        if (buf == NULL) { throw_kms_error(env, KMS_ERR_INTERNAL); return NULL; }

        size_t written = 0;
        int32_t rc = kms_generate_mnemonic((uint32_t)wordCount, buf, capacity, &written);
        if (rc == KMS_OK) {
            buf[written] = '\0';
            jstring result = (*env)->NewStringUTF(env, buf);
            secure_free(buf, capacity);
            return result;
        }
        if (rc == KMS_ERR_BUFFER_TOO_SMALL && written + 1 > capacity) {
            secure_free(buf, capacity);
            capacity = written + 1;
            continue;
        }
        secure_free(buf, capacity);
        throw_kms_error(env, rc);
        return NULL;
    }
    throw_kms_error(env, KMS_ERR_INTERNAL);
    return NULL;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_generateMnemonicFromEntropy(
    JNIEnv *env, jclass cls, jbyteArray entropy) {
    (void)cls;
    if (entropy == NULL) {
        throw_kms_error(env, KMS_ERR_NULL_POINTER);
        return NULL;
    }

    jsize len = (*env)->GetArrayLength(env, entropy);
    jbyte *data = (*env)->GetByteArrayElements(env, entropy, NULL);
    if (data == NULL) {
        /* Preserve a pending JVM exception (e.g. OOM) from GetByteArrayElements. */
        if (!(*env)->ExceptionCheck(env)) {
            throw_kms_error(env, KMS_ERR_INTERNAL);
        }
        return NULL;
    }

    size_t needed = 0;
    int32_t rc = kms_generate_mnemonic_from_entropy(
        (const uint8_t *)data, (size_t)len, NULL, 0, &needed);
    if (rc != KMS_OK) {
        (*env)->ReleaseByteArrayElements(env, entropy, data, JNI_ABORT);
        throw_kms_error(env, rc);
        return NULL;
    }

    size_t capacity = needed + 1;
    char *buf = (char *)malloc(capacity);
    if (buf == NULL) {
        (*env)->ReleaseByteArrayElements(env, entropy, data, JNI_ABORT);
        throw_kms_error(env, KMS_ERR_INTERNAL);
        return NULL;
    }

    size_t written = 0;
    rc = kms_generate_mnemonic_from_entropy(
        (const uint8_t *)data, (size_t)len, buf, capacity, &written);
    (*env)->ReleaseByteArrayElements(env, entropy, data, JNI_ABORT);

    if (rc != KMS_OK) { secure_free(buf, capacity); throw_kms_error(env, rc); return NULL; }

    buf[written] = '\0';
    jstring result = (*env)->NewStringUTF(env, buf);
    secure_free(buf, capacity);
    return result;
}

JNIEXPORT jint JNICALL Java_io_krustykms_KmsNative_validateMnemonic(
    JNIEnv *env, jclass cls, jstring phrase) {
    (void)cls;
    const char *p = require_utf_chars(env, phrase);
    if (p == NULL) return KMS_ERR_NULL_POINTER;
    int32_t rc = kms_validate_mnemonic(p);
    (*env)->ReleaseStringUTFChars(env, phrase, p);
    return rc;
}

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_mnemonicToSeed(
    JNIEnv *env, jclass cls, jstring phrase, jstring passphrase) {
    (void)cls;
    const char *p = require_utf_chars(env, phrase);
    if (p == NULL) return NULL;
    int pp_literal = 0;
    const char *pp = optional_utf_chars(env, passphrase, &pp_literal);
    if (pp == NULL) {
        (*env)->ReleaseStringUTFChars(env, phrase, p);
        return NULL;
    }

    uint8_t out[64];
    size_t written = 0;
    int32_t rc = kms_mnemonic_to_seed(p, pp, out, sizeof(out), &written);

    (*env)->ReleaseStringUTFChars(env, phrase, p);
    if (!pp_literal) {
        (*env)->ReleaseStringUTFChars(env, passphrase, pp);
    }

    if (rc != KMS_OK) {
        secure_wipe(out, sizeof(out));
        throw_kms_error(env, rc);
        return NULL;
    }

    jbyteArray arr = (*env)->NewByteArray(env, (jsize)written);
    if (arr == NULL) {
        secure_wipe(out, sizeof(out));
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, arr, 0, (jsize)written, (const jbyte *)out);
    secure_wipe(out, sizeof(out));
    return arr;
}

/* ====================================================================== */
/* Key derivation                                                          */
/* ====================================================================== */

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_derivePrivateKey(
    JNIEnv *env, jclass cls, jstring mnemonic, jint index,
    jint accountIndex, jint coinType, jstring passphrase) {
    (void)cls;
    const char *m = require_utf_chars(env, mnemonic);
    if (m == NULL) return NULL;
    int pp_literal = 0;
    const char *pp = optional_utf_chars(env, passphrase, &pp_literal);
    if (pp == NULL) {
        (*env)->ReleaseStringUTFChars(env, mnemonic, m);
        return NULL;
    }

    KmsFelt felt;
    int32_t rc = kms_derive_private_key_with_coin_type(
        m, (uint32_t)index, (uint32_t)accountIndex, (uint32_t)coinType, pp, &felt);

    (*env)->ReleaseStringUTFChars(env, mnemonic, m);
    if (!pp_literal) {
        (*env)->ReleaseStringUTFChars(env, passphrase, pp);
    }

    if (rc != KMS_OK) {
        secure_wipe(&felt, sizeof(felt));
        throw_kms_error(env, rc);
        return NULL;
    }
    jbyteArray arr = felt_to_jbytearray(env, &felt);
    secure_wipe(&felt, sizeof(felt));
    return arr;
}

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_deriveKeypair(
    JNIEnv *env, jclass cls, jstring mnemonic, jint index,
    jint accountIndex, jint coinType, jstring passphrase) {
    (void)cls;
    const char *m = require_utf_chars(env, mnemonic);
    if (m == NULL) return NULL;
    int pp_literal = 0;
    const char *pp = optional_utf_chars(env, passphrase, &pp_literal);
    if (pp == NULL) {
        (*env)->ReleaseStringUTFChars(env, mnemonic, m);
        return NULL;
    }

    KmsTongoKeyPair kp;
    memset(&kp, 0, sizeof(kp));
    int32_t rc = kms_derive_keypair_with_coin_type(
        m, (uint32_t)index, (uint32_t)accountIndex, (uint32_t)coinType, pp, &kp);

    (*env)->ReleaseStringUTFChars(env, mnemonic, m);
    if (!pp_literal) {
        (*env)->ReleaseStringUTFChars(env, passphrase, pp);
    }

    if (rc != KMS_OK) {
        secure_wipe(&kp, sizeof(kp));
        throw_kms_error(env, rc);
        return NULL;
    }

    /* Return 128 bytes: 32 private + 96 projective */
    jbyteArray arr = (*env)->NewByteArray(env, 128);
    if (arr == NULL) {
        secure_wipe(&kp, sizeof(kp));
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, arr, 0, 32, (const jbyte *)kp.private_key.bytes);
    (*env)->SetByteArrayRegion(env, arr, 32, 32, (const jbyte *)kp.public_key.x.bytes);
    (*env)->SetByteArrayRegion(env, arr, 64, 32, (const jbyte *)kp.public_key.y.bytes);
    (*env)->SetByteArrayRegion(env, arr, 96, 32, (const jbyte *)kp.public_key.z.bytes);
    secure_wipe(&kp, sizeof(kp));
    return arr;
}

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_deriveNostrPrivateKey(
    JNIEnv *env, jclass cls, jstring mnemonic, jint index,
    jint accountIndex, jstring passphrase) {
    (void)cls;
    const char *m = require_utf_chars(env, mnemonic);
    if (m == NULL) return NULL;
    int pp_literal = 0;
    const char *pp = optional_utf_chars(env, passphrase, &pp_literal);
    if (pp == NULL) {
        (*env)->ReleaseStringUTFChars(env, mnemonic, m);
        return NULL;
    }

    /* ABI: kms_derive_nostr_private_key always writes exactly 32 bytes. */
    uint8_t out[32];
    int32_t rc = kms_derive_nostr_private_key(
        m, (uint32_t)index, (uint32_t)accountIndex, pp, out);

    (*env)->ReleaseStringUTFChars(env, mnemonic, m);
    if (!pp_literal) {
        (*env)->ReleaseStringUTFChars(env, passphrase, pp);
    }

    if (rc != KMS_OK) {
        secure_wipe(out, sizeof(out));
        throw_kms_error(env, rc);
        return NULL;
    }

    jbyteArray arr = (*env)->NewByteArray(env, 32);
    if (arr == NULL) {
        secure_wipe(out, sizeof(out));
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, arr, 0, 32, (const jbyte *)out);
    secure_wipe(out, sizeof(out));
    return arr;
}

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_deriveNostrKeypair(
    JNIEnv *env, jclass cls, jstring mnemonic, jint index,
    jint accountIndex, jstring passphrase) {
    (void)cls;
    const char *m = require_utf_chars(env, mnemonic);
    if (m == NULL) return NULL;
    int pp_literal = 0;
    const char *pp = optional_utf_chars(env, passphrase, &pp_literal);
    if (pp == NULL) {
        (*env)->ReleaseStringUTFChars(env, mnemonic, m);
        return NULL;
    }

    KmsNostrKeyPair kp;
    memset(&kp, 0, sizeof(kp));
    int32_t rc = kms_derive_nostr_keypair(
        m, (uint32_t)index, (uint32_t)accountIndex, pp, &kp);

    (*env)->ReleaseStringUTFChars(env, mnemonic, m);
    if (!pp_literal) {
        (*env)->ReleaseStringUTFChars(env, passphrase, pp);
    }

    if (rc != KMS_OK) {
        secure_wipe(&kp, sizeof(kp));
        throw_kms_error(env, rc);
        return NULL;
    }

    jbyteArray arr = (*env)->NewByteArray(env, 64);
    if (arr == NULL) {
        secure_wipe(&kp, sizeof(kp));
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, arr, 0, 32, (const jbyte *)kp.private_key);
    (*env)->SetByteArrayRegion(env, arr, 32, 32, (const jbyte *)kp.public_key_xonly);
    secure_wipe(&kp, sizeof(kp));
    return arr;
}

/* ====================================================================== */
/* Address                                                                 */
/* ====================================================================== */

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_calculateContractAddress(
    JNIEnv *env, jclass cls, jbyteArray salt, jbyteArray classHash,
    jobjectArray constructorCalldata, jbyteArray deployerAddress) {
    (void)cls;
    KmsFelt cSalt, cClassHash, cDeployer, out;
    if (jbytearray_to_felt(env, salt, &cSalt)) return NULL;
    if (jbytearray_to_felt(env, classHash, &cClassHash)) return NULL;
    if (jbytearray_to_felt(env, deployerAddress, &cDeployer)) return NULL;
    if (constructorCalldata == NULL) { throw_kms_error(env, KMS_ERR_NULL_POINTER); return NULL; }

    jsize count = (*env)->GetArrayLength(env, constructorCalldata);
    KmsFelt *calldata = NULL;
    if (count > 0) {
        /* See poseidonHashMany: guard the allocation-size multiplication. */
        if ((size_t)count > SIZE_MAX / sizeof(KmsFelt)) {
            throw_kms_error(env, KMS_ERR_INVALID_INPUT);
            return NULL;
        }
        calldata = (KmsFelt *)calloc((size_t)count, sizeof(KmsFelt));
        if (calldata == NULL) { throw_kms_error(env, KMS_ERR_INTERNAL); return NULL; }
        for (jsize i = 0; i < count; i++) {
            jbyteArray elem = (jbyteArray)(*env)->GetObjectArrayElement(env, constructorCalldata, i);
            if (elem == NULL || jbytearray_to_felt(env, elem, &calldata[i])) {
                if (elem != NULL) (*env)->DeleteLocalRef(env, elem);
                free(calldata);
                if (!(*env)->ExceptionCheck(env)) {
                    throw_kms_error(env, KMS_ERR_NULL_POINTER);
                }
                return NULL;
            }
            (*env)->DeleteLocalRef(env, elem);
        }
    }

    int32_t rc = kms_calculate_contract_address(
        &cSalt, &cClassHash, calldata, (size_t)count, &cDeployer, &out);
    free(calldata);

    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }
    return felt_to_jbytearray(env, &out);
}

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_deriveOzAccountAddress(
    JNIEnv *env, jclass cls, jbyteArray publicKeyX, jbyteArray classHash, jbyteArray salt) {
    (void)cls;
    KmsFelt cPubKey, cClassHash, out;
    if (jbytearray_to_felt(env, publicKeyX, &cPubKey)) return NULL;
    if (jbytearray_to_felt(env, classHash, &cClassHash)) return NULL;

    KmsFelt cSalt;
    KmsFelt *pSalt = NULL;
    if (salt != NULL) {
        if (jbytearray_to_felt(env, salt, &cSalt)) return NULL;
        pSalt = &cSalt;
    }

    int32_t rc = kms_derive_oz_account_address(&cPubKey, &cClassHash, pSalt, &out);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }
    return felt_to_jbytearray(env, &out);
}

/* ====================================================================== */
/* Coin types                                                              */
/* ====================================================================== */

JNIEXPORT jint JNICALL Java_io_krustykms_KmsNative_coinTypeTongo(JNIEnv *env, jclass cls) {
    (void)env; (void)cls;
    return (jint)kms_get_coin_type_tongo();
}

JNIEXPORT jint JNICALL Java_io_krustykms_KmsNative_coinTypeStarknet(JNIEnv *env, jclass cls) {
    (void)env; (void)cls;
    return (jint)kms_get_coin_type_starknet();
}

JNIEXPORT jint JNICALL Java_io_krustykms_KmsNative_coinTypeNostr(JNIEnv *env, jclass cls) {
    (void)env; (void)cls;
    return (jint)kms_get_coin_type_nostr();
}

/* ====================================================================== */
/* Error                                                                   */
/* ====================================================================== */

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_errorName(
    JNIEnv *env, jclass cls, jint code) {
    (void)cls;
    const char *name = kms_error_name((int32_t)code);
    return (*env)->NewStringUTF(env, name ? name : "KMS_ERR_INTERNAL");
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_errorMessage(
    JNIEnv *env, jclass cls, jint code) {
    (void)cls;
    const char *msg = kms_error_message((int32_t)code);
    return (*env)->NewStringUTF(env, msg ? msg : "unknown error");
}

/* ====================================================================== */
/* Account management                                                      */
/* ====================================================================== */

JNIEXPORT jlong JNICALL Java_io_krustykms_KmsNative_accountCreateFromMnemonic(
    JNIEnv *env, jclass cls, jstring mnemonic, jint index,
    jint accountIndex, jbyteArray contractAddress, jstring passphrase) {
    (void)cls;
    const char *m = require_utf_chars(env, mnemonic);
    if (m == NULL) return 0;
    int pp_literal = 0;
    const char *pp = optional_utf_chars(env, passphrase, &pp_literal);
    if (pp == NULL) {
        (*env)->ReleaseStringUTFChars(env, mnemonic, m);
        return 0;
    }
    KmsFelt cAddr;
    if (jbytearray_to_felt(env, contractAddress, &cAddr)) {
        (*env)->ReleaseStringUTFChars(env, mnemonic, m);
        if (!pp_literal) {
            (*env)->ReleaseStringUTFChars(env, passphrase, pp);
        }
        return 0;
    }
    KmsAccountHandle handle = 0;

    int32_t rc = kms_account_create_from_mnemonic(
        m, (uint32_t)index, (uint32_t)accountIndex, &cAddr, pp, &handle);

    (*env)->ReleaseStringUTFChars(env, mnemonic, m);
    if (!pp_literal) {
        (*env)->ReleaseStringUTFChars(env, passphrase, pp);
    }

    if (rc != KMS_OK) { throw_kms_error(env, rc); return 0; }
    return (jlong)handle;
}

JNIEXPORT jlong JNICALL Java_io_krustykms_KmsNative_accountCreateFromPrivateKey(
    JNIEnv *env, jclass cls, jbyteArray privateKey,
    jbyteArray contractAddress) {
    (void)cls;
    KmsFelt cPrivateKey, cAddr;
    if (jbytearray_to_felt(env, privateKey, &cPrivateKey)) return 0;
    if (jbytearray_to_felt(env, contractAddress, &cAddr)) {
        secure_wipe(&cPrivateKey, sizeof(cPrivateKey));
        return 0;
    }
    KmsAccountHandle handle = 0;

    int32_t rc = kms_account_create_from_private_key(&cPrivateKey, &cAddr, &handle);
    secure_wipe(&cPrivateKey, sizeof(cPrivateKey));
    if (rc != KMS_OK) { throw_kms_error(env, rc); return 0; }
    return (jlong)handle;
}

JNIEXPORT jlongArray JNICALL Java_io_krustykms_KmsNative_accountGetState(
    JNIEnv *env, jclass cls, jlong handle) {
    (void)cls;
    KmsAccountState state;
    int32_t rc = kms_account_get_state((KmsAccountHandle)handle, &state);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }

    jlongArray arr = (*env)->NewLongArray(env, 5);
    if (arr == NULL) return NULL;
    jlong vals[5] = {
        (jlong)state.balance_low,
        (jlong)state.balance_high,
        (jlong)state.pending_balance_low,
        (jlong)state.pending_balance_high,
        (jlong)state.nonce
    };
    (*env)->SetLongArrayRegion(env, arr, 0, 5, vals);
    return arr;
}

JNIEXPORT void JNICALL Java_io_krustykms_KmsNative_accountUpdateState(
    JNIEnv *env, jclass cls, jlong handle,
    jlong balanceLow, jlong balanceHigh,
    jlong pendingBalanceLow, jlong pendingBalanceHigh, jlong nonce) {
    (void)cls;
    KmsAccountState state = {
        .balance_low = (uint64_t)balanceLow,
        .balance_high = (uint64_t)balanceHigh,
        .pending_balance_low = (uint64_t)pendingBalanceLow,
        .pending_balance_high = (uint64_t)pendingBalanceHigh,
        .nonce = (uint64_t)nonce
    };
    int32_t rc = kms_account_update_state((KmsAccountHandle)handle, &state);
    if (rc != KMS_OK) { throw_kms_error(env, rc); }
}

JNIEXPORT void JNICALL Java_io_krustykms_KmsNative_accountDestroy(
    JNIEnv *env, jclass cls, jlong handle) {
    (void)cls;
    int32_t rc = kms_account_destroy((KmsAccountHandle)handle);
    if (rc != KMS_OK) { throw_kms_error(env, rc); }
}

/* ====================================================================== */
/* Proof generation                                                        */
/* ====================================================================== */

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_generateFundProof(
    JNIEnv *env, jclass cls, jlong handle, jstring paramsJson) {
    (void)cls;
    const char *json = require_utf_chars(env, paramsJson);
    if (json == NULL) return NULL;
    jstring result = string_dynamic_handle(env, kms_generate_fund_proof,
        (KmsAccountHandle)handle, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_generateTransferProof(
    JNIEnv *env, jclass cls, jlong handle, jstring paramsJson) {
    (void)cls;
    const char *json = require_utf_chars(env, paramsJson);
    if (json == NULL) return NULL;
    jstring result = string_dynamic_handle(env, kms_generate_transfer_proof,
        (KmsAccountHandle)handle, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_generateRolloverProof(
    JNIEnv *env, jclass cls, jlong handle, jstring paramsJson) {
    (void)cls;
    const char *json = require_utf_chars(env, paramsJson);
    if (json == NULL) return NULL;
    jstring result = string_dynamic_handle(env, kms_generate_rollover_proof,
        (KmsAccountHandle)handle, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_generateWithdrawProof(
    JNIEnv *env, jclass cls, jlong handle, jstring paramsJson) {
    (void)cls;
    const char *json = require_utf_chars(env, paramsJson);
    if (json == NULL) return NULL;
    jstring result = string_dynamic_handle(env, kms_generate_withdraw_proof,
        (KmsAccountHandle)handle, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_generateRagequitProof(
    JNIEnv *env, jclass cls, jlong handle, jstring paramsJson) {
    (void)cls;
    const char *json = require_utf_chars(env, paramsJson);
    if (json == NULL) return NULL;
    jstring result = string_dynamic_handle(env, kms_generate_ragequit_proof,
        (KmsAccountHandle)handle, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

/* ====================================================================== */
/* ElGamal                                                                 */
/* ====================================================================== */

/* Shared two-call encrypt path for the legacy and strong JNI exports. */
static jobjectArray elgamal_encrypt_jni(
    JNIEnv *env,
    jbyteArray message, jbyteArray pubX, jbyteArray pubY, jbyteArray pubZ,
    jbyteArray random, jbyteArray prefix, int strong) {
    KmsFelt cMsg, cRand, cPrefix;
    KmsProjectivePoint cPub;
    if (jbytearray_to_felt(env, message, &cMsg)) return NULL;
    if (jbytearrays_to_projective(env, pubX, pubY, pubZ, &cPub)) {
        /* cMsg is often a confidential amount; wipe even on early failure. */
        secure_wipe(&cMsg, sizeof(cMsg));
        return NULL;
    }
    if (jbytearray_to_felt(env, random, &cRand)) {
        secure_wipe(&cMsg, sizeof(cMsg));
        return NULL;
    }
    if (jbytearray_to_felt(env, prefix, &cPrefix)) {
        secure_wipe(&cMsg, sizeof(cMsg));
        secure_wipe(&cRand, sizeof(cRand));
        return NULL;
    }

    KmsProjectivePoint outL, outR;

    /* First call: get proof size */
    size_t written = 0;
    int32_t rc = strong
        ? kms_elgamal_encrypt_strong(
            &cMsg, &cPub, &cRand, &cPrefix, &outL, &outR, NULL, 0, &written)
        : kms_elgamal_encrypt(
            &cMsg, &cPub, &cRand, &cPrefix, &outL, &outR, NULL, 0, &written);
    if (rc != KMS_OK) {
        secure_wipe(&cMsg, sizeof(cMsg));
        secure_wipe(&cRand, sizeof(cRand));
        throw_kms_error(env, rc);
        return NULL;
    }

    char *proofBuf = (char *)malloc(written + 1);
    if (proofBuf == NULL) {
        secure_wipe(&cMsg, sizeof(cMsg));
        secure_wipe(&cRand, sizeof(cRand));
        throw_kms_error(env, KMS_ERR_INTERNAL);
        return NULL;
    }

    /* Second call: fill proof and ciphertext */
    rc = strong
        ? kms_elgamal_encrypt_strong(
            &cMsg, &cPub, &cRand, &cPrefix, &outL, &outR,
            proofBuf, written + 1, &written)
        : kms_elgamal_encrypt(
            &cMsg, &cPub, &cRand, &cPrefix, &outL, &outR,
            proofBuf, written + 1, &written);
    secure_wipe(&cMsg, sizeof(cMsg));
    secure_wipe(&cRand, sizeof(cRand));
    if (rc != KMS_OK) { free(proofBuf); throw_kms_error(env, rc); return NULL; }

    /* Build result: byte[][7] = {lx, ly, lz, rx, ry, rz, proofBytes} */
    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    jobjectArray result = (*env)->NewObjectArray(env, 7, byteArrayClass, NULL);
    if (result == NULL) { free(proofBuf); return NULL; }

    (*env)->SetObjectArrayElement(env, result, 0, felt_to_jbytearray(env, &outL.x));
    (*env)->SetObjectArrayElement(env, result, 1, felt_to_jbytearray(env, &outL.y));
    (*env)->SetObjectArrayElement(env, result, 2, felt_to_jbytearray(env, &outL.z));
    (*env)->SetObjectArrayElement(env, result, 3, felt_to_jbytearray(env, &outR.x));
    (*env)->SetObjectArrayElement(env, result, 4, felt_to_jbytearray(env, &outR.y));
    (*env)->SetObjectArrayElement(env, result, 5, felt_to_jbytearray(env, &outR.z));

    jbyteArray proofArr = (*env)->NewByteArray(env, (jsize)written);
    if (proofArr != NULL) {
        (*env)->SetByteArrayRegion(env, proofArr, 0, (jsize)written, (const jbyte *)proofBuf);
    }
    (*env)->SetObjectArrayElement(env, result, 6, proofArr);

    free(proofBuf);
    return result;
}

JNIEXPORT jobjectArray JNICALL Java_io_krustykms_KmsNative_elgamalEncrypt(
    JNIEnv *env, jclass cls,
    jbyteArray message, jbyteArray pubX, jbyteArray pubY, jbyteArray pubZ,
    jbyteArray random, jbyteArray prefix) {
    (void)cls;
    return elgamal_encrypt_jni(env, message, pubX, pubY, pubZ, random, prefix, 0);
}

JNIEXPORT jobjectArray JNICALL Java_io_krustykms_KmsNative_elgamalEncryptStrong(
    JNIEnv *env, jclass cls,
    jbyteArray message, jbyteArray pubX, jbyteArray pubY, jbyteArray pubZ,
    jbyteArray random, jbyteArray prefix) {
    (void)cls;
    return elgamal_encrypt_jni(env, message, pubX, pubY, pubZ, random, prefix, 1);
}

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_elgamalDecrypt(
    JNIEnv *env, jclass cls,
    jbyteArray ciphLX, jbyteArray ciphLY, jbyteArray ciphLZ,
    jbyteArray ciphRX, jbyteArray ciphRY, jbyteArray ciphRZ,
    jbyteArray privateKey) {
    (void)cls;
    KmsProjectivePoint cL, cR;
    KmsFelt cKey;
    if (jbytearrays_to_projective(env, ciphLX, ciphLY, ciphLZ, &cL)) return NULL;
    if (jbytearrays_to_projective(env, ciphRX, ciphRY, ciphRZ, &cR)) return NULL;
    if (jbytearray_to_felt(env, privateKey, &cKey)) return NULL;

    KmsProjectivePoint out;
    int32_t rc = kms_elgamal_decrypt(&cL, &cR, &cKey, &out);
    secure_wipe(&cKey, sizeof(cKey));
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }
    return projective_to_jbytearray(env, &out);
}

/* ====================================================================== */
/* Signing                                                                 */
/* ====================================================================== */

JNIEXPORT jobjectArray JNICALL Java_io_krustykms_KmsNative_starkSign(
    JNIEnv *env, jclass cls, jbyteArray hash, jbyteArray privateKey) {
    (void)cls;
    KmsFelt cHash, cKey, outR, outS;
    if (jbytearray_to_felt(env, hash, &cHash)) return NULL;
    if (jbytearray_to_felt(env, privateKey, &cKey)) return NULL;

    int32_t rc = kms_stark_sign(&cHash, &cKey, &outR, &outS);
    secure_wipe(&cKey, sizeof(cKey));
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }

    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    jobjectArray result = (*env)->NewObjectArray(env, 2, byteArrayClass, NULL);
    if (result == NULL) return NULL;
    (*env)->SetObjectArrayElement(env, result, 0, felt_to_jbytearray(env, &outR));
    (*env)->SetObjectArrayElement(env, result, 1, felt_to_jbytearray(env, &outS));
    return result;
}

JNIEXPORT jobjectArray JNICALL Java_io_krustykms_KmsNative_ethSign(
    JNIEnv *env, jclass cls, jbyteArray hash, jbyteArray ethPrivateKeyBytes) {
    (void)cls;
    KmsFelt cHash;
    if (jbytearray_to_felt(env, hash, &cHash)) return NULL;
    uint8_t keyBytes[32];
    if (ethPrivateKeyBytes == NULL || (*env)->GetArrayLength(env, ethPrivateKeyBytes) != 32) {
        throw_kms_error(env, ethPrivateKeyBytes == NULL ? KMS_ERR_NULL_POINTER : KMS_ERR_INVALID_INPUT);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, ethPrivateKeyBytes, 0, 32, (jbyte *)keyBytes);
    if ((*env)->ExceptionCheck(env)) {
        secure_wipe(keyBytes, sizeof(keyBytes));
        return NULL;
    }

    KmsEthSignature sig;
    int32_t rc = kms_eth_sign(&cHash, keyBytes, &sig);
    secure_wipe(keyBytes, sizeof(keyBytes));
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }

    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    jobjectArray result = (*env)->NewObjectArray(env, 5, byteArrayClass, NULL);
    if (result == NULL) return NULL;
    (*env)->SetObjectArrayElement(env, result, 0, felt_to_jbytearray(env, &sig.r_low));
    (*env)->SetObjectArrayElement(env, result, 1, felt_to_jbytearray(env, &sig.r_high));
    (*env)->SetObjectArrayElement(env, result, 2, felt_to_jbytearray(env, &sig.s_low));
    (*env)->SetObjectArrayElement(env, result, 3, felt_to_jbytearray(env, &sig.s_high));
    (*env)->SetObjectArrayElement(env, result, 4, felt_to_jbytearray(env, &sig.v));
    return result;
}

/* ====================================================================== */
/* Calldata encoding                                                       */
/* ====================================================================== */

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_encodeErc20Approve(
    JNIEnv *env, jclass cls, jstring paramsJson) {
    (void)cls;
    const char *json = require_utf_chars(env, paramsJson);
    if (json == NULL) return NULL;
    jstring result = string_dynamic(env, kms_encode_erc20_approve, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_encodeFundCalls(
    JNIEnv *env, jclass cls, jstring paramsJson) {
    (void)cls;
    const char *json = require_utf_chars(env, paramsJson);
    if (json == NULL) return NULL;
    jstring result = string_dynamic(env, kms_encode_fund_calls, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_encodeTransferCalls(
    JNIEnv *env, jclass cls, jstring paramsJson) {
    (void)cls;
    const char *json = require_utf_chars(env, paramsJson);
    if (json == NULL) return NULL;
    jstring result = string_dynamic(env, kms_encode_transfer_calls, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_encodeRolloverCalls(
    JNIEnv *env, jclass cls, jstring paramsJson) {
    (void)cls;
    const char *json = require_utf_chars(env, paramsJson);
    if (json == NULL) return NULL;
    jstring result = string_dynamic(env, kms_encode_rollover_calls, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_encodeWithdrawCalls(
    JNIEnv *env, jclass cls, jstring paramsJson) {
    (void)cls;
    const char *json = require_utf_chars(env, paramsJson);
    if (json == NULL) return NULL;
    jstring result = string_dynamic(env, kms_encode_withdraw_calls, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_encodeRagequitCalls(
    JNIEnv *env, jclass cls, jstring paramsJson) {
    (void)cls;
    const char *json = require_utf_chars(env, paramsJson);
    if (json == NULL) return NULL;
    jstring result = string_dynamic(env, kms_encode_ragequit_calls, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}
