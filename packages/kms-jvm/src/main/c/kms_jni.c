#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "kms.h"

/* ====================================================================== */
/* Helpers                                                                  */
/* ====================================================================== */

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

static jbyteArray felt_to_jbytearray(JNIEnv *env, const KmsFelt *felt) {
    jbyteArray arr = (*env)->NewByteArray(env, 32);
    if (arr == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, arr, 0, 32, (const jbyte *)felt->bytes);
    return arr;
}

static void jbytearray_to_felt(JNIEnv *env, jbyteArray arr, KmsFelt *out) {
    (*env)->GetByteArrayRegion(env, arr, 0, 32, (jbyte *)out->bytes);
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

static void jbytearrays_to_projective(JNIEnv *env, jbyteArray x, jbyteArray y, jbyteArray z, KmsProjectivePoint *out) {
    (*env)->GetByteArrayRegion(env, x, 0, 32, (jbyte *)out->x.bytes);
    (*env)->GetByteArrayRegion(env, y, 0, 32, (jbyte *)out->y.bytes);
    (*env)->GetByteArrayRegion(env, z, 0, 32, (jbyte *)out->z.bytes);
}

/* Two-call dynamic string pattern: returns a newly allocated Java String */
static jstring string_dynamic(JNIEnv *env,
    int32_t (*fn)(const char*, char*, size_t, size_t*),
    const char *input) {
    size_t written = 0;
    int32_t rc = fn(input, NULL, 0, &written);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }

    char *buf = (char *)malloc(written + 1);
    if (buf == NULL) {
        throw_kms_error(env, KMS_ERR_INTERNAL);
        return NULL;
    }

    rc = fn(input, buf, written + 1, &written);
    if (rc != KMS_OK) { free(buf); throw_kms_error(env, rc); return NULL; }

    buf[written] = '\0';
    jstring result = (*env)->NewStringUTF(env, buf);
    free(buf);
    return result;
}

/* Two-call dynamic string pattern for handle-based proof functions */
static jstring string_dynamic_handle(JNIEnv *env,
    int32_t (*fn)(KmsAccountHandle, const char*, char*, size_t, size_t*),
    KmsAccountHandle handle, const char *input) {
    size_t written = 0;
    int32_t rc = fn(handle, input, NULL, 0, &written);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }

    char *buf = (char *)malloc(written + 1);
    if (buf == NULL) {
        throw_kms_error(env, KMS_ERR_INTERNAL);
        return NULL;
    }

    rc = fn(handle, input, buf, written + 1, &written);
    if (rc != KMS_OK) { free(buf); throw_kms_error(env, rc); return NULL; }

    buf[written] = '\0';
    jstring result = (*env)->NewStringUTF(env, buf);
    free(buf);
    return result;
}

/* Two-call dynamic string for parameterless functions */
static jstring string_dynamic_noarg(JNIEnv *env,
    int32_t (*fn)(char*, size_t, size_t*)) {
    size_t written = 0;
    int32_t rc = fn(NULL, 0, &written);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }

    char *buf = (char *)malloc(written + 1);
    if (buf == NULL) {
        throw_kms_error(env, KMS_ERR_INTERNAL);
        return NULL;
    }

    rc = fn(buf, written + 1, &written);
    if (rc != KMS_OK) { free(buf); throw_kms_error(env, rc); return NULL; }

    buf[written] = '\0';
    jstring result = (*env)->NewStringUTF(env, buf);
    free(buf);
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
    const char *h = (*env)->GetStringUTFChars(env, hex, NULL);
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
    jbytearray_to_felt(env, value, &felt);

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
    jsize len = (*env)->GetArrayLength(env, bytes);
    jbyte *data = (*env)->GetByteArrayElements(env, bytes, NULL);
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
    jbytearray_to_felt(env, value, &felt);
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
    (*env)->GetByteArrayRegion(env, affineX, 0, 32, (jbyte *)affine.x.bytes);
    (*env)->GetByteArrayRegion(env, affineY, 0, 32, (jbyte *)affine.y.bytes);
    KmsProjectivePoint out;
    int32_t rc = kms_projective_from_affine(&affine, &out);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }
    return projective_to_jbytearray(env, &out);
}

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_projectiveToAffine(
    JNIEnv *env, jclass cls, jbyteArray pointX, jbyteArray pointY, jbyteArray pointZ) {
    (void)cls;
    KmsProjectivePoint pt;
    jbytearrays_to_projective(env, pointX, pointY, pointZ, &pt);
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
    jbytearray_to_felt(env, left, &l);
    jbytearray_to_felt(env, right, &r);
    int32_t rc = kms_pedersen_hash(&l, &r, &out);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }
    return felt_to_jbytearray(env, &out);
}

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_poseidonHashMany(
    JNIEnv *env, jclass cls, jobjectArray values) {
    (void)cls;
    jsize count = (*env)->GetArrayLength(env, values);
    KmsFelt *felts = NULL;
    if (count > 0) {
        felts = (KmsFelt *)calloc((size_t)count, sizeof(KmsFelt));
        if (felts == NULL) { throw_kms_error(env, KMS_ERR_INTERNAL); return NULL; }
        for (jsize i = 0; i < count; i++) {
            jbyteArray elem = (jbyteArray)(*env)->GetObjectArrayElement(env, values, i);
            jbytearray_to_felt(env, elem, &felts[i]);
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
    size_t written = 0;
    int32_t rc = kms_generate_mnemonic((uint32_t)wordCount, NULL, 0, &written);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }

    char *buf = (char *)malloc(written + 1);
    if (buf == NULL) { throw_kms_error(env, KMS_ERR_INTERNAL); return NULL; }

    rc = kms_generate_mnemonic((uint32_t)wordCount, buf, written + 1, &written);
    if (rc != KMS_OK) { free(buf); throw_kms_error(env, rc); return NULL; }

    buf[written] = '\0';
    jstring result = (*env)->NewStringUTF(env, buf);
    free(buf);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_generateMnemonicFromEntropy(
    JNIEnv *env, jclass cls, jbyteArray entropy) {
    (void)cls;
    jsize len = (*env)->GetArrayLength(env, entropy);
    jbyte *data = (*env)->GetByteArrayElements(env, entropy, NULL);

    size_t written = 0;
    int32_t rc = kms_generate_mnemonic_from_entropy(
        (const uint8_t *)data, (size_t)len, NULL, 0, &written);
    if (rc != KMS_OK) {
        (*env)->ReleaseByteArrayElements(env, entropy, data, JNI_ABORT);
        throw_kms_error(env, rc);
        return NULL;
    }

    char *buf = (char *)malloc(written + 1);
    if (buf == NULL) {
        (*env)->ReleaseByteArrayElements(env, entropy, data, JNI_ABORT);
        throw_kms_error(env, KMS_ERR_INTERNAL);
        return NULL;
    }

    rc = kms_generate_mnemonic_from_entropy(
        (const uint8_t *)data, (size_t)len, buf, written + 1, &written);
    (*env)->ReleaseByteArrayElements(env, entropy, data, JNI_ABORT);

    if (rc != KMS_OK) { free(buf); throw_kms_error(env, rc); return NULL; }

    buf[written] = '\0';
    jstring result = (*env)->NewStringUTF(env, buf);
    free(buf);
    return result;
}

JNIEXPORT jint JNICALL Java_io_krustykms_KmsNative_validateMnemonic(
    JNIEnv *env, jclass cls, jstring phrase) {
    (void)cls;
    const char *p = (*env)->GetStringUTFChars(env, phrase, NULL);
    int32_t rc = kms_validate_mnemonic(p);
    (*env)->ReleaseStringUTFChars(env, phrase, p);
    return rc;
}

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_mnemonicToSeed(
    JNIEnv *env, jclass cls, jstring phrase, jstring passphrase) {
    (void)cls;
    const char *p = (*env)->GetStringUTFChars(env, phrase, NULL);
    const char *pp = (*env)->GetStringUTFChars(env, passphrase, NULL);

    uint8_t out[64];
    size_t written = 0;
    int32_t rc = kms_mnemonic_to_seed(p, pp, out, sizeof(out), &written);

    (*env)->ReleaseStringUTFChars(env, phrase, p);
    (*env)->ReleaseStringUTFChars(env, passphrase, pp);

    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }

    jbyteArray arr = (*env)->NewByteArray(env, (jsize)written);
    if (arr == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, arr, 0, (jsize)written, (const jbyte *)out);
    return arr;
}

/* ====================================================================== */
/* Key derivation                                                          */
/* ====================================================================== */

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_derivePrivateKey(
    JNIEnv *env, jclass cls, jstring mnemonic, jint index,
    jint accountIndex, jint coinType, jstring passphrase) {
    (void)cls;
    const char *m = (*env)->GetStringUTFChars(env, mnemonic, NULL);
    const char *pp = (*env)->GetStringUTFChars(env, passphrase, NULL);

    KmsFelt felt;
    int32_t rc = kms_derive_private_key_with_coin_type(
        m, (uint32_t)index, (uint32_t)accountIndex, (uint32_t)coinType, pp, &felt);

    (*env)->ReleaseStringUTFChars(env, mnemonic, m);
    (*env)->ReleaseStringUTFChars(env, passphrase, pp);

    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }
    return felt_to_jbytearray(env, &felt);
}

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_deriveKeypair(
    JNIEnv *env, jclass cls, jstring mnemonic, jint index,
    jint accountIndex, jint coinType, jstring passphrase) {
    (void)cls;
    const char *m = (*env)->GetStringUTFChars(env, mnemonic, NULL);
    const char *pp = (*env)->GetStringUTFChars(env, passphrase, NULL);

    KmsTongoKeyPair kp;
    int32_t rc = kms_derive_keypair_with_coin_type(
        m, (uint32_t)index, (uint32_t)accountIndex, (uint32_t)coinType, pp, &kp);

    (*env)->ReleaseStringUTFChars(env, mnemonic, m);
    (*env)->ReleaseStringUTFChars(env, passphrase, pp);

    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }

    /* Return 128 bytes: 32 private + 96 projective */
    jbyteArray arr = (*env)->NewByteArray(env, 128);
    if (arr == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, arr, 0, 32, (const jbyte *)kp.private_key.bytes);
    (*env)->SetByteArrayRegion(env, arr, 32, 32, (const jbyte *)kp.public_key.x.bytes);
    (*env)->SetByteArrayRegion(env, arr, 64, 32, (const jbyte *)kp.public_key.y.bytes);
    (*env)->SetByteArrayRegion(env, arr, 96, 32, (const jbyte *)kp.public_key.z.bytes);
    return arr;
}

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_deriveNostrPrivateKey(
    JNIEnv *env, jclass cls, jstring mnemonic, jint index,
    jint accountIndex, jstring passphrase) {
    (void)cls;
    const char *m = (*env)->GetStringUTFChars(env, mnemonic, NULL);
    const char *pp = (*env)->GetStringUTFChars(env, passphrase, NULL);

    uint8_t out[32];
    int32_t rc = kms_derive_nostr_private_key(
        m, (uint32_t)index, (uint32_t)accountIndex, pp, out);

    (*env)->ReleaseStringUTFChars(env, mnemonic, m);
    (*env)->ReleaseStringUTFChars(env, passphrase, pp);

    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }

    jbyteArray arr = (*env)->NewByteArray(env, 32);
    if (arr == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, arr, 0, 32, (const jbyte *)out);
    return arr;
}

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_deriveNostrKeypair(
    JNIEnv *env, jclass cls, jstring mnemonic, jint index,
    jint accountIndex, jstring passphrase) {
    (void)cls;
    const char *m = (*env)->GetStringUTFChars(env, mnemonic, NULL);
    const char *pp = (*env)->GetStringUTFChars(env, passphrase, NULL);

    KmsNostrKeyPair kp;
    int32_t rc = kms_derive_nostr_keypair(
        m, (uint32_t)index, (uint32_t)accountIndex, pp, &kp);

    (*env)->ReleaseStringUTFChars(env, mnemonic, m);
    (*env)->ReleaseStringUTFChars(env, passphrase, pp);

    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }

    jbyteArray arr = (*env)->NewByteArray(env, 64);
    if (arr == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, arr, 0, 32, (const jbyte *)kp.private_key);
    (*env)->SetByteArrayRegion(env, arr, 32, 32, (const jbyte *)kp.public_key_xonly);
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
    jbytearray_to_felt(env, salt, &cSalt);
    jbytearray_to_felt(env, classHash, &cClassHash);
    jbytearray_to_felt(env, deployerAddress, &cDeployer);

    jsize count = (*env)->GetArrayLength(env, constructorCalldata);
    KmsFelt *calldata = NULL;
    if (count > 0) {
        calldata = (KmsFelt *)calloc((size_t)count, sizeof(KmsFelt));
        if (calldata == NULL) { throw_kms_error(env, KMS_ERR_INTERNAL); return NULL; }
        for (jsize i = 0; i < count; i++) {
            jbyteArray elem = (jbyteArray)(*env)->GetObjectArrayElement(env, constructorCalldata, i);
            jbytearray_to_felt(env, elem, &calldata[i]);
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
    jbytearray_to_felt(env, publicKeyX, &cPubKey);
    jbytearray_to_felt(env, classHash, &cClassHash);

    KmsFelt cSalt;
    KmsFelt *pSalt = NULL;
    if (salt != NULL) {
        jbytearray_to_felt(env, salt, &cSalt);
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
    const char *m = (*env)->GetStringUTFChars(env, mnemonic, NULL);
    const char *pp = (*env)->GetStringUTFChars(env, passphrase, NULL);
    KmsFelt cAddr;
    jbytearray_to_felt(env, contractAddress, &cAddr);
    KmsAccountHandle handle = 0;

    int32_t rc = kms_account_create_from_mnemonic(
        m, (uint32_t)index, (uint32_t)accountIndex, &cAddr, pp, &handle);

    (*env)->ReleaseStringUTFChars(env, mnemonic, m);
    (*env)->ReleaseStringUTFChars(env, passphrase, pp);

    if (rc != KMS_OK) { throw_kms_error(env, rc); return 0; }
    return (jlong)handle;
}

JNIEXPORT jlong JNICALL Java_io_krustykms_KmsNative_accountCreateFromPrivateKey(
    JNIEnv *env, jclass cls, jbyteArray privateKey,
    jbyteArray contractAddress) {
    (void)cls;
    KmsFelt cPrivateKey, cAddr;
    jbytearray_to_felt(env, privateKey, &cPrivateKey);
    jbytearray_to_felt(env, contractAddress, &cAddr);
    KmsAccountHandle handle = 0;

    int32_t rc = kms_account_create_from_private_key(&cPrivateKey, &cAddr, &handle);
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
    const char *json = (*env)->GetStringUTFChars(env, paramsJson, NULL);
    jstring result = string_dynamic_handle(env, kms_generate_fund_proof,
        (KmsAccountHandle)handle, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_generateTransferProof(
    JNIEnv *env, jclass cls, jlong handle, jstring paramsJson) {
    (void)cls;
    const char *json = (*env)->GetStringUTFChars(env, paramsJson, NULL);
    jstring result = string_dynamic_handle(env, kms_generate_transfer_proof,
        (KmsAccountHandle)handle, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_generateRolloverProof(
    JNIEnv *env, jclass cls, jlong handle, jstring paramsJson) {
    (void)cls;
    const char *json = (*env)->GetStringUTFChars(env, paramsJson, NULL);
    jstring result = string_dynamic_handle(env, kms_generate_rollover_proof,
        (KmsAccountHandle)handle, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_generateWithdrawProof(
    JNIEnv *env, jclass cls, jlong handle, jstring paramsJson) {
    (void)cls;
    const char *json = (*env)->GetStringUTFChars(env, paramsJson, NULL);
    jstring result = string_dynamic_handle(env, kms_generate_withdraw_proof,
        (KmsAccountHandle)handle, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_generateRagequitProof(
    JNIEnv *env, jclass cls, jlong handle, jstring paramsJson) {
    (void)cls;
    const char *json = (*env)->GetStringUTFChars(env, paramsJson, NULL);
    jstring result = string_dynamic_handle(env, kms_generate_ragequit_proof,
        (KmsAccountHandle)handle, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

/* ====================================================================== */
/* ElGamal                                                                 */
/* ====================================================================== */

JNIEXPORT jobjectArray JNICALL Java_io_krustykms_KmsNative_elgamalEncrypt(
    JNIEnv *env, jclass cls,
    jbyteArray message, jbyteArray pubX, jbyteArray pubY, jbyteArray pubZ,
    jbyteArray random, jbyteArray prefix) {
    (void)cls;
    KmsFelt cMsg, cRand, cPrefix;
    KmsProjectivePoint cPub;
    jbytearray_to_felt(env, message, &cMsg);
    jbytearrays_to_projective(env, pubX, pubY, pubZ, &cPub);
    jbytearray_to_felt(env, random, &cRand);
    jbytearray_to_felt(env, prefix, &cPrefix);

    KmsProjectivePoint outL, outR;

    /* First call: get proof size */
    size_t written = 0;
    int32_t rc = kms_elgamal_encrypt(
        &cMsg, &cPub, &cRand, &cPrefix, &outL, &outR, NULL, 0, &written);
    if (rc != KMS_OK) { throw_kms_error(env, rc); return NULL; }

    char *proofBuf = (char *)malloc(written + 1);
    if (proofBuf == NULL) { throw_kms_error(env, KMS_ERR_INTERNAL); return NULL; }

    /* Second call: fill proof and ciphertext */
    rc = kms_elgamal_encrypt(
        &cMsg, &cPub, &cRand, &cPrefix, &outL, &outR,
        proofBuf, written + 1, &written);
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

JNIEXPORT jbyteArray JNICALL Java_io_krustykms_KmsNative_elgamalDecrypt(
    JNIEnv *env, jclass cls,
    jbyteArray ciphLX, jbyteArray ciphLY, jbyteArray ciphLZ,
    jbyteArray ciphRX, jbyteArray ciphRY, jbyteArray ciphRZ,
    jbyteArray privateKey) {
    (void)cls;
    KmsProjectivePoint cL, cR;
    KmsFelt cKey;
    jbytearrays_to_projective(env, ciphLX, ciphLY, ciphLZ, &cL);
    jbytearrays_to_projective(env, ciphRX, ciphRY, ciphRZ, &cR);
    jbytearray_to_felt(env, privateKey, &cKey);

    KmsProjectivePoint out;
    int32_t rc = kms_elgamal_decrypt(&cL, &cR, &cKey, &out);
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
    jbytearray_to_felt(env, hash, &cHash);
    jbytearray_to_felt(env, privateKey, &cKey);

    int32_t rc = kms_stark_sign(&cHash, &cKey, &outR, &outS);
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
    jbytearray_to_felt(env, hash, &cHash);
    uint8_t keyBytes[32];
    (*env)->GetByteArrayRegion(env, ethPrivateKeyBytes, 0, 32, (jbyte *)keyBytes);

    KmsEthSignature sig;
    int32_t rc = kms_eth_sign(&cHash, keyBytes, &sig);
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
    const char *json = (*env)->GetStringUTFChars(env, paramsJson, NULL);
    jstring result = string_dynamic(env, kms_encode_erc20_approve, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_encodeFundCalls(
    JNIEnv *env, jclass cls, jstring paramsJson) {
    (void)cls;
    const char *json = (*env)->GetStringUTFChars(env, paramsJson, NULL);
    jstring result = string_dynamic(env, kms_encode_fund_calls, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_encodeTransferCalls(
    JNIEnv *env, jclass cls, jstring paramsJson) {
    (void)cls;
    const char *json = (*env)->GetStringUTFChars(env, paramsJson, NULL);
    jstring result = string_dynamic(env, kms_encode_transfer_calls, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_encodeRolloverCalls(
    JNIEnv *env, jclass cls, jstring paramsJson) {
    (void)cls;
    const char *json = (*env)->GetStringUTFChars(env, paramsJson, NULL);
    jstring result = string_dynamic(env, kms_encode_rollover_calls, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_encodeWithdrawCalls(
    JNIEnv *env, jclass cls, jstring paramsJson) {
    (void)cls;
    const char *json = (*env)->GetStringUTFChars(env, paramsJson, NULL);
    jstring result = string_dynamic(env, kms_encode_withdraw_calls, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}

JNIEXPORT jstring JNICALL Java_io_krustykms_KmsNative_encodeRagequitCalls(
    JNIEnv *env, jclass cls, jstring paramsJson) {
    (void)cls;
    const char *json = (*env)->GetStringUTFChars(env, paramsJson, NULL);
    jstring result = string_dynamic(env, kms_encode_ragequit_calls, json);
    (*env)->ReleaseStringUTFChars(env, paramsJson, json);
    return result;
}
