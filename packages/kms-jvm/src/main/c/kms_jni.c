#include <jni.h>
#include <stdint.h>
#include <stdlib.h>

#include "kms.h"

static void throw_kms_error(JNIEnv *env, int32_t code) {
  const char *msg = kms_error_message(code);
  jclass ex = (*env)->FindClass(env, "java/lang/RuntimeException");
  if (ex != NULL) {
    (*env)->ThrowNew(env, ex, msg ? msg : "kms ffi error");
  }
}

JNIEXPORT jint JNICALL Java_io_ghoul_kms_KmsNative_validateMnemonic(
    JNIEnv *env,
    jclass cls,
    jstring phrase) {
  (void)cls;
  const char *p = (*env)->GetStringUTFChars(env, phrase, NULL);
  int32_t rc = kms_validate_mnemonic(p);
  (*env)->ReleaseStringUTFChars(env, phrase, p);
  return rc;
}

JNIEXPORT jbyteArray JNICALL Java_io_ghoul_kms_KmsNative_mnemonicToSeed(
    JNIEnv *env,
    jclass cls,
    jstring phrase,
    jstring passphrase) {
  (void)cls;
  const char *p = (*env)->GetStringUTFChars(env, phrase, NULL);
  const char *pp = (*env)->GetStringUTFChars(env, passphrase, NULL);

  uint8_t out[64];
  size_t written = 0;
  int32_t rc = kms_mnemonic_to_seed(p, pp, out, sizeof(out), &written);

  (*env)->ReleaseStringUTFChars(env, phrase, p);
  (*env)->ReleaseStringUTFChars(env, passphrase, pp);

  if (rc != KMS_OK) {
    throw_kms_error(env, rc);
    return NULL;
  }

  jbyteArray arr = (*env)->NewByteArray(env, (jsize)written);
  if (arr == NULL) {
    return NULL;
  }
  (*env)->SetByteArrayRegion(env, arr, 0, (jsize)written, (const jbyte *)out);
  return arr;
}

JNIEXPORT jbyteArray JNICALL Java_io_ghoul_kms_KmsNative_derivePrivateKey(
    JNIEnv *env,
    jclass cls,
    jstring mnemonic,
    jint index,
    jint accountIndex,
    jint coinType,
    jstring passphrase) {
  (void)cls;
  const char *m = (*env)->GetStringUTFChars(env, mnemonic, NULL);
  const char *pp = (*env)->GetStringUTFChars(env, passphrase, NULL);

  KmsFelt felt;
  int32_t rc = kms_derive_private_key_with_coin_type(
      m,
      (uint32_t)index,
      (uint32_t)accountIndex,
      (uint32_t)coinType,
      pp,
      &felt);

  (*env)->ReleaseStringUTFChars(env, mnemonic, m);
  (*env)->ReleaseStringUTFChars(env, passphrase, pp);

  if (rc != KMS_OK) {
    throw_kms_error(env, rc);
    return NULL;
  }

  jbyteArray arr = (*env)->NewByteArray(env, 32);
  if (arr == NULL) {
    return NULL;
  }
  (*env)->SetByteArrayRegion(env, arr, 0, 32, (const jbyte *)felt.bytes);
  return arr;
}

JNIEXPORT jint JNICALL Java_io_ghoul_kms_KmsNative_coinTypeTongo(JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;
  return (jint)kms_get_coin_type_tongo();
}

JNIEXPORT jint JNICALL Java_io_ghoul_kms_KmsNative_coinTypeStarknet(JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;
  return (jint)kms_get_coin_type_starknet();
}

JNIEXPORT jint JNICALL Java_io_ghoul_kms_KmsNative_coinTypeTongoView(JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;
  return (jint)kms_get_coin_type_tongo_view();
}

JNIEXPORT jint JNICALL Java_io_ghoul_kms_KmsNative_coinTypeNostr(JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;
  return (jint)kms_get_coin_type_nostr();
}

JNIEXPORT jstring JNICALL Java_io_ghoul_kms_KmsNative_errorMessage(JNIEnv *env, jclass cls, jint code) {
  (void)cls;
  const char *msg = kms_error_message((int32_t)code);
  return (*env)->NewStringUTF(env, msg ? msg : "unknown error");
}
