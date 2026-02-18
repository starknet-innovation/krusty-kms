package io.ghoul.kms;

public final class KmsException extends RuntimeException {
  private final int code;

  public KmsException(int code) {
    super("kms error " + code + ": " + KmsNative.errorMessage(code));
    this.code = code;
  }

  public int code() {
    return code;
  }
}
