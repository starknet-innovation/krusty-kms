import type { KmsApi } from "./types.js";

export class KmsNativeUnavailableError extends Error {
  constructor(message = "native kms backend is not available in this runtime") {
    super(message);
    this.name = "KmsNativeUnavailableError";
  }
}

export function loadNativeBackend(): KmsApi {
  throw new KmsNativeUnavailableError(
    "native ffi loader is not wired yet; build and load libkms in this package",
  );
}
