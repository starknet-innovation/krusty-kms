import type { KmsApi } from "./types.js";

export class KmsWasmUnavailableError extends Error {
  constructor(message = "wasm kms backend is not available") {
    super(message);
    this.name = "KmsWasmUnavailableError";
  }
}

export async function loadWasmBackend(): Promise<KmsApi> {
  throw new KmsWasmUnavailableError(
    "wasm loader is not wired yet",
  );
}
