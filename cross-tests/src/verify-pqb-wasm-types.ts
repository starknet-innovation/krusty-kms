// Consumer smoke test against declarations generated from the actual WASM package.
import { WasmPqbVault, type PqbPublicMaterial, type PqbDisclosure,
  type PqbRequestInfo, type PqbDeposit } from '../../crates/wasm/pkg/krusty_kms_wasm.js';

export async function disclose(phrase: string, passphrase: string | undefined,
  txHex: string, input: number, r0: number[], r1: number[], menus: number[],
  journal: (vault: string, digest: string) => Promise<void>): Promise<PqbDisclosure> {
  const vault = WasmPqbVault.fromMnemonic(phrase,0,'main',passphrase);
  let request;
  try {
    const p: PqbPublicMaterial = vault.publicMaterial();
    const d: PqbDeposit = vault.deposit();
    const signed: string = vault.signDepositPsbt('base64',[0]);
    void [d,signed];
    request = vault.prepareDisclosure(txHex,input,p.scriptSha256,r0,r1,menus);
    const info: PqbRequestInfo = request.info();
    await journal(p.scriptSha256,info.digest);
    return vault.authorize(request);
  } finally {
    request?.dispose(); request?.free(); vault.dispose(); vault.free();
  }
}
const restored: WasmPqbVault = WasmPqbVault.fromChildMnemonic('child words','regtest');
restored.dispose(); restored.free();
// No public constructor or raw-digest signing is part of this contract.
// @ts-expect-error opaque constructor
new WasmPqbVault();
// @ts-expect-error no arbitrary signing operation
WasmPqbVault.signDigest('00');
