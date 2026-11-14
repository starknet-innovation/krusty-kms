#!/usr/bin/env python3
"""Export PUBLIC test vectors from a local fireblocks-labs/pqb checkout.

Usage: python3 tools/pqb-kms-vectors.py /path/to/pqb > \
    crates/kms/tests/fixtures/pqb_kms_vectors.json
No wallet, chain or network access. All seeds are public test values.
"""
import base64
import hashlib
import struct
import json
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root / 'pqb' / 'src'))
from pqb import bip85 as b  # noqa: E402
from pqb.lock import Lock  # noqa: E402
from pqb.configs import get  # noqa: E402

v = json.loads((root / 'js/test/vectors.json').read_text())
# Keep only the production real-puzzle profile; never authorize elided scripts.
scripts = [s for s in v['scripts'] if s['seed'] and s['real_puzzles']]
spends = [s for s in v['spends'] if s['real_puzzles']]
wallets = []
words = 'abandon ' * 11 + 'about'
for index, password, network in [(0, '', 'main'), (1, 'TREZOR', 'regtest'), (2147483647, '', 'testnet4')]:
    entropy, _, _ = b.child(b.Root.from_mnemonic(words, password), index)
    seed = b.vault_seed(entropy, 'PQB', True, network)
    lock = Lock.build(get(), seed)
    wallets.append(dict(mnemonic=words, passphrase=password, index=index, network=network,
                        entropy=entropy.hex(), seed=seed.hex(), script_sha256=lock.sha256))
# Public grinder points; omit redundant full packets and large JSON integers.
menus = []
for packet in v['export']['cases'][-1]['packets']:
    menu = packet['raw']['menu']
    menus.append(dict(r=f"{menu['r']:064x}",
                      recovery_points=[variant['points'] for variant in menu['variants']]))
# Deposit signing with real, internally consistent previous transactions for
# Krusty's strict non_witness_utxo check; no chain funds are involved.
from pqb import seedcli
from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint

def varbytes(data):
    n = len(data)
    return (bytes([n]) if n < 253 else b'\xfd' + struct.pack('<H', n)) + data

def pair(key, data):
    return varbytes(key) + varbytes(data)

deposit_psbts = []
for count in range(3):
    seed = bytes(range(32)) if count == 0 else hashlib.sha256(f'pqb-deposit-vector-{count}'.encode()).digest()
    dep = seedcli._deposit_for_seed(seed, 'main')
    prev = CTransaction()
    prev.version = 2
    prev.vin = [CTxIn(COutPoint(123 + count, 0), b'', 0xffffffff)]
    script = bytes.fromhex(dep['script_pubkey'])
    prev.vout = [CTxOut(100000, script)]
    prev_raw = prev.serialize_without_witness()
    txid = hashlib.sha256(hashlib.sha256(prev_raw).digest()).digest()[::-1].hex()
    signed, _ = seedcli.build_spend_of_deposit(seed, [dict(txid=txid, vout=0, value=100000, height=1)], b'\x51', lambda _: 1000)
    unsigned = signed.serialize_without_witness()
    sig, pub = signed.wit.vtxinwit[0].scriptWitness.stack
    global_map = pair(b'\x00', unsigned) + b'\x00'
    input_map = pair(b'\x00', prev_raw) + pair(b'\x01', prev.vout[0].serialize())
    prefix = b'psbt\xff' + global_map
    psbt = prefix + input_map + b'\x00\x00'
    expected = prefix + input_map + pair(b'\x02' + pub, sig) + b'\x00\x00'
    deposit_psbts.append(dict(seed=seed.hex(), psbt=base64.b64encode(psbt).decode(), signed_psbt=base64.b64encode(expected).decode(), funding_txid=txid, signed_tx=signed.serialize_with_witness().hex()))
# The scripts/spends are the exact Python-generated fixtures consumed by TS.
# Include per-vault public grinder points through that reference's export cases.
out = dict(source_commit=subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
           source_vectors_sha256=hashlib.sha256((root/'js/test/vectors.json').read_bytes()).hexdigest(),
           note='PUBLIC TEST VECTORS ONLY; generated from the Python/TypeScript reference',
           scripts=scripts, spends=spends, deposits=v['deposits'], bip85=v['bip85'], wallets=wallets,
           menus=dict(seed=v['export']['seed'], stages=menus), deposit_psbts=deposit_psbts)
print(json.dumps(out, indent=2, sort_keys=True))
