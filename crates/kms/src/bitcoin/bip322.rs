//! BIP-322 "simple" message signatures for P2WPKH addresses.
//!
//! The signature is the witness that spends the virtual `to_spend` output,
//! committed to by a BIP-340 tagged hash of the message, in the virtual
//! `to_sign` transaction.

use super::keys::P2wpkhSigner;
use super::tx::{write_compact_size, write_var_bytes, OutPoint, Transaction, TxIn, TxOut};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use krusty_kms_common::{KmsError, Result};
use sha2::{Digest, Sha256};

const MESSAGE_TAG: &[u8] = b"BIP0322-signed-message";
const OP_RETURN: u8 = 0x6a;

/// Sign `message` for `address` with a BIP-322 "simple" signature and return
/// the base64 consensus-encoded witness stack `[signature, public key]`.
///
/// `address` must be this key's mainnet P2WPKH address (lowercase or
/// uppercase). The result carries no variant prefix: BIP-322 1.0.0 lets a
/// verifier treat an unprefixed signature as "simple", which is the form
/// BIP-322 implementations from before that revision produce and accept.
///
/// # Errors
///
/// - `InvalidPrivateKey` when the key is not a valid secp256k1 scalar
/// - `CryptoError` when `address` is not this key's P2WPKH address
pub fn sign_bip322_simple(private_key: &[u8; 32], address: &str, message: &[u8]) -> Result<String> {
    let signer = P2wpkhSigner::new(private_key)?;
    let own = signer.address();
    if address != own && address != own.to_ascii_uppercase() {
        return Err(KmsError::CryptoError(
            "BIP-322 address is not this key's mainnet P2WPKH address".into(),
        ));
    }

    let to_spend = to_spend(&signer.script_pubkey(), message);
    let sighash = to_sign(to_spend.txid()).p2wpkh_sighash_all(0, &signer.pubkey_hash, 0)?;
    let signature = signer.sign_sighash_all(&sighash)?;

    let mut witness = Vec::new();
    write_compact_size(&mut witness, 2);
    write_var_bytes(&mut witness, &signature);
    write_var_bytes(&mut witness, &signer.public_key);
    Ok(BASE64.encode(witness))
}

/// `sha256(sha256(tag) || sha256(tag) || message)`.
pub(super) fn message_hash(message: &[u8]) -> [u8; 32] {
    let tag = Sha256::digest(MESSAGE_TAG);
    Sha256::new()
        .chain_update(tag)
        .chain_update(tag)
        .chain_update(message)
        .finalize()
        .into()
}

pub(super) fn to_spend(message_challenge: &[u8], message: &[u8]) -> Transaction {
    let mut script_sig = vec![0x00, 0x20];
    script_sig.extend(message_hash(message));
    Transaction {
        version: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: [0; 32],
                vout: u32::MAX,
            },
            script_sig,
            sequence: 0,
        }],
        outputs: vec![TxOut {
            value: 0,
            script_pubkey: message_challenge.to_vec(),
        }],
        lock_time: 0,
    }
}

pub(super) fn to_sign(to_spend_txid: [u8; 32]) -> Transaction {
    Transaction {
        version: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: to_spend_txid,
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOut {
            value: 0,
            script_pubkey: vec![OP_RETURN],
        }],
        lock_time: 0,
    }
}
