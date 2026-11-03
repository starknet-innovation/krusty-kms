//! BIP-174 rules that span several pairs of one input map, checked once the
//! whole map has been read and each pair has passed the field table.

use super::super::tx::malformed;
use super::{find, Map, IN_PARTIAL_SIG, IN_SIGHASH_TYPE};
use krusty_kms_common::Result;

/// BIP-174: when an input declares `PSBT_IN_SIGHASH_TYPE`, every partial
/// signature on it must use that sighash type, which is the signature's
/// trailing byte. A mismatch makes the PSBT invalid for any finalizer, so it
/// is refused before anything is signed, whether or not the input is listed.
pub(super) fn require_declared_sighash(index: usize, map: &Map) -> Result<()> {
    let Some(declared) = find(map, IN_SIGHASH_TYPE) else {
        return Ok(());
    };
    // The field table has already checked the value is exactly four bytes.
    let declared: Option<[u8; 4]> = declared.try_into().ok();
    let mismatch = map.iter().any(|pair| {
        pair.key.first() == Some(&IN_PARTIAL_SIG)
            && pair.value.last().map(|&byte| [byte, 0, 0, 0]) != declared
    });
    if mismatch {
        return Err(malformed(format!(
            "input {index} has a partial signature that does not use its declared sighash type"
        )));
    }
    Ok(())
}
