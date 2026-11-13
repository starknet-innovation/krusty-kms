//! Inspection-only adapter. Runtime fixtures are written by Node into INPUT.
//! No fixture bytes are compiled into this module's data segments.
use std::ptr::addr_of_mut;
use zeroize::Zeroizing;

static mut INPUT: Vec<u8> = Vec::new();
static mut OUTPUT: Option<Zeroizing<String>> = None;

/// Host-readable metadata: output address/length, returned seed address/length.
static mut RANGES: [u32; 4] = [0; 4];

#[no_mangle]
pub extern "C" fn ranges() -> u32 {
    addr_of_mut!(RANGES) as u32
}

#[no_mangle]
pub extern "C" fn allocate_input(len: usize) -> u32 {
    unsafe {
        let input = &mut *addr_of_mut!(INPUT);
        input.resize(len, 0);
        input.as_mut_ptr() as u32
    }
}

/// 0 = encode entropy, 1 = validate phrase, 2 = derive seed, 3 = generate.
/// All allocations intentionally retained by the adapter are explicitly ranged.
#[no_mangle]
pub extern "C" fn run(operation: u32, entropy_len: usize, phrase_len: usize) {
    unsafe {
        let input = &*addr_of_mut!(INPUT);
        let phrase = std::str::from_utf8(&input[entropy_len..entropy_len + phrase_len]).unwrap();
        let passphrase = std::str::from_utf8(&input[entropy_len + phrase_len..]).unwrap();
        match operation {
            0 => {
                *addr_of_mut!(OUTPUT) =
                    Some(krusty_kms::mnemonic_from_entropy(&input[..entropy_len]).unwrap())
            }
            1 => krusty_kms::validate_mnemonic(phrase).unwrap(),
            2 => {
                let result = krusty_kms::mnemonic_to_seed(phrase, passphrase);
                let seed = result.as_ref().unwrap();
                (*addr_of_mut!(RANGES))[2] = seed.as_ptr() as u32;
                (*addr_of_mut!(RANGES))[3] = 64;
                // Register only this exact caller return slot. No intervening
                // WASM call may reuse it before the host's immediate scan.
                std::mem::forget(result);
            }
            3 => {
                *addr_of_mut!(OUTPUT) = Some(Zeroizing::new(
                    krusty_kms::generate_mnemonic(entropy_len * 3 / 4).unwrap(),
                ))
            }
            _ => panic!("unknown inspection operation"),
        }
        if let Some(output) = &*addr_of_mut!(OUTPUT) {
            (*addr_of_mut!(RANGES))[0] = output.as_ptr() as u32;
            (*addr_of_mut!(RANGES))[1] = output.len() as u32;
        }
    }
}
