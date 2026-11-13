//! Observe scrypt's fully initialized ROMix scratch at deallocation.
//! All credentials are synthetic and remain in this process.

use krusty_kms::{decrypt_ethers_keystore, decrypt_private_key, encrypt_private_key};
use std::alloc::{GlobalAlloc, Layout, System};
use std::fmt::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroizing;

const SCRATCH_BYTES: usize = 1024 * 1024;
const BLOCK_BYTES: usize = 1024;
static PHASE: AtomicUsize = AtomicUsize::new(0);
static LARGE_FREES: [AtomicUsize; 5] = [const { AtomicUsize::new(0) }; 5];
static NONZERO_LARGE_FREES: [AtomicUsize; 5] = [const { AtomicUsize::new(0) }; 5];
static BLOCK_FREES: [AtomicUsize; 5] = [const { AtomicUsize::new(0) }; 5];
static NONZERO_BLOCK_FREES: [AtomicUsize; 5] = [const { AtomicUsize::new(0) }; 5];

struct Inspect;

#[global_allocator]
static INSPECT: Inspect = Inspect;

unsafe impl GlobalAlloc for Inspect {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let phase = PHASE.load(Ordering::Relaxed);
        if phase != 0 && matches!(layout.size(), SCRATCH_BYTES | BLOCK_BYTES) {
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            let nonzero = bytes.iter().any(|byte| *byte != 0);
            if layout.size() == SCRATCH_BYTES {
                LARGE_FREES[phase].fetch_add(1, Ordering::Relaxed);
                if nonzero {
                    NONZERO_LARGE_FREES[phase].fetch_add(1, Ordering::Relaxed);
                }
            } else {
                BLOCK_FREES[phase].fetch_add(1, Ordering::Relaxed);
                if nonzero {
                    NONZERO_BLOCK_FREES[phase].fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

fn check_phase(phase: usize, expected: &str) {
    let large = LARGE_FREES[phase].load(Ordering::Relaxed);
    let nonzero_large = NONZERO_LARGE_FREES[phase].load(Ordering::Relaxed);
    let blocks = BLOCK_FREES[phase].load(Ordering::Relaxed);
    let nonzero_blocks = NONZERO_BLOCK_FREES[phase].load(Ordering::Relaxed);
    assert_eq!(large, 1, "expected exactly one ROMix V free");
    assert_eq!(blocks, 2, "expected exactly two ROMix B/T frees");
    if expected == "clean" {
        assert_eq!(nonzero_large, 0, "ROMix V scratch was not wiped");
        assert_eq!(nonzero_blocks, 0, "ROMix B/T scratch was not wiped");
    } else {
        assert_eq!(nonzero_large, 1, "vacuous non-wiping V control");
        assert!(nonzero_blocks > 0, "vacuous non-wiping B/T control");
    }
    println!("scrypt phase={phase} large_frees={large} nonzero_large_frees={nonzero_large} block_frees={blocks} nonzero_block_frees={nonzero_blocks}");
}

fn random_hex_key() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *bytes).expect("runtime key fixture randomness");
    bytes[0] &= 0x03;
    bytes[31] |= 1;
    let mut key = Zeroizing::new(String::with_capacity(64));
    for byte in bytes.iter() {
        write!(&mut *key, "{byte:02x}").expect("write synthetic key");
    }
    key
}

fn random_password() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 24]);
    getrandom::fill(&mut *bytes).expect("runtime password fixture randomness");
    Zeroizing::new(
        bytes
            .iter()
            .map(|byte| char::from(b'a' + *byte % 26))
            .collect(),
    )
}

fn main() {
    let expected = std::env::args()
        .nth(1)
        .expect("usage: scrypt_heap clean|control");
    assert!(matches!(expected.as_str(), "clean" | "control"));
    let secret = random_hex_key();
    let password = random_password();
    let mut wrong_password = random_password();
    wrong_password.push('x');

    PHASE.store(1, Ordering::Relaxed);
    let encrypted = encrypt_private_key(&secret, &password, 1024).expect("encrypt");
    PHASE.store(2, Ordering::Relaxed);
    assert_eq!(
        decrypt_private_key(&encrypted, &password, 1024).expect("decrypt"),
        secret.as_str()
    );
    PHASE.store(3, Ordering::Relaxed);
    assert!(decrypt_private_key(&encrypted, &wrong_password, 1024).is_err());
    PHASE.store(4, Ordering::Relaxed);
    let salt = random_hex_key();
    let iv = random_hex_key();
    let ciphertext = random_hex_key();
    let v3 = format!(
        r#"{{"version":3,"crypto":{{"cipher":"aes-128-ctr","kdf":"scrypt","kdfparams":{{"n":1024,"r":8,"p":1,"dklen":32,"salt":"{}"}},"cipherparams":{{"iv":"{}"}},"ciphertext":"{}","mac":"00"}}}}"#,
        salt.as_str(),
        &iv[..32],
        ciphertext.as_str()
    );
    let error = decrypt_ethers_keystore(&v3, &password).expect_err("synthetic v3 MAC must fail");
    assert!(
        format!("{error}").contains("MAC verification failed"),
        "v3 import did not reach MAC verification"
    );
    PHASE.store(0, Ordering::Relaxed);

    for phase in 1..=4 {
        check_phase(phase, &expected);
    }
    println!("scrypt result=pass mode={expected}");
}
