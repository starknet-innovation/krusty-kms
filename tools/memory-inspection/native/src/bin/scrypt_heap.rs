//! Observe scrypt's fully initialized ROMix scratch at deallocation.
//! All credentials are synthetic and remain in this process.

use krusty_kms::{decrypt_private_key, encrypt_private_key};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

const SCRATCH_BYTES: usize = 1024 * 1024;
static PHASE: AtomicUsize = AtomicUsize::new(0);
static LARGE_FREES: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static NONZERO_FREES: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];

struct Inspect;

#[global_allocator]
static INSPECT: Inspect = Inspect;

unsafe impl GlobalAlloc for Inspect {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let phase = PHASE.load(Ordering::Relaxed);
        if phase != 0 && layout.size() == SCRATCH_BYTES {
            LARGE_FREES[phase].fetch_add(1, Ordering::Relaxed);
            // The only allocation of this exact size in the controlled KDF
            // phase is the initialized ROMix V vector (N=1024, r=8).
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if bytes.iter().any(|byte| *byte != 0) {
                NONZERO_FREES[phase].fetch_add(1, Ordering::Relaxed);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

fn check_phase(phase: usize, expected: &str) {
    let large = LARGE_FREES[phase].load(Ordering::Relaxed);
    let nonzero = NONZERO_FREES[phase].load(Ordering::Relaxed);
    assert_eq!(large, 1, "expected exactly one ROMix V free");
    if expected == "clean" {
        assert_eq!(nonzero, 0, "ROMix scratch was not wiped");
    } else {
        assert_eq!(nonzero, 1, "vacuous non-wiping control");
    }
    println!("scrypt phase={phase} large_frees={large} nonzero_large_frees={nonzero}");
}

fn main() {
    let expected = std::env::args()
        .nth(1)
        .expect("usage: scrypt_heap clean|control");
    assert!(matches!(expected.as_str(), "clean" | "control"));
    let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    PHASE.store(1, Ordering::Relaxed);
    let encrypted = encrypt_private_key(secret, "synthetic-password", 1024).expect("encrypt");
    PHASE.store(2, Ordering::Relaxed);
    assert_eq!(
        decrypt_private_key(&encrypted, "synthetic-password", 1024).expect("decrypt"),
        secret
    );
    PHASE.store(3, Ordering::Relaxed);
    assert!(decrypt_private_key(&encrypted, "wrong-password", 1024).is_err());
    PHASE.store(0, Ordering::Relaxed);

    for phase in 1..=3 {
        check_phase(phase, &expected);
    }
    println!("scrypt result=pass mode={expected}");
}
