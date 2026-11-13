//! OS-mediated dead-stack inspection. All secrets are throwaway runtime fixtures.
use bip39::Mnemonic;
use sha2::{Digest, Sha512};
use std::ffi::c_void;
use zeroize::{Zeroize, Zeroizing};

const SNAPSHOT_BYTES: usize = 64 * 1024;
const ITERATIONS: usize = 4;

unsafe extern "C" {
    fn inspection_stack_boundary() -> usize;
    fn inspection_snapshot(
        exercise: extern "C" fn(*mut c_void) -> usize,
        fixture: *mut c_void,
        out: *mut u8,
        length: usize,
    ) -> i32;
}

struct Fixture {
    entropy: Zeroizing<Vec<u8>>,
    phrase: Zeroizing<String>,
    seed: Zeroizing<[u8; 64]>,
    passphrase: Zeroizing<String>,
    operation: usize,
}

// The fixed Rust frame contains caller-owned returned values ABOVE its current
// SP. We capture its lower boundary before entering production code, so those
// values (and this harness's own spills) are excluded from the snapshot.
#[inline(never)]
extern "C" fn exercise(pointer: *mut c_void) -> usize {
    let fixture = unsafe { &*(pointer.cast::<Fixture>()) };
    let boundary = unsafe { inspection_stack_boundary() };
    match fixture.operation {
        0 => {
            let output = krusty_kms::mnemonic_from_entropy(&*fixture.entropy).expect("encode");
            assert!(*output == *fixture.phrase, "encoding output mismatch");
        }
        1 => krusty_kms::validate_mnemonic(&fixture.phrase).expect("validate"),
        2 => {
            let output = Zeroizing::new(
                krusty_kms::mnemonic_to_seed(&fixture.phrase, &fixture.passphrase).expect("derive"),
            );
            assert!(*output == *fixture.seed, "seed output mismatch");
        }
        _ => panic!("unknown operation"),
    }
    std::hint::black_box(boundary)
}

fn patterns(fixture: &Fixture) -> Vec<(&'static str, Zeroizing<Vec<u8>>)> {
    let mnemonic = Zeroizing::new(Mnemonic::parse(&*fixture.phrase).expect("reference parse"));
    let indices = Zeroizing::new(
        mnemonic
            .word_indices()
            .flat_map(|index| (index as u16).to_ne_bytes())
            .collect::<Vec<u8>>(),
    );
    let mut pad = Zeroizing::new(vec![0u8; 128]);
    let key = Zeroizing::new(if fixture.phrase.len() > 128 {
        Sha512::digest(fixture.phrase.as_bytes()).to_vec()
    } else {
        fixture.phrase.as_bytes().to_vec()
    });
    pad[..key.len()].copy_from_slice(&key);
    pad.iter_mut().for_each(|byte| *byte ^= 0x36);
    vec![
        ("entropy", Zeroizing::new(fixture.entropy[..16].to_vec())),
        (
            "entropy_bits",
            Zeroizing::new(
                fixture
                    .entropy
                    .iter()
                    .flat_map(|byte| (0..8).rev().map(move |bit| (byte >> bit) & 1))
                    .take(128)
                    .collect(),
            ),
        ),
        ("word_indices", Zeroizing::new(indices[..16].to_vec())),
        ("seed", Zeroizing::new(fixture.seed.to_vec())),
        ("hmac_ipad", pad),
    ]
}

fn count(buffer: &[u8], pattern: &[u8]) -> usize {
    assert!(!pattern.is_empty(), "empty search pattern");
    buffer
        .windows(pattern.len())
        .filter(|bytes| *bytes == pattern)
        .count()
}

fn main() {
    let expected = std::env::args()
        .nth(1)
        .expect("usage: native-inspection clean|control");
    assert!(
        matches!(expected.as_str(), "clean" | "control"),
        "unknown mode"
    );
    let mut control_hits = [0usize; 3];
    for iteration in 0..ITERATIONS {
        let mut entropy = Zeroizing::new(vec![0u8; if iteration % 2 == 0 { 16 } else { 32 }]);
        getrandom::fill(&mut *entropy).expect("runtime fixture randomness");
        let reference =
            Zeroizing::new(Mnemonic::from_entropy(&*entropy).expect("reference encode"));
        let phrase = Zeroizing::new(reference.to_string());
        let passphrase = Zeroizing::new(format!("inspection-{}-\u{e9}", iteration));
        let seed = Zeroizing::new(reference.to_seed(&*passphrase));
        let mut fixture = Box::new(Fixture {
            entropy,
            phrase,
            passphrase,
            seed,
            operation: 0,
        });
        let patterns = patterns(&fixture);
        // Prove the actual matcher finds a non-aligned pattern, and detects a
        // corrupted pattern as different. No fixture bytes are printed.
        for (_, pattern) in &patterns {
            let mut haystack = Zeroizing::new(vec![0xa5; pattern.len() + 14]);
            haystack[7..7 + pattern.len()].copy_from_slice(pattern);
            assert_eq!(count(&haystack, pattern), 1, "matcher positive calibration");
            haystack[7] ^= 1;
            assert_eq!(count(&haystack, pattern), 0, "matcher negative calibration");
        }
        for operation in 0..3 {
            fixture.operation = operation;
            let mut snapshot = Zeroizing::new(vec![0u8; SNAPSHOT_BYTES]);
            let result = unsafe {
                inspection_snapshot(
                    exercise,
                    (&mut *fixture as *mut Fixture).cast(),
                    snapshot.as_mut_ptr(),
                    snapshot.len(),
                )
            };
            assert_eq!(result, 0, "OS stack snapshot failed");
            let mut total = 0;
            for (name, pattern) in &patterns {
                let count = count(&snapshot, pattern);
                total += count;
                println!("native operation={operation} iteration={iteration} entropy_bytes={} pattern={name} hits={count}", fixture.entropy.len());
            }
            control_hits[operation] += total;
            if expected == "clean" {
                assert_eq!(total, 0, "residual secret material detected");
            } else {
                assert!(
                    total > 0,
                    "vacuous control: each operation and fixture must expose a remnant"
                );
            }
            snapshot.zeroize();
        }
    }
    if expected == "control" {
        assert!(
            control_hits.iter().all(|hits| *hits > 0),
            "vacuous control: every operation must expose a remnant"
        );
    }
    println!(
        "native result=pass mode={expected} iterations={ITERATIONS} scanned_bytes={SNAPSHOT_BYTES}"
    );
}
