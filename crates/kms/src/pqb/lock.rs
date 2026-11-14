// Portions ported from fireblocks-labs/pqb, Copyright (c) 2026 Fireblocks Ltd.
// MIT license: ../../licenses/PQB-MIT.txt (included in this crate package).
//! Fixed-profile script emitter. The stack model computes OP_ROLL depths;
//! neither caller-provided opcodes nor secret signatures enter the lock.
use super::PqbPublicMenu;
use bitcoin_hashes::{hash160, Hash as _};

const DEPTH: u8 = 0x74;
const DUP: u8 = 0x76;
const HASH160: u8 = 0xa9;
const EQUALVERIFY: u8 = 0x88;
const CHECKSIGVERIFY: u8 = 0xad;
const TWODUP: u8 = 0x6e;
const SHA256: u8 = 0xa8;
const CHECKSIG: u8 = 0xac;
const TRUE: u8 = 0x51;
const ROLL: u8 = 0x7a;
const MIN: u8 = 0xa3;
const SHA1: u8 = 0xa7;
const RIPEMD160: u8 = 0xa6;
const TUCK: u8 = 0x7d;
const SIZE: u8 = 0x82;
const DROP: u8 = 0x75;
const CHECKMULTISIGVERIFY: u8 = 0xaf;

// All stack transitions and push sizes are fixed by this profile, not inputs.
struct Emit {
    bytes: Vec<u8>,
    stack: Vec<String>,
}
impl Emit {
    fn op(&mut self, opcode: u8) {
        self.bytes.push(opcode);
    }
    fn push(&mut self, slot: impl Into<String>, bytes: &[u8]) {
        self.bytes.extend(push_data(bytes));
        self.stack.push(slot.into());
    }
    fn number(&mut self, number: usize) {
        self.push("#const", &script_number(number));
    }
    fn drop(&mut self, n: usize) {
        self.stack.truncate(self.stack.len() - n);
    }
    fn dup(&mut self) {
        self.stack
            .push(self.stack.last().expect("fixed stack").clone());
    }
    fn position(&self, slot: &str) -> usize {
        self.stack
            .iter()
            .position(|s| s == slot)
            .expect("fixed stack slot")
    }
    fn roll(&mut self, slot: &str) {
        let position = self.position(slot);
        let depth = self.stack.len() - 1 - position;
        self.number(depth);
        self.drop(1);
        self.op(ROLL);
        let value = self.stack.remove(position);
        self.stack.push(value);
    }
    fn fetch(&mut self, sentinel: &str, offset: usize, name: &str) {
        self.drop(1);
        let position = self.position(sentinel);
        self.stack.remove(position + offset);
        self.stack.push(name.into());
    }
    fn clamp(&mut self, sentinel: &str) {
        let cap = self.stack.len() - 3 - self.position(sentinel);
        self.number(cap);
        self.op(MIN);
        self.drop(2);
        self.stack.push("#clamped".into());
    }
    fn der_key(&mut self) {
        self.push("#pk33", &DER_PUZZLE_PUBLIC_KEY);
    }
    fn menu(&mut self, sentinel: &str, menu: &PqbPublicMenu) {
        self.push(sentinel, &[1]);
        for (i, commitment) in menu.commitments.iter().enumerate() {
            self.push(format!("{sentinel}_{i}"), commitment);
        }
    }
}

// Fixed generator public key used only for the DER-form puzzle CHECKSIG.
const DER_PUZZLE_PUBLIC_KEY: [u8; 33] = [
    2, 121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155, 252, 219,
    45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152,
];

/// ScriptSig slots in bottom-to-top order, without optional selector ladders.
fn slots() -> Vec<String> {
    let mut slots = Vec::new();
    for (r, t) in [8, 9].iter().enumerate() {
        slots.push(format!("kn{r}"));
        for a in 0..*t {
            slots.push(format!("k{r}_{a}"));
        }
    }
    for prefix in ["pre", "i"] {
        for (r, t) in [(1, 9), (0, 8)] {
            for a in (0..t).rev() {
                slots.push(format!("{prefix}{r}_{a}"));
            }
        }
    }
    for r in 0..2 {
        slots.extend([format!("msig{r}"), format!("midx{r}")]);
    }
    slots.extend(["menu_idx", "menu_sig", "knpin", "cosig_sig", "cosig_pk"].map(str::to_owned));
    slots
}

pub(super) fn build(
    commitments: &[[u8; 20]; 109],
    menus: &[PqbPublicMenu; 3],
    cosig_key: &[u8; 33],
) -> Vec<u8> {
    let mut e = Emit {
        bytes: Vec::new(),
        stack: slots(),
    };
    depth_guard(&mut e);
    e.op(DUP);
    e.dup();
    e.op(HASH160);
    e.push("#h160", &hash160::Hash::hash(cosig_key).to_byte_array());
    e.op(EQUALVERIFY);
    e.drop(2);
    e.op(CHECKSIGVERIFY);
    e.drop(2);
    pinning(&mut e, &menus[0]);
    e.push("TSENT", &[1]);
    for (j, signature) in super::menu::dummy_signatures().iter().enumerate() {
        e.push(format!("D_{j}"), signature);
        e.push(format!("F_{j}"), &[1]);
        e.push(format!("C_{j}"), &commitments[j]);
    }
    for (r, t) in [8, 9].iter().enumerate() {
        round(&mut e, r, *t, &menus[r + 1]);
    }
    e.op(TRUE);
    e.bytes
}
fn depth_guard(e: &mut Emit) {
    let w = e.stack.len();
    e.op(DEPTH);
    e.stack.push("#depth".into());
    e.number(w);
    e.op(EQUALVERIFY);
    e.drop(2);
}
fn pinning(e: &mut Emit, menu: &PqbPublicMenu) {
    e.op(TWODUP);
    let n = e.stack.len();
    e.stack.extend_from_within(n - 2..);
    e.op(CHECKSIGVERIFY);
    e.drop(2);
    e.op(SHA256);
    e.der_key();
    e.op(CHECKSIG);
    e.drop(2);
    e.stack.push("#false".into());
    e.menu("MSENT", menu);
    e.roll("menu_idx");
    e.clamp("MSENT");
    e.op(ROLL);
    e.fetch("MSENT", 1, "MC_sel");
    e.roll("menu_sig");
    e.op(SHA1);
    e.op(EQUALVERIFY);
    e.drop(2);
}
fn round(e: &mut Emit, r: usize, t: usize, menu: &PqbPublicMenu) {
    let sentinel = format!("MSENT{r}");
    e.menu(&sentinel, menu);
    e.push(format!("dummy{r}"), &[]);
    select_hors(e, r, t);
    open_round_menu(e, r, &sentinel);
    e.number(t + 1);
    for a in 0..t {
        e.roll(&format!("k{r}_{a}"));
    }
    e.roll(&format!("kn{r}"));
    if r == 1 {
        e.op(SIZE);
        e.dup();
        e.number(33);
        e.drop(1);
        e.op(EQUALVERIFY);
        e.drop(1);
    }
    e.op(DUP);
    e.dup();
    e.op(SHA256);
    e.der_key();
    e.op(CHECKSIG);
    e.drop(2);
    e.stack.push("#false".into());
    e.op(DROP);
    e.drop(1);
    e.number(t + 1);
    e.op(CHECKMULTISIGVERIFY);
    e.drop(2 * (t + 1) + 3);
}

fn select_hors(e: &mut Emit, r: usize, t: usize) {
    for a in 0..t {
        e.roll(&format!("i{r}_{a}"));
        e.op(DUP);
        e.dup();
        e.op(ROLL);
        e.fetch("TSENT", 3, "CSEL");
        e.roll(&format!("pre{r}_{a}"));
        e.op(if r == 0 { HASH160 } else { RIPEMD160 });
        e.op(EQUALVERIFY);
        e.drop(2);
        e.op(ROLL);
        e.fetch("TSENT", 1, "SIG");
    }
}

fn open_round_menu(e: &mut Emit, r: usize, sentinel: &str) {
    e.roll(&format!("midx{r}"));
    e.clamp(sentinel);
    e.op(ROLL);
    e.fetch(sentinel, 1, "MC_sel");
    e.roll(&format!("msig{r}"));
    e.op(TUCK);
    let last = e.stack.last().expect("fixed stack").clone();
    e.stack.insert(e.stack.len() - 2, last);
    e.op(SHA1);
    e.op(EQUALVERIFY);
    e.drop(2);
}

pub(super) fn script_number(mut n: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    while n != 0 {
        bytes.push(n as u8);
        n >>= 8;
    }
    if bytes.last().is_some_and(|b| b & 0x80 != 0) {
        bytes.push(0);
    }
    bytes
}
pub(super) fn push_data(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    match data {
        [] => out.push(0),
        [b @ 1..=16] => out.push(0x50 + b),
        [0x81] => out.push(0x4f),
        _ => {
            assert!(data.len() < 76, "fixed PQB push");
            out.push(data.len() as u8);
            out.extend(data);
        }
    }
    out
}
