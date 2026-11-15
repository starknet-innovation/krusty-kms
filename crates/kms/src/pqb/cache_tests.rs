//! Cache laws: only public data is retained and exported copies are independent.
use super::*;

#[test]
fn cached_material_survives_copies_and_disclosure_operations() {
    let vault = PqbVault::from_seed(&[0; 32]); // Public test value only.
    assert!(vault.public.get().is_none());
    let mut copy = vault.public_material().unwrap();
    let cached = vault.cached_public_material().unwrap() as *const _;
    let expected = copy.clone();
    copy.script.clear();
    copy.commitments[0].fill(0);
    copy.menus[0].recovery_points.clear();
    assert_eq!(vault.public_material().unwrap(), expected);
    let fixture = super::tests::vectors();
    let spend = &fixture["spends"][0];
    let request = vault
        .prepare_disclosure(
            &super::tests::unsigned(spend),
            0,
            &expected.script_sha256,
            super::tests::selection(spend),
        )
        .unwrap();
    let first = vault.authorize(&request).unwrap();
    let retry = vault.authorize(&request).unwrap();
    assert_eq!(first.cosignature(), retry.cosignature());
    assert_eq!(cached, vault.cached_public_material().unwrap() as *const _);
}

#[test]
fn cache_preserves_thread_safe_vault_sharing() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<PqbVault>();
    let vault = PqbVault::from_seed(&[0; 32]);
    let hashes = std::thread::scope(|scope| {
        let a = scope.spawn(|| vault.public_material().unwrap().script_sha256);
        let b = scope.spawn(|| vault.public_material().unwrap().script_sha256);
        (a.join().unwrap(), b.join().unwrap())
    });
    assert_eq!(hashes.0, hashes.1);
    assert_eq!(hashes.0, vault.public_material().unwrap().script_sha256);
}
