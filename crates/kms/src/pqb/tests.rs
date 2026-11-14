//! PUBLIC TEST VECTORS ONLY. Never fund these seeds.
use super::*;
use crate::bitcoin::tx::Transaction;
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../tests/fixtures/pqb_kms_vectors.json")).unwrap()
}
fn bytes(s: &Value) -> Vec<u8> {
    hex::decode(s.as_str().unwrap()).unwrap()
}
fn seed(s: &Value) -> [u8; 32] {
    bytes(s).try_into().unwrap()
}
fn network(s: &str) -> PqbNetwork {
    match s {
        "main" => PqbNetwork::Mainnet,
        "regtest" => PqbNetwork::Regtest,
        "testnet4" => PqbNetwork::Testnet4,
        _ => panic!("test chain"),
    }
}
fn selection(s: &Value) -> PqbSelection {
    let default = serde_json::json!([
        [3, 14, 25, 36, 47, 58, 69, 80],
        [10, 21, 32, 43, 54, 65, 76, 87, 98]
    ]);
    let sel = if s["selection"].is_null() {
        &default
    } else {
        &s["selection"]
    };
    let round = |i: usize| {
        sel[i]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap() as u8)
            .collect::<Vec<_>>()
    };
    let pick = |key: &str| s["menu_pick"][key].as_u64().unwrap_or(0) as u8;
    PqbSelection::new(
        round(0).try_into().unwrap(),
        round(1).try_into().unwrap(),
        [pick("pin"), pick("0"), pick("1")],
    )
    .unwrap()
}
fn unsigned(s: &Value) -> Vec<u8> {
    let mut tx = Transaction::parse_legacy(&bytes(&s["tx"])).unwrap();
    for input in &mut tx.inputs {
        input.script_sig.clear();
    }
    tx.serialize_legacy()
}

#[test]
fn python_typescript_lock_and_deposit_vectors() {
    let v = vectors();
    for s in v["scripts"].as_array().unwrap() {
        let vault = PqbVault::from_seed(&seed(&s["seed"]));
        let public = vault.public_material().unwrap();
        assert_eq!(public.script.len(), 4908);
        assert_eq!(hex::encode(&public.script), s["script"]);
        assert_eq!(hex::encode(public.script_sha256), s["sha256"]);
        assert_eq!(hex::encode(public.cosig_public_key), s["cosig_pubkey"]);
    }
    for d in v["deposits"].as_array().unwrap() {
        let got = PqbVault::from_seed(&seed(&d["seed"]))
            .deposit(network(d["network"].as_str().unwrap()))
            .unwrap();
        assert_eq!(got.address, d["address"]);
        assert_eq!(hex::encode(got.public_key), d["pubkey"]);
        assert_eq!(hex::encode(got.script_pubkey), d["script_pubkey"]);
    }
}
#[test]
fn python_bip85_and_network_binding_vectors() {
    let v = vectors();
    for c in v["bip85"]["children"].as_array().unwrap() {
        for net in ["main", "regtest"] {
            let vault = PqbVault::from_child_entropy(&seed(&c["entropy"]), network(net)).unwrap();
            assert_eq!(
                hex::encode(vault.seed.as_ref()),
                c["seeds"][format!("PQB|True|{net}")]
            );
        }
    }
    for w in v["wallets"].as_array().unwrap() {
        let vault = PqbVault::from_mnemonic(
            w["mnemonic"].as_str().unwrap(),
            w["passphrase"].as_str().unwrap(),
            w["index"].as_u64().unwrap() as u32,
            network(w["network"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(hex::encode(vault.seed.as_ref()), w["seed"]);
        assert_eq!(
            hex::encode(vault.public_material().unwrap().script_sha256),
            w["script_sha256"]
        );
    }
}
#[test]
fn python_typescript_spend_signatures_sighashes_and_reveals() {
    for s in vectors()["spends"].as_array().unwrap() {
        let vault = PqbVault::from_seed(&seed(&s["seed"]));
        let public = vault.public_material().unwrap();
        let request = vault
            .prepare_disclosure(&unsigned(s), 0, &public.script_sha256, selection(s))
            .unwrap();
        assert_eq!(hex::encode(request.cosig_sighash()), s["z_cosig"]);
        for (got, want) in request
            .stage_sighashes()
            .iter()
            .zip(s["z"].as_array().unwrap())
        {
            assert_eq!(hex::encode(got), *want);
        }
        let disclosure = vault.authorize(&request).unwrap();
        assert_eq!(hex::encode(disclosure.cosignature()), s["cosig_sig"]);
        let mut revealed = disclosure
            .round0()
            .iter()
            .map(hex::encode)
            .chain(disclosure.round1().iter().map(hex::encode))
            .chain(disclosure.menus().iter().map(hex::encode))
            .collect::<Vec<_>>();
        revealed.sort();
        assert_eq!(serde_json::json!(revealed), s["revealed"]);
        assert_eq!(format!("{vault:?}"), "PqbVault(***)");
        assert_eq!(format!("{disclosure:?}"), "PqbDisclosure(***)");
    }
}
#[test]
fn rejects_bad_selection_and_wallet_inputs() {
    let a = [0, 1, 2, 3, 4, 5, 6, 7];
    let b = [8, 9, 10, 11, 12, 13, 14, 15, 16];
    assert!(PqbSelection::new(a, b, [12, 0, 0]).is_err());
    assert!(PqbSelection::new(a, b, [0, 16, 0]).is_err());
    assert!(PqbSelection::new(a, b, [0, 0, 16]).is_err());
    let mut bad = b;
    bad[0] = 7;
    assert!(PqbSelection::new(a, bad, [0; 3]).is_err());
    bad[0] = 109;
    assert!(PqbSelection::new(a, bad, [0; 3]).is_err());
    bad[0] = bad[1];
    assert!(PqbSelection::new(a, bad, [0; 3]).is_err());
    assert!(PqbVault::from_mnemonic("invalid", "", 0, PqbNetwork::Mainnet).is_err());
    assert!(PqbVault::from_mnemonic("invalid", "", 1 << 31, PqbNetwork::Mainnet).is_err());
}
#[test]
fn request_binding_and_cross_vault_rejection() {
    let v = vectors();
    let s = &v["spends"][0];
    let vault = PqbVault::from_seed(&seed(&s["seed"]));
    let hash = vault.public_material().unwrap().script_sha256;
    let tx = unsigned(s);
    let request = vault
        .prepare_disclosure(&tx, 0, &hash, selection(s))
        .unwrap();
    assert!(PqbVault::from_seed(&[99; 32]).authorize(&request).is_err());
    assert!(vault
        .prepare_disclosure(&tx, 1, &hash, selection(s))
        .is_err());
    assert!(vault
        .prepare_disclosure(&tx, 0, &[0; 32], selection(s))
        .is_err());
    let mut changed = Transaction::parse_legacy(&tx).unwrap();
    changed.outputs[0].value -= 1;
    let other = vault
        .prepare_disclosure(&changed.serialize_legacy(), 0, &hash, selection(s))
        .unwrap();
    assert_ne!(request.digest(), other.digest());
    assert_ne!(request.cosig_sighash(), other.cosig_sighash());
    let base = selection(s);
    let mut menus = *base.menus();
    menus[0] = (menus[0] + 1) % 12;
    let changed_selection = PqbSelection::new(*base.rounds().0, *base.rounds().1, menus).unwrap();
    assert_ne!(
        request.digest(),
        vault
            .prepare_disclosure(&tx, 0, &hash, changed_selection)
            .unwrap()
            .digest()
    );
    let mut trailing = tx.clone();
    trailing.push(0);
    assert!(vault
        .prepare_disclosure(&trailing, 0, &hash, selection(s))
        .is_err());
    assert!(vault
        .prepare_disclosure(&bytes(&s["tx"]), 0, &hash, selection(s))
        .is_err());
    for n in 0..tx.len() {
        assert!(vault
            .prepare_disclosure(&tx[..n], 0, &hash, selection(s))
            .is_err());
    }
}

#[test]
fn python_typescript_grinder_points_and_python_deposit_psbts() {
    let v = vectors();
    let public = PqbVault::from_seed(&seed(&v["menus"]["seed"]))
        .public_material()
        .unwrap();
    for (got, want) in public
        .menus
        .iter()
        .zip(v["menus"]["stages"].as_array().unwrap())
    {
        assert_eq!(hex::encode(got.r), want["r"]);
        let points = got
            .recovery_points
            .iter()
            .map(|row| row.iter().map(hex::encode).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        assert_eq!(serde_json::json!(points), want["recovery_points"]);
    }
    for p in v["deposit_psbts"].as_array().unwrap() {
        let vault = PqbVault::from_seed(&seed(&p["seed"]));
        let signed = vault
            .sign_deposit_psbt(p["psbt"].as_str().unwrap(), &[0])
            .unwrap();
        assert_eq!(signed, p["signed_psbt"]);
        assert!(PqbVault::from_seed(&[99; 32])
            .sign_deposit_psbt(p["psbt"].as_str().unwrap(), &[0])
            .is_err());
        assert!(vault
            .sign_deposit_psbt(p["psbt"].as_str().unwrap(), &[1])
            .is_err());
    }
}

#[test]
fn child_words_restore_the_same_vault() {
    let v = vectors();
    for child in v["bip85"]["children"].as_array().unwrap() {
        let vault =
            PqbVault::from_child_mnemonic(child["words"].as_str().unwrap(), PqbNetwork::Mainnet)
                .unwrap();
        assert_eq!(
            hex::encode(vault.seed.as_ref()),
            child["seeds"]["PQB|True|main"]
        );
    }
    assert!(PqbVault::from_child_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", PqbNetwork::Mainnet).is_err());
}

#[test]
fn rejects_context_free_invalid_transactions_before_disclosure() {
    let v = vectors();
    let s = &v["spends"][0];
    let vault = PqbVault::from_seed(&seed(&s["seed"]));
    let hash = vault.public_material().unwrap().script_sha256;
    let tx = Transaction::parse_legacy(&unsigned(s)).unwrap();
    let mut cases = Vec::new();
    let mut bad = tx.clone();
    bad.inputs.clear();
    cases.push(bad);
    let mut bad = tx.clone();
    bad.outputs.clear();
    cases.push(bad);
    let mut bad = tx.clone();
    bad.inputs.push(bad.inputs[0].clone());
    cases.push(bad);
    let mut bad = tx.clone();
    bad.inputs[0].previous_output.txid = [0; 32];
    bad.inputs[0].previous_output.vout = u32::MAX;
    cases.push(bad);
    let mut bad = tx.clone();
    bad.outputs[0].value = 2_100_000_000_000_001;
    cases.push(bad);
    let mut bad = tx.clone();
    bad.outputs[0].value = 2_100_000_000_000_000;
    bad.outputs.push(bad.outputs[0].clone());
    cases.push(bad);
    let mut bad = tx.clone();
    bad.outputs[0].script_pubkey.resize(10001, 0);
    cases.push(bad);
    for bad in cases {
        assert!(vault
            .prepare_disclosure(&bad.serialize_legacy(), 0, &hash, selection(s))
            .is_err());
    }
    assert!(vault
        .prepare_disclosure(&[0; 50001], 0, &hash, selection(s))
        .is_err());
    let req = vault
        .prepare_disclosure(&unsigned(s), 0, &hash, selection(s))
        .unwrap();
    assert_eq!(
        vault.authorize(&req).unwrap().cosignature(),
        vault.authorize(&req).unwrap().cosignature()
    );
}
