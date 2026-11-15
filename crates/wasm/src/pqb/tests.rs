//! Public Python/TypeScript fixtures exercised through the WASM bindings.
use super::*;
use serde_json::{json, Value};
use wasm_bindgen_test::*;
fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../kms/tests/fixtures/pqb_kms_vectors.json"
    ))
    .unwrap()
}
fn value(v: JsValue) -> Value {
    serde_wasm_bindgen::from_value(v).unwrap()
}
fn js(v: Value) -> JsValue {
    serde_wasm_bindgen::to_value(&v).unwrap()
}
fn fixture_vault(seed: &Value) -> WasmPqbVault {
    let seed: [u8; 32] = hex::decode(seed.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    WasmPqbVault {
        vault: Some(PqbVault::from_seed(&seed)),
        network: PqbNetwork::Mainnet,
    }
}
fn unsigned(s: &Value) -> String {
    // Committed assembly vectors have one input; remove its variable-length scriptSig.
    let tx = hex::decode(s["tx"].as_str().unwrap()).unwrap();
    assert_eq!(tx[4], 1);
    let (len, start) = if tx[41] == 253 {
        (usize::from(u16::from_le_bytes([tx[42], tx[43]])), 44)
    } else {
        (usize::from(tx[41]), 42)
    };
    hex::encode([&tx[..41], &[0], &tx[start + len..]].concat())
}
#[wasm_bindgen_test]
fn committed_reference_scripts_menus_and_deposits() {
    let v = vectors();
    for s in v["scripts"].as_array().unwrap() {
        let p = value(fixture_vault(&s["seed"]).public_material().unwrap());
        assert_eq!(p["script"], s["script"]);
        assert_eq!(p["scriptSha256"], s["sha256"]);
        assert_eq!(p["cosigPublicKey"], s["cosig_pubkey"]);
        assert_eq!(p["commitments"].as_array().unwrap().len(), 109);
    }
    let p = value(
        fixture_vault(&v["menus"]["seed"])
            .public_material()
            .unwrap(),
    );
    for i in 0..3 {
        assert_eq!(p["menus"][i]["r"], v["menus"]["stages"][i]["r"]);
        assert_eq!(
            p["menus"][i]["recoveryPoints"],
            v["menus"]["stages"][i]["recovery_points"]
        );
    }
    for d in v["deposits"].as_array().unwrap() {
        let mut vault = fixture_vault(&d["seed"]);
        vault.network = network(&d["network"].as_str().unwrap().into()).unwrap();
        let got = value(vault.deposit().unwrap());
        assert_eq!(got["address"], d["address"]);
        assert_eq!(got["publicKey"], d["pubkey"]);
        assert_eq!(got["scriptPubkey"], d["script_pubkey"]);
    }
    for p in v["deposit_psbts"].as_array().unwrap() {
        let vault = fixture_vault(&p["seed"]);
        assert_eq!(
            vault
                .sign_deposit_psbt(p["psbt"].as_str().unwrap().into(), js(json!([0])))
                .unwrap(),
            p["signed_psbt"]
        );
        assert!(vault
            .sign_deposit_psbt(p["psbt"].as_str().unwrap().into(), js(json!([1])))
            .is_err());
    }
}
#[wasm_bindgen_test]
fn committed_reference_disclosures() {
    for s in vectors()["spends"].as_array().unwrap() {
        let vault = fixture_vault(&s["seed"]);
        let hash = value(vault.public_material().unwrap())["scriptSha256"]
            .as_str()
            .unwrap()
            .to_owned();
        let selection = if s["selection"].is_null() {
            json!([
                [3, 14, 25, 36, 47, 58, 69, 80],
                [10, 21, 32, 43, 54, 65, 76, 87, 98]
            ])
        } else {
            s["selection"].clone()
        };
        let menu = |key: &str| s["menu_pick"][key].as_u64().unwrap_or(0);
        let request = vault
            .prepare_disclosure(
                unsigned(s).into(),
                0.into(),
                hash.as_str().into(),
                js(selection[0].clone()),
                js(selection[1].clone()),
                js(json!([menu("pin"), menu("0"), menu("1")])),
            )
            .unwrap();
        let info = value(request.info().unwrap());
        assert_eq!(info["cosigSighash"], s["z_cosig"]);
        assert_eq!(info["stageSighashes"], s["z"]);
        let d = value(vault.authorize(&request).unwrap());
        assert_eq!(d["cosignature"], s["cosig_sig"]);
        let mut revealed: Vec<_> = ["round0", "round1", "menus"]
            .iter()
            .flat_map(|k| d[k].as_array().unwrap().iter().map(|v| v.as_str().unwrap()))
            .collect();
        revealed.sort();
        assert_eq!(json!(revealed), s["revealed"]);
        assert_eq!(d, value(vault.authorize(&request).unwrap()));
    }
}
