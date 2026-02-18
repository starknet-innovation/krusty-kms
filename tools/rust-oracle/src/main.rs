use ghoul_common::ElGamalCiphertext;
use kms::{
    calculate_contract_address, derive_keypair_with_coin_type, derive_nostr_keypair,
    derive_nostr_private_key, derive_oz_account_address, derive_private_key_with_coin_type,
    derive_view_keypair, derive_view_private_key, validate_mnemonic, NOSTR_COIN_TYPE,
    STARKNET_COIN_TYPE, TONGO_COIN_TYPE, TONGO_VIEW_COIN_TYPE,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use she_core::{
    poseidon_hash_many, AuditProver, ElGamal, ProofOfExponentiation, ProofOfExponentiation2,
    StarkCurve,
};
use she_core::scalar::{reduce_scalar, scalar_add, scalar_mul};
use starknet_client::{build_erc20_approve, build_rollover_call};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, StarkHash};
use std::io::{Read, Write};
use tongo_sdk::operations::{
    fund, ragequit, rollover, transfer, withdraw, FundParams, RagequitParams, RolloverParams,
    TransferParams, WithdrawParams,
};
use tongo_sdk::{decrypt_as_auditor, encrypt_for_auditor, TongoAccount};

const VERSION: &str = "rust-oracle/0.2.0";

#[derive(Debug, Deserialize)]
struct OracleRequest {
    op: String,
    #[serde(default)]
    inputs: Value,
    #[serde(default)]
    rng: Option<RngRequest>,
}

#[derive(Debug, Deserialize)]
struct RngRequest {
    mode: String,
    seed_hex: String,
    stream: String,
}

#[derive(Debug, Serialize)]
struct OracleResponse {
    ok: bool,
    output: Value,
    output_bytes_hex: String,
    error: Option<String>,
    meta: Meta,
}

#[derive(Debug, Serialize)]
struct Meta {
    rng_draws: u64,
    impl_version: &'static str,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        match args[1].as_str() {
            "coin-types" => {
                println!(
                    "{}",
                    json!({
                        "tongo": TONGO_COIN_TYPE,
                        "starknet": STARKNET_COIN_TYPE,
                        "tongo_view": TONGO_VIEW_COIN_TYPE,
                        "nostr": NOSTR_COIN_TYPE,
                    })
                );
                return;
            }
            "derive-private" => {
                if args.len() < 6 {
                    usage();
                    std::process::exit(2);
                }
                let mnemonic = &args[2];
                let index = parse_u32_str(&args[3], "index");
                let account_index = parse_u32_str(&args[4], "account_index");
                let coin_type = parse_u32_str(&args[5], "coin_type");
                let passphrase = args.get(6).map(String::as_str);
                let kp = derive_keypair_with_coin_type(
                    mnemonic,
                    index,
                    account_index,
                    coin_type,
                    passphrase,
                )
                .expect("derive-private");
                println!("{}", felt_hex(&kp.private_key));
                return;
            }
            "derive-nostr" => {
                if args.len() < 5 {
                    usage();
                    std::process::exit(2);
                }
                let mnemonic = &args[2];
                let index = parse_u32_str(&args[3], "index");
                let account_index = parse_u32_str(&args[4], "account_index");
                let passphrase = args.get(5).map(String::as_str);
                let kp = derive_nostr_keypair(mnemonic, index, account_index, passphrase)
                    .expect("derive-nostr");
                println!(
                    "{}",
                    json!({
                        "private_key_hex": hex::encode(kp.private_key),
                        "public_key_xonly_hex": hex::encode(kp.public_key),
                    })
                );
                return;
            }
            "derive-oz-address" => {
                if args.len() < 7 {
                    usage();
                    std::process::exit(2);
                }
                let mnemonic = &args[2];
                let index = parse_u32_str(&args[3], "index");
                let account_index = parse_u32_str(&args[4], "account_index");
                let coin_type = parse_u32_str(&args[5], "coin_type");
                let class_hash = felt_from_hex(&args[6]).expect("class_hash");
                let salt = args
                    .get(7)
                    .map(|s| felt_from_hex(s).expect("salt"))
                    .unwrap_or(Felt::ZERO);

                let kp = derive_keypair_with_coin_type(mnemonic, index, account_index, coin_type, None)
                    .expect("derive-keypair");
                let pub_x = kp.public_key.to_affine().expect("affine").x();
                let addr = derive_oz_account_address(&pub_x, &class_hash, Some(&salt)).expect("address");

                println!(
                    "{}",
                    json!({
                        "public_key_x": felt_hex(&pub_x),
                        "address": felt_hex(&addr),
                    })
                );
                return;
            }
            "json" => {
                let req = read_request_from_stdin();
                let res = execute_request(req);
                print_response(&res);
                return;
            }
            _ => {
                usage();
                std::process::exit(2);
            }
        }
    }

    // JSON mode by default when invoked with no args.
    let req = read_request_from_stdin();
    let res = execute_request(req);
    print_response(&res);
}

fn usage() {
    eprintln!(
        "usage:\n  rust-oracle coin-types\n  rust-oracle derive-private <mnemonic> <index> <account_index> <coin_type> [passphrase]\n  rust-oracle derive-nostr <mnemonic> <index> <account_index> [passphrase]\n  rust-oracle derive-oz-address <mnemonic> <index> <account_index> <coin_type> <class_hash> [salt]\n  rust-oracle json < request.json>"
    );
}

fn read_request_from_stdin() -> OracleRequest {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .expect("read stdin");
    serde_json::from_str(&buf).expect("valid oracle request json")
}

fn print_response(resp: &OracleResponse) {
    let text = serde_json::to_string(resp).expect("serialize response");
    let mut out = std::io::stdout();
    out.write_all(text.as_bytes()).expect("write response");
}

fn execute_request(req: OracleRequest) -> OracleResponse {
    let mut rng_enabled = false;
    if let Some(cfg) = &req.rng {
        if cfg.mode == "deterministic" {
            match seed32_from_hex(&cfg.seed_hex) {
                Ok(seed) => {
                    she_core::set_deterministic_rng(seed, cfg.stream.as_bytes());
                    nostr_messaging::set_deterministic_rng(seed, cfg.stream.as_bytes());
                    rng_enabled = true;
                }
                Err(e) => {
                    return error_response(format!("invalid rng.seed_hex: {e}"));
                }
            }
        }
    }

    let result = match handle_op(&req.op, &req.inputs) {
        Ok((output, bytes)) => success_response(output, bytes),
        Err(err) => error_response(err),
    };

    if rng_enabled {
        she_core::clear_deterministic_rng();
        nostr_messaging::clear_deterministic_rng();
    }

    result
}

fn success_response(output: Value, bytes: Vec<u8>) -> OracleResponse {
    let output_bytes_hex = if bytes.is_empty() {
        hex::encode(canonical_output_bytes(&output))
    } else {
        hex::encode(bytes)
    };

    OracleResponse {
        ok: true,
        output,
        output_bytes_hex,
        error: None,
        meta: Meta {
            rng_draws: 0,
            impl_version: VERSION,
        },
    }
}

fn error_response(error: String) -> OracleResponse {
    OracleResponse {
        ok: false,
        output: Value::Null,
        output_bytes_hex: String::new(),
        error: Some(error),
        meta: Meta {
            rng_draws: 0,
            impl_version: VERSION,
        },
    }
}

fn handle_op(op: &str, inputs: &Value) -> Result<(Value, Vec<u8>), String> {
    match op {
        "kms.coin_types" => {
            let out = json!({
                "tongo": TONGO_COIN_TYPE,
                "starknet": STARKNET_COIN_TYPE,
                "tongo_view": TONGO_VIEW_COIN_TYPE,
                "nostr": NOSTR_COIN_TYPE,
            });
            Ok((out, vec![]))
        }
        "kms.felt_roundtrip_hex" => {
            let hex = req_str(inputs, "hex")?;
            let felt = felt_from_hex(hex)?;
            let out = json!({ "hex": felt_hex(&felt) });
            Ok((out, felt.to_bytes_be().to_vec()))
        }
        "kms.pedersen_hash" => {
            let left = felt_from_hex(req_str(inputs, "left")?)?;
            let right = felt_from_hex(req_str(inputs, "right")?)?;
            let h = Pedersen::hash(&left, &right);
            let out = json!({ "hash": felt_hex(&h) });
            Ok((out, h.to_bytes_be().to_vec()))
        }
        "kms.poseidon_hash_many" => {
            let values = req_felt_array(inputs, "values")?;
            let h = poseidon_hash_many(&values);
            let out = json!({ "hash": felt_hex(&h) });
            Ok((out, h.to_bytes_be().to_vec()))
        }
        "kms.validate_mnemonic" => {
            let phrase = req_str(inputs, "phrase")?;
            let valid = validate_mnemonic(phrase).is_ok();
            let out = json!({ "valid": valid });
            Ok((out, vec![if valid { 1 } else { 0 }]))
        }
        "kms.mnemonic_to_seed" => {
            let phrase = req_str(inputs, "phrase")?;
            let passphrase = req_str_default(inputs, "passphrase", "");
            let mnemonic = bip39::Mnemonic::parse(phrase).map_err(err_to_string)?;
            let seed = mnemonic.to_seed(passphrase);
            let out = json!({ "seed_hex": hex::encode(seed) });
            Ok((out, seed.to_vec()))
        }
        "kms.derive_private_key_with_coin_type" => {
            let mnemonic = req_str(inputs, "mnemonic")?;
            let index = req_u32(inputs, "index")?;
            let account_index = req_u32(inputs, "account_index")?;
            let coin_type = req_u32(inputs, "coin_type")?;
            let passphrase = req_optional_str(inputs, "passphrase");
            let private = derive_private_key_with_coin_type(
                mnemonic,
                index,
                account_index,
                coin_type,
                passphrase,
            )
            .map_err(err_to_string)?;
            let out = json!({ "private_key": felt_hex(&private) });
            Ok((out, private.to_bytes_be().to_vec()))
        }
        "kms.derive_keypair_with_coin_type" => {
            let mnemonic = req_str(inputs, "mnemonic")?;
            let index = req_u32(inputs, "index")?;
            let account_index = req_u32(inputs, "account_index")?;
            let coin_type = req_u32(inputs, "coin_type")?;
            let passphrase = req_optional_str(inputs, "passphrase");
            let kp = derive_keypair_with_coin_type(
                mnemonic,
                index,
                account_index,
                coin_type,
                passphrase,
            )
            .map_err(err_to_string)?;
            let out = json!({
                "private_key": felt_hex(&kp.private_key),
                "public_key": point_json(&kp.public_key)?,
            });
            Ok((out, concat_bytes(&[&kp.private_key.to_bytes_be(), &projective_bytes(&kp.public_key)?])))
        }
        "kms.derive_view_private_key" => {
            let mnemonic = req_str(inputs, "mnemonic")?;
            let index = req_u32(inputs, "index")?;
            let account_index = req_u32(inputs, "account_index")?;
            let passphrase = req_optional_str(inputs, "passphrase");
            let private = derive_view_private_key(mnemonic, index, account_index, passphrase)
                .map_err(err_to_string)?;
            let out = json!({ "private_key": felt_hex(&private) });
            Ok((out, private.to_bytes_be().to_vec()))
        }
        "kms.derive_view_keypair" => {
            let mnemonic = req_str(inputs, "mnemonic")?;
            let index = req_u32(inputs, "index")?;
            let account_index = req_u32(inputs, "account_index")?;
            let passphrase = req_optional_str(inputs, "passphrase");
            let kp = derive_view_keypair(mnemonic, index, account_index, passphrase)
                .map_err(err_to_string)?;
            let out = json!({
                "private_key": felt_hex(&kp.private_key),
                "public_key": point_json(&kp.public_key)?,
            });
            Ok((out, concat_bytes(&[&kp.private_key.to_bytes_be(), &projective_bytes(&kp.public_key)?])))
        }
        "kms.derive_nostr_private_key" => {
            let mnemonic = req_str(inputs, "mnemonic")?;
            let index = req_u32(inputs, "index")?;
            let account_index = req_u32(inputs, "account_index")?;
            let passphrase = req_optional_str(inputs, "passphrase");
            let key = derive_nostr_private_key(mnemonic, index, account_index, passphrase)
                .map_err(err_to_string)?;
            let out = json!({ "private_key_hex": hex::encode(key) });
            Ok((out, key.to_vec()))
        }
        "kms.derive_nostr_keypair" => {
            let mnemonic = req_str(inputs, "mnemonic")?;
            let index = req_u32(inputs, "index")?;
            let account_index = req_u32(inputs, "account_index")?;
            let passphrase = req_optional_str(inputs, "passphrase");
            let kp = derive_nostr_keypair(mnemonic, index, account_index, passphrase)
                .map_err(err_to_string)?;
            let out = json!({
                "private_key_hex": hex::encode(kp.private_key),
                "public_key_xonly_hex": hex::encode(kp.public_key),
            });
            Ok((out, concat_bytes(&[&kp.private_key, &kp.public_key])))
        }
        "kms.calculate_contract_address" => {
            let salt = felt_from_hex(req_str(inputs, "salt")?)?;
            let class_hash = felt_from_hex(req_str(inputs, "class_hash")?)?;
            let deployer = felt_from_hex(req_str(inputs, "deployer")?)?;
            let calldata = req_felt_array(inputs, "constructor_calldata")?;
            let addr = calculate_contract_address(&salt, &class_hash, &calldata, &deployer)
                .map_err(err_to_string)?;
            let out = json!({ "address": felt_hex(&addr) });
            Ok((out, addr.to_bytes_be().to_vec()))
        }
        "kms.derive_oz_account_address" => {
            let public_key_x = felt_from_hex(req_str(inputs, "public_key_x")?)?;
            let class_hash = felt_from_hex(req_str(inputs, "class_hash")?)?;
            let salt = req_optional_str(inputs, "salt")
                .map(felt_from_hex)
                .transpose()?;
            let addr = derive_oz_account_address(&public_key_x, &class_hash, salt.as_ref())
                .map_err(err_to_string)?;
            let out = json!({ "address": felt_hex(&addr) });
            Ok((out, addr.to_bytes_be().to_vec()))
        }
        "she.scalar_add" => {
            let a = felt_from_hex(req_str(inputs, "a")?)?;
            let b = felt_from_hex(req_str(inputs, "b")?)?;
            let out_f = scalar_add(&a, &b).map_err(err_to_string)?;
            let out = json!({ "result": felt_hex(&out_f) });
            Ok((out, out_f.to_bytes_be().to_vec()))
        }
        "she.scalar_mul" => {
            let a = felt_from_hex(req_str(inputs, "a")?)?;
            let b = felt_from_hex(req_str(inputs, "b")?)?;
            let out_f = scalar_mul(&a, &b).map_err(err_to_string)?;
            let out = json!({ "result": felt_hex(&out_f) });
            Ok((out, out_f.to_bytes_be().to_vec()))
        }
        "she.reduce_scalar" => {
            let a = felt_from_hex(req_str(inputs, "a")?)?;
            let out_f = reduce_scalar(&a).map_err(err_to_string)?;
            let out = json!({ "result": felt_hex(&out_f) });
            Ok((out, out_f.to_bytes_be().to_vec()))
        }
        "she.curve_mul_generator" => {
            let scalar = felt_from_hex(req_str(inputs, "scalar")?)?;
            let point = StarkCurve::mul_generator(&scalar);
            let out = json!({ "point": point_json(&point)? });
            Ok((out, projective_bytes(&point)?))
        }
        "she.curve_add" => {
            let p1 = projective_from_inputs(inputs, "p1")?;
            let p2 = projective_from_inputs(inputs, "p2")?;
            let sum = StarkCurve::add(&p1, &p2);
            let out = json!({ "point": point_json(&sum)? });
            Ok((out, projective_bytes(&sum)?))
        }
        "she.poseidon_hash_many" => {
            let felts = req_felt_array(inputs, "values")?;
            let h = poseidon_hash_many(&felts);
            let out = json!({ "hash": felt_hex(&h) });
            Ok((out, h.to_bytes_be().to_vec()))
        }
        "she.poe_prove_verify" => {
            let x = felt_from_hex(req_str(inputs, "x")?)?;
            let prefix = felt_from_hex(req_str(inputs, "prefix")?)?;
            let (y, proof) = ProofOfExponentiation::prove(&x, &prefix).map_err(err_to_string)?;
            let valid = ProofOfExponentiation::verify(&y, &proof, &prefix).map_err(err_to_string)?;
            let out = json!({ "valid": valid, "y": point_json(&y)? });
            Ok((out, concat_bytes(&[&projective_bytes(&y)?, &[if valid { 1 } else { 0 }]])))
        }
        "she.poe2_prove_verify" => {
            let x1 = felt_from_hex(req_str(inputs, "x1")?)?;
            let x2 = felt_from_hex(req_str(inputs, "x2")?)?;
            let prefix = felt_from_hex(req_str(inputs, "prefix")?)?;
            let (y, proof) =
                ProofOfExponentiation2::prove(&x1, &x2, &StarkCurve::GENERATOR, &StarkCurve::GENERATOR_H, &prefix)
                    .map_err(err_to_string)?;
            let valid = ProofOfExponentiation2::verify(
                &y,
                &StarkCurve::GENERATOR,
                &StarkCurve::GENERATOR_H,
                &proof,
                &prefix,
            )
            .map_err(err_to_string)?;
            let out = json!({ "valid": valid, "y": point_json(&y)? });
            Ok((out, concat_bytes(&[&projective_bytes(&y)?, &[if valid { 1 } else { 0 }]])))
        }
        "she.elgamal_encrypt_verify_decrypt" => {
            let message = felt_from_hex(req_str(inputs, "message")?)?;
            let sk = felt_from_hex(req_str(inputs, "private_key")?)?;
            let randomness = felt_from_hex(req_str(inputs, "randomness")?)?;
            let prefix = felt_from_hex(req_str(inputs, "prefix")?)?;
            let pk = StarkCurve::mul(&sk, Some(&StarkCurve::GENERATOR));
            let enc = ElGamal::encrypt(&message, &pk, &randomness, &prefix).map_err(err_to_string)?;
            let valid = ElGamal::verify(&enc.l, &enc.r, &pk, &enc.proof, &prefix).map_err(err_to_string)?;
            let dec = ElGamal::decrypt(&ElGamalCiphertext { l: enc.l.clone(), r: enc.r.clone() }, &sk)
                .map_err(err_to_string)?;
            let out = json!({
                "valid": valid,
                "l": point_json(&enc.l)?,
                "r": point_json(&enc.r)?,
                "decrypted": point_json(&dec)?,
            });
            Ok((out, concat_bytes(&[
                &projective_bytes(&enc.l)?,
                &projective_bytes(&enc.r)?,
                &projective_bytes(&dec)?,
                &[if valid { 1 } else { 0 }],
            ])))
        }
        "she.bit_prove_verify" => {
            let bit = req_u8(inputs, "bit")?;
            let random = felt_from_hex(req_str(inputs, "random")?)?;
            let prefix = felt_from_hex(req_str(inputs, "prefix")?)?;
            let (v, proof) = she_core::bit::prove(bit, &random, &StarkCurve::GENERATOR, &StarkCurve::GENERATOR_H, &prefix)
                .map_err(err_to_string)?;
            let valid = she_core::bit::verify(&v, &StarkCurve::GENERATOR, &StarkCurve::GENERATOR_H, &proof, &prefix)
                .map_err(err_to_string)?;
            let out = json!({ "valid": valid, "v": point_json(&v)? });
            Ok((out, concat_bytes(&[&projective_bytes(&v)?, &[if valid { 1 } else { 0 }]])))
        }
        "she.range_prove_verify" => {
            let value = req_u128(inputs, "value")?;
            let bit_size = req_usize(inputs, "bit_size")?;
            let prefix = felt_from_hex(req_str(inputs, "prefix")?)?;
            let (range, _r) = she_core::range::prove(value, bit_size, &StarkCurve::GENERATOR, &StarkCurve::GENERATOR_H, &prefix)
                .map_err(err_to_string)?;
            let v = she_core::range::verify(&range, bit_size, &StarkCurve::GENERATOR, &StarkCurve::GENERATOR_H, &prefix)
                .map_err(err_to_string)?;
            let out = json!({
                "commitments": range.commitments.len(),
                "proofs": range.proofs.len(),
                "v": point_json(&v)?,
            });
            Ok((out, concat_bytes(&[
                &(range.commitments.len() as u32).to_be_bytes(),
                &(range.proofs.len() as u32).to_be_bytes(),
                &projective_bytes(&v)?,
            ])))
        }
        "she.audit_prove_verify" => {
            let private_key = felt_from_hex(req_str(inputs, "private_key")?)?;
            let balance = req_u128(inputs, "balance")?;
            let r0 = felt_from_hex(req_str(inputs, "cipher_random")?)?;
            let auditor_sk = felt_from_hex(req_str(inputs, "auditor_private_key")?)?;
            let g = StarkCurve::GENERATOR;
            let user_pk = StarkCurve::mul(&private_key, Some(&g));
            let auditor_pk = StarkCurve::mul(&auditor_sk, Some(&g));

            let l0 = StarkCurve::add(
                &StarkCurve::mul(&Felt::from(balance), Some(&g)),
                &StarkCurve::mul(&r0, Some(&user_pk)),
            );
            let cipher0 = ElGamalCiphertext {
                l: l0,
                r: StarkCurve::mul(&r0, Some(&g)),
            };

            let (proof, cipher1) =
                AuditProver::prove(&private_key, balance, &cipher0, &auditor_pk)
                    .map_err(err_to_string)?;
            let valid = AuditProver::verify(&proof, &user_pk, &cipher0, &cipher1, &auditor_pk)
                .map_err(err_to_string)?;
            let out = json!({
                "valid": valid,
                "cipher1_l": point_json(&cipher1.l)?,
                "cipher1_r": point_json(&cipher1.r)?,
            });
            Ok((out, concat_bytes(&[
                &projective_bytes(&cipher1.l)?,
                &projective_bytes(&cipher1.r)?,
                &[if valid { 1 } else { 0 }],
            ])))
        }
        "tongo.audit_hint_roundtrip" => {
            let balance = req_u128(inputs, "balance")?;
            let user_sk = felt_from_hex(req_str(inputs, "user_private_key")?)?;
            let auditor_sk = felt_from_hex(req_str(inputs, "auditor_private_key")?)?;
            let g = StarkCurve::GENERATOR;
            let user_pk = StarkCurve::mul(&user_sk, Some(&g));
            let auditor_pk = StarkCurve::mul(&auditor_sk, Some(&g));
            let (ciphertext, nonce) = encrypt_for_auditor(balance, &user_sk, &auditor_pk).map_err(err_to_string)?;
            let decrypted = decrypt_as_auditor(&ciphertext, &nonce, &auditor_sk, &user_pk).map_err(err_to_string)?;
            let out = json!({
                "decrypted": decrypted.to_string(),
                "ciphertext_hex": hex::encode(ciphertext),
                "nonce_hex": hex::encode(nonce),
            });
            Ok((out, concat_bytes(&[&ciphertext, &nonce, &decrypted.to_be_bytes()])))
        }
        "tongo.account_from_mnemonic" => {
            let mnemonic = req_str(inputs, "mnemonic")?;
            let index = req_u32(inputs, "index")?;
            let account_index = req_u32(inputs, "account_index")?;
            let contract_address = felt_from_hex(req_str(inputs, "contract_address")?)?;
            let passphrase = req_optional_str(inputs, "passphrase");
            let account = TongoAccount::from_mnemonic(
                mnemonic,
                index,
                account_index,
                contract_address,
                passphrase,
            )
            .map_err(err_to_string)?;
            let owner = account.keypair.public_key.to_affine().map_err(|_| "owner point at infinity".to_string())?;
            let view = account
                .view_keypair
                .as_ref()
                .map(|v| v.public_key.to_affine())
                .transpose()
                .map_err(|_| "view point at infinity".to_string())?;
            let out = json!({
                "owner_x": felt_hex(&owner.x()),
                "owner_y": felt_hex(&owner.y()),
                "has_view_key": account.has_view_key(),
                "view_x": view.as_ref().map(|p| felt_hex(&p.x())),
                "view_y": view.as_ref().map(|p| felt_hex(&p.y())),
            });
            Ok((out, vec![]))
        }
        "tongo.fund" => {
            let mut account = req_test_account(inputs)?;
            let amount = req_u128(inputs, "amount")?;
            let nonce = felt_from_hex(req_str(inputs, "nonce")?)?;
            let chain_id = felt_from_hex(req_str(inputs, "chain_id")?)?;
            let tongo_address = account.contract_address;
            let current_balance = req_current_balance(inputs, &account)?;

            let proof = fund(
                &account,
                FundParams {
                    amount,
                    nonce,
                    chain_id,
                    tongo_address,
                    auditor_pub_key: None,
                    current_balance,
                },
            )
            .map_err(err_to_string)?;

            let y = proof.y.to_affine().map_err(|_| "fund y infinity".to_string())?;
            let out = json!({
                "amount": proof.amount.to_string(),
                "y_x": felt_hex(&y.x()),
                "y_y": felt_hex(&y.y()),
            });
            Ok((out, concat_bytes(&[&proof.amount.to_be_bytes(), &projective_bytes(&proof.y)?])))
        }
        "tongo.rollover" => {
            let account = req_test_account(inputs)?;
            let nonce = felt_from_hex(req_str(inputs, "nonce")?)?;
            let chain_id = felt_from_hex(req_str(inputs, "chain_id")?)?;
            let tongo_address = account.contract_address;
            let proof = rollover(
                &account,
                RolloverParams {
                    nonce,
                    chain_id,
                    tongo_address,
                },
            )
            .map_err(err_to_string)?;
            let out = json!({ "pending_amount": proof.pending_amount.to_string(), "y": point_json(&proof.y)? });
            Ok((out, concat_bytes(&[&proof.pending_amount.to_be_bytes(), &projective_bytes(&proof.y)?])))
        }
        "tongo.transfer" => {
            let mut account = req_test_account(inputs)?;
            let amount = req_u128(inputs, "amount")?;
            let nonce = felt_from_hex(req_str(inputs, "nonce")?)?;
            let chain_id = felt_from_hex(req_str(inputs, "chain_id")?)?;
            let bit_size = req_usize(inputs, "bit_size")?;
            let recipient_private = felt_from_hex(req_str(inputs, "recipient_private_key")?)?;
            let recipient_public_key = StarkCurve::mul_generator(&recipient_private);
            let current_balance = req_current_balance(inputs, &account)?;

            let proof = transfer(
                &account,
                TransferParams {
                    recipient_public_key,
                    amount,
                    nonce,
                    chain_id,
                    tongo_address: account.contract_address,
                    current_balance,
                    bit_size,
                    auditor_pub_key: None,
                },
            )
            .map_err(err_to_string)?;

            let out = json!({
                "transfer_l": point_json(&proof.transfer_balance_l)?,
                "transfer_r": point_json(&proof.transfer_balance_r)?,
                "new_balance_l": point_json(&proof.new_balance_cipher.l)?,
                "new_balance_r": point_json(&proof.new_balance_cipher.r)?,
            });
            Ok((out, vec![]))
        }
        "tongo.withdraw" => {
            let account = req_test_account(inputs)?;
            let amount = req_u128(inputs, "amount")?;
            let nonce = felt_from_hex(req_str(inputs, "nonce")?)?;
            let chain_id = felt_from_hex(req_str(inputs, "chain_id")?)?;
            let bit_size = req_usize(inputs, "bit_size")?;
            let recipient = felt_from_hex(req_str(inputs, "recipient")?)?;
            let current_balance = req_current_balance(inputs, &account)?;

            let proof = withdraw(
                &account,
                WithdrawParams {
                    recipient_address: recipient,
                    amount,
                    nonce,
                    chain_id,
                    tongo_address: account.contract_address,
                    current_balance,
                    bit_size,
                    auditor_key: None,
                },
            )
            .map_err(err_to_string)?;

            let out = json!({
                "amount": proof.amount.to_string(),
                "recipient": felt_hex(&proof.recipient),
                "y": point_json(&proof.y)?,
            });
            Ok((out, concat_bytes(&[&proof.amount.to_be_bytes(), &proof.recipient.to_bytes_be(), &projective_bytes(&proof.y)?])))
        }
        "tongo.ragequit" => {
            let account = req_test_account(inputs)?;
            let nonce = felt_from_hex(req_str(inputs, "nonce")?)?;
            let chain_id = felt_from_hex(req_str(inputs, "chain_id")?)?;
            let recipient = felt_from_hex(req_str(inputs, "recipient")?)?;
            let current_balance = req_current_balance(inputs, &account)?;

            let proof = ragequit(
                &account,
                RagequitParams {
                    recipient_address: recipient,
                    nonce,
                    chain_id,
                    tongo_address: account.contract_address,
                    current_balance,
                    auditor_key: None,
                },
            )
            .map_err(err_to_string)?;
            let out = json!({
                "amount": proof.amount.to_string(),
                "recipient": felt_hex(&proof.recipient),
                "y": point_json(&proof.y)?,
            });
            Ok((out, concat_bytes(&[&proof.amount.to_be_bytes(), &proof.recipient.to_bytes_be(), &projective_bytes(&proof.y)?])))
        }
        "nostr.derive_shared_secret" => {
            let sender_sk = req_str(inputs, "sender_sk_hex")?;
            let receiver_pk = req_str(inputs, "receiver_pk_hex")?;
            let shared = nostr_messaging::derive_shared_secret(sender_sk, receiver_pk)
                .map_err(err_to_string)?;
            let out = json!({ "shared_secret_hex": hex::encode(shared) });
            Ok((out, shared.to_vec()))
        }
        "nostr.derive_public_key" => {
            let secret = req_str(inputs, "secret_hex")?;
            let pk = nostr_messaging::derive_public_key(secret).map_err(err_to_string)?;
            let out = json!({ "public_key_hex": pk.clone() });
            Ok((out, hex::decode(pk).map_err(err_to_string)?))
        }
        "nostr.encrypt_decrypt_roundtrip" => {
            let sender_sk = req_str(inputs, "sender_sk_hex")?;
            let receiver_sk = req_str(inputs, "receiver_sk_hex")?;
            let plaintext = req_str(inputs, "plaintext")?.as_bytes().to_vec();
            let sender_pk = nostr_messaging::derive_public_key(sender_sk).map_err(err_to_string)?;
            let receiver_pk = nostr_messaging::derive_public_key(receiver_sk).map_err(err_to_string)?;
            let payload = nostr_messaging::encrypt_message(sender_sk, &receiver_pk, &plaintext)
                .map_err(err_to_string)?;
            let decrypted = nostr_messaging::decrypt_message(receiver_sk, &sender_pk, &payload)
                .map_err(err_to_string)?;
            let out = json!({
                "payload_b64": payload,
                "decrypted": String::from_utf8_lossy(&decrypted),
            });
            Ok((out, decrypted))
        }
        "starknet.selector_from_name" => {
            let name = req_str(inputs, "name")?;
            let selector = starknet_client::starknet::core::utils::get_selector_from_name(name)
                .map_err(err_to_string)?;
            let selector = Felt::from_bytes_be(&selector.to_bytes_be());
            let out = json!({ "selector": felt_hex(&selector) });
            Ok((out, selector.to_bytes_be().to_vec()))
        }
        "starknet.serialize_projective_point" => {
            let point = projective_from_inputs(inputs, "point")?;
            let (x, y) = starknet_client::serialization::serialize_projective_point(&point)
                .map_err(err_to_string)?;
            let out = json!({ "x": felt_hex(&x), "y": felt_hex(&y) });
            Ok((out, concat_bytes(&[&x.to_bytes_be(), &y.to_bytes_be()])))
        }
        "starknet.u128_u256_roundtrip" => {
            let value = req_u128(inputs, "value")?;
            let (low, high) = starknet_client::serialization::u128_to_u256(value);
            let back = starknet_client::serialization::u256_to_u128(low, high)
                .map_err(err_to_string)?;
            let out = json!({
                "low": felt_hex(&low),
                "high": felt_hex(&high),
                "roundtrip": back.to_string(),
            });
            Ok((out, concat_bytes(&[&low.to_bytes_be(), &high.to_bytes_be(), &back.to_be_bytes()])))
        }
        "starknet.build_erc20_approve" => {
            let erc20 = felt_from_hex(req_str(inputs, "erc20_address")?)?;
            let spender = felt_from_hex(req_str(inputs, "spender")?)?;
            let amount = req_u128(inputs, "amount")?;
            let call = build_erc20_approve(erc20, spender, amount).map_err(err_to_string)?;
            let calldata_hex: Vec<String> = call.calldata.iter().map(felt_hex).collect();
            let out = json!({
                "to": felt_hex(&call.to),
                "selector": felt_hex(&call.selector),
                "calldata": calldata_hex,
            });
            let mut bytes = vec![];
            bytes.extend_from_slice(&call.to.to_bytes_be());
            bytes.extend_from_slice(&call.selector.to_bytes_be());
            bytes.extend_from_slice(&(call.calldata.len() as u32).to_be_bytes());
            for felt in call.calldata {
                bytes.extend_from_slice(&felt.to_bytes_be());
            }
            Ok((out, bytes))
        }
        "starknet.build_rollover_call" => {
            let account = req_test_account(inputs)?;
            let nonce = felt_from_hex(req_str(inputs, "nonce")?)?;
            let chain_id = felt_from_hex(req_str(inputs, "chain_id")?)?;
            let tongo_address = account.contract_address;
            let rollover_proof = rollover(
                &account,
                RolloverParams {
                    nonce,
                    chain_id,
                    tongo_address,
                },
            )
            .map_err(err_to_string)?;
            let hint_ct = [0u8; 64];
            let hint_nonce = [0u8; 24];
            let call = build_rollover_call(tongo_address, &rollover_proof, &hint_ct, &hint_nonce)
                .map_err(err_to_string)?;
            let out = json!({
                "to": felt_hex(&call.to),
                "selector": felt_hex(&call.selector),
                "calldata_len": call.calldata.len(),
            });
            let mut bytes = vec![];
            bytes.extend_from_slice(&call.to.to_bytes_be());
            bytes.extend_from_slice(&call.selector.to_bytes_be());
            bytes.extend_from_slice(&(call.calldata.len() as u32).to_be_bytes());
            Ok((out, bytes))
        }
        _ => Err(format!("unsupported op: {op}")),
    }
}

fn req_test_account(inputs: &Value) -> Result<TongoAccount, String> {
    let private_key = felt_from_hex(req_str(inputs, "private_key")?)?;
    let contract_address = felt_from_hex(req_str(inputs, "contract_address")?)?;
    let mut account = TongoAccount::from_private_key(private_key, contract_address)
        .map_err(err_to_string)?;
    account.state.balance = req_u128(inputs, "balance")?;
    account.state.pending_balance = req_u128_default(inputs, "pending_balance", 0)?;
    account.state.nonce = req_u64_default(inputs, "account_nonce", 0)?;
    Ok(account)
}

fn req_current_balance(inputs: &Value, account: &TongoAccount) -> Result<ElGamalCiphertext, String> {
    if let Some(current) = inputs.get("current_balance") {
        let l = projective_from_value(current.get("l").ok_or_else(|| "current_balance.l missing".to_string())?)?;
        let r = projective_from_value(current.get("r").ok_or_else(|| "current_balance.r missing".to_string())?)?;
        return Ok(ElGamalCiphertext { l, r });
    }

    let random = req_optional_str(inputs, "current_balance_random")
        .map(felt_from_hex)
        .transpose()?
        .unwrap_or_else(|| Felt::from(1u64));

    let y = account.keypair.public_key.clone();
    let g = StarkCurve::GENERATOR;
    let l = StarkCurve::add(
        &StarkCurve::mul(&Felt::from(account.state.balance), Some(&g)),
        &StarkCurve::mul(&random, Some(&y)),
    );
    let r = StarkCurve::mul(&random, Some(&g));
    Ok(ElGamalCiphertext { l, r })
}

fn req_str<'a>(inputs: &'a Value, key: &str) -> Result<&'a str, String> {
    inputs
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field: {key}"))
}

fn req_optional_str<'a>(inputs: &'a Value, key: &str) -> Option<&'a str> {
    inputs.get(key).and_then(Value::as_str)
}

fn req_str_default<'a>(inputs: &'a Value, key: &str, default: &'a str) -> &'a str {
    req_optional_str(inputs, key).unwrap_or(default)
}

fn req_u32(inputs: &Value, key: &str) -> Result<u32, String> {
    let v = req_u64(inputs, key)?;
    u32::try_from(v).map_err(|_| format!("field {key} exceeds u32"))
}

fn req_u8(inputs: &Value, key: &str) -> Result<u8, String> {
    let v = req_u64(inputs, key)?;
    u8::try_from(v).map_err(|_| format!("field {key} exceeds u8"))
}

fn req_u64(inputs: &Value, key: &str) -> Result<u64, String> {
    if let Some(v) = inputs.get(key) {
        if let Some(n) = v.as_u64() {
            return Ok(n);
        }
        if let Some(s) = v.as_str() {
            return s
                .parse::<u64>()
                .map_err(|e| format!("invalid u64 {key}: {e}"));
        }
    }
    Err(format!("missing u64 field: {key}"))
}

fn req_u64_default(inputs: &Value, key: &str, default: u64) -> Result<u64, String> {
    match inputs.get(key) {
        None => Ok(default),
        Some(v) if v.is_null() => Ok(default),
        Some(_) => req_u64(inputs, key),
    }
}

fn req_u128(inputs: &Value, key: &str) -> Result<u128, String> {
    if let Some(v) = inputs.get(key) {
        if let Some(n) = v.as_u64() {
            return Ok(n as u128);
        }
        if let Some(s) = v.as_str() {
            return s
                .parse::<u128>()
                .map_err(|e| format!("invalid u128 {key}: {e}"));
        }
    }
    Err(format!("missing u128 field: {key}"))
}

fn req_u128_default(inputs: &Value, key: &str, default: u128) -> Result<u128, String> {
    match inputs.get(key) {
        None => Ok(default),
        Some(v) if v.is_null() => Ok(default),
        Some(_) => req_u128(inputs, key),
    }
}

fn req_usize(inputs: &Value, key: &str) -> Result<usize, String> {
    let v = req_u64(inputs, key)?;
    usize::try_from(v).map_err(|_| format!("field {key} exceeds usize"))
}

fn req_felt_array(inputs: &Value, key: &str) -> Result<Vec<Felt>, String> {
    let arr = inputs
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing array field: {key}"))?;
    arr.iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| format!("{key} entries must be hex strings"))
                .and_then(felt_from_hex)
        })
        .collect()
}

fn projective_from_inputs(inputs: &Value, key: &str) -> Result<ProjectivePoint, String> {
    let value = inputs
        .get(key)
        .ok_or_else(|| format!("missing point field: {key}"))?;
    projective_from_value(value)
}

fn projective_from_value(value: &Value) -> Result<ProjectivePoint, String> {
    let x = value
        .get("x")
        .and_then(Value::as_str)
        .ok_or_else(|| "point.x missing".to_string())?;
    let y = value
        .get("y")
        .and_then(Value::as_str)
        .ok_or_else(|| "point.y missing".to_string())?;
    let x_f = felt_from_hex(x)?;
    let y_f = felt_from_hex(y)?;
    ProjectivePoint::from_affine(x_f, y_f)
        .map_err(|e| format!("invalid affine point: {e:?}"))
}

fn point_json(point: &ProjectivePoint) -> Result<Value, String> {
    let affine = point
        .to_affine()
        .map_err(|_| "point at infinity".to_string())?;
    Ok(json!({
        "x": felt_hex(&affine.x()),
        "y": felt_hex(&affine.y()),
    }))
}

fn projective_bytes(point: &ProjectivePoint) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; 96];
    match point.to_affine() {
        Ok(affine) => {
            out[0..32].copy_from_slice(&affine.x().to_bytes_be());
            out[32..64].copy_from_slice(&affine.y().to_bytes_be());
            let mut z = [0u8; 32];
            z[31] = 1;
            out[64..96].copy_from_slice(&z);
            Ok(out)
        }
        Err(_) => Ok(out),
    }
}

fn seed32_from_hex(input: &str) -> Result<[u8; 32], String> {
    let raw = strip_0x(input);
    let bytes = hex::decode(raw).map_err(err_to_string)?;
    if bytes.len() != 32 {
        return Err(format!("seed_hex must be 32 bytes, got {}", bytes.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

fn felt_from_hex(input: &str) -> Result<Felt, String> {
    Felt::from_hex(input).map_err(err_to_string)
}

fn felt_hex(felt: &Felt) -> String {
    format!("0x{}", hex::encode(felt.to_bytes_be()))
}

fn concat_bytes(parts: &[&[u8]]) -> Vec<u8> {
    let total = parts.iter().map(|p| p.len()).sum();
    let mut out = Vec::with_capacity(total);
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

fn canonical_output_bytes(output: &Value) -> Vec<u8> {
    serde_json::to_vec(output).unwrap_or_default()
}

fn parse_u32_str(input: &str, field: &str) -> u32 {
    input.parse::<u32>().unwrap_or_else(|_| panic!("invalid {}", field))
}

fn strip_0x(input: &str) -> &str {
    input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input)
}

fn err_to_string<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}
