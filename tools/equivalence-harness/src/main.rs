use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Deserialize, Serialize, Clone)]
struct RngConfig {
    mode: String,
    seed_hex: String,
    stream: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct OracleRequest {
    op: String,
    #[serde(default)]
    inputs: Value,
    #[serde(default)]
    rng: Option<RngConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
struct OracleResponse {
    ok: bool,
    output: Value,
    output_bytes_hex: String,
    error: Option<String>,
    meta: Meta,
}

#[derive(Debug, Deserialize, Serialize)]
struct Meta {
    rng_draws: u64,
    impl_version: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct VectorCase {
    id: String,
    op: String,
    #[serde(default)]
    inputs: Value,
    #[serde(default)]
    rng: Option<RngConfig>,
}

#[derive(Debug, Deserialize)]
struct VectorSuite {
    name: String,
    cases: Vec<VectorCase>,
}

#[derive(Debug, Serialize)]
struct MismatchReport {
    id: String,
    op: String,
    request: OracleRequest,
    rust_response: OracleResponse,
    zig_response: OracleResponse,
    reason: String,
    replay: Replay,
}

#[derive(Debug, Serialize)]
struct Replay {
    rust_bin: String,
    zig_bin: String,
    request_json: String,
}

#[derive(Debug)]
struct Config {
    rust_bin: PathBuf,
    zig_bin: PathBuf,
    vectors: PathBuf,
    mode: String,
    random_cases: usize,
    seed_hex: String,
    artifacts_dir: PathBuf,
    fail_fast: bool,
}

fn main() {
    let cfg = match parse_args(std::env::args().skip(1).collect()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("argument error: {e}");
            print_usage();
            std::process::exit(2);
        }
    };

    if let Err(e) = run(cfg) {
        eprintln!("equivalence harness failed: {e}");
        std::process::exit(1);
    }
}

fn run(cfg: Config) -> Result<(), String> {
    let mut cases = load_vector_cases(&cfg.vectors)?;

    if cfg.mode != "vectors" {
        let random = generate_random_cases(&cfg.mode, cfg.random_cases, &cfg.seed_hex)?;
        cases.extend(random);
    }

    if cases.is_empty() {
        return Err("no cases to run".to_string());
    }

    fs::create_dir_all(&cfg.artifacts_dir).map_err(err_to_string)?;
    clear_stale_mismatches(&cfg.artifacts_dir)?;

    let mut total = 0usize;
    let mut failed = 0usize;

    for case in cases {
        total += 1;
        let request = OracleRequest {
            op: case.op.clone(),
            inputs: case.inputs.clone(),
            rng: case.rng.clone(),
        };

        let rust_resp = run_oracle(&cfg.rust_bin, &request)?;
        let zig_resp = run_oracle(&cfg.zig_bin, &request)?;

        match compare_responses(&request, &rust_resp, &zig_resp) {
            Ok(()) => {}
            Err(reason) => {
                failed += 1;
                let report = MismatchReport {
                    id: case.id.clone(),
                    op: case.op.clone(),
                    request: request.clone(),
                    rust_response: rust_resp,
                    zig_response: zig_resp,
                    reason,
                    replay: Replay {
                        rust_bin: cfg.rust_bin.display().to_string(),
                        zig_bin: cfg.zig_bin.display().to_string(),
                        request_json: serde_json::to_string_pretty(&request).map_err(err_to_string)?,
                    },
                };
                write_mismatch(&cfg.artifacts_dir, &report)?;
                eprintln!("[FAIL] {} ({})", case.id, case.op);
                if cfg.fail_fast {
                    break;
                }
            }
        }
    }

    println!(
        "equivalence run complete: total={}, failed={}, mode={}",
        total, failed, cfg.mode
    );

    if failed > 0 {
        return Err(format!("{} mismatches detected", failed));
    }
    Ok(())
}

fn compare_responses(
    request: &OracleRequest,
    rust_resp: &OracleResponse,
    zig_resp: &OracleResponse,
) -> Result<(), String> {
    if rust_resp.ok != zig_resp.ok {
        return Err("ok flag mismatch".to_string());
    }

    if rust_resp.ok {
        if rust_resp.output != zig_resp.output {
            return Err("structured output mismatch".to_string());
        }

        let canonical = canonical_output_bytes(&request.op, &rust_resp.output)?;
        let rust_bytes = decode_or_fallback_bytes(&rust_resp.output_bytes_hex, &canonical)?;
        let zig_bytes = decode_or_fallback_bytes(&zig_resp.output_bytes_hex, &canonical)?;
        if rust_bytes != zig_bytes {
            return Err("output_bytes_hex mismatch".to_string());
        }

        return Ok(());
    }

    if rust_resp.error != zig_resp.error {
        return Err("error string mismatch".to_string());
    }

    Ok(())
}

fn decode_or_fallback_bytes(bytes_hex: &str, fallback: &[u8]) -> Result<Vec<u8>, String> {
    if bytes_hex.is_empty() {
        return Ok(fallback.to_vec());
    }
    hex::decode(bytes_hex).map_err(err_to_string)
}

fn canonical_output_bytes(_op: &str, output: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(output).map_err(err_to_string)
}

fn load_vector_cases(path: &Path) -> Result<Vec<VectorCase>, String> {
    let text = fs::read_to_string(path).map_err(err_to_string)?;
    let suite: VectorSuite = serde_json::from_str(&text).map_err(err_to_string)?;
    if suite.cases.is_empty() {
        return Err(format!("vector suite '{}' has no cases", suite.name));
    }
    Ok(suite.cases)
}

fn generate_random_cases(mode: &str, count: usize, seed_hex: &str) -> Result<Vec<VectorCase>, String> {
    let seed = seed32(seed_hex)?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut cases = Vec::with_capacity(count);

    let fixed_mnemonic = "habit hope tip crystal because grunt nation idea electric witness alert like";
    let ops = [
        "kms.pedersen_hash",
        "kms.poseidon_hash_many",
        "she.scalar_add",
        "she.scalar_mul",
        "she.curve_mul_generator",
        "kms.derive_private_key_with_coin_type",
    ];

    for i in 0..count {
        let op = ops[i % ops.len()];
        let case = match op {
            "kms.pedersen_hash" => VectorCase {
                id: format!("rand-{}-{i}", mode),
                op: op.to_string(),
                inputs: serde_json::json!({
                    "left": random_felt_hex(&mut rng),
                    "right": random_felt_hex(&mut rng),
                }),
                rng: None,
            },
            "kms.poseidon_hash_many" => VectorCase {
                id: format!("rand-{}-{i}", mode),
                op: op.to_string(),
                inputs: serde_json::json!({
                    "values": [random_felt_hex(&mut rng), random_felt_hex(&mut rng), random_felt_hex(&mut rng)],
                }),
                rng: None,
            },
            "she.scalar_add" | "she.scalar_mul" => VectorCase {
                id: format!("rand-{}-{i}", mode),
                op: op.to_string(),
                inputs: serde_json::json!({
                    "a": random_felt_hex(&mut rng),
                    "b": random_felt_hex(&mut rng),
                }),
                rng: None,
            },
            "she.curve_mul_generator" => VectorCase {
                id: format!("rand-{}-{i}", mode),
                op: op.to_string(),
                inputs: serde_json::json!({
                    "scalar": random_felt_hex(&mut rng),
                }),
                rng: None,
            },
            "kms.derive_private_key_with_coin_type" => {
                let coin = if i % 2 == 0 { 5454 } else { 9004 };
                VectorCase {
                    id: format!("rand-{}-{i}", mode),
                    op: op.to_string(),
                    inputs: serde_json::json!({
                        "mnemonic": fixed_mnemonic,
                        "index": (rng.gen::<u32>() % 5),
                        "account_index": (rng.gen::<u32>() % 5),
                        "coin_type": coin,
                        "passphrase": "",
                    }),
                    rng: None,
                }
            }
            _ => unreachable!(),
        };
        cases.push(case);
    }

    Ok(cases)
}

fn run_oracle(bin: &Path, request: &OracleRequest) -> Result<OracleResponse, String> {
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(err_to_string)?;

    {
        let mut stdin = child.stdin.take().ok_or_else(|| "oracle stdin unavailable".to_string())?;
        let payload = serde_json::to_vec(request).map_err(err_to_string)?;
        stdin.write_all(&payload).map_err(err_to_string)?;
    }

    let output = child.wait_with_output().map_err(err_to_string)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "oracle {} exited with {}: {}",
            bin.display(),
            output.status,
            stderr
        ));
    }

    serde_json::from_slice::<OracleResponse>(&output.stdout).map_err(|e| {
        format!(
            "invalid oracle response from {}: {e}; stdout={} stderr={}",
            bin.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn write_mismatch(dir: &Path, report: &MismatchReport) -> Result<(), String> {
    let file = dir.join(format!("mismatch-{}.json", sanitize_id(&report.id)));
    let latest = dir.join("latest-mismatch.json");
    let json = serde_json::to_string_pretty(report).map_err(err_to_string)?;
    fs::write(&file, &json).map_err(err_to_string)?;
    fs::write(&latest, &json).map_err(err_to_string)?;
    Ok(())
}

fn clear_stale_mismatches(dir: &Path) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(err_to_string)?;
    for entry in entries {
        let entry = entry.map_err(err_to_string)?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name == "latest-mismatch.json"
            || (name.starts_with("mismatch-") && name.ends_with(".json"))
        {
            fs::remove_file(&path).map_err(err_to_string)?;
        }
    }
    Ok(())
}

fn parse_args(args: Vec<String>) -> Result<Config, String> {
    let mut map = BTreeMap::new();
    let mut i = 0usize;
    while i < args.len() {
        let key = &args[i];
        if !key.starts_with("--") {
            return Err(format!("unexpected argument: {key}"));
        }
        if i + 1 >= args.len() {
            return Err(format!("missing value for {key}"));
        }
        map.insert(key.clone(), args[i + 1].clone());
        i += 2;
    }

    let rust_bin = map
        .get("--rust-bin")
        .ok_or_else(|| "--rust-bin is required".to_string())?;
    let zig_bin = map
        .get("--zig-bin")
        .ok_or_else(|| "--zig-bin is required".to_string())?;

    let vectors = map
        .get("--vectors")
        .cloned()
        .unwrap_or_else(|| "fixtures/vectors/parity/core-vectors.json".to_string());
    let mode = map
        .get("--mode")
        .cloned()
        .unwrap_or_else(|| "vectors".to_string());
    let random_cases = map
        .get("--random-cases")
        .map(|v| v.parse::<usize>().map_err(err_to_string))
        .transpose()?
        .unwrap_or(64);
    let seed_hex = map
        .get("--seed")
        .cloned()
        .unwrap_or_else(|| "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string());
    let artifacts_dir = map
        .get("--artifacts-dir")
        .cloned()
        .unwrap_or_else(|| "tools/equivalence-harness/artifacts".to_string());
    let fail_fast = map
        .get("--fail-fast")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true);

    Ok(Config {
        rust_bin: PathBuf::from(rust_bin),
        zig_bin: PathBuf::from(zig_bin),
        vectors: PathBuf::from(vectors),
        mode,
        random_cases,
        seed_hex,
        artifacts_dir: PathBuf::from(artifacts_dir),
        fail_fast,
    })
}

fn print_usage() {
    eprintln!(
        "usage: equivalence-harness \\\n  --rust-bin <path> \\\n  --zig-bin <path> \\\n  [--vectors fixtures/vectors/parity/core-vectors.json] \\\n  [--mode vectors|random-pr|random-nightly] \\\n  [--random-cases 64] \\\n  [--seed <32-byte-hex>] \\\n  [--artifacts-dir tools/equivalence-harness/artifacts] \\\n  [--fail-fast true|false]"
    );
}

fn random_felt_hex(rng: &mut ChaCha20Rng) -> String {
    // Keep generated values in low 248 bits to avoid field overflow parse issues.
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    bytes[0] &= 0x03;
    format!("0x{}", hex::encode(bytes))
}

fn seed32(seed_hex: &str) -> Result<[u8; 32], String> {
    let raw = strip_0x(seed_hex);
    let bytes = hex::decode(raw).map_err(err_to_string)?;
    if bytes.len() != 32 {
        return Err(format!("seed must be 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn strip_0x(input: &str) -> &str {
    input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input)
}

fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn err_to_string<E: std::fmt::Display>(err: E) -> String {
    err.to_string()
}
