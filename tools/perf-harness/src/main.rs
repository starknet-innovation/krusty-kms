use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize, Clone)]
struct VectorCase {
    id: String,
    op: String,
    #[serde(default)]
    inputs: Value,
    #[serde(default)]
    rng: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct VectorSuite {
    cases: Vec<VectorCase>,
}

#[derive(Debug, Serialize)]
struct PerfReport {
    generated_at_unix: u64,
    git_commit: String,
    config: ReportConfig,
    cases: Vec<CaseReport>,
}

#[derive(Debug, Serialize)]
struct ReportConfig {
    samples: usize,
    warmup: usize,
    rust_bin: String,
    zig_bin: String,
    vectors: String,
}

#[derive(Debug, Serialize)]
struct CaseReport {
    name: String,
    op: String,
    rust: RunnerStats,
    zig: RunnerStats,
    ratio_zig_over_rust: Option<f64>,
}

#[derive(Debug, Serialize)]
struct RunnerStats {
    status: String,
    error: Option<String>,
    samples_ms: Vec<f64>,
    median_ms: Option<f64>,
    p95_ms: Option<f64>,
    stddev_ms: Option<f64>,
}

#[derive(Debug)]
struct Config {
    rust_bin: PathBuf,
    zig_bin: PathBuf,
    vectors: PathBuf,
    out_dir: PathBuf,
    samples: usize,
    warmup: usize,
}

#[derive(Debug, Clone)]
struct CaseDef {
    name: &'static str,
    req: Value,
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
        eprintln!("perf harness failed: {e}");
        std::process::exit(1);
    }
}

fn run(cfg: Config) -> Result<(), String> {
    fs::create_dir_all(&cfg.out_dir).map_err(err_to_string)?;

    let vectors_text = fs::read_to_string(&cfg.vectors).map_err(err_to_string)?;
    let suite: VectorSuite = serde_json::from_str(&vectors_text).map_err(err_to_string)?;
    let vector_map: BTreeMap<String, VectorCase> = suite
        .cases
        .into_iter()
        .map(|c| (c.id.clone(), c))
        .collect();

    let defs = build_case_defs(&vector_map)?;

    let mut reports = Vec::with_capacity(defs.len());
    for def in defs {
        let rust = benchmark_runner(&cfg.rust_bin, &def.req, cfg.samples, cfg.warmup);
        let zig = benchmark_runner(&cfg.zig_bin, &def.req, cfg.samples, cfg.warmup);

        let ratio = match (rust.median_ms, zig.median_ms) {
            (Some(r), Some(z)) if r > 0.0 => Some(z / r),
            _ => None,
        };

        reports.push(CaseReport {
            name: def.name.to_string(),
            op: def.req.get("op").and_then(Value::as_str).unwrap_or("unknown").to_string(),
            rust,
            zig,
            ratio_zig_over_rust: ratio,
        });
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(err_to_string)?
        .as_secs();

    let report = PerfReport {
        generated_at_unix: now,
        git_commit: git_commit(),
        config: ReportConfig {
            samples: cfg.samples,
            warmup: cfg.warmup,
            rust_bin: cfg.rust_bin.display().to_string(),
            zig_bin: cfg.zig_bin.display().to_string(),
            vectors: cfg.vectors.display().to_string(),
        },
        cases: reports,
    };

    let json_path = cfg.out_dir.join(format!("perf-{now}.json"));
    let md_path = cfg.out_dir.join(format!("perf-{now}.md"));
    let latest_json = cfg.out_dir.join("latest.json");
    let latest_md = cfg.out_dir.join("latest.md");

    let json_text = serde_json::to_string_pretty(&report).map_err(err_to_string)?;
    fs::write(&json_path, &json_text).map_err(err_to_string)?;
    fs::write(&latest_json, &json_text).map_err(err_to_string)?;

    let markdown = render_markdown(&report);
    fs::write(&md_path, &markdown).map_err(err_to_string)?;
    fs::write(&latest_md, &markdown).map_err(err_to_string)?;

    println!("perf report written:");
    println!("  {}", json_path.display());
    println!("  {}", md_path.display());

    Ok(())
}

fn build_case_defs(vectors: &BTreeMap<String, VectorCase>) -> Result<Vec<CaseDef>, String> {
    let mut out = Vec::new();

    let required = [
        ("mnemonic_to_seed", "kms-mnemonic-to-seed"),
        ("derive_keypair", "kms-derive-keypair-tongo"),
        ("pedersen_hash", "kms-pedersen"),
        ("poseidon_hash_many", "kms-poseidon-many"),
        ("curve_mul_generator", "she-curve-mul-generator"),
        ("poe_prove_verify", "she-poe-prove-verify"),
        ("elgamal_prove_verify_decrypt", "she-elgamal-evd"),
        ("range_prove_verify", "she-range-prove-verify"),
        ("audit_prove_verify", "she-audit-prove-verify"),
    ];

    for (name, id) in required {
        let case = vectors
            .get(id)
            .ok_or_else(|| format!("missing vector case: {id}"))?;
        let mut req = json!({ "op": case.op, "inputs": case.inputs });
        if let Some(rng) = &case.rng {
            req["rng"] = rng.clone();
        }
        out.push(CaseDef { name, req });
    }

    // Synthetic TONGO operation requests for throughput profiling coverage.
    let base = json!({
        "private_key": "0x3039",
        "contract_address": "0x1234",
        "balance": "1000",
        "pending_balance": "0",
        "account_nonce": 0,
        "nonce": "0x55",
        "chain_id": "0x534e5f5345504f4c4941",
        "bit_size": 16,
        "recipient_private_key": "0x22",
        "recipient": "0x4242",
        "amount": "10"
    });

    for (name, op) in [
        ("tongo_fund", "tongo.fund"),
        ("tongo_transfer", "tongo.transfer"),
        ("tongo_rollover", "tongo.rollover"),
        ("tongo_withdraw", "tongo.withdraw"),
        ("tongo_ragequit", "tongo.ragequit"),
    ] {
        out.push(CaseDef {
            name,
            req: json!({ "op": op, "inputs": base }),
        });
    }

    Ok(out)
}

fn benchmark_runner(bin: &Path, request: &Value, samples: usize, warmup: usize) -> RunnerStats {
    for _ in 0..warmup {
        let _ = run_once(bin, request, Duration::from_secs(240));
    }

    let mut values = Vec::with_capacity(samples);
    for _ in 0..samples {
        match run_once(bin, request, Duration::from_secs(240)) {
            Ok(ms) => values.push(ms),
            Err(e) => {
                return RunnerStats {
                    status: "error".to_string(),
                    error: Some(e),
                    samples_ms: values,
                    median_ms: None,
                    p95_ms: None,
                    stddev_ms: None,
                };
            }
        }
    }

    let median = median(&values);
    let p95 = percentile(&values, 0.95);
    let stddev = stddev(&values);

    RunnerStats {
        status: "ok".to_string(),
        error: None,
        samples_ms: values,
        median_ms: Some(median),
        p95_ms: Some(p95),
        stddev_ms: Some(stddev),
    }
}

fn run_once(bin: &Path, request: &Value, timeout: Duration) -> Result<f64, String> {
    let payload = serde_json::to_vec(request).map_err(err_to_string)?;

    let start = Instant::now();
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(err_to_string)?;

    {
        let mut stdin = child.stdin.take().ok_or_else(|| "stdin unavailable".to_string())?;
        stdin.write_all(&payload).map_err(err_to_string)?;
    }

    let output = wait_with_timeout(child, timeout)?;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

    if !output.status.success() {
        return Err(format!(
            "{} exited with {}: {}",
            bin.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let parsed: Value = serde_json::from_slice(&output.stdout).map_err(|e| {
        format!(
            "invalid json from {}: {e}; stdout={} stderr={}",
            bin.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })?;

    let ok = parsed.get("ok").and_then(Value::as_bool).unwrap_or(false);
    if !ok {
        let err = parsed
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("unknown error")
            .to_string();
        return Err(format!("oracle error: {err}"));
    }

    Ok(elapsed_ms)
}

fn wait_with_timeout(mut child: std::process::Child, timeout: Duration) -> Result<std::process::Output, String> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(err_to_string)? {
            let mut stdout = Vec::new();
            if let Some(mut out) = child.stdout.take() {
                use std::io::Read;
                out.read_to_end(&mut stdout).map_err(err_to_string)?;
            }
            let mut stderr = Vec::new();
            if let Some(mut err) = child.stderr.take() {
                use std::io::Read;
                err.read_to_end(&mut stderr).map_err(err_to_string)?;
            }
            return Ok(std::process::Output { status, stdout, stderr });
        }

        if start.elapsed() > timeout {
            let _ = child.kill();
            return Err("oracle timed out".to_string());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn median(values: &[f64]) -> f64 {
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if v.len() % 2 == 0 {
        (v[v.len() / 2] + v[(v.len() / 2) - 1]) / 2.0
    } else {
        v[v.len() / 2]
    }
}

fn percentile(values: &[f64], p: f64) -> f64 {
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((v.len() as f64 * p).ceil() as usize).saturating_sub(1);
    v[idx.min(v.len().saturating_sub(1))]
}

fn stddev(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let var = values
        .iter()
        .map(|x| {
            let d = x - mean;
            d * d
        })
        .sum::<f64>()
        / values.len() as f64;
    var.sqrt()
}

fn git_commit() -> String {
    let output = Command::new("git").args(["rev-parse", "HEAD"]).output();
    match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => "unknown".to_string(),
    }
}

fn render_markdown(report: &PerfReport) -> String {
    let mut md = String::new();
    md.push_str("# KMS Perf Report\n\n");
    md.push_str(&format!("- generated_at_unix: {}\n", report.generated_at_unix));
    md.push_str(&format!("- git_commit: `{}`\n", report.git_commit));
    md.push_str(&format!("- samples: {}\n", report.config.samples));
    md.push_str(&format!("- warmup: {}\n\n", report.config.warmup));

    md.push_str("| Case | Rust median (ms) | Zig median (ms) | Zig/Rust | Rust p95 | Zig p95 | Status |\n");
    md.push_str("|---|---:|---:|---:|---:|---:|---|\n");

    for case in &report.cases {
        let rust_med = fmt_opt(case.rust.median_ms);
        let zig_med = fmt_opt(case.zig.median_ms);
        let ratio = fmt_opt(case.ratio_zig_over_rust);
        let rust_p95 = fmt_opt(case.rust.p95_ms);
        let zig_p95 = fmt_opt(case.zig.p95_ms);
        let status = if case.rust.status == "ok" && case.zig.status == "ok" {
            "ok".to_string()
        } else {
            format!(
                "rust={}, zig={}{}{}",
                case.rust.status,
                case.zig.status,
                case.rust
                    .error
                    .as_ref()
                    .map(|e| format!(", rust_err={e}"))
                    .unwrap_or_default(),
                case.zig
                    .error
                    .as_ref()
                    .map(|e| format!(", zig_err={e}"))
                    .unwrap_or_default()
            )
        };

        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            case.name, rust_med, zig_med, ratio, rust_p95, zig_p95, status
        ));
    }

    md
}

fn fmt_opt(v: Option<f64>) -> String {
    v.map(|x| format!("{x:.3}"))
        .unwrap_or_else(|| "n/a".to_string())
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

    let rust_bin = PathBuf::from(
        map.get("--rust-bin")
            .cloned()
            .unwrap_or_else(|| "target/release/rust-oracle".to_string()),
    );
    let zig_bin = PathBuf::from(
        map.get("--zig-bin")
            .cloned()
            .unwrap_or_else(|| "tools/zig-oracle/zig-oracle-release".to_string()),
    );
    let vectors = PathBuf::from(
        map.get("--vectors")
            .cloned()
            .unwrap_or_else(|| "fixtures/vectors/parity/core-vectors.json".to_string()),
    );
    let out_dir = PathBuf::from(
        map.get("--out-dir")
            .cloned()
            .unwrap_or_else(|| "tools/perf-harness/results".to_string()),
    );
    let samples = map
        .get("--samples")
        .map(|s| s.parse::<usize>().map_err(err_to_string))
        .transpose()?
        .unwrap_or(5);
    let warmup = map
        .get("--warmup")
        .map(|s| s.parse::<usize>().map_err(err_to_string))
        .transpose()?
        .unwrap_or(1);

    Ok(Config {
        rust_bin,
        zig_bin,
        vectors,
        out_dir,
        samples,
        warmup,
    })
}

fn print_usage() {
    eprintln!(
        "usage: perf-harness [--rust-bin path] [--zig-bin path] [--vectors path] [--out-dir path] [--samples n] [--warmup n]"
    );
}

fn err_to_string<E: std::fmt::Display>(err: E) -> String {
    err.to_string()
}
