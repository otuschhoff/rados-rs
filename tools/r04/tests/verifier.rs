use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rados_r04_tools::{
    GO_REVISION, GO_TREE, MAX_RECORD_BYTES, MAX_RECORDS, MAX_REPORT_BYTES,
    clean_go_command_for_tests, default_request_json, file_digest, hex_digest, path_digest,
    run_rust_probe, rust_source_digest, verify_report_bytes_for_tests,
    verify_report_bytes_with_timeout_for_tests,
};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

const TEST_GO_TARGET: &str = if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
    "darwin/arm64"
} else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
    "darwin/amd64"
} else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
    "linux/arm64"
} else {
    "linux/amd64"
};

fn command(program: &str, arguments: &[&str], root: &Path) -> String {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(root)
        .output()
        .expect("run command");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("UTF-8 output")
        .trim()
        .to_owned()
}

fn temporary_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "rados-r04-{name}-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ))
}

fn records_digest(output: &[u8], implementation: &str) -> String {
    if implementation == "rust" {
        hex_digest(output)
    } else {
        hex_digest(
            &String::from_utf8(output.to_vec())
                .expect("UTF-8 JSONL")
                .replace(
                    "\"implementation_id\":\"rust\"",
                    "\"implementation_id\":\"go\"",
                )
                .into_bytes(),
        )
    }
}

fn valid_report() -> (serde_json::Value, PathBuf, PathBuf, PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let report_path = temporary_path("report.json");
    let verifier = temporary_path("verify");
    let probe = temporary_path("probe");
    let mut output = Vec::new();
    run_rust_probe(&root, default_request_json().as_bytes(), &mut output).expect("probe output");
    let rust_records = output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).expect("record"))
        .collect::<Vec<_>>();
    let mut go_records = rust_records.clone();
    for record in &mut go_records {
        record["implementation_id"] = serde_json::json!("go");
    }
    fs::write(
        &probe,
        format!(
            "#!/bin/sh\ncat <<'EOF'\n{}EOF\n",
            String::from_utf8(output.clone()).expect("UTF-8 JSONL")
        ),
    )
    .expect("write probe");
    let mut permissions = fs::metadata(&probe).expect("metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&probe, permissions).expect("permissions");
    let request: serde_json::Value =
        serde_json::from_str(&default_request_json()).expect("canonical request");
    let fixtures = request["cases"]
        .as_array()
        .expect("request cases")
        .iter()
        .map(|case| {
            let path = case["path"].as_str();
            let manifest = path.map(|value| format!("{value}.manifest.json"));
            serde_json::json!({
                "case_id": case["case_id"],
                "path": path,
                "sha256": case["sha256"],
                "manifest_path": manifest,
                "manifest_sha256": manifest.as_ref().map(|value| file_digest(&root.join(value)).expect("manifest digest"))
            })
        })
        .collect::<Vec<_>>();
    let rust_target = command("rustc", &["-vV"], &root)
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .expect("host")
        .to_owned();
    let go_compiler = format!("go version go1.26.8 {TEST_GO_TARGET}");
    let report = serde_json::json!({
        "schema_version":1,"suite_id":"r04/cephx-core-v1","status":"passed","generated_at":"2026-09-17T00:00:00Z",
        "bounds":request["bounds"],
        "fixtures":fixtures,
        "rust":{"implementation_id":"rust","source_revision":command("git",&["rev-parse","HEAD"],&root),"source_tree":command("git",&["rev-parse","HEAD^{tree}"],&root),"source_files_sha256":rust_source_digest(&root).expect("source digest"),"lockfile_sha256":file_digest(&root.join("Cargo.lock")).expect("lock"),"compiler":command("rustc",&["--version"],&root),"target":rust_target,"driver_sha256":file_digest(&probe).expect("probe digest"),"command":[probe.to_string_lossy()],"exit_code":0,"stdout_sha256":records_digest(&output,"rust"),"records":rust_records},
        "go":{"implementation_id":"go","source_revision":GO_REVISION,"source_tree":GO_TREE,"source_files_sha256":"0".repeat(64),"lockfile_sha256":"0".repeat(64),"compiler":go_compiler,"target":TEST_GO_TARGET,"driver_sha256":path_digest(&root,Path::new("tools/r04/go-probe")).expect("adapter"),"command":["go","run","./tools/rados-rs-r04-probe","--fixture-root","./tools/rados-rs-r04-probe/fixtures"],"exit_code":0,"stdout_sha256":records_digest(&output,"go"),"records":go_records},
        "artifacts":{"adapter_path":"tools/r04/go-probe","adapter_sha256":path_digest(&root,Path::new("tools/r04/go-probe")).expect("adapter"),"schema_path":"integration/r04/report.schema.json","schema_sha256":file_digest(&root.join("integration/r04/report.schema.json")).expect("schema")},
        "controller":{"path":"integration/r04/reproduce.sh","sha256":file_digest(&root.join("integration/r04/reproduce.sh")).expect("controller"),"command":["integration/r04/reproduce.sh","--go-root","/unused/go","--rust-probe",probe.to_string_lossy(),"--verifier",verifier.to_string_lossy(),"--report",report_path.to_string_lossy()]}
    });
    (report, root, report_path, verifier, probe)
}

fn verify(
    report: &serde_json::Value,
    root: &Path,
    report_path: &Path,
    verifier: &Path,
    probe: &Path,
) -> Result<(), String> {
    verify_report_bytes_for_tests(
        root,
        report_path,
        verifier,
        probe,
        &serde_json::to_vec(report).expect("report JSON"),
    )
}

#[test]
fn verifier_accepts_complete_canonical_report() {
    let (report, root, report_path, verifier, probe) = valid_report();
    verify(&report, &root, &report_path, &verifier, &probe).expect("valid report");
}

#[test]
fn verifier_rejects_stale_report() {
    let (mut report, root, report_path, verifier, probe) = valid_report();
    report["fixtures"][0]["sha256"] = serde_json::json!("0".repeat(64));
    assert!(verify(&report, &root, &report_path, &verifier, &probe).is_err());
}

#[test]
fn verifier_rejects_unpinned_rust_compiler() {
    let (mut report, root, report_path, verifier, probe) = valid_report();
    report["rust"]["compiler"] = serde_json::json!("rustc 1.99.0 (untrusted 2099-01-01)");
    assert!(verify(&report, &root, &report_path, &verifier, &probe).is_err());
}

#[test]
fn verifier_rejects_mutated_fixture_provenance() {
    let (mut report, root, report_path, verifier, probe) = valid_report();
    report["fixtures"][0]["manifest_sha256"] = serde_json::json!("0".repeat(64));
    assert!(verify(&report, &root, &report_path, &verifier, &probe).is_err());
}

#[test]
fn verifier_rejects_substituted_executable() {
    let (mut report, root, report_path, verifier, probe) = valid_report();
    let substitute = temporary_path("substitute");
    fs::copy(&probe, &substitute).expect("copy substitute");
    report["rust"]["command"][0] = serde_json::json!(substitute.to_string_lossy());
    report["rust"]["driver_sha256"] = serde_json::json!(file_digest(&substitute).expect("digest"));
    assert!(verify(&report, &root, &report_path, &verifier, &probe).is_err());
}

#[test]
fn verifier_rejects_malformed_and_oversized_reports() {
    let (_, root, report_path, verifier, probe) = valid_report();
    assert!(verify_report_bytes_for_tests(&root, &report_path, &verifier, &probe, b"{").is_err());
    let oversized = usize::try_from(MAX_REPORT_BYTES).expect("report bound") + 1;
    assert!(
        verify_report_bytes_for_tests(
            &root,
            &report_path,
            &verifier,
            &probe,
            &vec![b' '; oversized]
        )
        .is_err()
    );
}

#[test]
fn verifier_rejects_oversized_probe_output() {
    let (mut report, root, report_path, verifier, probe) = valid_report();
    let bytes = MAX_RECORD_BYTES * u64::try_from(MAX_RECORDS).expect("record count") + 1;
    fs::write(
        &probe,
        format!("#!/bin/sh\ndd if=/dev/zero bs=1 count={bytes} 2>/dev/null\n"),
    )
    .expect("write oversized-output probe");
    report["rust"]["driver_sha256"] =
        serde_json::json!(file_digest(&probe).expect("oversized probe digest"));
    let error = verify(&report, &root, &report_path, &verifier, &probe)
        .expect_err("oversized probe output must fail");
    assert!(error.contains("exceeds bound"), "unexpected error: {error}");
}

#[test]
fn verifier_times_out_a_partial_output_probe() {
    let (mut report, root, report_path, verifier, probe) = valid_report();
    let descendant_pid = temporary_path("descendant.pid");
    fs::write(
        &probe,
        format!(
            "#!/bin/sh\nsleep 60 &\nprintf '%s' $! > '{}'\nprintf partial\nwait\n",
            descendant_pid.display()
        ),
    )
    .expect("write hanging probe");
    report["rust"]["driver_sha256"] =
        serde_json::json!(file_digest(&probe).expect("hanging probe digest"));
    let started = Instant::now();
    let error = verify_report_bytes_with_timeout_for_tests(
        &root,
        &report_path,
        &verifier,
        &probe,
        &serde_json::to_vec(&report).expect("report JSON"),
        Duration::from_secs(2),
    )
    .expect_err("hanging probe must fail");
    assert!(error.contains("timed out"), "unexpected error: {error}");
    assert!(started.elapsed() < Duration::from_secs(5));
    let pid = fs::read_to_string(&descendant_pid).expect("descendant pid");
    assert!(
        !Command::new("kill")
            .args(["-0", pid.trim()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("inspect descendant")
            .success(),
        "timed-out probe descendant survived"
    );
}

#[test]
fn verifier_kills_descendant_holding_output_after_probe_exit() {
    let (mut report, root, report_path, verifier, probe) = valid_report();
    let descendant_pid = temporary_path("orphan-descendant.pid");
    fs::write(
        &probe,
        format!(
            "#!/bin/sh\nsleep 60 &\nprintf '%s' $! > '{}'\nprintf partial\nexit 0\n",
            descendant_pid.display()
        ),
    )
    .expect("write orphaning probe");
    report["rust"]["driver_sha256"] =
        serde_json::json!(file_digest(&probe).expect("orphaning probe digest"));
    let error = verify(&report, &root, &report_path, &verifier, &probe)
        .expect_err("descendant-held output must fail");
    assert!(error.contains("did not close"), "unexpected error: {error}");
    let pid = fs::read_to_string(&descendant_pid).expect("descendant pid");
    assert!(
        !Command::new("kill")
            .args(["-0", pid.trim()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("inspect descendant")
            .success(),
        "orphaned probe descendant survived"
    );
}

#[test]
fn verifier_ignores_poisoned_go_environment() {
    const CHILD_MARKER: &str = "RADOS_R04_POISONED_GO_ENV_CHILD";
    if std::env::var_os(CHILD_MARKER).is_some() {
        let probe = temporary_path("go-environment");
        fs::write(
            &probe,
            "#!/bin/sh\nprintf '%s|%s|%s|%s' \"$GOENV\" \"$GOWORK\" \"$GOFLAGS\" \"$GOTOOLCHAIN\"\n",
        )
        .expect("write environment probe");
        let mut permissions = fs::metadata(&probe).expect("metadata").permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&probe, permissions).expect("permissions");
        let output = clean_go_command_for_tests(&probe)
            .output()
            .expect("run clean environment probe");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"off|off||local");
        return;
    }
    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "verifier_ignores_poisoned_go_environment",
            "--nocapture",
        ])
        .env(CHILD_MARKER, "1")
        .env("GOENV", "/does/not/exist")
        .env("GOWORK", "/does/not/exist")
        .env("GOFLAGS", "-invalid-poisoned-flag")
        .env("GOTOOLCHAIN", "invalid-poisoned-toolchain")
        .output()
        .expect("run isolated verifier test");
    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
