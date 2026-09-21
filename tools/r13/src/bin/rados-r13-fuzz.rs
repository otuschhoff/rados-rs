#![forbid(unsafe_code)]
//! `rados-r13-fuzz` CLI.
//!
//! Modes:
//!
//! * default (`--verify`): verify a fuzz report bound to the repository. The
//!   `--profile` flag selects the minimum gate (`pending`, `smoke`,
//!   `certifying`; defaults to `certifying`). Requires `--corpus-root` for
//!   smoke/certifying so per-target corpus tree digests can be compared.
//! * `--verify-shape`: only decode and validate report shape, no I/O beyond
//!   the report file.
//! * `--check-inventory` (read-only): validate that `fuzz/Cargo.toml`,
//!   `fuzz/fuzz_targets/*.rs`, and the frozen R13 constant list all agree on
//!   the 42-target matrix.
//! * `--print-targets`: print the canonical sorted target list.
//! * `--print-checks`: print the ordered list of verification stages this
//!   binary performs (useful for CI enumeration).

use std::path::PathBuf;
use std::process::ExitCode;

use rados_r13_tools::constants::{
    FUZZ_LIVE_PATH, FUZZ_PROFILE_CERTIFYING, FUZZ_TARGETS,
};
use rados_r13_tools::fuzz;

const CHECK_STAGES: &[&str] = &[
    "inventory-cargo-toml",
    "inventory-filesystem",
    "shape-schema",
    "shape-profile",
    "identity-toolchain",
    "digest-schema",
    "digest-source",
    "digest-target-source",
    "digest-corpus-tree",
    "digest-output-log",
    "matrix-complete",
    "matrix-status",
];

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rados-r13-fuzz: {error}");
            ExitCode::FAILURE
        }
    }
}

enum Mode {
    Verify,
    VerifyShape,
    CheckInventory,
    PrintTargets,
    PrintChecks,
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut mode = Mode::Verify;
    let mut root: PathBuf = PathBuf::from(".");
    let mut report: PathBuf = PathBuf::from(FUZZ_LIVE_PATH);
    let mut corpus_root: Option<PathBuf> = None;
    let mut profile: String = FUZZ_PROFILE_CERTIFYING.to_owned();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--verify" => mode = Mode::Verify,
            "--verify-shape" => mode = Mode::VerifyShape,
            "--check-inventory" => mode = Mode::CheckInventory,
            "--print-targets" => mode = Mode::PrintTargets,
            "--print-checks" => mode = Mode::PrintChecks,
            "--root" => root = PathBuf::from(next_value(&mut args, "--root")?),
            "--report" => report = PathBuf::from(next_value(&mut args, "--report")?),
            "--corpus-root" => {
                corpus_root = Some(PathBuf::from(next_value(&mut args, "--corpus-root")?));
            }
            "--profile" => profile = next_value(&mut args, "--profile")?,
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            other => return Err(format!("unknown argument {other:?}").into()),
        }
    }
    match mode {
        Mode::Verify => {
            let selected = fuzz::Profile::parse(&profile)?;
            let corpus = match selected {
                fuzz::Profile::Pending => PathBuf::from("."),
                fuzz::Profile::Smoke | fuzz::Profile::Certifying => corpus_root.ok_or_else(|| {
                    format!(
                        "--corpus-root is required for profile {:?}",
                        selected.as_str()
                    )
                })?,
            };
            let bound = fuzz::verify_report(&root, &report, &corpus, selected)?;
            println!(
                "R13 fuzz report verified: {} profile={} status={} campaigns={}",
                report.display(),
                bound.profile,
                bound.status,
                bound.campaigns.len()
            );
        }
        Mode::VerifyShape => {
            let bytes = std::fs::read(&report)
                .map_err(|error| format!("read {}: {error}", report.display()))?;
            let bound = fuzz::verify_bytes(&bytes)?;
            println!(
                "R13 fuzz report shape verified: {} profile={} status={}",
                report.display(),
                bound.profile,
                bound.status
            );
        }
        Mode::CheckInventory => {
            let targets = fuzz::verify_inventory(&root)?;
            println!(
                "R13 fuzz inventory verified: {} targets present in Cargo.toml, filesystem, and frozen constants",
                targets.len()
            );
        }
        Mode::PrintTargets => {
            for target in FUZZ_TARGETS {
                println!("{target}");
            }
        }
        Mode::PrintChecks => {
            for stage in CHECK_STAGES {
                println!("{stage}");
            }
        }
    }
    Ok(())
}

fn print_help() {
    println!(
        "Usage:\n\
         \n  rados-r13-fuzz [--verify] --root PATH --report PATH --corpus-root PATH [--profile pending|smoke|certifying]\n\
         \n  rados-r13-fuzz --verify-shape --report PATH\n\
         \n  rados-r13-fuzz --check-inventory [--root PATH]\n\
         \n  rados-r13-fuzz --print-targets\n\
         \n  rados-r13-fuzz --print-checks\n\
         \n\
         Default mode requires the report file to bind the exact per-target\n\
         source, corpus, and log hashes, the current source digest, the\n\
         schema digest, and, for smoke/certifying, the whole 42-target matrix\n\
         with per-target budgets at or above 60 s (smoke) / 600 s (certifying)."
    );
}

fn next_value(
    args: &mut std::iter::Skip<std::env::Args>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}
