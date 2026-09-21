#![forbid(unsafe_code)]
//! `rados-r13-candidate` CLI.
//!
//! Modes:
//!
//! * default (`--verify`): verify a candidate report bound to the workspace.
//!   Defaults to `integration/r13/report.json`. Fails if the report status
//!   is `non-certifying` unless `--allow-non-certifying` is passed.
//! * `--verify-shape`: only decode and validate the report shape. Does not
//!   touch fuzz, qualification, release artefacts, or source binding.
//! * `--schema-digest`: print the SHA-256 of
//!   `integration/r13/report.schema.json`.

use std::path::PathBuf;
use std::process::ExitCode;

use rados_r13_tools::candidate;
use rados_r13_tools::constants::CANDIDATE_REPORT_LIVE_PATH;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rados-r13-candidate: {error}");
            ExitCode::FAILURE
        }
    }
}

enum Mode {
    Verify,
    VerifyShape,
    SchemaDigest,
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut mode = Mode::Verify;
    let mut root: PathBuf = PathBuf::from(".");
    let mut report: PathBuf = PathBuf::from(CANDIDATE_REPORT_LIVE_PATH);
    let mut allow_non_certifying = false;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--verify" => mode = Mode::Verify,
            "--verify-shape" => mode = Mode::VerifyShape,
            "--schema-digest" => mode = Mode::SchemaDigest,
            "--allow-non-certifying" => allow_non_certifying = true,
            "--root" => root = PathBuf::from(next_value(&mut args, "--root")?),
            "--report" => report = PathBuf::from(next_value(&mut args, "--report")?),
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            other => return Err(format!("unknown argument {other:?}").into()),
        }
    }
    match mode {
        Mode::Verify => {
            let bound = candidate::verify_report(&root, &report, allow_non_certifying)?;
            println!(
                "R13 candidate report verified: {} status={}",
                report.display(),
                bound.status
            );
        }
        Mode::VerifyShape => {
            let bytes = std::fs::read(&report)
                .map_err(|error| format!("read {}: {error}", report.display()))?;
            let bound = candidate::verify_bytes(&bytes, allow_non_certifying)?;
            println!(
                "R13 candidate report shape verified: {} status={}",
                report.display(),
                bound.status
            );
        }
        Mode::SchemaDigest => {
            println!("{}", candidate::schema_digest(&root)?);
        }
    }
    Ok(())
}

fn print_help() {
    println!(
        "Usage:\n\
         \n  rados-r13-candidate [--verify] --root PATH --report PATH [--allow-non-certifying]\n\
         \n  rados-r13-candidate --verify-shape --report PATH [--allow-non-certifying]\n\
         \n  rados-r13-candidate --schema-digest --root PATH\n\
         \n\
         Default mode rejects non-certifying reports so quick-harness output\n\
         cannot be confused with a certifying candidate. --allow-non-certifying\n\
         explicitly opts in to validating quick evidence and is refused for\n\
         final gating."
    );
}

fn next_value(
    args: &mut std::iter::Skip<std::env::Args>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next().ok_or_else(|| format!("{flag} requires a value").into())
}
