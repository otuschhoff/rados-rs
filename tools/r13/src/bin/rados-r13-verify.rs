#![forbid(unsafe_code)]
//! `rados-r13-verify` CLI.
//!
//! Modes:
//!
//! * default (no subcommand): read `docs/r13/human-review.json`,
//!   `docs/r13/reviewer-trust.json`, and `integration/r13/report.json`,
//!   then verify the fully approved, detached-signed contract. Fails when
//!   either record is still pending.
//! * `--pending`: verify the canonical pending state of both detached
//!   records. Passes only when neither document names a reviewer or
//!   candidate.
//! * `print-review-payload <role>`: reprint the canonical Ed25519 payload
//!   bytes for one role. Never generates or handles signatures.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use rados_r13_tools::{
    CANDIDATE_REPORT_PATH, HUMAN_REVIEW_PATH, REVIEWER_TRUST_PATH, print_review_payload,
    verify_approved, verify_pending,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rados-r13-verify: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut mode = Mode::Final;
    let mut review_path = HUMAN_REVIEW_PATH.to_owned();
    let mut trust_path = REVIEWER_TRUST_PATH.to_owned();
    let mut report_path = CANDIDATE_REPORT_PATH.to_owned();
    let mut positional: Vec<String> = Vec::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--pending" => mode = Mode::Pending,
            "--review" => review_path = next_value(&mut args, "--review")?,
            "--trust" => trust_path = next_value(&mut args, "--trust")?,
            "--report" => report_path = next_value(&mut args, "--report")?,
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            "print-review-payload" => {
                mode = Mode::PrintPayload;
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown flag {other}").into());
            }
            other => positional.push(other.to_owned()),
        }
    }
    match mode {
        Mode::Final => {
            let review = read_file(&review_path)?;
            let trust = read_file(&trust_path)?;
            let report = read_file(&report_path)?;
            verify_approved(&review, &trust, &report)?;
            println!("R13 approved review record verified");
        }
        Mode::Pending => {
            let review = read_file(&review_path)?;
            let trust = read_file(&trust_path)?;
            verify_pending(&review, &trust)?;
            println!("R13 pending review record verified");
        }
        Mode::PrintPayload => {
            let role = positional
                .first()
                .ok_or("print-review-payload requires a ROLE argument")?;
            let review = read_file(&review_path)?;
            let report = read_file(&report_path)?;
            let payload = print_review_payload(role, &review, &report)?;
            io::stdout().write_all(&payload)?;
        }
    }
    Ok(())
}

enum Mode {
    Final,
    Pending,
    PrintPayload,
}

fn next_value(
    args: &mut std::iter::Skip<std::env::Args>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn read_file(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    std::fs::read(Path::new(path)).map_err(|error| format!("read {path}: {error}").into())
}

fn print_help() {
    println!(
        "Usage:\n  rados-r13-verify [--review PATH] [--trust PATH] [--report PATH]\n\
         \n  rados-r13-verify --pending [--review PATH] [--trust PATH]\n\
         \n  rados-r13-verify print-review-payload ROLE [--review PATH] [--report PATH]\n\
         \n\
Never generates signatures. Default mode fails the canonical pending state."
    );
}
