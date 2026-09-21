#![forbid(unsafe_code)]
//! `rados-r13-qualify` CLI.
//!
//! Modes:
//!
//! * default: verify an existing qualification report bound to the repository
//!   root (`--root PATH`, `--report PATH`). Fails if any check is missing,
//!   any prior binding is stale, or the source digest disagrees.
//! * `--check-inventory` (read-only): validate the frozen 623-row native
//!   inventory and the current 905-row parity ledger. Does not touch other
//!   evidence.
//! * `--print-checks`: print the canonical ordered list of check ids so a
//!   harness can drive the checks externally.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rados_r13_tools::constants::{CHECK_IDS, FUZZ_LIVE_PATH};
use rados_r13_tools::fuzz;
use rados_r13_tools::inventory::check as check_inventory;
use rados_r13_tools::qualify;
use rados_r13_tools::source;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rados-r13-qualify: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut mode = Mode::Verify;
    let mut root: PathBuf = PathBuf::from(".");
    let mut report: PathBuf = PathBuf::from(rados_r13_tools::constants::QUALIFICATION_LIVE_PATH);
    let mut fuzz_report: PathBuf = PathBuf::from(FUZZ_LIVE_PATH);
    let mut corpus_root: Option<PathBuf> = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--check-inventory" => mode = Mode::CheckInventory,
            "--print-checks" => mode = Mode::PrintChecks,
            "--print-source-artifacts" => mode = Mode::PrintSourceArtifacts,
            "--print-source-digest" => mode = Mode::PrintSourceDigest,
            "--require-fuzz-certifying" => mode = Mode::RequireFuzzCertifying,
            "--root" => root = PathBuf::from(next_value(&mut args, "--root")?),
            "--report" => report = PathBuf::from(next_value(&mut args, "--report")?),
            "--fuzz-report" => fuzz_report = PathBuf::from(next_value(&mut args, "--fuzz-report")?),
            "--corpus-root" => {
                corpus_root = Some(PathBuf::from(next_value(&mut args, "--corpus-root")?));
            }
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            other => return Err(format!("unknown argument {other:?}").into()),
        }
    }
    match mode {
        Mode::Verify => {
            qualify::verify_report(&root, &report)?;
            println!(
                "R13 qualification report verified: {}",
                Path::new(&report).display()
            );
        }
        Mode::CheckInventory => {
            let summary = check_inventory(&root)?;
            println!(
                "R13 inventory check passed: native_rows={} ledger_rows={}",
                summary.native_rows, summary.ledger_rows
            );
        }
        Mode::PrintChecks => {
            for id in CHECK_IDS {
                println!("{id}");
            }
        }
        Mode::PrintSourceArtifacts => {
            let artifacts = source::source_artifacts(&root)?;
            let bytes = serde_json::to_vec(&artifacts)
                .map_err(|error| format!("encode source artifacts: {error}"))?;
            std::io::Write::write_all(&mut std::io::stdout(), &bytes)?;
            println!();
        }
        Mode::PrintSourceDigest => {
            println!("{}", source::source_digest(&root)?);
        }
        Mode::RequireFuzzCertifying => {
            let corpus = corpus_root.ok_or_else(|| {
                "--require-fuzz-certifying requires --corpus-root".to_owned()
            })?;
            let bound = fuzz::verify_report(
                &root,
                &fuzz_report,
                &corpus,
                fuzz::Profile::Certifying,
            )?;
            println!(
                "R13 fuzz certifying gate passed: {} campaigns={}",
                Path::new(&fuzz_report).display(),
                bound.campaigns.len()
            );
        }
    }
    Ok(())
}

fn print_help() {
    println!(
        "Usage:\n\
         \n  rados-r13-qualify --root PATH --report PATH\n\
         \n  rados-r13-qualify --check-inventory [--root PATH]\n\
         \n  rados-r13-qualify --print-checks\n\
         \n  rados-r13-qualify --print-source-artifacts --root PATH\n\
         \n  rados-r13-qualify --print-source-digest --root PATH\n\
         \n  rados-r13-qualify --require-fuzz-certifying --root PATH \\\n\
         \n                     --fuzz-report PATH --corpus-root PATH\n\
         \n\
         Default mode requires the report file to bind exact prior R03-R12\n\
         hashes, the current source digest, the fixed inventory row counts,\n\
         and a deterministic-release proof. --require-fuzz-certifying binds\n\
         the current tree to a passed R13 certifying fuzz report.\n\
         --print-source-artifacts emits a canonical {{path: sha256}} JSON\n\
         object over the R13 source closure (git-tracked, excluding the R13\n\
         self-reference set) so shell producers do not duplicate the walk.\n\
         --print-source-digest emits the aggregate SHA-256 that binds the\n\
         same closure."
    );
}

enum Mode {
    Verify,
    CheckInventory,
    PrintChecks,
    PrintSourceArtifacts,
    PrintSourceDigest,
    RequireFuzzCertifying,
}

fn next_value(
    args: &mut std::iter::Skip<std::env::Args>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}
