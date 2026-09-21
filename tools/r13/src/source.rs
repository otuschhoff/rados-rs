//! Deterministic source inventory used by qualification.
//!
//! Enumerates the tracked Rust source tree via `git ls-files` and computes an
//! aggregate SHA-256 that is independent of the R13 outputs themselves so
//! rerunning qualification cannot rehash the previous run's artefacts.

use std::fs;
use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::hash::lower_hex;

/// Paths that name R13 outputs and therefore must NEVER contribute to the
/// source digest. Excluding them avoids a self-reference cycle when the
/// qualification, candidate, and release outputs are checked in.
pub const SELF_REFERENCE_EXCLUSIONS: &[&str] = &[
    "docs/r13/qualification-report.json",
    "docs/r13/qualification-report.pending.json",
    "docs/r13/human-review.json",
    "docs/r13/reviewer-trust.json",
    "docs/r13/fuzz-report.json",
    "docs/r13/fuzz-report.pending.json",
    "docs/r13/report.pending.json",
    "integration/r13/report.json",
];

/// Prefixes whose entire subtree is excluded from the source digest (the
/// retained release-artifact directory ships with certifying candidates only
/// and would otherwise create a self-reference cycle).
pub const SELF_REFERENCE_EXCLUSION_PREFIXES: &[&str] = &["docs/r13/release-artifacts/"];

/// Explicit pathspecs walked by the source digest. Kept identical to the
/// R12 practice but broadened to cover every R13 scope input.
pub const SOURCE_PATHSPECS: &[&str] = &[
    "src/**",
    "tools/r13/**",
    "integration/r13/**",
    "examples/**",
    "fuzz/fuzz_targets/**",
    "Cargo.toml",
    "Cargo.lock",
    "build.rs",
    "deny.toml",
    "rust-toolchain.toml",
    "README.md",
    "LICENSE",
    "RUST_THIRD_PARTY_NOTICES",
    "THIRD_PARTY_NOTICES",
];

/// Enumerate the source path list. Sorted, deduped, filesystem-relative.
///
/// # Errors
///
/// Returns an error if `git ls-files` fails, if the output is not UTF-8, or
/// if no paths were returned.
pub fn source_paths(root: &Path) -> Result<Vec<String>, String> {
    let mut arguments: Vec<&str> = vec!["ls-files", "-co", "--exclude-standard", "--"];
    arguments.extend(SOURCE_PATHSPECS.iter().copied());
    let output = Command::new("git")
        .args(&arguments)
        .current_dir(root)
        .output()
        .map_err(|error| format!("git ls-files: {error}"))?;
    if !output.status.success() {
        return Err("git ls-files failed".into());
    }
    let listing = String::from_utf8(output.stdout)
        .map_err(|_| "git ls-files output is not UTF-8".to_owned())?;
    let mut paths: Vec<String> = listing
        .lines()
        .filter(|line| {
            !line.is_empty()
                && !SELF_REFERENCE_EXCLUSIONS.contains(line)
                && !SELF_REFERENCE_EXCLUSION_PREFIXES
                    .iter()
                    .any(|prefix| line.starts_with(prefix))
        })
        .map(str::to_owned)
        .collect();
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        return Err("R13 source path set is empty".into());
    }
    Ok(paths)
}

/// Aggregate SHA-256 digest of all source paths.
///
/// # Errors
///
/// Returns an error if the underlying path enumeration or any file read
/// fails.
pub fn source_digest(root: &Path) -> Result<String, String> {
    let paths = source_paths(root)?;
    let mut aggregate = Sha256::new();
    for path in &paths {
        let bytes = fs::read(root.join(path)).map_err(|error| format!("read {path}: {error}"))?;
        let file_hash = lower_hex(&Sha256::digest(bytes));
        aggregate.update(format!("{file_hash}  {path}\n").as_bytes());
    }
    Ok(lower_hex(&aggregate.finalize()))
}

/// Per-path SHA-256 map for candidate report source binding.
///
/// # Errors
///
/// Returns an error if the underlying path enumeration or any file read
/// fails.
pub fn source_artifacts(root: &Path) -> Result<std::collections::BTreeMap<String, String>, String> {
    let paths = source_paths(root)?;
    let mut out = std::collections::BTreeMap::new();
    for path in paths {
        let bytes = fs::read(root.join(&path)).map_err(|error| format!("read {path}: {error}"))?;
        out.insert(path, lower_hex(&Sha256::digest(bytes)));
    }
    Ok(out)
}
