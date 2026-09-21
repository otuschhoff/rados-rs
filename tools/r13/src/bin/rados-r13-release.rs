#![forbid(unsafe_code)]
//! `rados-r13-release` CLI.
//!
//! Reads a directory (`--input`) whose contents form the R13 release package
//! source set and emits the four deterministic release artefacts
//! (`--output`) — tarball, zip, SPDX, SHA256SUMS — for a given `--version`.
//!
//! The tool refuses to package unsafe paths (absolute, `..`, control
//! characters, backslashes, case-insensitive collisions) and refuses to
//! follow symlinks encountered during enumeration.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rados_r13_tools::release::{ReleaseInput, build};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rados-r13-release: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut version: Option<String> = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--input" => input = Some(PathBuf::from(next_value(&mut args, "--input")?)),
            "--output" => output = Some(PathBuf::from(next_value(&mut args, "--output")?)),
            "--version" => version = Some(next_value(&mut args, "--version")?),
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            other => return Err(format!("unknown argument {other:?}").into()),
        }
    }
    let input = input.ok_or("--input is required")?;
    let output = output.ok_or("--output is required")?;
    let version = version.ok_or("--version is required")?;

    let files = enumerate(&input)?;
    let artifacts = build(&ReleaseInput { version, files })?;

    fs::create_dir_all(&output)?;
    fs::write(output.join(&artifacts.names.tarball), &artifacts.tarball)?;
    fs::write(output.join(&artifacts.names.zip), &artifacts.zip)?;
    fs::write(output.join(&artifacts.names.spdx), &artifacts.spdx)?;
    fs::write(
        output.join(&artifacts.names.checksums),
        &artifacts.checksums,
    )?;
    println!("R13 release artefacts written to {}", output.display());
    for name in artifacts.names.as_array() {
        println!("  {name}");
    }
    Ok(())
}

fn print_help() {
    println!(
        "Usage: rados-r13-release --input DIR --output DIR --version vX.Y.Z\n\n\
         Emits four deterministic artefacts: <base>.crate, <base>.zip,\n\
         <base>.spdx.json, SHA256SUMS. Refuses symlinks and unsafe paths."
    );
}

fn next_value(
    args: &mut std::iter::Skip<std::env::Args>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn enumerate(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "release input {} is a symlink; refusing to follow",
            root.display()
        )
        .into());
    }
    if !metadata.is_dir() {
        return Err(format!("release input {} is not a directory", root.display()).into());
    }
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    walk(root, root, &mut files)?;
    if files.is_empty() {
        return Err(format!("release input {} has no files", root.display()).into());
    }
    Ok(files)
}

/// Directories and files that must never be packaged into the release
/// artefact, expressed as workspace-root-relative paths (forward slashes).
///
/// Includes VCS/build outputs (`.git`, `target`), fuzz working state
/// (`fuzz/artifacts`, `fuzz/target`, `fuzz/corpus`), prior release
/// outputs (`docs/r13/release-artifacts`), and every non-R13 subtree the
/// crate's `include` list in the root `Cargo.toml` also excludes (`docs`
/// / `integration` / `tools` under R07..R13). Excluding these here mirrors
/// the manifest so a mistaken run against the workspace root never leaks
/// generated evidence or unrelated tooling into the released tarball.
const RELEASE_EXCLUDED_PREFIXES: &[&str] = &[
    ".git",
    "target",
    "fuzz/artifacts",
    "fuzz/target",
    "fuzz/corpus",
    "docs/r13/release-artifacts",
    "docs/r06",
    "docs/r07",
    "docs/r08",
    "docs/r09",
    "docs/r10",
    "docs/r11",
    "docs/r12",
    "docs/r13",
    "integration/r05",
    "integration/r06",
    "integration/r07",
    "integration/r08",
    "integration/r09",
    "integration/r10",
    "integration/r11",
    "integration/r12",
    "integration/r13",
    "tools/r00",
    "tools/r01",
    "tools/r02",
    "tools/r03",
    "tools/r04",
    "tools/r05",
    "tools/r06",
    "tools/r07",
    "tools/r08",
    "tools/r09",
    "tools/r10",
    "tools/r11",
    "tools/r12",
    "tools/r13",
    "src/r04_integration.rs",
    "src/r05_integration.rs",
    "src/r06_integration.rs",
    "src/r07_integration.rs",
    "src/r08_integration.rs",
    "src/r09_integration.rs",
    "src/r10_integration.rs",
    "src/r11_integration.rs",
    "src/r12_integration.rs",
    "testdata/r06",
    "testdata/p04",
];

fn is_release_excluded(relative: &str) -> bool {
    for prefix in RELEASE_EXCLUDED_PREFIXES {
        if relative == *prefix || relative.starts_with(&format!("{prefix}/")) {
            return true;
        }
    }
    false
}

fn walk(
    root: &Path,
    dir: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut entries: Vec<_> = fs::read_dir(dir)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "path escaped root".to_owned())?
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 path {}", path.display()))?
            .replace('\\', "/");
        if is_release_excluded(&relative) {
            continue;
        }
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "release input {} contains symlink {}",
                root.display(),
                path.display()
            )
            .into());
        }
        if metadata.is_dir() {
            walk(root, &path, files)?;
        } else if metadata.is_file() {
            let bytes = fs::read(&path)?;
            files.insert(relative, bytes);
        } else {
            return Err(format!("unsupported filesystem entry {}", path.display()).into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{RELEASE_EXCLUDED_PREFIXES, enumerate, is_release_excluded};
    use std::path::PathBuf;

    #[test]
    fn excluded_prefixes_are_documented_and_sorted_by_scope() {
        assert!(RELEASE_EXCLUDED_PREFIXES.contains(&".git"));
        assert!(RELEASE_EXCLUDED_PREFIXES.contains(&"target"));
        assert!(RELEASE_EXCLUDED_PREFIXES.contains(&"docs/r13/release-artifacts"));
        assert!(RELEASE_EXCLUDED_PREFIXES.contains(&"fuzz/corpus"));
        assert!(RELEASE_EXCLUDED_PREFIXES.contains(&"fuzz/target"));
    }

    #[test]
    fn exclusion_matches_directory_and_descendants() {
        assert!(is_release_excluded("target"));
        assert!(is_release_excluded("target/debug/rados-rs"));
        assert!(is_release_excluded("docs/r13/release-artifacts/SHA256SUMS"));
        assert!(!is_release_excluded("targets/foo"));
        assert!(!is_release_excluded("docs/r13-notes.txt"));
    }

    #[test]
    fn end_to_end_repository_root_release_excludes_generated_evidence() {
        // Locate the workspace root from CARGO_MANIFEST_DIR (tools/r13).
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(|parent| parent.parent())
            .expect("workspace root");
        // Guard: skip when the workspace root is not present (out-of-tree
        // publish/vendored builds); otherwise verify the enumerator both
        // walks the root and refuses every excluded prefix.
        if !workspace_root.join("Cargo.toml").exists() {
            return;
        }
        let files = enumerate(workspace_root).expect("enumerate workspace root");
        assert!(
            !files.is_empty(),
            "workspace root enumeration produced no files"
        );
        for path in files.keys() {
            for prefix in RELEASE_EXCLUDED_PREFIXES {
                let owned_prefix = (*prefix).to_owned();
                let with_slash = format!("{prefix}/");
                assert!(
                    path != &owned_prefix && !path.starts_with(&with_slash),
                    "release enumeration leaked excluded path {path:?} (prefix {prefix:?})"
                );
            }
        }
        // Assert positive presence of a known included file so we know we
        // are actually seeing something (README ships in every configuration).
        assert!(
            files.contains_key("README.md"),
            "workspace root release must include README.md"
        );
    }
}
