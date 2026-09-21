//! Deterministic release artifact production.
//!
//! Produces the R13 v1 release-artifact set:
//!
//! 1. `rados-rs-vX.Y.Z.crate` — reproducible ustar+gzip of the packaged file
//!    set (mode 0644, mtime 0, gzip OS byte 0xFF).
//! 2. `rados-rs-vX.Y.Z.zip`   — reproducible STORED zip of the same set
//!    (DOS date 1980-01-01, no compression).
//! 3. `rados-rs-vX.Y.Z.spdx.json` — SPDX 2.3 document with
//!    `created = 1970-01-01T00:00:00Z` and per-file SHA-256/SHA-1 checksums.
//! 4. `SHA256SUMS` — `<sha256>  <name>\n` lines for the three artefacts
//!    above, sorted by name.
//!
//! The whole encoder is byte-for-byte stable so two calls with the same
//! input produce identical outputs. Rejection rules refuse any path that
//! could allow a package to escape its root (see [`validate_path`]).

use std::collections::BTreeMap;
use std::fmt;

use crate::hash::{lower_hex, sha1_hex, sha256_hex, upper_hex};
use sha1::{Digest as _, Sha1};

pub const ARTIFACT_COUNT: usize = 4;
pub const CHECKSUMS_NAME: &str = "SHA256SUMS";

/// Rejection reason. Callers only inspect the string form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseError(pub String);

impl fmt::Display for ReleaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ReleaseError {}

/// Input to the deterministic encoder.
#[derive(Debug, Clone)]
pub struct ReleaseInput {
    pub version: String,
    pub files: BTreeMap<String, Vec<u8>>,
}

/// Encoded artefacts.
#[derive(Debug, Clone)]
pub struct ReleaseArtifacts {
    pub tarball: Vec<u8>,
    pub zip: Vec<u8>,
    pub spdx: Vec<u8>,
    pub checksums: Vec<u8>,
    pub names: ReleaseNames,
}

/// Artefact filenames derived from `version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseNames {
    pub tarball: String,
    pub zip: String,
    pub spdx: String,
    pub checksums: String,
}

impl ReleaseNames {
    /// # Errors
    ///
    /// Rejects a version string that is not a valid semver-like `vX.Y.Z`
    /// (optionally with `-pre` / `+build` segments) since the artefact name
    /// participates in the release-artifacts binding.
    pub fn from_version(version: &str) -> Result<Self, ReleaseError> {
        if !valid_version(version) {
            return Err(ReleaseError(format!("invalid release version {version:?}")));
        }
        let base = format!("rados-rs-{version}");
        Ok(Self {
            tarball: format!("{base}.crate"),
            zip: format!("{base}.zip"),
            spdx: format!("{base}.spdx.json"),
            checksums: CHECKSUMS_NAME.to_owned(),
        })
    }

    #[must_use]
    pub fn as_array(&self) -> [&str; ARTIFACT_COUNT] {
        [&self.tarball, &self.zip, &self.spdx, &self.checksums]
    }
}

/// Build the deterministic release-artefact set.
///
/// # Errors
///
/// Returns an error when the input `version` is not semver-shaped, when
/// the file set is empty, or when any packaged path fails validation.
pub fn build(input: &ReleaseInput) -> Result<ReleaseArtifacts, ReleaseError> {
    let names = ReleaseNames::from_version(&input.version)?;
    validate_file_set(&input.files)?;
    let base = format!("rados-rs-{}", input.version);
    let mut tar_entries: Vec<TarEntry> = Vec::with_capacity(input.files.len());
    for (path, contents) in &input.files {
        tar_entries.push(TarEntry {
            path: format!("{base}/{path}"),
            contents: contents.clone(),
        });
    }
    let tar_bytes = encode_tar(&tar_entries)?;
    let tarball = gzip_wrap(&tar_bytes);

    let mut zip_entries: Vec<ZipEntry> = Vec::with_capacity(input.files.len());
    for (path, contents) in &input.files {
        zip_entries.push(ZipEntry {
            path: format!("{base}/{path}"),
            contents: contents.clone(),
        });
    }
    let zip_bytes = encode_zip(&zip_entries);

    let spdx = encode_spdx(&input.version, &input.files, &names);

    let mut lines: Vec<(String, String)> = vec![
        (names.tarball.clone(), sha256_hex(&tarball)),
        (names.zip.clone(), sha256_hex(&zip_bytes)),
        (names.spdx.clone(), sha256_hex(&spdx)),
    ];
    lines.sort_by(|first, second| first.0.cmp(&second.0));
    let mut checksums = String::new();
    for (name, digest) in &lines {
        use std::fmt::Write as _;
        writeln!(checksums, "{digest}  {name}").expect("String write");
    }

    Ok(ReleaseArtifacts {
        tarball,
        zip: zip_bytes,
        spdx,
        checksums: checksums.into_bytes(),
        names,
    })
}

/// Compute the four expected release-artefact SHA-256 hashes for
/// `input` without holding the encoded bytes.
#[must_use]
pub fn artifact_hashes(artifacts: &ReleaseArtifacts) -> BTreeMap<String, String> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    map.insert(
        artifacts.names.tarball.clone(),
        sha256_hex(&artifacts.tarball),
    );
    map.insert(artifacts.names.zip.clone(), sha256_hex(&artifacts.zip));
    map.insert(artifacts.names.spdx.clone(), sha256_hex(&artifacts.spdx));
    map.insert(
        artifacts.names.checksums.clone(),
        sha256_hex(&artifacts.checksums),
    );
    map
}

fn validate_file_set(files: &BTreeMap<String, Vec<u8>>) -> Result<(), ReleaseError> {
    if files.is_empty() {
        return Err(ReleaseError("release input has no files".into()));
    }
    let mut lowered: BTreeMap<String, String> = BTreeMap::new();
    for path in files.keys() {
        validate_path(path)?;
        let lower = path.to_ascii_lowercase();
        if let Some(existing) = lowered.insert(lower.clone(), path.clone()) {
            return Err(ReleaseError(format!(
                "release input has a case-insensitive path collision: {existing:?} vs {path:?}"
            )));
        }
    }
    Ok(())
}

/// # Errors
///
/// Returns an error if `path` uses absolute form, contains a `..` segment,
/// contains a `.` segment, is empty, contains a NUL or control character,
/// or begins/ends with whitespace.
pub fn validate_path(path: &str) -> Result<(), ReleaseError> {
    if path.is_empty() {
        return Err(ReleaseError("release path is empty".into()));
    }
    if path.starts_with('/') || path.contains(':') {
        return Err(ReleaseError(format!("release path {path:?} is absolute")));
    }
    if path.starts_with('\\') || path.contains('\\') {
        return Err(ReleaseError(format!(
            "release path {path:?} contains a backslash"
        )));
    }
    if path.chars().any(|character| character.is_ascii_control()) {
        return Err(ReleaseError(format!(
            "release path {path:?} contains a control character"
        )));
    }
    if path.starts_with(' ') || path.ends_with(' ') {
        return Err(ReleaseError(format!(
            "release path {path:?} has leading or trailing whitespace"
        )));
    }
    for segment in path.split('/') {
        if segment.is_empty() {
            return Err(ReleaseError(format!(
                "release path {path:?} has an empty segment"
            )));
        }
        if segment == "." || segment == ".." {
            return Err(ReleaseError(format!(
                "release path {path:?} contains a `.` or `..` segment"
            )));
        }
    }
    Ok(())
}

fn valid_version(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('v') else {
        return false;
    };
    // Split off optional +build.
    let core = rest.split('+').next().unwrap_or(rest);
    // Split off optional -pre.
    let (numeric, prerelease) = match core.split_once('-') {
        Some((left, right)) => (left, Some(right)),
        None => (core, None),
    };
    let parts: Vec<&str> = numeric.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    for part in &parts {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        if part.len() > 1 && part.starts_with('0') {
            return false;
        }
    }
    if let Some(pre) = prerelease {
        if pre.is_empty() {
            return false;
        }
        if !pre.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }) {
            return false;
        }
    }
    if let Some(build) = rest.split('+').nth(1)
        && (build.is_empty()
            || !build.split('.').all(|segment| {
                !segment.is_empty()
                    && segment
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            }))
    {
        return false;
    }
    true
}

// ---------------------------------------------------------------- tar/ustar

struct TarEntry {
    path: String,
    contents: Vec<u8>,
}

fn encode_tar(entries: &[TarEntry]) -> Result<Vec<u8>, ReleaseError> {
    let mut out: Vec<u8> = Vec::new();
    for entry in entries {
        write_tar_header(&mut out, &entry.path, entry.contents.len())?;
        out.extend_from_slice(&entry.contents);
        let padding = (512 - (entry.contents.len() % 512)) % 512;
        out.extend(std::iter::repeat_n(0_u8, padding));
    }
    out.extend(std::iter::repeat_n(0_u8, 1024));
    Ok(out)
}

fn write_tar_header(out: &mut Vec<u8>, path: &str, size: usize) -> Result<(), ReleaseError> {
    let (name, prefix) = split_ustar_name(path)?;
    let mut header = [0_u8; 512];
    put_bytes(&mut header, 0, name.as_bytes());
    put_octal(&mut header, 100, 8, 0o0644);
    put_octal(&mut header, 108, 8, 0);
    put_octal(&mut header, 116, 8, 0);
    put_octal_size(&mut header, 124, 12, size);
    put_octal(&mut header, 136, 12, 0);
    for slot in &mut header[148..156] {
        *slot = b' ';
    }
    header[156] = b'0';
    put_bytes(&mut header, 257, b"ustar\x00");
    put_bytes(&mut header, 263, b"00");
    put_bytes(&mut header, 345, prefix.as_bytes());
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    let checksum_bytes = format!("{checksum:06o}");
    for (index, byte) in checksum_bytes.bytes().enumerate() {
        header[148 + index] = byte;
    }
    header[148 + checksum_bytes.len()] = 0;
    header[148 + checksum_bytes.len() + 1] = b' ';
    out.extend_from_slice(&header);
    Ok(())
}

fn split_ustar_name(path: &str) -> Result<(&str, &str), ReleaseError> {
    if path.len() <= 100 {
        return Ok((path, ""));
    }
    // Find the largest split index in [1, 155] such that the remainder fits
    // in 100 bytes, at a '/' boundary.
    let bytes = path.as_bytes();
    let start = path.len().saturating_sub(100);
    for index in (start..path.len()).rev() {
        if bytes[index] == b'/' {
            let prefix = &path[..index];
            let name = &path[index + 1..];
            if !prefix.is_empty() && prefix.len() <= 155 && !name.is_empty() && name.len() <= 100 {
                return Ok((name, prefix));
            }
        }
    }
    Err(ReleaseError(format!(
        "release path {path:?} does not fit in a ustar header"
    )))
}

fn put_bytes(header: &mut [u8; 512], offset: usize, value: &[u8]) {
    header[offset..offset + value.len()].copy_from_slice(value);
}

fn put_octal(header: &mut [u8; 512], offset: usize, width: usize, value: u64) {
    let string = format!("{value:0width$o}", width = width - 1);
    for (index, byte) in string.bytes().enumerate() {
        header[offset + index] = byte;
    }
    header[offset + width - 1] = 0;
}

fn put_octal_size(header: &mut [u8; 512], offset: usize, width: usize, size: usize) {
    put_octal(header, offset, width, size as u64);
}

// ---------------------------------------------------------------- gzip/deflate

fn gzip_wrap(payload: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(payload.len() + 32);
    out.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]);
    deflate_stored(&mut out, payload);
    let crc = crc32(payload);
    out.extend_from_slice(&crc.to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    let isize_value = (payload.len() as u32).to_le_bytes();
    out.extend_from_slice(&isize_value);
    out
}

fn deflate_stored(out: &mut Vec<u8>, payload: &[u8]) {
    const BLOCK: usize = 65_535;
    if payload.is_empty() {
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);
        return;
    }
    let mut position = 0_usize;
    while position < payload.len() {
        let remaining = payload.len() - position;
        let take = remaining.min(BLOCK);
        let final_block = take == remaining;
        out.push(u8::from(final_block));
        #[allow(clippy::cast_possible_truncation)]
        let length = take as u16;
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&(!length).to_le_bytes());
        out.extend_from_slice(&payload[position..position + take]);
        position += take;
    }
}

const fn crc32_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut index = 0_u32;
    while index < 256 {
        let mut value = index;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 == 1 {
                0xedb8_8320 ^ (value >> 1)
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index as usize] = value;
        index += 1;
    }
    table
}
const CRC32_TABLE: [u32; 256] = crc32_table();

fn crc32(data: &[u8]) -> u32 {
    let mut value = !0_u32;
    for byte in data {
        let index = usize::try_from((value ^ u32::from(*byte)) & 0xff).expect("byte index");
        value = CRC32_TABLE[index] ^ (value >> 8);
    }
    !value
}

// ---------------------------------------------------------------- zip STORED

struct ZipEntry {
    path: String,
    contents: Vec<u8>,
}

fn encode_zip(entries: &[ZipEntry]) -> Vec<u8> {
    #[derive(Clone)]
    struct EntryPointer {
        name: String,
        crc: u32,
        size: u32,
        offset: u32,
    }

    let mut body: Vec<u8> = Vec::new();
    let mut pointers: Vec<EntryPointer> = Vec::with_capacity(entries.len());
    for entry in entries {
        let offset =
            u32::try_from(body.len()).expect("release archive exceeds 4 GiB local-header space");
        let crc = crc32(&entry.contents);
        let size = u32::try_from(entry.contents.len()).expect("release file exceeds 4 GiB");
        let name_bytes = entry.path.as_bytes();
        let name_len = u16::try_from(name_bytes.len()).expect("release path exceeds 64 KiB in zip");
        body.extend_from_slice(&0x0403_4b50_u32.to_le_bytes());
        body.extend_from_slice(&20_u16.to_le_bytes());
        body.extend_from_slice(&0_u16.to_le_bytes());
        body.extend_from_slice(&0_u16.to_le_bytes());
        body.extend_from_slice(&0_u16.to_le_bytes()); // mod time = 00:00:00
        body.extend_from_slice(&0x0021_u16.to_le_bytes()); // mod date = 1980-01-01
        body.extend_from_slice(&crc.to_le_bytes());
        body.extend_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&name_len.to_le_bytes());
        body.extend_from_slice(&0_u16.to_le_bytes());
        body.extend_from_slice(name_bytes);
        body.extend_from_slice(&entry.contents);
        pointers.push(EntryPointer {
            name: entry.path.clone(),
            crc,
            size,
            offset,
        });
    }
    let cd_offset = u32::try_from(body.len()).expect("central-directory offset overflow");
    for pointer in &pointers {
        let name_bytes = pointer.name.as_bytes();
        let name_len = u16::try_from(name_bytes.len()).expect("release path exceeds 64 KiB");
        body.extend_from_slice(&0x0201_4b50_u32.to_le_bytes());
        body.extend_from_slice(&0x0003_u16.to_le_bytes()); // version made by (Unix)
        body.extend_from_slice(&20_u16.to_le_bytes());
        body.extend_from_slice(&0_u16.to_le_bytes());
        body.extend_from_slice(&0_u16.to_le_bytes());
        body.extend_from_slice(&0_u16.to_le_bytes());
        body.extend_from_slice(&0x0021_u16.to_le_bytes());
        body.extend_from_slice(&pointer.crc.to_le_bytes());
        body.extend_from_slice(&pointer.size.to_le_bytes());
        body.extend_from_slice(&pointer.size.to_le_bytes());
        body.extend_from_slice(&name_len.to_le_bytes());
        body.extend_from_slice(&0_u16.to_le_bytes());
        body.extend_from_slice(&0_u16.to_le_bytes());
        body.extend_from_slice(&0_u16.to_le_bytes());
        body.extend_from_slice(&0_u16.to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.extend_from_slice(&pointer.offset.to_le_bytes());
        body.extend_from_slice(name_bytes);
    }
    let cd_size = u32::try_from(body.len()).expect("cd size overflow") - cd_offset;
    let entries_count = u16::try_from(pointers.len()).expect("release entries exceed 64 KiB");
    body.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&entries_count.to_le_bytes());
    body.extend_from_slice(&entries_count.to_le_bytes());
    body.extend_from_slice(&cd_size.to_le_bytes());
    body.extend_from_slice(&cd_offset.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body
}

// ---------------------------------------------------------------- SPDX 2.3

fn encode_spdx(version: &str, files: &BTreeMap<String, Vec<u8>>, names: &ReleaseNames) -> Vec<u8> {
    let mut file_sha1s: Vec<[u8; 20]> = Vec::with_capacity(files.len());
    let mut file_entries: Vec<String> = Vec::with_capacity(files.len());
    for (index, (path, bytes)) in files.iter().enumerate() {
        let sha256 = sha256_hex(bytes);
        let sha1 = sha1_hex(bytes);
        let mut sha1_bytes = [0_u8; 20];
        Sha1::digest(bytes)
            .as_slice()
            .iter()
            .enumerate()
            .for_each(|(offset, byte)| sha1_bytes[offset] = *byte);
        file_sha1s.push(sha1_bytes);
        file_entries.push(format!(
            "    {{\
\"fileName\":\"./{path}\",\
\"SPDXID\":\"SPDXRef-File-{index}\",\
\"checksums\":[\
{{\"algorithm\":\"SHA256\",\"checksumValue\":\"{sha256}\"}},\
{{\"algorithm\":\"SHA1\",\"checksumValue\":\"{sha1}\"}}\
],\
\"licenseConcluded\":\"NOASSERTION\",\
\"licenseInfoInFiles\":[\"NOASSERTION\"],\
\"copyrightText\":\"NOASSERTION\"}}",
            path = json_escape(path),
        ));
    }
    // Package verification code per SPDX 2.3: SHA1 of concatenated lowercase-hex
    // per-file SHA1 digests sorted.
    let mut sorted_sha1_hex: Vec<String> =
        file_sha1s.iter().map(|bytes| lower_hex(bytes)).collect();
    sorted_sha1_hex.sort_unstable();
    let verification_source: String = sorted_sha1_hex.join("");
    let verification_code = sha1_hex(verification_source.as_bytes());
    let namespace = format!(
        "https://github.com/otuschhoff/rados-rs/spdx/{version}/{}",
        upper_hex(verification_code.as_bytes())
            .get(..16)
            .unwrap_or("0000000000000000")
    );
    let package_name = format!("rados-rs-{version}");
    let spdx_body = format!(
        "{{\
\"spdxVersion\":\"SPDX-2.3\",\
\"dataLicense\":\"CC0-1.0\",\
\"SPDXID\":\"SPDXRef-DOCUMENT\",\
\"name\":\"{name}\",\
\"documentNamespace\":\"{namespace}\",\
\"creationInfo\":{{\
\"created\":\"1970-01-01T00:00:00Z\",\
\"creators\":[\"Tool: rados-r13-release\"]\
}},\
\"packages\":[{{\
\"SPDXID\":\"SPDXRef-Package-rados-rs\",\
\"name\":\"rados-rs\",\
\"versionInfo\":\"{version}\",\
\"downloadLocation\":\"NOASSERTION\",\
\"filesAnalyzed\":true,\
\"packageVerificationCode\":{{\"packageVerificationCodeValue\":\"{verification_code}\"}},\
\"licenseConcluded\":\"LGPL-2.1-only\",\
\"licenseDeclared\":\"LGPL-2.1-only\",\
\"copyrightText\":\"NOASSERTION\",\
\"hasFiles\":[{has_files}]\
}}],\
\"files\":[\n{files}\n],\
\"relationships\":[\
{{\"spdxElementId\":\"SPDXRef-DOCUMENT\",\"relationshipType\":\"DESCRIBES\",\"relatedSpdxElement\":\"SPDXRef-Package-rados-rs\"}}\
],\
\"artifactNames\":[\"{tar}\",\"{zip}\",\"{spdx}\",\"{sums}\"]\
}}",
        name = json_escape(&package_name),
        namespace = json_escape(&namespace),
        version = json_escape(version),
        verification_code = verification_code,
        has_files = (0..files.len())
            .map(|index| format!("\"SPDXRef-File-{index}\""))
            .collect::<Vec<_>>()
            .join(","),
        files = file_entries.join(",\n"),
        tar = json_escape(&names.tarball),
        zip = json_escape(&names.zip),
        spdx = json_escape(&names.spdx),
        sums = json_escape(&names.checksums),
    );
    spdx_body.into_bytes()
}

fn json_escape(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                write!(out, "\\u{:04x}", character as u32).expect("String write");
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input() -> ReleaseInput {
        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        files.insert("Cargo.toml".into(), b"[package]\nname = \"x\"\n".to_vec());
        files.insert("src/lib.rs".into(), b"pub fn one() -> u8 { 1 }\n".to_vec());
        files.insert("LICENSE".into(), b"LGPL-2.1-only\n".to_vec());
        ReleaseInput {
            version: "v0.1.0".into(),
            files,
        }
    }

    #[test]
    fn two_runs_produce_identical_bytes() {
        let first = build(&sample_input()).expect("first build");
        let second = build(&sample_input()).expect("second build");
        assert_eq!(first.tarball, second.tarball);
        assert_eq!(first.zip, second.zip);
        assert_eq!(first.spdx, second.spdx);
        assert_eq!(first.checksums, second.checksums);
        assert_eq!(first.names, second.names);
    }

    #[test]
    fn rejects_absolute_path() {
        let mut input = sample_input();
        input.files.insert("/etc/passwd".into(), vec![0]);
        assert!(build(&input).is_err());
    }

    #[test]
    fn rejects_dotdot_path() {
        let mut input = sample_input();
        input.files.insert("../etc/passwd".into(), vec![0]);
        assert!(build(&input).is_err());
    }

    #[test]
    fn rejects_case_collision() {
        let mut input = sample_input();
        input.files.insert("README.md".into(), b"a".to_vec());
        input.files.insert("readme.md".into(), b"b".to_vec());
        assert!(build(&input).is_err());
    }

    #[test]
    fn rejects_control_character() {
        let mut input = sample_input();
        input.files.insert("bad\u{7}file".into(), vec![0]);
        assert!(build(&input).is_err());
    }

    #[test]
    fn rejects_backslash_path() {
        let mut input = sample_input();
        input.files.insert(r"windows\path".into(), vec![0]);
        assert!(build(&input).is_err());
    }

    #[test]
    fn rejects_bad_version() {
        let mut input = sample_input();
        input.version = "1.2.3".into();
        assert!(build(&input).is_err());
    }

    #[test]
    fn names_are_four_and_ordered() {
        let names = ReleaseNames::from_version("v1.2.3").expect("names");
        assert_eq!(names.tarball, "rados-rs-v1.2.3.crate");
        assert_eq!(names.zip, "rados-rs-v1.2.3.zip");
        assert_eq!(names.spdx, "rados-rs-v1.2.3.spdx.json");
        assert_eq!(names.checksums, "SHA256SUMS");
        assert_eq!(names.as_array().len(), ARTIFACT_COUNT);
    }

    #[test]
    fn checksums_lines_sorted_by_name() {
        let artifacts = build(&sample_input()).expect("build");
        let text = String::from_utf8(artifacts.checksums.clone()).expect("utf8");
        let names: Vec<&str> = text
            .lines()
            .filter_map(|line| line.split_whitespace().nth(1))
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn gzip_prefix_is_deterministic() {
        let artifacts = build(&sample_input()).expect("build");
        assert_eq!(
            &artifacts.tarball[..10],
            &[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]
        );
    }

    #[test]
    fn zip_uses_1980_date() {
        let artifacts = build(&sample_input()).expect("build");
        // First local file header starts at byte 0. Bytes 10..12 = mod time,
        // 12..14 = mod date, followed by CRC32.
        assert_eq!(&artifacts.zip[10..12], &[0x00, 0x00]);
        assert_eq!(&artifacts.zip[12..14], &[0x21, 0x00]);
    }
}
