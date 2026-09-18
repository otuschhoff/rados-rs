use crate::cephx::{parse_key, parse_keyring};
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs::File;
use std::io::Read as _;
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

const MAX_CONFIG_BYTES: usize = 1 << 20;
const MAX_CONFIG_OPTIONS: usize = 256;
const MAX_MONITORS: usize = 64;
const MAX_MONITOR_BYTES: usize = 1_024;
const MAX_ENTITY_BYTES: usize = 256;
const MAX_KEY_BYTES: usize = 65_536;
const MAX_KEYRING_BYTES: usize = 1 << 20;
const MAX_GO_DURATION_NANOS: u128 = i64::MAX as u128;

const FILE_OPTIONS: &[&str] = &[
    "cluster",
    "entity",
    "name",
    "mon_host",
    "fsid",
    "key",
    "keyring",
    "ms_mode",
    "dial_timeout",
    "handshake_timeout",
    "operation_timeout",
];

const ENV_OPTIONS: &[(&str, &str)] = &[
    ("CLUSTER", "cluster"),
    ("ENTITY", "entity"),
    ("MON_HOST", "mon_host"),
    ("KEYRING", "keyring"),
    ("FSID", "fsid"),
    ("KEY", "key"),
    ("MS_MODE", "ms_mode"),
    ("DIAL_TIMEOUT", "dial_timeout"),
    ("HANDSHAKE_TIMEOUT", "handshake_timeout"),
    ("OPERATION_TIMEOUT", "operation_timeout"),
];

/// Messenger security policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SecurityMode {
    #[default]
    Secure,
    Crc,
}

/// Owned authentication key bytes with redacted formatting.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretKey(Zeroizing<Vec<u8>>);

impl SecretKey {
    /// Copies a bounded key value.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for an empty key or one over 64 KiB.
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > MAX_KEY_BYTES {
            return Err(Error::invalid("SecretKey::new"));
        }
        Ok(Self(Zeroizing::new(value.to_vec())))
    }

    /// Borrows the key bytes. They are never included in `Debug` output.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretKey([REDACTED])")
    }
}

/// Locally validated, owned client configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    cluster: String,
    monitors: Vec<String>,
    entity: String,
    cluster_fsid: Option<String>,
    key: Option<SecretKey>,
    keyring: Option<String>,
    options: BTreeMap<String, String>,
    security_mode: SecurityMode,
    dial_timeout: Duration,
    handshake_timeout: Duration,
    operation_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cluster: "ceph".to_owned(),
            monitors: Vec::new(),
            entity: "client.admin".to_owned(),
            cluster_fsid: None,
            key: None,
            keyring: None,
            options: BTreeMap::new(),
            security_mode: SecurityMode::Secure,
            dial_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(15),
            operation_timeout: Duration::from_secs(30),
        }
    }
}

impl Config {
    /// Parses the bounded supported Ceph configuration subset.
    ///
    /// `[global]` is applied first. The resulting entity selects the one exact
    /// entity section applied second; all other sections are ignored.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for malformed syntax, excessive input,
    /// too many properties, or an invalid known option.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let sections = parse_sections(data)?;
        let mut config = Self::default();
        config.apply_section(sections.get("global"))?;
        let entity = config.entity.clone();
        config.apply_section(sections.get(&entity))?;
        Ok(config)
    }

    /// Loads a bounded configuration file and its selected keyring, if needed.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when the file or keyring cannot be read
    /// or parsed.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let data = read_bounded_file(path.as_ref(), MAX_CONFIG_BYTES, "Config::load")?;
        let mut config = Self::parse(&data)?;
        if config.key.is_none() && config.keyring.is_some() {
            config.load_configured_keyring()?;
        }
        Ok(config)
    }

    /// Loads a copied canonical encoded key for an entity from a bounded keyring.
    ///
    /// An empty entity selects `client.admin`.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when the keyring cannot be read or its
    /// selected credential is absent or malformed.
    pub fn load_keyring(path: impl AsRef<Path>, entity: &str) -> Result<SecretKey> {
        let entity = if entity.is_empty() {
            "client.admin"
        } else {
            entity
        };
        let data = read_bounded_file(path.as_ref(), MAX_KEYRING_BYTES, "Config::load_keyring")?;
        parse_keyring(&data, entity, MAX_KEYRING_BYTES)
            .map_err(|_| Error::invalid("Config::load_keyring"))?;
        let encoded = encoded_key_from_keyring(&data, entity)
            .ok_or_else(|| Error::invalid("Config::load_keyring"))?;
        SecretKey::new(encoded.as_bytes())
    }

    /// Returns an independent configuration with one option applied.
    ///
    /// Unknown options are retained for [`Self::option`] but remain inert.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for an invalid option or keyring.
    pub fn with_option(self, name: &str, value: &str) -> Result<Self> {
        self.with_option_internal(name, value, true)
    }

    /// Returns an owned effective value for a known or retained option.
    #[must_use]
    pub fn option(&self, name: &str) -> Option<String> {
        match normalize_option_name(name).as_str() {
            "cluster" => Some(self.cluster.clone()),
            "entity" | "name" => Some(self.entity.clone()),
            "mon_host" if !self.monitors.is_empty() => Some(self.monitors.join(",")),
            "fsid" => self.cluster_fsid.clone(),
            "key" => self
                .key
                .as_ref()
                .map(|key| String::from_utf8_lossy(key.expose()).into_owned()),
            "keyring" => self.keyring.clone(),
            "ms_mode" => Some(match self.security_mode {
                SecurityMode::Secure => "secure".to_owned(),
                SecurityMode::Crc => "crc".to_owned(),
            }),
            "dial_timeout" => Some(format_duration(self.dial_timeout)),
            "handshake_timeout" => Some(format_duration(self.handshake_timeout)),
            "operation_timeout" => Some(format_duration(self.operation_timeout)),
            name => self.options.get(name).cloned(),
        }
    }

    /// Applies recognized long options and returns all other arguments unchanged.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for an invalid option or keyring.
    pub fn parse_args<I, S>(self, arguments: I) -> Result<(Self, Vec<String>)>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
        let mut config = self;
        let mut remainder = Vec::new();
        let mut option_count = 0usize;
        let mut key_seen = false;
        let mut keyring_seen = false;
        let mut index = 0usize;
        while index < arguments.len() {
            let argument = &arguments[index];
            if argument == "--" {
                remainder.extend(arguments[index..].iter().cloned());
                break;
            }
            let Some(name_value) = argument.strip_prefix("--") else {
                remainder.push(argument.clone());
                index += 1;
                continue;
            };
            let (name, inline_value) = name_value
                .split_once('=')
                .map_or((name_value, None), |(name, value)| (name, Some(value)));
            let mut normalized = normalize_option_name(name);
            if !is_argument_option(&normalized) {
                remainder.push(argument.clone());
                index += 1;
                continue;
            }
            option_count += 1;
            if option_count > MAX_CONFIG_OPTIONS {
                return Err(Error::invalid("Config::parse_args"));
            }
            let value = if let Some(value) = inline_value {
                value.to_owned()
            } else {
                index += 1;
                arguments
                    .get(index)
                    .cloned()
                    .ok_or_else(|| Error::invalid("Config::parse_args"))?
            };
            let value = if normalized == "id" {
                "entity".clone_into(&mut normalized);
                format!("client.{value}")
            } else {
                value
            };
            key_seen |= normalized == "key";
            keyring_seen |= normalized == "keyring";
            config = config.with_option_internal(&normalized, &value, false)?;
            index += 1;
        }
        if keyring_seen && !key_seen {
            config.load_configured_keyring()?;
        }
        Ok((config, remainder))
    }

    /// Applies only process variables under the explicitly selected prefix.
    ///
    /// An empty prefix selects `GO_LIBRADOS`. No other API reads the process
    /// environment.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for an invalid option or keyring.
    pub fn parse_env(self, prefix: &str) -> Result<Self> {
        self.parse_env_from(prefix, |name| env::var(name).ok())
    }

    /// Replaces monitor endpoints with an owned bounded copy.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for an empty list, too many endpoints,
    /// or an empty/oversized endpoint.
    pub fn with_monitors<I, S>(mut self, monitors: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let monitors = monitors.into_iter().map(Into::into).collect::<Vec<_>>();
        if monitors.is_empty()
            || monitors.len() > MAX_MONITORS
            || monitors
                .iter()
                .any(|monitor| monitor.is_empty() || monitor.len() > MAX_MONITOR_BYTES)
        {
            return Err(Error::invalid("Config::with_monitors"));
        }
        self.monitors = monitors;
        Ok(self)
    }

    /// Sets the bounded Ceph entity name.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for an empty or oversized entity.
    pub fn with_entity(mut self, entity: impl Into<String>) -> Result<Self> {
        let entity = entity.into();
        if entity.is_empty() || entity.len() > MAX_ENTITY_BYTES {
            return Err(Error::invalid("Config::with_entity"));
        }
        self.entity = entity;
        Ok(self)
    }

    /// Sets an optional cluster FSID pin.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error unless the value is a canonical UUID.
    pub fn with_cluster_fsid(mut self, fsid: impl Into<String>) -> Result<Self> {
        let fsid = fsid.into();
        if !valid_fsid(&fsid) {
            return Err(Error::invalid("Config::with_cluster_fsid"));
        }
        self.cluster_fsid = Some(fsid);
        Ok(self)
    }

    /// Sets copied authentication key bytes.
    #[must_use]
    pub fn with_key(mut self, key: SecretKey) -> Self {
        self.key = Some(key);
        self
    }

    /// Sets the messenger security policy.
    #[must_use]
    pub const fn with_security_mode(mut self, mode: SecurityMode) -> Self {
        self.security_mode = mode;
        self
    }

    /// Sets finite nonzero dial, handshake, and operation defaults.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when a duration exceeds the Go
    /// signed 64-bit nanosecond range used by configuration overlays.
    pub fn with_timeouts(
        mut self,
        dial: Duration,
        handshake: Duration,
        operation: Duration,
    ) -> Result<Self> {
        if [dial, handshake, operation]
            .iter()
            .any(|duration| duration.as_nanos() > MAX_GO_DURATION_NANOS)
        {
            return Err(Error::invalid("Config::with_timeouts"));
        }
        self.dial_timeout = if dial.is_zero() {
            Duration::from_secs(10)
        } else {
            dial
        };
        self.handshake_timeout = if handshake.is_zero() {
            Duration::from_secs(15)
        } else {
            handshake
        };
        self.operation_timeout = if operation.is_zero() {
            Duration::from_secs(30)
        } else {
            operation
        };
        Ok(self)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.monitors.is_empty() {
            return Err(Error::invalid("Client::new"));
        }
        Ok(())
    }

    /// Returns the monitor endpoints.
    #[must_use]
    pub fn monitors(&self) -> &[String] {
        &self.monitors
    }

    /// Returns the configured cluster name.
    #[must_use]
    pub fn cluster(&self) -> &str {
        &self.cluster
    }

    /// Returns the configured entity name.
    #[must_use]
    pub fn entity(&self) -> &str {
        &self.entity
    }

    /// Returns the optional cluster FSID pin.
    #[must_use]
    pub fn cluster_fsid(&self) -> Option<&str> {
        self.cluster_fsid.as_deref()
    }

    /// Returns the messenger security policy.
    #[must_use]
    pub const fn security_mode(&self) -> SecurityMode {
        self.security_mode
    }

    /// Returns the optional redacted authentication key wrapper.
    #[must_use]
    pub const fn key(&self) -> Option<&SecretKey> {
        self.key.as_ref()
    }

    /// Returns the finite dial timeout.
    #[must_use]
    pub const fn dial_timeout(&self) -> Duration {
        self.dial_timeout
    }

    /// Returns the finite handshake timeout.
    #[must_use]
    pub const fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    /// Returns the finite operation timeout.
    #[must_use]
    pub const fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }

    fn parse_env_from<F>(self, prefix: &str, mut lookup: F) -> Result<Self>
    where
        F: FnMut(&str) -> Option<String>,
    {
        let prefix = prefix.trim().strip_suffix('_').unwrap_or(prefix.trim());
        let prefix = if prefix.is_empty() {
            "GO_LIBRADOS"
        } else {
            prefix
        };
        let mut config = self;
        let mut credential_option = None;
        for &(suffix, option) in ENV_OPTIONS {
            let name = format!("{prefix}_{suffix}");
            let Some(value) = lookup(&name) else {
                continue;
            };
            if matches!(option, "key" | "keyring") {
                credential_option = Some(option);
            }
            config = config.with_option_internal(option, &value, false)?;
        }
        if credential_option == Some("keyring") {
            config.load_configured_keyring()?;
        }
        Ok(config)
    }

    fn apply_section(&mut self, section: Option<&BTreeMap<String, String>>) -> Result<()> {
        let Some(section) = section else {
            return Ok(());
        };
        if section.contains_key("include") || section.contains_key("include_dir") {
            return Err(Error::invalid("Config::parse"));
        }
        for &name in FILE_OPTIONS {
            if let Some(value) = section.get(name) {
                *self = self.clone().with_option_internal(name, value, false)?;
            }
        }
        Ok(())
    }

    fn with_option_internal(mut self, name: &str, value: &str, load_keyring: bool) -> Result<Self> {
        let name = normalize_option_name(name);
        if name.is_empty() {
            return Err(Error::invalid("Config::with_option"));
        }
        let value = value.trim();
        match name.as_str() {
            "cluster" => {
                if !valid_simple_name(value) {
                    return Err(Error::invalid("Config::with_option"));
                }
                value.clone_into(&mut self.cluster);
            }
            "entity" | "name" => {
                if value.len() > MAX_ENTITY_BYTES || !valid_client_entity(value) {
                    return Err(Error::invalid("Config::with_option"));
                }
                value.clone_into(&mut self.entity);
            }
            "mon_host" => self.monitors = parse_monitor_seeds(value)?,
            "fsid" => {
                if !valid_fsid(value) {
                    return Err(Error::invalid("Config::with_option"));
                }
                self.cluster_fsid = Some(value.to_owned());
            }
            "key" => {
                parse_key(&self.entity, value, MAX_KEY_BYTES)
                    .map_err(|_| Error::invalid("Config::with_option"))?;
                self.key = Some(SecretKey::new(value.as_bytes())?);
            }
            "keyring" => {
                if value.is_empty() || value.contains(['\0', '\r', '\n']) {
                    return Err(Error::invalid("Config::with_option"));
                }
                self.keyring = Some(value.to_owned());
                if load_keyring {
                    self.load_configured_keyring()?;
                }
            }
            "ms_mode" => {
                self.security_mode = match value.to_ascii_lowercase().as_str() {
                    "secure" => SecurityMode::Secure,
                    "crc" => SecurityMode::Crc,
                    _ => return Err(Error::invalid("Config::with_option")),
                };
            }
            "dial_timeout" => self.dial_timeout = parse_duration(value)?,
            "handshake_timeout" => self.handshake_timeout = parse_duration(value)?,
            "operation_timeout" => self.operation_timeout = parse_duration(value)?,
            _ => {
                if !self.options.contains_key(&name) && self.options.len() >= MAX_CONFIG_OPTIONS {
                    return Err(Error::invalid("Config::with_option"));
                }
                self.options.insert(name, value.to_owned());
            }
        }
        Ok(self)
    }

    fn load_configured_keyring(&mut self) -> Result<()> {
        let path = self
            .keyring
            .as_deref()
            .ok_or_else(|| Error::invalid("Config::load_keyring"))?
            .replace("$cluster", &self.cluster)
            .replace("$name", &self.entity);
        self.key = Some(Self::load_keyring(path, &self.entity)?);
        Ok(())
    }
}

fn parse_sections(data: &[u8]) -> Result<BTreeMap<String, BTreeMap<String, String>>> {
    if data.len() > MAX_CONFIG_BYTES {
        return Err(Error::invalid("Config::parse"));
    }
    let text = std::str::from_utf8(data).map_err(|_| Error::invalid("Config::parse"))?;
    let mut sections = BTreeMap::from([("global".to_owned(), BTreeMap::new())]);
    let mut section = "global".to_owned();
    let mut option_count = 0usize;
    for raw_line in text.lines() {
        let line = strip_hash_comment(raw_line.trim());
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            let line = strip_comment(line);
            if !line.ends_with(']')
                || line.matches('[').count() != 1
                || line.matches(']').count() != 1
            {
                return Err(Error::invalid("Config::parse"));
            }
            line[1..line.len() - 1].trim().clone_into(&mut section);
            if section.is_empty() {
                return Err(Error::invalid("Config::parse"));
            }
            sections.entry(section.clone()).or_default();
            continue;
        }
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| Error::invalid("Config::parse"))?;
        let name = normalize_option_name(name);
        if name.is_empty() {
            return Err(Error::invalid("Config::parse"));
        }
        if matches!(name.as_str(), "include" | "include_dir") {
            return Err(Error::invalid("Config::parse"));
        }
        let value = if name == "mon_host" {
            value.trim()
        } else {
            strip_comment(value.trim())
        };
        option_count = option_count
            .checked_add(1)
            .ok_or_else(|| Error::invalid("Config::parse"))?;
        if option_count > MAX_CONFIG_OPTIONS {
            return Err(Error::invalid("Config::parse"));
        }
        sections
            .entry(section.clone())
            .or_default()
            .insert(name, unquote(value).to_owned());
    }
    Ok(sections)
}

fn read_bounded_file(path: &Path, limit: usize, operation: &'static str) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|_| Error::invalid(operation))?;
    let mut data = Vec::new();
    file.take((limit as u64) + 1)
        .read_to_end(&mut data)
        .map_err(|_| Error::invalid(operation))?;
    if data.len() > limit {
        return Err(Error::invalid(operation));
    }
    Ok(data)
}

fn encoded_key_from_keyring(data: &[u8], entity: &str) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    let mut section = "";
    for raw_line in text.lines() {
        let line = strip_comment(raw_line.trim());
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim();
            continue;
        }
        if section != entity {
            continue;
        }
        let (name, value) = line.split_once('=')?;
        if name.trim() == "key" {
            return Some(unquote(value.trim()).to_owned());
        }
    }
    None
}

fn strip_comment(line: &str) -> &str {
    let mut quote = None;
    for (index, character) in line.char_indices() {
        match character {
            '\'' | '"' if quote.is_none() => quote = Some(character),
            '\'' | '"' if quote == Some(character) => quote = None,
            '#' if quote.is_none() => return line[..index].trim(),
            ';' if quote.is_none()
                && (index == 0
                    || line[..index]
                        .chars()
                        .next_back()
                        .is_some_and(char::is_whitespace)) =>
            {
                return line[..index].trim();
            }
            _ => {}
        }
    }
    line
}

fn strip_hash_comment(line: &str) -> &str {
    let mut quote = None;
    for (index, character) in line.char_indices() {
        match character {
            '\'' | '"' if quote.is_none() => quote = Some(character),
            '\'' | '"' if quote == Some(character) => quote = None,
            '#' if quote.is_none() => return line[..index].trim(),
            _ => {}
        }
    }
    line
}

fn unquote(value: &str) -> &str {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if matches!(
            (bytes[0], bytes[value.len() - 1]),
            (b'\'', b'\'') | (b'"', b'"')
        ) {
            return &value[1..value.len() - 1];
        }
    }
    value
}

fn normalize_option_name(name: &str) -> String {
    name.trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("_")
}

fn is_argument_option(name: &str) -> bool {
    matches!(
        name,
        "name"
            | "id"
            | "cluster"
            | "mon_host"
            | "fsid"
            | "key"
            | "keyring"
            | "ms_mode"
            | "dial_timeout"
            | "handshake_timeout"
            | "operation_timeout"
    )
}

fn valid_simple_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ENTITY_BYTES
        && !value
            .bytes()
            .any(|byte| matches!(byte, b'[' | b']' | b'/' | b'\\' | b'\0' | b'\r' | b'\n'))
}

fn valid_client_entity(value: &str) -> bool {
    value.strip_prefix("client.").is_some_and(|id| {
        !id.is_empty()
            && !id
                .bytes()
                .any(|byte| matches!(byte, b'[' | b']' | b'\0' | b'\r' | b'\n'))
    })
}

fn parse_monitor_seeds(value: &str) -> Result<Vec<String>> {
    if value.contains(['\0', '\r', '\n']) {
        return Err(Error::invalid("Config::parse"));
    }
    let value = value.trim();
    let value = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(value);
    let monitors = value
        .split(|character: char| character == ',' || character == ';' || character.is_whitespace())
        .map(|monitor| monitor.trim_matches(['[', ']']))
        .filter(|monitor| !monitor.is_empty() && !monitor.starts_with("v1:"))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if monitors.is_empty()
        || monitors.len() > MAX_MONITORS
        || monitors
            .iter()
            .any(|monitor| monitor.len() > MAX_MONITOR_BYTES)
    {
        return Err(Error::invalid("Config::parse"));
    }
    Ok(monitors)
}

fn parse_duration(value: &str) -> Result<Duration> {
    let value = value.strip_prefix('+').unwrap_or(value);
    if value.is_empty() {
        return Err(Error::invalid("Config::with_option"));
    }
    let mut remaining = value;
    let mut total_nanos = 0u128;
    while !remaining.is_empty() {
        let number_end = remaining
            .char_indices()
            .find_map(|(index, character)| {
                (!character.is_ascii_digit() && character != '.').then_some(index)
            })
            .ok_or_else(|| Error::invalid("Config::with_option"))?;
        let number = &remaining[..number_end];
        remaining = &remaining[number_end..];
        let unit_end = remaining
            .char_indices()
            .find_map(|(index, character)| {
                (character.is_ascii_digit() || character == '.').then_some(index)
            })
            .unwrap_or(remaining.len());
        let unit = &remaining[..unit_end];
        remaining = &remaining[unit_end..];
        let multiplier = match unit {
            "ns" => 1u128,
            "us" | "µs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60 * 1_000_000_000,
            "h" => 60 * 60 * 1_000_000_000,
            _ => return Err(Error::invalid("Config::with_option")),
        };
        let segment = parse_duration_number(number, multiplier)?;
        total_nanos = total_nanos
            .checked_add(segment)
            .filter(|total| *total <= MAX_GO_DURATION_NANOS)
            .ok_or_else(|| Error::invalid("Config::with_option"))?;
    }
    if total_nanos == 0 {
        return Err(Error::invalid("Config::with_option"));
    }
    let seconds = u64::try_from(total_nanos / 1_000_000_000)
        .map_err(|_| Error::invalid("Config::with_option"))?;
    let nanos = u32::try_from(total_nanos % 1_000_000_000)
        .map_err(|_| Error::invalid("Config::with_option"))?;
    Ok(Duration::new(seconds, nanos))
}

fn parse_duration_number(number: &str, multiplier: u128) -> Result<u128> {
    let (integer, fraction) = number
        .split_once('.')
        .map_or((number, None), |(integer, fraction)| {
            (integer, Some(fraction))
        });
    if integer.is_empty() && fraction.is_none_or(str::is_empty) {
        return Err(Error::invalid("Config::with_option"));
    }
    if !integer.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.is_some_and(|digits| !digits.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(Error::invalid("Config::with_option"));
    }
    let integer = if integer.is_empty() {
        0
    } else {
        integer
            .parse::<u128>()
            .map_err(|_| Error::invalid("Config::with_option"))?
    };
    let mut result = integer
        .checked_mul(multiplier)
        .ok_or_else(|| Error::invalid("Config::with_option"))?;
    if let Some(fraction) = fraction.filter(|digits| !digits.is_empty()) {
        let mut scale = 1u128;
        let mut numerator = 0u128;
        for byte in fraction.bytes().take(19) {
            scale = scale
                .checked_mul(10)
                .ok_or_else(|| Error::invalid("Config::with_option"))?;
            numerator = numerator
                .checked_mul(10)
                .and_then(|value| value.checked_add(u128::from(byte - b'0')))
                .ok_or_else(|| Error::invalid("Config::with_option"))?;
        }
        result = result
            .checked_add(
                numerator
                    .checked_mul(multiplier)
                    .ok_or_else(|| Error::invalid("Config::with_option"))?
                    / scale,
            )
            .ok_or_else(|| Error::invalid("Config::with_option"))?;
    }
    Ok(result)
}

fn format_duration(duration: Duration) -> String {
    let nanos = duration.as_nanos();
    if nanos < 1_000 {
        return format!("{nanos}ns");
    }
    if nanos < 1_000_000 {
        return format_decimal_duration(nanos, 1_000, "µs");
    }
    if nanos < 1_000_000_000 {
        return format_decimal_duration(nanos, 1_000_000, "ms");
    }
    let hours = nanos / 3_600_000_000_000;
    let after_hours = nanos % 3_600_000_000_000;
    let minutes = after_hours / 60_000_000_000;
    let seconds_nanos = after_hours % 60_000_000_000;
    let seconds = format_decimal_duration(seconds_nanos, 1_000_000_000, "s");
    if hours != 0 {
        format!("{hours}h{minutes}m{seconds}")
    } else if minutes != 0 {
        format!("{minutes}m{seconds}")
    } else {
        seconds
    }
}

fn format_decimal_duration(value: u128, unit: u128, suffix: &str) -> String {
    let whole = value / unit;
    let fraction = value % unit;
    if fraction == 0 {
        return format!("{whole}{suffix}");
    }
    let width = unit.ilog10() as usize;
    let fraction = format!("{fraction:0width$}");
    format!("{whole}.{}{suffix}", fraction.trim_end_matches('0'))
}

fn valid_fsid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    const TEST_KEY: &str = "AQB7AAAAyAEAABAAMTIzNDU2Nzg5MDEyMzQ1Ng==";
    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time after Unix epoch")
                .as_nanos();
            let path = env::temp_dir().join(format!(
                "rados-rs-config-{}-{timestamp}-{sequence}",
                std::process::id(),
            ));
            fs::create_dir(&path).expect("create temp directory");
            Self(path)
        }

        fn join(&self, path: impl AsRef<Path>) -> std::path::PathBuf {
            self.0.join(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn defaults_are_finite_and_zero_selects_defaults() {
        let config = Config::default()
            .with_timeouts(Duration::ZERO, Duration::ZERO, Duration::ZERO)
            .expect("zero selects defaults");
        assert_eq!(config.entity(), "client.admin");
        assert_eq!(config.option("cluster").as_deref(), Some("ceph"));
        assert_eq!(config.security_mode(), SecurityMode::Secure);
        assert_eq!(config.dial_timeout(), Duration::from_secs(10));
        assert_eq!(config.handshake_timeout(), Duration::from_secs(15));
        assert_eq!(config.operation_timeout(), Duration::from_secs(30));
        assert!(
            Config::default()
                .with_timeouts(
                    Duration::from_nanos(u64::try_from(MAX_GO_DURATION_NANOS + 1).unwrap()),
                    Duration::ZERO,
                    Duration::ZERO,
                )
                .is_err()
        );
    }

    #[test]
    fn key_debug_is_redacted_and_inputs_are_copied() {
        let mut source = b"secret".to_vec();
        let key = SecretKey::new(&source).expect("key");
        source.fill(b'x');
        assert_eq!(key.expose(), b"secret");
        assert_eq!(format!("{key:?}"), "SecretKey([REDACTED])");
        assert!(!format!("{:?}", Config::default().with_key(key)).contains("secret"));
    }

    #[test]
    fn parse_selects_entity_applies_known_options_and_ignores_unknowns() {
        let config = Config::parse(
            b"[global]\ncluster = test\nname = client.test\nmon host = v2:192.0.2.1:3300/0 # preferred\nms mode = crc\ndial timeout = 3s\nunknown = ignored\n[client.other]\nmon_host = 192.0.2.9\n[client.test]\nmon_host = 192.0.2.2:3300\noperation_timeout = 9s\n",
        )
        .expect("supported config");

        assert_eq!(config.cluster(), "test");
        assert_eq!(config.entity(), "client.test");
        assert_eq!(config.monitors(), ["192.0.2.2:3300"]);
        assert_eq!(config.security_mode(), SecurityMode::Crc);
        assert_eq!(config.dial_timeout(), Duration::from_secs(3));
        assert_eq!(config.operation_timeout(), Duration::from_secs(9));
        assert_eq!(config.option("unknown"), None);

        let config = Config::parse(b"[global]\nmon_host = 192.0.2.1 ; 192.0.2.2\n")
            .expect("semicolon monitor list");
        assert_eq!(config.monitors(), ["192.0.2.1", "192.0.2.2"]);
    }

    #[test]
    fn parse_rejects_malformed_known_values_includes_and_bounds() {
        for data in [
            "[global\nmon_host=a",
            "[global]\nms_mode = plaintext\n",
            "[global]\nfsid = no\n",
            "[global]\ndial_timeout = forever\n",
            "[global]\ninclude = /etc/ceph/other.conf\n",
            "[global]\ninclude_dir = /etc/ceph/conf.d\n",
            "[client.other]\ninclude = /etc/ceph/other.conf\n",
        ] {
            let error = Config::parse(data.as_bytes()).expect_err("invalid config");
            assert_eq!(error.kind(), ErrorKind::InvalidArgument);
        }
        assert_eq!(
            Config::parse(&vec![b'x'; MAX_CONFIG_BYTES + 1])
                .expect_err("oversized config")
                .kind(),
            ErrorKind::InvalidArgument
        );
        let excessive = "option=value\n".repeat(MAX_CONFIG_OPTIONS + 1);
        assert!(Config::parse(excessive.as_bytes()).is_err());
    }

    #[test]
    fn with_option_is_immutable_and_retains_unknown_options() {
        let base = Config::default()
            .with_monitors(["192.0.2.1"])
            .expect("base monitors");
        let configured = base
            .clone()
            .with_option("mon-host", "192.0.2.2,192.0.2.3")
            .expect("monitor option")
            .with_option("future_option", "enabled")
            .expect("unknown option");
        assert_eq!(base.monitors(), ["192.0.2.1"]);
        assert_eq!(configured.monitors(), ["192.0.2.2", "192.0.2.3"]);
        assert_eq!(
            configured.option("future-option").as_deref(),
            Some("enabled")
        );
        let second = configured
            .clone()
            .with_option("another", "value")
            .expect("second unknown option");
        assert_eq!(configured.option("another"), None);
        assert_eq!(second.option("another").as_deref(), Some("value"));
    }

    #[test]
    fn parse_args_applies_options_and_preserves_remainder() {
        let (config, remainder) = Config::default()
            .parse_args([
                "input",
                "--unknown",
                "value",
                "--id=test",
                "--mon-host",
                "192.0.2.1:3300",
                "--operation-timeout=4s",
                "--",
                "--cluster=ignored",
            ])
            .expect("arguments");
        assert_eq!(config.entity(), "client.test");
        assert_eq!(config.operation_timeout(), Duration::from_secs(4));
        assert_eq!(config.monitors(), ["192.0.2.1:3300"]);
        assert_eq!(
            remainder,
            ["input", "--unknown", "value", "--", "--cluster=ignored"]
        );
        assert!(Config::default().parse_args(["--cluster"]).is_err());
    }

    #[test]
    fn parse_env_uses_only_the_explicit_prefix_without_mutating_process_env() {
        let values = BTreeMap::from([
            ("GO_LIBRADOS_ENTITY", "client.default"),
            ("CUSTOM_ENTITY", "client.custom"),
            ("CUSTOM_MON_HOST", "192.0.2.4"),
            ("CUSTOM_HANDSHAKE_TIMEOUT", "7s"),
        ]);
        let config = Config::default()
            .parse_env_from("CUSTOM", |name| values.get(name).map(ToString::to_string))
            .expect("environment overlay");
        assert_eq!(config.entity(), "client.custom");
        assert_eq!(config.handshake_timeout(), Duration::from_secs(7));
        assert_eq!(config.monitors(), ["192.0.2.4"]);
    }

    #[test]
    fn load_expands_keyring_and_direct_key_takes_precedence() {
        let directory = TempDir::new();
        let keyring_directory = directory.join("test");
        fs::create_dir(&keyring_directory).expect("keyring directory");
        let keyring_path = keyring_directory.join("client.test.keyring");
        fs::write(
            &keyring_path,
            format!("[client.test]\n key = '{TEST_KEY}' ; generated\n"),
        )
        .expect("write keyring");
        let config_path = directory.join("ceph.conf");
        fs::write(
            &config_path,
            format!(
                "[global]\ncluster = test\nentity = client.test\nmon_host = 192.0.2.1\nkeyring = {}/$cluster/$name.keyring\n",
                directory.0.display()
            ),
        )
        .expect("write config");
        let config = Config::load(&config_path).expect("load config");
        assert_eq!(
            config.key().expect("loaded key").expose(),
            TEST_KEY.as_bytes()
        );

        fs::remove_file(&keyring_path).expect("remove keyring");
        fs::write(
            &config_path,
            format!(
                "[global]\nentity = client.test\nkey = {TEST_KEY}\nkeyring = {}\n",
                keyring_path.display()
            ),
        )
        .expect("write direct-key config");
        assert_eq!(
            Config::load(config_path)
                .expect("direct key avoids keyring")
                .key()
                .expect("direct key")
                .expose(),
            TEST_KEY.as_bytes()
        );
    }

    #[test]
    fn explicit_keyring_loads_after_argument_entity_and_key_wins() {
        let directory = TempDir::new();
        let path = directory.join("client.test.keyring");
        fs::write(&path, format!("[client.test]\nkey = {TEST_KEY}\n")).expect("write keyring");
        let keyring_pattern = directory.join("$name.keyring");
        let (config, remainder) = Config::default()
            .parse_args([
                "--keyring".to_owned(),
                keyring_pattern.to_string_lossy().into_owned(),
                "--name".to_owned(),
                "client.test".to_owned(),
            ])
            .expect("deferred keyring");
        assert!(remainder.is_empty());
        assert_eq!(config.key().expect("key").expose(), TEST_KEY.as_bytes());

        let missing = directory.join("missing.keyring");
        let (config, _) = Config::default()
            .parse_args([
                "--keyring".to_owned(),
                missing.to_string_lossy().into_owned(),
                format!("--key={TEST_KEY}"),
            ])
            .expect("direct key wins");
        assert_eq!(config.key().expect("key").expose(), TEST_KEY.as_bytes());
    }

    #[test]
    fn with_option_keyring_loads_canonical_key() {
        let directory = TempDir::new();
        let path = directory.join("client.test.keyring");
        fs::write(&path, format!("[client.test]\nkey = {TEST_KEY}\n")).expect("write keyring");
        let configured = Config::default()
            .with_option("name", "client.test")
            .expect("entity")
            .with_option("keyring", &path.to_string_lossy())
            .expect("keyring");
        assert_eq!(configured.key().expect("key").expose(), TEST_KEY.as_bytes());
        assert!(Config::default().with_option("key", "not-base64").is_err());
    }

    #[test]
    fn load_and_keyring_are_bounded() {
        let directory = TempDir::new();
        let path = directory.join("oversized");
        fs::write(&path, vec![b'x'; MAX_CONFIG_BYTES + 1]).expect("write oversized file");
        assert_eq!(
            Config::load(&path).expect_err("bounded config").kind(),
            ErrorKind::InvalidArgument
        );
        assert_eq!(
            Config::load_keyring(path, "client.test")
                .expect_err("bounded keyring")
                .kind(),
            ErrorKind::InvalidArgument
        );
    }

    #[test]
    fn durations_match_positive_go_syntax_without_overflow() {
        for (value, expected) in [
            ("1ns", Duration::from_nanos(1)),
            ("2us", Duration::from_micros(2)),
            ("3µs", Duration::from_micros(3)),
            ("1.5ms", Duration::from_micros(1_500)),
            ("1h2m3.004005006s", Duration::new(3_723, 4_005_006)),
            (
                "1.0000000000000000000000000000000000000000s",
                Duration::from_secs(1),
            ),
            (".5s", Duration::from_millis(500)),
            ("1.s", Duration::from_secs(1)),
        ] {
            assert_eq!(parse_duration(value).expect(value), expected);
            assert_eq!(
                parse_duration(&format_duration(expected)).expect(value),
                expected
            );
        }
        for value in [
            "0s",
            "-1s",
            "NaNs",
            "infs",
            "1",
            "1ss",
            "1..2s",
            "9223372036854775808ns",
            "999999999999999999999999999999999999999999999999999h",
        ] {
            assert!(parse_duration(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn monitor_vectors_ignore_v1_entries() {
        let config = Config::default()
            .with_option(
                "mon_host",
                "[v2:192.0.2.1:3300/0,v1:192.0.2.1:6789/0] v1:192.0.2.2:6789/0 host",
            )
            .expect("mixed monitor vector");
        assert_eq!(config.monitors(), ["v2:192.0.2.1:3300/0", "host"]);
        assert!(
            Config::default()
                .with_option("mon_host", "v1:host:6789")
                .is_err()
        );
    }

    #[test]
    fn programmatic_option_count_is_bounded() {
        let mut config = Config::default();
        for index in 0..MAX_CONFIG_OPTIONS {
            config = config
                .with_option(&format!("future_{index}"), "value")
                .expect("within option bound");
        }
        assert!(config.clone().with_option("one_more", "value").is_err());
        assert!(config.with_option("future_0", "updated").is_ok());
    }
}
