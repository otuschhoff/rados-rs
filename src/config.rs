use crate::{Error, Result};
use std::fmt;
use std::time::Duration;
use zeroize::Zeroizing;

const MAX_MONITORS: usize = 64;
const MAX_MONITOR_BYTES: usize = 1_024;
const MAX_ENTITY_BYTES: usize = 256;
const MAX_KEY_BYTES: usize = 65_536;

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
    monitors: Vec<String>,
    entity: String,
    cluster_fsid: Option<String>,
    key: Option<SecretKey>,
    security_mode: SecurityMode,
    dial_timeout: Duration,
    handshake_timeout: Duration,
    operation_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            monitors: Vec::new(),
            entity: "client.admin".to_owned(),
            cluster_fsid: None,
            key: None,
            security_mode: SecurityMode::Secure,
            dial_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(15),
            operation_timeout: Duration::from_secs(30),
        }
    }
}

impl Config {
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
    /// This bounded Rust duration API currently has no error case; the result
    /// reserves validation compatibility for future configuration overlays.
    pub fn with_timeouts(
        mut self,
        dial: Duration,
        handshake: Duration,
        operation: Duration,
    ) -> Result<Self> {
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

    #[test]
    fn defaults_are_finite_and_zero_selects_defaults() {
        let config = Config::default()
            .with_timeouts(Duration::ZERO, Duration::ZERO, Duration::ZERO)
            .expect("zero selects defaults");
        assert_eq!(config.entity(), "client.admin");
        assert_eq!(config.security_mode(), SecurityMode::Secure);
        assert_eq!(config.dial_timeout(), Duration::from_secs(10));
        assert_eq!(config.handshake_timeout(), Duration::from_secs(15));
        assert_eq!(config.operation_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn key_debug_is_redacted_and_inputs_are_copied() {
        let mut source = b"secret".to_vec();
        let key = SecretKey::new(&source).expect("key");
        source.fill(b'x');
        assert_eq!(key.expose(), b"secret");
        assert_eq!(format!("{key:?}"), "SecretKey([REDACTED])");
    }
}
