use std::env;
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::net::TcpStream;

use crate::cephx::connector::{AuthMetadata, ConnectorError, MonitorConnector, TicketMetadata};
use crate::cephx::core::{CONNECTION_MODE_SECURE, SERVICE_AUTH, SERVICE_MONITOR, TicketBlob};
use crate::cephx::crypto::Limits as CephxLimits;
use crate::cephx::parse_keyring;
use crate::msgr::control::ClientIdent;
use crate::msgr::frame::Limits;
use crate::msgr::session::{Config as SessionConfig, Event, Machine, ReconnectPolicy, State};
use crate::msgr::supervisor::{ConnectFuture, Connector, Session};
use crate::protocol::address::{EntityAddr, EntityAddrVec};
use crate::protocol::features::GlobalFeatures;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_KEYRING_BYTES: usize = 1 << 20;
const MESSAGE_LIMITS: Limits = Limits {
    max_segment_bytes: 8 << 20,
    max_frame_bytes: 32 << 20,
    max_addresses: 64,
    max_auth_bytes: 1 << 20,
};
const CEPHX_LIMITS: CephxLimits = CephxLimits {
    max_auth_bytes: 1 << 20,
    max_ticket_blob_bytes: 1 << 20,
    max_decrypt_bytes: 1 << 20,
    max_encrypt_bytes: 1 << 20,
    max_connection_secret_bytes: 64,
    max_tickets: 64,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct Arguments {
    monitor: SocketAddr,
    client_address: SocketAddr,
    entity: String,
    keyring: String,
    timeout: Duration,
    exercise_lifecycle: bool,
}

#[derive(Debug)]
pub struct LiveProbeError(String);

impl fmt::Display for LiveProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for LiveProbeError {}

#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProbeReport {
    authenticated_mode: &'static str,
    global_id: u64,
    reconnected: bool,
    ticket_renewed: bool,
    initial_ticket_sha256: String,
    renewed_ticket_sha256: String,
    expiry_rejected: bool,
    expired_reconnect: bool,
    renewed_global_id: u64,
    post_expiry_global_id: u64,
    server_global_id: i64,
    server_addresses: Vec<String>,
    server_features: u64,
    server_cookie: u64,
}

pub fn run_cli() -> Result<(), LiveProbeError> {
    let arguments = parse_arguments(env::args().skip(1))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| safe_error("could not start async runtime"))?;
    let report = runtime.block_on(async {
        tokio::time::timeout(arguments.timeout, run_probe(&arguments))
            .await
            .map_err(|_| safe_error("probe timeout"))?
    })?;
    println!(
        "{}",
        serde_json::to_string(&report).map_err(|_| safe_error("could not encode report"))?
    );
    Ok(())
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = String>,
) -> Result<Arguments, LiveProbeError> {
    let mut monitor = None;
    let mut client_address = None;
    let mut entity = "client.r04".to_owned();
    let mut keyring = None;
    let mut timeout = DEFAULT_TIMEOUT;
    let mut exercise_lifecycle = false;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--monitor" => monitor = Some(parse_ipv4(&next_value(&mut arguments, "--monitor")?)?),
            "--client-address" => {
                client_address = Some(parse_ipv4(&next_value(
                    &mut arguments,
                    "--client-address",
                )?)?);
            }
            "--entity" => entity = next_value(&mut arguments, "--entity")?,
            "--keyring" => keyring = Some(next_value(&mut arguments, "--keyring")?),
            "--timeout-seconds" => {
                let value = next_value(&mut arguments, "--timeout-seconds")?;
                let seconds = value.parse::<u64>().map_err(|_| usage_error())?;
                if seconds == 0 {
                    return Err(usage_error());
                }
                timeout = Duration::from_secs(seconds);
            }
            "--exercise-lifecycle" => exercise_lifecycle = true,
            _ => return Err(usage_error()),
        }
    }
    Ok(Arguments {
        monitor: monitor.ok_or_else(usage_error)?,
        client_address: client_address.ok_or_else(usage_error)?,
        entity,
        keyring: keyring.ok_or_else(usage_error)?,
        timeout,
        exercise_lifecycle,
    })
}

fn next_value(
    arguments: &mut impl Iterator<Item = String>,
    _option: &str,
) -> Result<String, LiveProbeError> {
    arguments.next().ok_or_else(usage_error)
}

fn parse_ipv4(value: &str) -> Result<SocketAddr, LiveProbeError> {
    let endpoint = value.parse::<SocketAddr>().map_err(|_| usage_error())?;
    if !endpoint.is_ipv4() {
        return Err(usage_error());
    }
    Ok(endpoint)
}

fn usage_error() -> LiveProbeError {
    safe_error(
        "usage: rados-r04-live --monitor IPV4:PORT --client-address IPV4:PORT --keyring PATH [--entity client.NAME] [--timeout-seconds N] [--exercise-lifecycle]",
    )
}

#[allow(clippy::too_many_lines)]
async fn run_probe(arguments: &Arguments) -> Result<ProbeReport, LiveProbeError> {
    let keyring = fs::read(&arguments.keyring).map_err(|_| safe_error("could not read keyring"))?;
    let credential = parse_keyring(&keyring, &arguments.entity, MAX_KEYRING_BYTES)
        .map_err(|_| safe_error("invalid keyring or entity"))?;
    let monitor_address = EntityAddr::ipv4_v2(arguments.monitor)
        .map_err(|_| safe_error("invalid monitor address"))?;
    let client_address = EntityAddr::ipv4_v2(arguments.client_address)
        .map_err(|_| safe_error("invalid client address"))?;
    let connector = Arc::new(
        MonitorConnector::new(crate::cephx::connector::Config {
            credential,
            target_address: monitor_address.clone(),
            message_limits: MESSAGE_LIMITS,
            cephx_limits: CEPHX_LIMITS,
            handshake_timeout: arguments.timeout,
            max_banner_payload: 64,
            requested_keys: SERVICE_AUTH | SERVICE_MONITOR,
            allow_crc: false,
            global_id: 0,
            old_ticket: TicketBlob {
                secret_id: 0,
                blob: Vec::new(),
            },
            now: Arc::new(unix_now),
            challenge: Arc::new(MonitorConnector::os_challenge),
        })
        .map_err(classify_connector_error)?,
    );

    if !arguments.exercise_lifecycle {
        let stream = TcpStream::connect(arguments.monitor)
            .await
            .map_err(|_| safe_error("monitor connection failed"))?;
        connector
            .connect(stream)
            .await
            .map_err(classify_connector_error)?;
    }

    let (session, first_metadata, mut report) = start_and_identify(
        Arc::clone(&connector),
        arguments.monitor,
        monitor_address.clone(),
        client_address.clone(),
    )
    .await?;
    if !arguments.exercise_lifecycle {
        session.shutdown().await;
        return Ok(report);
    }

    let first_ticket = first_metadata
        .tickets
        .get(&SERVICE_MONITOR)
        .cloned()
        .ok_or_else(|| safe_error("authenticated session has no monitor ticket"))?;
    let second_metadata = wait_for_renewal(&session, &connector, &first_ticket).await?;
    if second_metadata.global_id != first_metadata.global_id {
        session.shutdown().await;
        return Err(safe_error("renewal changed global ID"));
    }
    let second_ticket = second_metadata
        .tickets
        .get(&SERVICE_MONITOR)
        .cloned()
        .ok_or_else(|| safe_error("renewal returned no monitor ticket"))?;
    if same_ticket(&first_ticket, &second_ticket) {
        session.shutdown().await;
        return Err(safe_error("monitor ticket did not rotate"));
    }
    let auth_ticket = second_metadata
        .tickets
        .get(&SERVICE_AUTH)
        .ok_or_else(|| safe_error("renewal returned no auth ticket"))?;
    report.reconnected = true;
    report.ticket_renewed = true;
    report.renewed_global_id = second_metadata.global_id;
    report.initial_ticket_sha256 = hex(&first_ticket.fingerprint);
    report.renewed_ticket_sha256 = hex(&second_ticket.fingerprint);

    let expiry = second_ticket.expires_at.max(auth_ticket.expires_at);
    session.shutdown().await;
    let wait = expiry.saturating_sub(unix_now()) + Duration::from_millis(100);
    tokio::time::sleep(wait).await;
    match connector.service_authorization(SERVICE_MONITOR) {
        Err(ConnectorError::Cephx(crate::cephx::Error::ExpiredTicket)) => {}
        _ => return Err(safe_error("expired monitor ticket was not rejected")),
    }
    report.expiry_rejected = true;

    let (third_session, third_metadata, _) = start_and_identify(
        connector,
        arguments.monitor,
        monitor_address,
        client_address,
    )
    .await?;
    third_session.shutdown().await;
    if third_metadata.global_id == 0 || third_metadata.global_id == second_metadata.global_id {
        return Err(safe_error(
            "post-expiry authentication did not issue a fresh global ID",
        ));
    }
    report.expired_reconnect = true;
    report.post_expiry_global_id = third_metadata.global_id;
    Ok(report)
}

async fn start_and_identify(
    connector: Arc<MonitorConnector>,
    endpoint: SocketAddr,
    monitor_address: EntityAddr,
    client_address: EntityAddr,
) -> Result<(Session, AuthMetadata, ProbeReport), LiveProbeError> {
    let connector_for_connect = Arc::clone(&connector);
    let session_connector: Connector = Arc::new(move || {
        let connector = Arc::clone(&connector_for_connect);
        Box::pin(async move {
            let stream = TcpStream::connect(endpoint)
                .await
                .map_err(|_| crate::msgr::session::SessionError::Disconnected)?;
            connector.connect(stream).await.map_err(Into::into)
        }) as ConnectFuture
    });
    let machine = Machine::new(SessionConfig {
        limits: MESSAGE_LIMITS,
        max_queued_messages: 16,
        max_retained_bytes: 1 << 20,
        max_in_flight_transactions: 16,
        max_reconnect_attempts: 2,
        max_handshake_transitions: 16,
        reconnect_policy: ReconnectPolicy::ReplayPending,
        client_ident: ClientIdent {
            addresses: EntityAddrVec(vec![client_address]),
            target_address: monitor_address,
            global_id: 0,
            global_sequence: 0,
            supported_features: GlobalFeatures::MESSAGE_ADDRESS_V2.0,
            required_features: GlobalFeatures::MESSAGE_ADDRESS_V2.0,
            flags: 0,
            cookie: 0,
        },
        client_cookie: random_nonzero()?,
        server_cookie: 0,
        global_sequence: 0,
        connect_sequence: 0,
        replacement_cookies: vec![random_nonzero()?, random_nonzero()?, random_nonzero()?],
    })
    .map_err(|_| safe_error("invalid session configuration"))?;
    let session = Session::spawn(machine, None, Some(session_connector));
    loop {
        match session.next_event().await {
            Some(Event::StateChanged(State::Ready)) => break,
            Some(Event::TransportFault(_)) if session.terminal().is_some() => {
                session.shutdown().await;
                return Err(safe_error("session handshake failed"));
            }
            Some(_) => {}
            None => return Err(safe_error("session closed during handshake")),
        }
    }
    let snapshot = session
        .snapshot()
        .await
        .map_err(|_| safe_error("could not inspect live session"))?;
    let metadata = connector.metadata();
    if metadata.mode != CONNECTION_MODE_SECURE || metadata.global_id == 0 {
        session.shutdown().await;
        return Err(safe_error(
            "monitor did not establish secure authentication",
        ));
    }
    if snapshot
        .server_addresses
        .0
        .iter()
        .all(|address| address.endpoint() != Some(endpoint))
    {
        session.shutdown().await;
        return Err(safe_error(
            "server identity omitted the target monitor address",
        ));
    }
    let report = ProbeReport {
        authenticated_mode: "secure",
        global_id: metadata.global_id,
        reconnected: false,
        ticket_renewed: false,
        initial_ticket_sha256: String::new(),
        renewed_ticket_sha256: String::new(),
        expiry_rejected: false,
        expired_reconnect: false,
        renewed_global_id: 0,
        post_expiry_global_id: 0,
        server_global_id: snapshot.server_global_id,
        server_addresses: snapshot
            .server_addresses
            .0
            .iter()
            .filter_map(EntityAddr::endpoint)
            .map(|address| address.to_string())
            .collect(),
        server_features: snapshot.server_features,
        server_cookie: snapshot.server_cookie,
    };
    Ok((session, metadata, report))
}

async fn wait_for_renewal(
    session: &Session,
    connector: &MonitorConnector,
    original: &TicketMetadata,
) -> Result<AuthMetadata, LiveProbeError> {
    loop {
        match session.next_event().await {
            Some(Event::CredentialRenewalCompleted | Event::StateChanged(State::Ready)) => {
                let metadata = connector.metadata();
                if metadata
                    .tickets
                    .get(&SERVICE_MONITOR)
                    .is_some_and(|ticket| !same_ticket(original, ticket))
                {
                    return Ok(metadata);
                }
            }
            Some(Event::TransportFault(_)) if session.terminal().is_some() => {
                return Err(safe_error("session renewal failed"));
            }
            Some(_) => {}
            None => return Err(safe_error("session closed during renewal")),
        }
    }
}

fn same_ticket(first: &TicketMetadata, second: &TicketMetadata) -> bool {
    first.secret_id == second.secret_id && first.fingerprint == second.fingerprint
}

fn unix_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}

fn random_nonzero() -> Result<u64, LiveProbeError> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| safe_error("random source unavailable"))?;
    Ok(u64::from_le_bytes(bytes).max(1))
}

fn classify_connector_error(error: ConnectorError) -> LiveProbeError {
    match error {
        ConnectorError::Rejected => safe_error("cephx authentication rejected"),
        ConnectorError::Downgrade => safe_error("cephx auth downgrade rejected"),
        _ => safe_error("cephx monitor connection failed"),
    }
}

fn safe_error(message: &str) -> LiveProbeError {
    LiveProbeError(message.to_owned())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn parses_required_ipv4_arguments() {
        let arguments = parse_arguments(
            [
                "--monitor",
                "172.30.94.10:3300",
                "--client-address",
                "172.30.94.20:0",
                "--keyring",
                "/tmp/client.keyring",
                "--exercise-lifecycle",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .expect("arguments");
        assert_eq!(arguments.monitor.to_string(), "172.30.94.10:3300");
        assert_eq!(arguments.entity, "client.r04");
        assert!(arguments.exercise_lifecycle);
    }

    #[test]
    fn rejects_ipv6_and_zero_timeout() {
        for arguments in [
            vec![
                "--monitor",
                "[::1]:3300",
                "--client-address",
                "127.0.0.1:0",
                "--keyring",
                "x",
            ],
            vec![
                "--monitor",
                "127.0.0.1:3300",
                "--client-address",
                "127.0.0.1:0",
                "--keyring",
                "x",
                "--timeout-seconds",
                "0",
            ],
        ] {
            assert!(parse_arguments(arguments.into_iter().map(str::to_owned)).is_err());
        }
    }

    #[test]
    fn formats_fingerprints_without_exposing_ticket_bytes() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    }

    #[test]
    fn live_gate_scripts_have_valid_posix_shell_syntax() {
        let root = env!("CARGO_MANIFEST_DIR");
        let status = Command::new("sh")
            .arg("-n")
            .arg(format!("{root}/integration/r04/live-reproduce.sh"))
            .arg(format!("{root}/integration/r04/verify-live-report.sh"))
            .status()
            .expect("run sh syntax check");
        assert!(status.success());
    }
}
