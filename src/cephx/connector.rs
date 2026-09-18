use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;

use super::core::{
    Authorizer, CONNECTION_MODE_CRC, CONNECTION_MODE_SECURE, CONNECTION_SECRET_SIZE_SECURE,
    SERVICE_AUTH, ServiceTicket, TicketBlob, add_authorizer_challenge, build_authorizer,
    build_challenge_request, build_initial_payload, parse_auth_session_reply,
    parse_server_challenge, verify_authorizer_reply,
};
use super::crypto::{Limits as CephxLimits, transcript_signature, verify_transcript_signature};
use super::{Credential, CryptoKey, Error as CephxError};
use crate::msgr::banner::Banner;
use crate::msgr::control::{AuthRequest, Control, Hello};
use crate::msgr::frame::{CrcCodec, FrameError, Limits};
use crate::msgr::secure::SecureCodec;
use crate::msgr::session::SessionError;
use crate::msgr::supervisor::ConnectionSetup;
use crate::msgr::transport::{Codec, IoStream};
use crate::protocol::address::EntityAddr;

const AUTH_METHOD_CEPHX: u32 = 2;
const ENTITY_MONITOR: u8 = 1;
const ENTITY_OSD: u8 = 4;
const ENTITY_CLIENT: u8 = 8;
const ENTITY_MANAGER: u8 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConnectorError {
    InvalidConfig,
    Timeout,
    Io,
    Frame(FrameError),
    Cephx(CephxError),
    WrongPeer,
    Rejected,
    Downgrade,
    InvalidGlobalId,
    UnexpectedFlow,
    SignatureMismatch,
}

impl fmt::Display for ConnectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CephX monitor connection failed: {self:?}")
    }
}

impl std::error::Error for ConnectorError {}

impl From<FrameError> for ConnectorError {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}

impl From<CephxError> for ConnectorError {
    fn from(value: CephxError) -> Self {
        Self::Cephx(value)
    }
}

impl From<ConnectorError> for SessionError {
    fn from(value: ConnectorError) -> Self {
        match value {
            ConnectorError::Frame(error) => Self::Frame(error),
            ConnectorError::Downgrade => Self::UnsupportedFeature,
            ConnectorError::UnexpectedFlow | ConnectorError::WrongPeer => Self::Malformed,
            _ => Self::Disconnected,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TicketMetadata {
    pub(crate) service_id: u32,
    pub(crate) secret_id: u64,
    pub(crate) fingerprint: [u8; 32],
    pub(crate) expires_at: Duration,
    pub(crate) renew_after: Duration,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct AuthMetadata {
    pub(crate) global_id: u64,
    pub(crate) method: u32,
    pub(crate) mode: u32,
    pub(crate) tickets: BTreeMap<u32, TicketMetadata>,
}

#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) credential: Credential,
    pub(crate) target_address: EntityAddr,
    pub(crate) message_limits: Limits,
    pub(crate) cephx_limits: CephxLimits,
    pub(crate) handshake_timeout: Duration,
    pub(crate) max_banner_payload: u16,
    pub(crate) requested_keys: u32,
    pub(crate) allow_crc: bool,
    pub(crate) global_id: u64,
    pub(crate) old_ticket: TicketBlob,
    pub(crate) now: Arc<dyn Fn() -> Duration + Send + Sync>,
    pub(crate) challenge: Arc<dyn Fn() -> Result<u64, ConnectorError> + Send + Sync>,
}

#[derive(Clone, Default)]
struct State {
    global_id: u64,
    mode: u32,
    tickets: BTreeMap<u32, ServiceTicket>,
}

pub(crate) struct MonitorConnector {
    config: Config,
    gate: AsyncMutex<()>,
    state: Mutex<State>,
}

#[derive(Clone)]
pub(crate) struct ServiceConfig {
    pub(crate) authority: Arc<MonitorConnector>,
    pub(crate) service_type: u8,
    pub(crate) target_address: EntityAddr,
    pub(crate) message_limits: Limits,
    pub(crate) handshake_timeout: Duration,
    pub(crate) max_banner_payload: u16,
    pub(crate) allow_crc: bool,
}

pub(crate) struct ServiceConnector {
    config: ServiceConfig,
    gate: AsyncMutex<()>,
}

impl MonitorConnector {
    pub(crate) fn new(config: Config) -> Result<Self, ConnectorError> {
        if config.handshake_timeout.is_zero()
            || config.max_banner_payload < 16
            || config.message_limits.max_segment_bytes == 0
            || config.message_limits.max_frame_bytes == 0
            || config.message_limits.max_auth_bytes == 0
        {
            return Err(ConnectorError::InvalidConfig);
        }
        Ok(Self {
            config,
            gate: AsyncMutex::new(()),
            state: Mutex::new(State::default()),
        })
    }

    pub(crate) fn os_challenge() -> Result<u64, ConnectorError> {
        let mut bytes = [0_u8; 8];
        getrandom::fill(&mut bytes).map_err(|_| ConnectorError::Io)?;
        Ok(u64::from_le_bytes(bytes))
    }

    pub(crate) fn metadata(&self) -> AuthMetadata {
        let state = self.state.lock().expect("connector state mutex");
        metadata(state.global_id, state.mode, &state.tickets)
    }

    pub(crate) async fn connect<S>(&self, stream: S) -> Result<ConnectionSetup, ConnectorError>
    where
        S: IoStream,
    {
        tokio::time::timeout(self.config.handshake_timeout, self.connect_inner(stream))
            .await
            .map_err(|_| ConnectorError::Timeout)?
    }

    #[allow(clippy::too_many_lines)]
    async fn connect_inner<S>(&self, stream: S) -> Result<ConnectionSetup, ConnectorError>
    where
        S: IoStream,
    {
        let _guard = self.gate.lock().await;
        let now = (self.config.now)();
        let (global_id, old_ticket, old_auth_key) = self.renewal_snapshot(now);
        let requested_global_id = if global_id == 0 {
            self.config.global_id
        } else {
            global_id
        };
        let old_ticket = if old_ticket.blob.is_empty() {
            self.config.old_ticket.clone()
        } else {
            old_ticket
        };
        let mut stream = TranscriptStream::new(stream);
        let crc = CrcCodec {
            with_data_crc: true,
        };

        stream
            .write_all(&Banner::client().encode())
            .await
            .map_err(map_io)?;
        let peer_banner = read_banner(&mut stream, self.config.max_banner_payload).await?;
        Banner::client().negotiate(peer_banner)?;

        write_control(
            &mut stream,
            &mut HandshakeCodec::Crc(crc),
            Control::Hello(Hello {
                entity_type: ENTITY_CLIENT,
                peer_address: self.config.target_address.clone(),
            }),
            self.config.message_limits,
        )
        .await?;
        match read_control(
            &mut stream,
            &mut HandshakeCodec::Crc(crc),
            self.config.message_limits,
        )
        .await?
        {
            Control::Hello(hello) if hello.entity_type == ENTITY_MONITOR => {}
            Control::Hello(_) => return Err(ConnectorError::WrongPeer),
            _ => return Err(ConnectorError::UnexpectedFlow),
        }

        let initial = build_initial_payload(
            &self.config.credential,
            requested_global_id,
            self.config.cephx_limits,
        )?;
        write_control(
            &mut stream,
            &mut HandshakeCodec::Crc(crc),
            Control::AuthRequest(AuthRequest {
                method: AUTH_METHOD_CEPHX,
                preferred_modes: self.preferred_modes(),
                auth_payload: initial,
            }),
            self.config.message_limits,
        )
        .await?;
        let challenge_payload = match read_control(
            &mut stream,
            &mut HandshakeCodec::Crc(crc),
            self.config.message_limits,
        )
        .await?
        {
            Control::AuthReplyMore(payload) => payload,
            Control::AuthBadMethod(value) => return Err(self.classify_bad_method(&value)),
            _ => return Err(ConnectorError::UnexpectedFlow),
        };
        let server_challenge =
            parse_server_challenge(&challenge_payload, self.config.cephx_limits)?;
        let client_challenge = (self.config.challenge)()?;
        let response = build_challenge_request(
            &self.config.credential,
            server_challenge,
            client_challenge,
            &old_ticket,
            self.config.requested_keys,
            self.config.cephx_limits,
        )?;
        write_control(
            &mut stream,
            &mut HandshakeCodec::Crc(crc),
            Control::AuthRequestMore(response),
            self.config.message_limits,
        )
        .await?;
        let done = match read_control(
            &mut stream,
            &mut HandshakeCodec::Crc(crc),
            self.config.message_limits,
        )
        .await?
        {
            Control::AuthDone(done) => done,
            Control::AuthBadMethod(value) => return Err(self.classify_bad_method(&value)),
            _ => return Err(ConnectorError::UnexpectedFlow),
        };
        if done.global_id == 0 || done.global_id > i64::MAX as u64 {
            return Err(ConnectorError::InvalidGlobalId);
        }
        if done.connection_mode != CONNECTION_MODE_SECURE
            && !(self.config.allow_crc && done.connection_mode == CONNECTION_MODE_CRC)
        {
            return Err(ConnectorError::Downgrade);
        }
        let mut reply = parse_auth_session_reply(
            &done.auth_payload,
            self.config.credential.secret(),
            old_auth_key.as_ref(),
            done.connection_mode,
            now,
            self.config.cephx_limits,
        )?;
        let mut codec = match done.connection_mode {
            CONNECTION_MODE_SECURE => {
                HandshakeCodec::Secure(Box::new(SecureCodec::new(&reply.connection_secret, false)?))
            }
            CONNECTION_MODE_CRC => HandshakeCodec::Crc(crc),
            _ => return Err(ConnectorError::Downgrade),
        };

        let client_signature = transcript_signature(&reply.auth_session_key, stream.rx());
        stream.stop_capture();
        write_control(
            &mut stream,
            &mut codec,
            Control::AuthSignature(client_signature),
            self.config.message_limits,
        )
        .await?;
        let Control::AuthSignature(server_signature) =
            read_control(&mut stream, &mut codec, self.config.message_limits).await?
        else {
            return Err(ConnectorError::UnexpectedFlow);
        };
        if !verify_transcript_signature(&reply.auth_session_key, stream.tx(), &server_signature) {
            return Err(ConnectorError::SignatureMismatch);
        }

        let metadata = metadata(done.global_id, done.connection_mode, &reply.tickets);
        let identity = credential_identity(&metadata);
        let renewal_after = metadata
            .tickets
            .values()
            .map(|ticket| ticket.renew_after.saturating_sub(now))
            .min();
        let transport_codec = match codec {
            HandshakeCodec::Crc(value) => Codec::Crc(value),
            HandshakeCodec::Secure(value) => Codec::Secure(value),
        };
        let stream = stream.into_inner();
        self.store_authenticated(
            done.global_id,
            done.connection_mode,
            std::mem::take(&mut reply.tickets),
        );
        Ok(ConnectionSetup {
            stream: Box::new(stream),
            codec: transport_codec,
            requires_identification: true,
            authenticated_global_id: Some(done.global_id),
            credential_identity: Some(identity),
            renewal_after,
        })
    }

    fn preferred_modes(&self) -> Vec<u32> {
        if self.config.allow_crc {
            vec![CONNECTION_MODE_SECURE, CONNECTION_MODE_CRC]
        } else {
            vec![CONNECTION_MODE_SECURE]
        }
    }

    fn classify_bad_method(&self, value: &crate::msgr::control::AuthBadMethod) -> ConnectorError {
        let method_allowed = value.allowed_methods.contains(&AUTH_METHOD_CEPHX);
        let mode_allowed = value
            .allowed_modes
            .iter()
            .any(|mode| self.preferred_modes().contains(mode));
        if value.method != AUTH_METHOD_CEPHX || !method_allowed || !mode_allowed {
            ConnectorError::Downgrade
        } else {
            ConnectorError::Rejected
        }
    }

    fn renewal_snapshot(&self, now: Duration) -> (u64, TicketBlob, Option<CryptoKey>) {
        let mut state = self.state.lock().expect("connector state mutex");
        let Some(ticket) = state.tickets.get(&SERVICE_AUTH) else {
            return (
                state.global_id,
                TicketBlob {
                    secret_id: 0,
                    blob: Vec::new(),
                },
                None,
            );
        };
        if ticket.expires_at.is_zero() || now >= ticket.expires_at {
            *state = State::default();
            return (
                0,
                TicketBlob {
                    secret_id: 0,
                    blob: Vec::new(),
                },
                None,
            );
        }
        (
            state.global_id,
            ticket.ticket.clone(),
            Some(ticket.session_key.clone()),
        )
    }

    pub(crate) fn service_authorization(
        &self,
        service_id: u32,
    ) -> Result<(u64, ServiceTicket, Authorizer), ConnectorError> {
        let now = (self.config.now)();
        let mut state = self.state.lock().expect("connector state mutex");
        let Some(ticket) = state.tickets.get(&service_id) else {
            return Err(CephxError::MissingTicket.into());
        };
        if ticket.expires_at.is_zero() || now >= ticket.expires_at {
            if service_id == SERVICE_AUTH {
                *state = State::default();
            } else {
                state.tickets.remove(&service_id);
            }
            return Err(CephxError::ExpiredTicket.into());
        }
        let global_id = state.global_id;
        let ticket = ticket.clone();
        let mut random = [0_u8; 24];
        getrandom::fill(&mut random).map_err(|_| ConnectorError::Io)?;
        let nonce = u64::from_le_bytes(random[..8].try_into().expect("fixed random slice"));
        let confounder: [u8; 16] = random[8..].try_into().expect("fixed random slice");
        let authorizer = build_authorizer(
            service_id,
            global_id,
            &ticket,
            now,
            nonce,
            Some(&confounder),
            self.config.cephx_limits,
        )?;
        Ok((global_id, ticket, authorizer))
    }

    fn store_authenticated(
        &self,
        global_id: u64,
        mode: u32,
        tickets: BTreeMap<u32, ServiceTicket>,
    ) {
        *self.state.lock().expect("connector state mutex") = State {
            global_id,
            mode,
            tickets,
        };
    }
}

impl ServiceConnector {
    pub(crate) fn new(config: ServiceConfig) -> Result<Self, ConnectorError> {
        if !matches!(config.service_type, ENTITY_OSD | ENTITY_MANAGER)
            || config.handshake_timeout.is_zero()
            || config.max_banner_payload < 16
            || config.message_limits.max_segment_bytes == 0
            || config.message_limits.max_frame_bytes == 0
            || config.message_limits.max_auth_bytes == 0
        {
            return Err(ConnectorError::InvalidConfig);
        }
        Ok(Self {
            config,
            gate: AsyncMutex::new(()),
        })
    }

    pub(crate) async fn connect<S>(&self, stream: S) -> Result<ConnectionSetup, ConnectorError>
    where
        S: IoStream,
    {
        tokio::time::timeout(self.config.handshake_timeout, self.connect_inner(stream))
            .await
            .map_err(|_| ConnectorError::Timeout)?
    }

    #[allow(clippy::too_many_lines)]
    async fn connect_inner<S>(&self, stream: S) -> Result<ConnectionSetup, ConnectorError>
    where
        S: IoStream,
    {
        let _guard = self.gate.lock().await;
        let service_id = u32::from(self.config.service_type);
        let (global_id, ticket, mut authorizer) =
            self.config.authority.service_authorization(service_id)?;
        let crc = CrcCodec {
            with_data_crc: true,
        };
        let mut stream = TranscriptStream::new(stream);

        stream
            .write_all(&Banner::client().encode())
            .await
            .map_err(map_io)?;
        let peer_banner = read_banner(&mut stream, self.config.max_banner_payload).await?;
        Banner::client().negotiate(peer_banner)?;
        write_control(
            &mut stream,
            &mut HandshakeCodec::Crc(crc),
            Control::Hello(Hello {
                entity_type: ENTITY_CLIENT,
                peer_address: self.config.target_address.clone(),
            }),
            self.config.message_limits,
        )
        .await?;
        match read_control(
            &mut stream,
            &mut HandshakeCodec::Crc(crc),
            self.config.message_limits,
        )
        .await?
        {
            Control::Hello(hello) if hello.entity_type == self.config.service_type => {}
            Control::Hello(_) => return Err(ConnectorError::WrongPeer),
            _ => return Err(ConnectorError::UnexpectedFlow),
        }

        write_control(
            &mut stream,
            &mut HandshakeCodec::Crc(crc),
            Control::AuthRequest(AuthRequest {
                method: AUTH_METHOD_CEPHX,
                preferred_modes: self.preferred_modes(),
                auth_payload: authorizer.payload.clone(),
            }),
            self.config.message_limits,
        )
        .await?;
        let mut response = read_control(
            &mut stream,
            &mut HandshakeCodec::Crc(crc),
            self.config.message_limits,
        )
        .await?;
        if let Control::AuthReplyMore(challenge) = response {
            let mut confounder = [0_u8; 16];
            getrandom::fill(&mut confounder).map_err(|_| ConnectorError::Io)?;
            authorizer = add_authorizer_challenge(
                &authorizer,
                &challenge,
                &ticket.session_key,
                Some(&confounder),
                self.config.authority.config.cephx_limits,
            )?;
            write_control(
                &mut stream,
                &mut HandshakeCodec::Crc(crc),
                Control::AuthRequestMore(authorizer.payload.clone()),
                self.config.message_limits,
            )
            .await?;
            response = read_control(
                &mut stream,
                &mut HandshakeCodec::Crc(crc),
                self.config.message_limits,
            )
            .await?;
        }
        let done = match response {
            Control::AuthDone(done) => done,
            Control::AuthBadMethod(value) => {
                return Err(self.config.authority.classify_bad_method(&value));
            }
            _ => return Err(ConnectorError::UnexpectedFlow),
        };
        if done.global_id == 0 || done.global_id > i64::MAX as u64 || done.global_id != global_id {
            return Err(ConnectorError::InvalidGlobalId);
        }
        if done.connection_mode != CONNECTION_MODE_SECURE
            && !(self.config.allow_crc && done.connection_mode == CONNECTION_MODE_CRC)
        {
            return Err(ConnectorError::Downgrade);
        }
        let connection_secret = verify_authorizer_reply(
            &done.auth_payload,
            &ticket.session_key,
            authorizer.nonce,
            self.config.authority.config.cephx_limits,
        )?;
        let mut codec = match done.connection_mode {
            CONNECTION_MODE_SECURE if connection_secret.len() == CONNECTION_SECRET_SIZE_SECURE => {
                HandshakeCodec::Secure(Box::new(SecureCodec::new(&connection_secret, false)?))
            }
            CONNECTION_MODE_SECURE => return Err(CephxError::MalformedPayload.into()),
            CONNECTION_MODE_CRC if connection_secret.is_empty() => HandshakeCodec::Crc(crc),
            CONNECTION_MODE_CRC => return Err(CephxError::InvalidMode.into()),
            _ => return Err(ConnectorError::Downgrade),
        };

        let client_signature = transcript_signature(&ticket.session_key, stream.rx());
        stream.stop_capture();
        write_control(
            &mut stream,
            &mut codec,
            Control::AuthSignature(client_signature),
            self.config.message_limits,
        )
        .await?;
        let Control::AuthSignature(server_signature) =
            read_control(&mut stream, &mut codec, self.config.message_limits).await?
        else {
            return Err(ConnectorError::UnexpectedFlow);
        };
        if !verify_transcript_signature(&ticket.session_key, stream.tx(), &server_signature) {
            return Err(ConnectorError::SignatureMismatch);
        }

        let tickets = BTreeMap::from([(service_id, ticket.clone())]);
        let metadata = metadata(global_id, done.connection_mode, &tickets);
        let renewal_at = service_renewal_time(&ticket);
        let renewal_after = Some(renewal_at.saturating_sub((self.config.authority.config.now)()));
        let transport_codec = match codec {
            HandshakeCodec::Crc(value) => Codec::Crc(value),
            HandshakeCodec::Secure(value) => Codec::Secure(value),
        };
        Ok(ConnectionSetup {
            stream: Box::new(stream.into_inner()),
            codec: transport_codec,
            requires_identification: true,
            authenticated_global_id: Some(global_id),
            credential_identity: Some(credential_identity(&metadata)),
            renewal_after,
        })
    }

    fn preferred_modes(&self) -> Vec<u32> {
        if self.config.allow_crc {
            vec![CONNECTION_MODE_SECURE, CONNECTION_MODE_CRC]
        } else {
            vec![CONNECTION_MODE_SECURE]
        }
    }
}

fn service_renewal_time(ticket: &ServiceTicket) -> Duration {
    ticket
        .expires_at
        .checked_sub(ticket.renew_after)
        .map_or(ticket.renew_after, |window| ticket.renew_after + window / 2)
}

fn metadata(global_id: u64, mode: u32, tickets: &BTreeMap<u32, ServiceTicket>) -> AuthMetadata {
    AuthMetadata {
        global_id,
        method: if mode == 0 { 0 } else { AUTH_METHOD_CEPHX },
        mode,
        tickets: tickets
            .iter()
            .map(|(&service_id, ticket)| {
                (
                    service_id,
                    TicketMetadata {
                        service_id,
                        secret_id: ticket.ticket.secret_id,
                        fingerprint: Sha256::digest(&ticket.ticket.blob).into(),
                        expires_at: ticket.expires_at,
                        renew_after: ticket.renew_after,
                    },
                )
            })
            .collect(),
    }
}

fn credential_identity(metadata: &AuthMetadata) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(metadata.global_id.to_le_bytes());
    digest.update(metadata.method.to_le_bytes());
    digest.update(metadata.mode.to_le_bytes());
    for ticket in metadata.tickets.values() {
        digest.update(ticket.service_id.to_le_bytes());
        digest.update(ticket.secret_id.to_le_bytes());
        digest.update(ticket.fingerprint);
        digest.update(ticket.expires_at.as_secs().to_le_bytes());
        digest.update(ticket.expires_at.subsec_nanos().to_le_bytes());
        digest.update(ticket.renew_after.as_secs().to_le_bytes());
        digest.update(ticket.renew_after.subsec_nanos().to_le_bytes());
    }
    digest.finalize().into()
}

enum HandshakeCodec {
    Crc(CrcCodec),
    Secure(Box<SecureCodec>),
}

impl HandshakeCodec {
    fn encode(
        &mut self,
        frame: &crate::msgr::frame::Frame,
        limits: Limits,
    ) -> Result<Vec<u8>, FrameError> {
        match self {
            Self::Crc(codec) => codec.encode(frame, limits),
            Self::Secure(codec) => codec.encode(frame, limits),
        }
    }

    async fn read<S>(
        &mut self,
        stream: &mut S,
        limits: Limits,
    ) -> Result<crate::msgr::frame::Frame, FrameError>
    where
        S: AsyncRead + Unpin,
    {
        match self {
            Self::Crc(codec) => codec.read_async(stream, limits).await,
            Self::Secure(codec) => codec.read_async(stream, limits).await,
        }
    }
}

async fn write_control<S>(
    stream: &mut S,
    codec: &mut HandshakeCodec,
    control: Control,
    limits: Limits,
) -> Result<(), ConnectorError>
where
    S: AsyncWrite + Unpin,
{
    let frame = control.encode(limits)?;
    let wire = codec.encode(&frame, limits)?;
    stream.write_all(&wire).await.map_err(map_io)
}

async fn read_control<S>(
    stream: &mut S,
    codec: &mut HandshakeCodec,
    limits: Limits,
) -> Result<Control, ConnectorError>
where
    S: AsyncRead + Unpin,
{
    let frame = codec.read(stream, limits).await?;
    Control::decode(&frame, limits).map_err(Into::into)
}

async fn read_banner<S>(stream: &mut S, max_payload: u16) -> Result<Banner, ConnectorError>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0_u8; 10];
    stream.read_exact(&mut header).await.map_err(map_io)?;
    if &header[..8] != b"ceph v2\n" {
        return Err(ConnectorError::Frame(FrameError::Malformed));
    }
    let size = u16::from_le_bytes([header[8], header[9]]);
    if size < 16 {
        return Err(ConnectorError::Frame(FrameError::Malformed));
    }
    if size > max_payload {
        return Err(ConnectorError::Frame(FrameError::LimitExceeded));
    }
    let mut payload = vec![0_u8; usize::from(size)];
    stream.read_exact(&mut payload).await.map_err(map_io)?;
    let supported = u64::from_le_bytes(
        payload[..8]
            .try_into()
            .map_err(|_| ConnectorError::UnexpectedFlow)?,
    );
    let required = u64::from_le_bytes(
        payload[8..16]
            .try_into()
            .map_err(|_| ConnectorError::UnexpectedFlow)?,
    );
    Ok(Banner {
        supported,
        required,
    })
}

fn map_io(_: io::Error) -> ConnectorError {
    ConnectorError::Io
}

struct TranscriptStream<S> {
    inner: S,
    tx: Vec<u8>,
    rx: Vec<u8>,
    capture: bool,
}

impl<S> TranscriptStream<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            tx: Vec::new(),
            rx: Vec::new(),
            capture: true,
        }
    }

    fn stop_capture(&mut self) {
        self.capture = false;
    }

    fn tx(&self) -> &[u8] {
        &self.tx
    }

    fn rx(&self) -> &[u8] {
        &self.rx
    }

    fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TranscriptStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled = buffer.filled().len();
        match Pin::new(&mut self.inner).poll_read(context, buffer) {
            Poll::Ready(Ok(())) => {
                if self.capture {
                    self.rx.extend_from_slice(&buffer.filled()[filled..]);
                }
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TranscriptStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::new(&mut self.inner).poll_write(context, buffer) {
            Poll::Ready(Ok(written)) => {
                if self.capture {
                    self.tx.extend_from_slice(&buffer[..written]);
                }
                Poll::Ready(Ok(written))
            }
            result => result,
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::io::{DuplexStream, duplex};

    use super::*;
    use crate::cephx::crypto::{
        KEY_USAGE_AUTH_CONNECTION_SECRET, KEY_USAGE_AUTHORIZE, KEY_USAGE_AUTHORIZE_CHALLENGE,
        KEY_USAGE_AUTHORIZE_REPLY, KEY_USAGE_TICKET_SESSION_KEY, decrypt_with_magic,
        encrypt_with_magic,
    };
    use crate::cephx::parse_key;
    use crate::msgr::control::{AuthBadMethod, AuthDone, Timestamp};
    use crate::wire::{Decoder, Encoder};

    const KEY: &str = "AQB7AAAAyAEAABAAMTIzNDU2Nzg5MDEyMzQ1Ng==";
    const MESSAGE_LIMITS: Limits = Limits {
        max_segment_bytes: 4096,
        max_frame_bytes: 8192,
        max_addresses: 4,
        max_auth_bytes: 4096,
    };

    #[derive(Clone, Copy)]
    #[allow(clippy::struct_excessive_bools)]
    struct Script {
        mode: u32,
        global_id: u64,
        peer_type: u8,
        bad_method: bool,
        bad_signature: bool,
        malformed_flow: bool,
        validity: u32,
        ticket_byte: u8,
        post_auth: bool,
    }

    impl Default for Script {
        fn default() -> Self {
            Self {
                mode: CONNECTION_MODE_SECURE,
                global_id: 42,
                peer_type: ENTITY_MONITOR,
                bad_method: false,
                bad_signature: false,
                malformed_flow: false,
                validity: 60,
                ticket_byte: 0x41,
                post_auth: true,
            }
        }
    }

    #[derive(Debug)]
    struct Observed {
        requested_global_id: u64,
        reclaimed_ticket: bool,
        modes: Vec<u32>,
    }

    fn credential() -> Credential {
        parse_key("client.test", KEY, 64).expect("credential")
    }

    fn address() -> EntityAddr {
        let encoded = [
            0x01, 0x01, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0c, 0xe4, 0xc0, 0x00, 0x02, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut decoder = Decoder::new(&encoded, encoded.len());
        EntityAddr::decode(&mut decoder).expect("address")
    }

    fn config(now: Arc<AtomicU64>, allow_crc: bool, timeout: Duration) -> Config {
        Config {
            credential: credential(),
            target_address: address(),
            message_limits: MESSAGE_LIMITS,
            cephx_limits: CephxLimits::default(),
            handshake_timeout: timeout,
            max_banner_payload: 64,
            requested_keys: SERVICE_AUTH,
            allow_crc,
            global_id: 0,
            old_ticket: TicketBlob {
                secret_id: 0,
                blob: Vec::new(),
            },
            now: Arc::new(move || Duration::from_secs(now.load(Ordering::SeqCst))),
            challenge: Arc::new(|| Ok(0x0102_0304_0506_0708)),
        }
    }

    fn encode_envelope(
        key: &CryptoKey,
        plaintext: &[u8],
        usage: u32,
        limits: CephxLimits,
    ) -> Vec<u8> {
        let encrypted = encrypt_with_magic(key, plaintext, usage, Some(&[0x5a; 16]), limits)
            .expect("encrypt envelope");
        let mut envelope = Encoder::new(limits.max_auth_bytes);
        envelope.bytes(&encrypted);
        envelope.finish().expect("envelope")
    }

    fn auth_reply(
        principal: &CryptoKey,
        session_key: &CryptoKey,
        mode: u32,
        validity: u32,
        ticket_byte: u8,
    ) -> Vec<u8> {
        let limits = CephxLimits::default();
        let mut secret = Encoder::new(limits.max_auth_bytes);
        secret.u8(1);
        secret.u16(session_key.type_id);
        secret.u32(0);
        secret.u32(0);
        secret.u16(u16::try_from(session_key.secret.len()).expect("key length"));
        secret.raw(&session_key.secret);
        secret.u32(validity);
        secret.u32(0);
        let encrypted_secret = encode_envelope(
            principal,
            &secret.finish().expect("session key"),
            KEY_USAGE_TICKET_SESSION_KEY,
            limits,
        );
        let mut ticket = Encoder::new(limits.max_auth_bytes);
        ticket.u8(1);
        ticket.u64(u64::from(ticket_byte));
        ticket.bytes(&[ticket_byte; 8]);

        let mut reply = Encoder::new(limits.max_auth_bytes);
        reply.u16(0x0100);
        reply.i32(0);
        reply.u8(1);
        reply.u32(1);
        reply.u32(SERVICE_AUTH);
        reply.u8(1);
        reply.raw(&encrypted_secret);
        reply.u8(0);
        reply.bytes(&ticket.finish().expect("ticket"));
        if mode == CONNECTION_MODE_SECURE {
            let connection_secret = [0x33; 64];
            let mut plaintext = Encoder::new(limits.max_auth_bytes);
            plaintext.bytes(&connection_secret);
            let encrypted = encode_envelope(
                session_key,
                &plaintext.finish().expect("connection secret"),
                KEY_USAGE_AUTH_CONNECTION_SECRET,
                limits,
            );
            reply.bytes(&encrypted);
            reply.bytes(&[]);
        }
        reply.finish().expect("auth reply")
    }

    fn requested_global_id(payload: &[u8]) -> u64 {
        let mut decoder = Decoder::new(payload, payload.len());
        assert_eq!(decoder.u8(), 10);
        assert_eq!(decoder.u32(), 8);
        assert_eq!(decoder.string(), "test");
        decoder.u64()
    }

    #[allow(clippy::too_many_lines)]
    async fn server(mut stream: DuplexStream, script: Script) -> Result<Observed, ConnectorError> {
        let principal = credential().secret().clone();
        let session_key = principal.clone();
        let crc = CrcCodec {
            with_data_crc: true,
        };
        let mut stream = TranscriptStream::new(&mut stream);
        let banner = read_banner(&mut stream, 64).await?;
        Banner::client().negotiate(banner)?;
        stream
            .write_all(&Banner::client().encode())
            .await
            .map_err(map_io)?;

        let hello =
            read_control(&mut stream, &mut HandshakeCodec::Crc(crc), MESSAGE_LIMITS).await?;
        assert!(matches!(hello, Control::Hello(_)));
        write_control(
            &mut stream,
            &mut HandshakeCodec::Crc(crc),
            Control::Hello(Hello {
                entity_type: script.peer_type,
                peer_address: address(),
            }),
            MESSAGE_LIMITS,
        )
        .await?;
        if script.peer_type != ENTITY_MONITOR {
            return Ok(Observed {
                requested_global_id: 0,
                reclaimed_ticket: false,
                modes: Vec::new(),
            });
        }

        let request =
            read_control(&mut stream, &mut HandshakeCodec::Crc(crc), MESSAGE_LIMITS).await?;
        let Control::AuthRequest(request) = request else {
            return Err(ConnectorError::UnexpectedFlow);
        };
        let observed_global_id = requested_global_id(&request.auth_payload);
        if script.bad_method {
            write_control(
                &mut stream,
                &mut HandshakeCodec::Crc(crc),
                Control::AuthBadMethod(AuthBadMethod {
                    method: 1,
                    result: -1,
                    allowed_methods: vec![1],
                    allowed_modes: vec![CONNECTION_MODE_CRC],
                }),
                MESSAGE_LIMITS,
            )
            .await?;
            return Ok(Observed {
                requested_global_id: observed_global_id,
                reclaimed_ticket: false,
                modes: request.preferred_modes,
            });
        }
        if script.malformed_flow {
            write_control(
                &mut stream,
                &mut HandshakeCodec::Crc(crc),
                Control::Keepalive2(Timestamp {
                    seconds: 0,
                    nanoseconds: 0,
                }),
                MESSAGE_LIMITS,
            )
            .await?;
            return Ok(Observed {
                requested_global_id: observed_global_id,
                reclaimed_ticket: false,
                modes: request.preferred_modes,
            });
        }
        let mut challenge = Encoder::new(32);
        challenge.u8(1);
        challenge.u64(0x1122_3344_5566_7788);
        write_control(
            &mut stream,
            &mut HandshakeCodec::Crc(crc),
            Control::AuthReplyMore(challenge.finish().expect("challenge")),
            MESSAGE_LIMITS,
        )
        .await?;
        let response =
            read_control(&mut stream, &mut HandshakeCodec::Crc(crc), MESSAGE_LIMITS).await?;
        let Control::AuthRequestMore(response) = response else {
            return Err(ConnectorError::UnexpectedFlow);
        };
        let reclaimed_ticket = response.windows(8).any(|bytes| bytes == [0x41; 8]);
        let payload = auth_reply(
            &principal,
            &session_key,
            script.mode,
            script.validity,
            script.ticket_byte,
        );
        write_control(
            &mut stream,
            &mut HandshakeCodec::Crc(crc),
            Control::AuthDone(AuthDone {
                global_id: script.global_id,
                connection_mode: script.mode,
                auth_payload: payload,
            }),
            MESSAGE_LIMITS,
        )
        .await?;
        if script.global_id == 0
            || script.mode != CONNECTION_MODE_SECURE && script.mode != CONNECTION_MODE_CRC
            || !request.preferred_modes.contains(&script.mode)
        {
            return Ok(Observed {
                requested_global_id: observed_global_id,
                reclaimed_ticket,
                modes: request.preferred_modes,
            });
        }
        let mut codec = if script.mode == CONNECTION_MODE_SECURE {
            HandshakeCodec::Secure(Box::new(SecureCodec::new(&[0x33; 64], true)?))
        } else {
            HandshakeCodec::Crc(crc)
        };
        let expected_client = transcript_signature(&session_key, stream.tx());
        stream.stop_capture();
        let signature = read_control(&mut stream, &mut codec, MESSAGE_LIMITS).await?;
        let Control::AuthSignature(signature) = signature else {
            return Err(ConnectorError::UnexpectedFlow);
        };
        assert_eq!(signature, expected_client);
        let mut server_signature = transcript_signature(&session_key, stream.rx());
        if script.bad_signature {
            server_signature[0] ^= 1;
        }
        write_control(
            &mut stream,
            &mut codec,
            Control::AuthSignature(server_signature),
            MESSAGE_LIMITS,
        )
        .await?;
        if script.post_auth && !script.bad_signature {
            write_control(&mut stream, &mut codec, Control::Ack(77), MESSAGE_LIMITS).await?;
        }
        Ok(Observed {
            requested_global_id: observed_global_id,
            reclaimed_ticket,
            modes: request.preferred_modes,
        })
    }

    async fn connect_script(
        connector: &MonitorConnector,
        script: Script,
    ) -> (Result<ConnectionSetup, ConnectorError>, Observed) {
        let (client, server_stream) = duplex(32 * 1024);
        let server_task = tokio::spawn(server(server_stream, script));
        let result = connector.connect(client).await;
        let observed = server_task
            .await
            .expect("server task")
            .expect("server script");
        (result, observed)
    }

    async fn read_setup_control(mut setup: ConnectionSetup) -> Control {
        let frame = match &mut setup.codec {
            Codec::Crc(codec) => codec.read_async(&mut setup.stream, MESSAGE_LIMITS).await,
            Codec::Secure(codec) => codec.read_async(&mut setup.stream, MESSAGE_LIMITS).await,
        }
        .expect("post-auth frame");
        Control::decode(&frame, MESSAGE_LIMITS).expect("post-auth control")
    }

    #[tokio::test]
    async fn secure_success_hands_off_codec_and_post_auth_frame() {
        let now = Arc::new(AtomicU64::new(100));
        let connector = MonitorConnector::new(config(now, false, Duration::from_secs(1))).unwrap();
        let (setup, observed) = connect_script(&connector, Script::default()).await;
        let setup = setup.expect("secure setup");
        assert_eq!(observed.modes, vec![CONNECTION_MODE_SECURE]);
        assert_eq!(setup.authenticated_global_id, Some(42));
        assert_eq!(setup.renewal_after, Some(Duration::from_secs(45)));
        assert!(matches!(read_setup_control(setup).await, Control::Ack(77)));
    }

    #[tokio::test]
    async fn crc_requires_explicit_opt_in() {
        let now = Arc::new(AtomicU64::new(100));
        let secure_only =
            MonitorConnector::new(config(now.clone(), false, Duration::from_secs(1))).unwrap();
        let (result, observed) = connect_script(
            &secure_only,
            Script {
                mode: CONNECTION_MODE_CRC,
                post_auth: false,
                ..Script::default()
            },
        )
        .await;
        assert!(matches!(result, Err(ConnectorError::Downgrade)));
        assert_eq!(observed.modes, vec![CONNECTION_MODE_SECURE]);

        let crc_allowed = MonitorConnector::new(config(now, true, Duration::from_secs(1))).unwrap();
        let (result, observed) = connect_script(
            &crc_allowed,
            Script {
                mode: CONNECTION_MODE_CRC,
                ..Script::default()
            },
        )
        .await;
        assert_eq!(
            observed.modes,
            vec![CONNECTION_MODE_SECURE, CONNECTION_MODE_CRC]
        );
        assert!(matches!(
            read_setup_control(result.expect("CRC setup")).await,
            Control::Ack(77)
        ));
    }

    #[tokio::test]
    async fn rejects_signature_mismatch_wrong_peer_and_malformed_flow() {
        for (script, expected) in [
            (
                Script {
                    bad_signature: true,
                    post_auth: false,
                    ..Script::default()
                },
                ConnectorError::SignatureMismatch,
            ),
            (
                Script {
                    peer_type: 4,
                    post_auth: false,
                    ..Script::default()
                },
                ConnectorError::WrongPeer,
            ),
            (
                Script {
                    malformed_flow: true,
                    post_auth: false,
                    ..Script::default()
                },
                ConnectorError::UnexpectedFlow,
            ),
            (
                Script {
                    global_id: 0,
                    post_auth: false,
                    ..Script::default()
                },
                ConnectorError::InvalidGlobalId,
            ),
            (
                Script {
                    bad_method: true,
                    post_auth: false,
                    ..Script::default()
                },
                ConnectorError::Downgrade,
            ),
        ] {
            let connector = MonitorConnector::new(config(
                Arc::new(AtomicU64::new(100)),
                false,
                Duration::from_secs(1),
            ))
            .unwrap();
            let (result, _) = connect_script(&connector, script).await;
            assert!(matches!(result, Err(error) if error == expected));
            assert_eq!(connector.metadata(), AuthMetadata::default());
        }
    }

    #[tokio::test]
    async fn failed_reconnect_preserves_state_and_successful_rotation_changes_identity() {
        let now = Arc::new(AtomicU64::new(100));
        let connector = MonitorConnector::new(config(now, false, Duration::from_secs(1))).unwrap();
        let (first, _) = connect_script(&connector, Script::default()).await;
        let first = first.expect("first setup");
        let first_identity = first.credential_identity;
        let first_metadata = connector.metadata();

        let (failed, observed) = connect_script(
            &connector,
            Script {
                global_id: 43,
                ticket_byte: 0x42,
                bad_signature: true,
                post_auth: false,
                ..Script::default()
            },
        )
        .await;
        assert!(matches!(failed, Err(ConnectorError::SignatureMismatch)));
        assert_eq!(observed.requested_global_id, 42);
        assert!(observed.reclaimed_ticket);
        assert_eq!(connector.metadata(), first_metadata);

        let (rotated, _) = connect_script(
            &connector,
            Script {
                global_id: 43,
                ticket_byte: 0x42,
                ..Script::default()
            },
        )
        .await;
        assert_ne!(
            rotated.expect("rotated setup").credential_identity,
            first_identity
        );
        assert_eq!(connector.metadata().global_id, 43);
    }

    #[tokio::test]
    async fn expired_auth_state_is_cleared_before_reconnect() {
        let now = Arc::new(AtomicU64::new(100));
        let connector =
            MonitorConnector::new(config(now.clone(), false, Duration::from_secs(1))).unwrap();
        connect_script(&connector, Script::default())
            .await
            .0
            .expect("first setup");
        now.store(161, Ordering::SeqCst);
        let (result, observed) = connect_script(
            &connector,
            Script {
                malformed_flow: true,
                post_auth: false,
                ..Script::default()
            },
        )
        .await;
        assert!(matches!(result, Err(ConnectorError::UnexpectedFlow)));
        assert_eq!(observed.requested_global_id, 0);
        assert_eq!(connector.metadata(), AuthMetadata::default());
    }

    #[tokio::test]
    async fn timeout_cancellation_and_gate_wait_are_bounded() {
        let connector = Arc::new(
            MonitorConnector::new(config(
                Arc::new(AtomicU64::new(100)),
                false,
                Duration::from_millis(20),
            ))
            .unwrap(),
        );
        let (first, _blocked_server) = duplex(64);
        let held = {
            let connector = connector.clone();
            tokio::spawn(async move { connector.connect(first).await })
        };
        tokio::task::yield_now().await;
        let (second, _second_server) = duplex(64);
        assert!(matches!(
            connector.connect(second).await,
            Err(ConnectorError::Timeout)
        ));
        assert!(matches!(
            held.await.expect("first task"),
            Err(ConnectorError::Timeout)
        ));

        let (cancelled, _server) = duplex(64);
        let task = {
            let connector = connector.clone();
            tokio::spawn(async move { connector.connect(cancelled).await })
        };
        tokio::task::yield_now().await;
        task.abort();
        let cancelled = task.await;
        assert!(matches!(cancelled, Err(error) if error.is_cancelled()));
    }

    #[derive(Clone, Copy)]
    #[allow(clippy::struct_excessive_bools)]
    struct ServiceScript {
        challenge: bool,
        peer_type: u8,
        global_id: u64,
        mode: u32,
        bad_nonce: bool,
        bad_secret: bool,
        bad_signature: bool,
    }

    impl Default for ServiceScript {
        fn default() -> Self {
            Self {
                challenge: false,
                peer_type: ENTITY_OSD,
                global_id: 77,
                mode: CONNECTION_MODE_SECURE,
                bad_nonce: false,
                bad_secret: false,
                bad_signature: false,
            }
        }
    }

    fn service_ticket(service_id: u32, renew_after: u64, expires_at: u64) -> ServiceTicket {
        ServiceTicket {
            service_id,
            ticket: TicketBlob {
                secret_id: 9,
                blob: b"service-ticket".to_vec(),
            },
            session_key: credential().secret().clone(),
            expires_at: Duration::from_secs(expires_at),
            renew_after: Duration::from_secs(renew_after),
        }
    }

    fn service_connector(
        authority: Arc<MonitorConnector>,
        service_type: u8,
        allow_crc: bool,
        timeout: Duration,
    ) -> ServiceConnector {
        ServiceConnector::new(ServiceConfig {
            authority,
            service_type,
            target_address: address(),
            message_limits: MESSAGE_LIMITS,
            handshake_timeout: timeout,
            max_banner_payload: 64,
            allow_crc,
        })
        .expect("service connector")
    }

    fn authority_with_ticket(now: Arc<AtomicU64>, ticket: ServiceTicket) -> Arc<MonitorConnector> {
        let authority = Arc::new(
            MonitorConnector::new(config(now, false, Duration::from_secs(1)))
                .expect("monitor connector"),
        );
        authority.store_authenticated(
            77,
            CONNECTION_MODE_SECURE,
            BTreeMap::from([(ticket.service_id, ticket)]),
        );
        authority
    }

    fn authorizer_nonce(payload: &[u8], ticket: &ServiceTicket) -> Result<u64, ConnectorError> {
        let limits = CephxLimits::default();
        let mut decoder = Decoder::new(payload, limits.max_auth_bytes);
        if decoder.u8() != 1
            || decoder.u64() != 77
            || decoder.u32() != ticket.service_id
            || decoder.u8() != 1
            || decoder.u64() != ticket.ticket.secret_id
            || decoder.bytes() != ticket.ticket.blob
        {
            return Err(ConnectorError::UnexpectedFlow);
        }
        let encrypted = decoder.bytes();
        decoder.finish().map_err(CephxError::from)?;
        let plaintext =
            decrypt_with_magic(&ticket.session_key, &encrypted, KEY_USAGE_AUTHORIZE, limits)?;
        let mut authorize = Decoder::new(&plaintext, limits.max_auth_bytes);
        if authorize.u8() != 2 {
            return Err(ConnectorError::UnexpectedFlow);
        }
        Ok(authorize.u64())
    }

    fn service_reply(
        ticket: &ServiceTicket,
        nonce: u64,
        mode: u32,
        bad_nonce: bool,
        bad_secret: bool,
    ) -> Vec<u8> {
        let limits = CephxLimits::default();
        let mut plaintext = Encoder::new(limits.max_auth_bytes);
        plaintext.u8(2);
        plaintext.u64(nonce.wrapping_add(u64::from(!bad_nonce)));
        let secret_length = if mode == CONNECTION_MODE_CRC {
            0
        } else if bad_secret {
            CONNECTION_SECRET_SIZE_SECURE - 1
        } else {
            CONNECTION_SECRET_SIZE_SECURE
        };
        plaintext.bytes(&vec![0x51; secret_length]);
        let encrypted = encrypt_with_magic(
            &ticket.session_key,
            &plaintext.finish().expect("authorizer reply"),
            KEY_USAGE_AUTHORIZE_REPLY,
            Some(&[0x5a; 16]),
            limits,
        )
        .expect("encrypt authorizer reply");
        let mut outer = Encoder::new(limits.max_auth_bytes);
        outer.bytes(&encrypted);
        outer.finish().expect("reply envelope")
    }

    #[allow(clippy::too_many_lines)]
    async fn service_server(
        mut stream: DuplexStream,
        ticket: ServiceTicket,
        script: ServiceScript,
    ) -> Result<(), ConnectorError> {
        let crc = CrcCodec {
            with_data_crc: true,
        };
        let mut stream = TranscriptStream::new(&mut stream);
        let banner = read_banner(&mut stream, 64).await?;
        Banner::client().negotiate(banner)?;
        stream
            .write_all(&Banner::client().encode())
            .await
            .map_err(map_io)?;
        let hello =
            read_control(&mut stream, &mut HandshakeCodec::Crc(crc), MESSAGE_LIMITS).await?;
        if !matches!(hello, Control::Hello(_)) {
            return Err(ConnectorError::UnexpectedFlow);
        }
        write_control(
            &mut stream,
            &mut HandshakeCodec::Crc(crc),
            Control::Hello(Hello {
                entity_type: script.peer_type,
                peer_address: address(),
            }),
            MESSAGE_LIMITS,
        )
        .await?;
        if u32::from(script.peer_type) != ticket.service_id {
            return Ok(());
        }
        let Control::AuthRequest(request) =
            read_control(&mut stream, &mut HandshakeCodec::Crc(crc), MESSAGE_LIMITS).await?
        else {
            return Err(ConnectorError::UnexpectedFlow);
        };
        let nonce = authorizer_nonce(&request.auth_payload, &ticket)?;
        if script.challenge {
            let mut challenge = Encoder::new(32);
            challenge.u8(1);
            challenge.u64(19);
            let encrypted = encrypt_with_magic(
                &ticket.session_key,
                &challenge.finish().expect("challenge"),
                KEY_USAGE_AUTHORIZE_CHALLENGE,
                Some(&[0x6b; 16]),
                CephxLimits::default(),
            )?;
            write_control(
                &mut stream,
                &mut HandshakeCodec::Crc(crc),
                Control::AuthReplyMore(encrypted),
                MESSAGE_LIMITS,
            )
            .await?;
            let Control::AuthRequestMore(payload) =
                read_control(&mut stream, &mut HandshakeCodec::Crc(crc), MESSAGE_LIMITS).await?
            else {
                return Err(ConnectorError::UnexpectedFlow);
            };
            if authorizer_nonce(&payload, &ticket)? != nonce {
                return Err(ConnectorError::UnexpectedFlow);
            }
        }
        let reply = service_reply(
            &ticket,
            nonce,
            script.mode,
            script.bad_nonce,
            script.bad_secret,
        );
        write_control(
            &mut stream,
            &mut HandshakeCodec::Crc(crc),
            Control::AuthDone(AuthDone {
                global_id: script.global_id,
                connection_mode: script.mode,
                auth_payload: reply,
            }),
            MESSAGE_LIMITS,
        )
        .await?;
        if script.global_id != 77 || script.bad_nonce || script.bad_secret {
            return Ok(());
        }
        let mut codec = if script.mode == CONNECTION_MODE_SECURE {
            HandshakeCodec::Secure(Box::new(SecureCodec::new(&[0x51; 64], true)?))
        } else {
            HandshakeCodec::Crc(crc)
        };
        let expected_client = transcript_signature(&ticket.session_key, stream.tx());
        stream.stop_capture();
        let Control::AuthSignature(signature) =
            read_control(&mut stream, &mut codec, MESSAGE_LIMITS).await?
        else {
            return Err(ConnectorError::UnexpectedFlow);
        };
        if signature != expected_client {
            return Err(ConnectorError::SignatureMismatch);
        }
        let mut signature = transcript_signature(&ticket.session_key, stream.rx());
        if script.bad_signature {
            signature[0] ^= 1;
        }
        write_control(
            &mut stream,
            &mut codec,
            Control::AuthSignature(signature),
            MESSAGE_LIMITS,
        )
        .await?;
        if !script.bad_signature {
            write_control(&mut stream, &mut codec, Control::Ack(88), MESSAGE_LIMITS).await?;
        }
        Ok(())
    }

    async fn connect_service_script(
        connector: &ServiceConnector,
        ticket: ServiceTicket,
        script: ServiceScript,
    ) -> Result<ConnectionSetup, ConnectorError> {
        let (client, server_stream) = duplex(32 * 1024);
        let server_task = tokio::spawn(service_server(server_stream, ticket, script));
        let result = connector.connect(client).await;
        server_task.await.expect("service server task").ok();
        result
    }

    #[tokio::test]
    async fn service_direct_and_challenge_success_for_osd_and_manager() {
        for (service_type, challenge) in [
            (ENTITY_OSD, false),
            (ENTITY_OSD, true),
            (ENTITY_MANAGER, false),
        ] {
            let ticket = service_ticket(u32::from(service_type), 120, 160);
            let authority = authority_with_ticket(Arc::new(AtomicU64::new(100)), ticket.clone());
            let connector =
                service_connector(authority, service_type, false, Duration::from_secs(1));
            let setup = connect_service_script(
                &connector,
                ticket,
                ServiceScript {
                    challenge,
                    peer_type: service_type,
                    ..ServiceScript::default()
                },
            )
            .await
            .expect("service setup");
            assert_eq!(setup.authenticated_global_id, Some(77));
            assert!(setup.credential_identity.is_some());
            assert_eq!(setup.renewal_after, Some(Duration::from_secs(40)));
            assert!(matches!(read_setup_control(setup).await, Control::Ack(88)));
        }

        let ticket = service_ticket(u32::from(ENTITY_OSD), 120, 160);
        let authority = authority_with_ticket(Arc::new(AtomicU64::new(100)), ticket.clone());
        let connector = service_connector(authority, ENTITY_OSD, true, Duration::from_secs(1));
        let setup = connect_service_script(
            &connector,
            ticket,
            ServiceScript {
                mode: CONNECTION_MODE_CRC,
                ..ServiceScript::default()
            },
        )
        .await
        .expect("CRC service setup");
        assert!(matches!(setup.codec, Codec::Crc(_)));
        assert!(matches!(read_setup_control(setup).await, Control::Ack(88)));
    }

    #[tokio::test]
    async fn service_rejects_nonce_global_id_mode_secret_and_signature() {
        for (script, expected) in [
            (
                ServiceScript {
                    bad_nonce: true,
                    ..ServiceScript::default()
                },
                ConnectorError::Cephx(CephxError::InvalidNonce),
            ),
            (
                ServiceScript {
                    global_id: 78,
                    ..ServiceScript::default()
                },
                ConnectorError::InvalidGlobalId,
            ),
            (
                ServiceScript {
                    mode: CONNECTION_MODE_CRC,
                    ..ServiceScript::default()
                },
                ConnectorError::Downgrade,
            ),
            (
                ServiceScript {
                    bad_secret: true,
                    ..ServiceScript::default()
                },
                ConnectorError::Cephx(CephxError::MalformedPayload),
            ),
            (
                ServiceScript {
                    bad_signature: true,
                    ..ServiceScript::default()
                },
                ConnectorError::SignatureMismatch,
            ),
        ] {
            let ticket = service_ticket(u32::from(ENTITY_OSD), 120, 160);
            let authority = authority_with_ticket(Arc::new(AtomicU64::new(100)), ticket.clone());
            let connector = service_connector(authority, ENTITY_OSD, false, Duration::from_secs(1));
            let result = connect_service_script(&connector, ticket, script).await;
            assert!(matches!(result, Err(error) if error == expected));
        }
    }

    #[test]
    fn service_authorization_rejects_missing_and_clears_only_expired_ticket() {
        let now = Arc::new(AtomicU64::new(100));
        let auth_ticket = service_ticket(SERVICE_AUTH, 120, 160);
        let expired_osd = service_ticket(u32::from(ENTITY_OSD), 90, 100);
        let authority = authority_with_ticket(now, auth_ticket.clone());
        authority
            .state
            .lock()
            .expect("connector state mutex")
            .tickets
            .insert(u32::from(ENTITY_OSD), expired_osd);
        assert!(matches!(
            authority.service_authorization(u32::from(ENTITY_MANAGER)),
            Err(ConnectorError::Cephx(CephxError::MissingTicket))
        ));
        assert!(matches!(
            authority.service_authorization(u32::from(ENTITY_OSD)),
            Err(ConnectorError::Cephx(CephxError::ExpiredTicket))
        ));
        let metadata = authority.metadata();
        assert_eq!(metadata.global_id, 77);
        assert!(metadata.tickets.contains_key(&SERVICE_AUTH));

        authority
            .state
            .lock()
            .expect("connector state mutex")
            .tickets
            .insert(SERVICE_AUTH, service_ticket(SERVICE_AUTH, 90, 100));
        assert!(matches!(
            authority.service_authorization(SERVICE_AUTH),
            Err(ConnectorError::Cephx(CephxError::ExpiredTicket))
        ));
        assert_eq!(authority.metadata(), AuthMetadata::default());
    }

    #[test]
    fn service_renewal_leaves_authority_refresh_window() {
        let ticket = service_ticket(u32::from(ENTITY_OSD), 100, 120);
        assert_eq!(service_renewal_time(&ticket), Duration::from_secs(110));
    }

    #[tokio::test]
    async fn service_timeout_and_gate_wait_are_bounded() {
        let ticket = service_ticket(u32::from(ENTITY_OSD), 120, 160);
        let authority = authority_with_ticket(Arc::new(AtomicU64::new(100)), ticket);
        let connector = Arc::new(service_connector(
            authority,
            ENTITY_OSD,
            false,
            Duration::from_millis(20),
        ));
        let (first, _first_server) = duplex(64);
        let held = {
            let connector = connector.clone();
            tokio::spawn(async move { connector.connect(first).await })
        };
        tokio::task::yield_now().await;
        let (second, _second_server) = duplex(64);
        assert!(matches!(
            connector.connect(second).await,
            Err(ConnectorError::Timeout)
        ));
        assert!(matches!(
            held.await.expect("first task"),
            Err(ConnectorError::Timeout)
        ));

        let (cancelled, _server) = duplex(64);
        let task = {
            let connector = connector.clone();
            tokio::spawn(async move { connector.connect(cancelled).await })
        };
        tokio::task::yield_now().await;
        task.abort();
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    }
}
