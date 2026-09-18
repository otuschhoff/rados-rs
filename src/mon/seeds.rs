use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;

use hickory_resolver::TokioResolver;

use crate::protocol::address::EntityAddr;
use crate::wire::{Decoder, Encoder, WireError};

pub(crate) const DEFAULT_MONITOR_V2_PORT: u16 = 3300;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Endpoint {
    pub(crate) address: SocketAddr,
    pub(crate) entity_address: EntityAddr,
    pub(crate) priority: u16,
    pub(crate) weight: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SrvRecord {
    pub(crate) target: String,
    pub(crate) port: u16,
    pub(crate) priority: u16,
    pub(crate) weight: u16,
}

pub(crate) trait Resolver: Send + Sync {
    fn lookup_ip<'a>(
        &'a self,
        host: &'a str,
        maximum: u32,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, SeedError>> + Send + 'a>>;

    fn lookup_srv<'a>(
        &'a self,
        service: &'a str,
        protocol: &'a str,
        name: &'a str,
        maximum: u32,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SrvRecord>, SeedError>> + Send + 'a>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SeedLimits {
    pub(crate) max_seeds: u32,
    pub(crate) max_addresses: u32,
}

#[derive(Debug)]
pub(crate) enum SeedError {
    LimitExceeded,
    Malformed(&'static str),
    UnsupportedVersion,
    Lookup {
        operation: &'static str,
        name: String,
        source: io::Error,
    },
}

impl fmt::Display for SeedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded => formatter.write_str("monitor seed limit exceeded"),
            Self::Malformed(detail) => write!(formatter, "malformed monitor seed: {detail}"),
            Self::UnsupportedVersion => formatter.write_str("messenger v1 monitor seed"),
            Self::Lookup {
                operation,
                name,
                source,
            } => write!(
                formatter,
                "monitor {operation} lookup for {name:?} failed: {source}"
            ),
        }
    }
}

impl std::error::Error for SeedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Lookup { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub(crate) struct SystemResolver {
    resolver: TokioResolver,
}

impl SystemResolver {
    fn new() -> Result<Self, SeedError> {
        let builder = TokioResolver::builder_tokio()
            .map_err(|source| lookup_error("resolver configuration", "system", source))?;
        let resolver = builder
            .build()
            .map_err(|source| lookup_error("resolver configuration", "system", source))?;
        Ok(Self { resolver })
    }
}

impl Resolver for SystemResolver {
    fn lookup_ip<'a>(
        &'a self,
        host: &'a str,
        maximum: u32,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, SeedError>> + Send + 'a>> {
        Box::pin(async move {
            let lookup = self
                .resolver
                .lookup_ip(host)
                .await
                .map_err(|source| lookup_error("address", host, source))?;
            let mut addresses = Vec::new();
            for address in lookup.iter() {
                ensure_below_limit(addresses.len(), maximum)?;
                addresses.push(address);
            }
            Ok(addresses)
        })
    }

    fn lookup_srv<'a>(
        &'a self,
        service: &'a str,
        protocol: &'a str,
        name: &'a str,
        maximum: u32,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SrvRecord>, SeedError>> + Send + 'a>> {
        Box::pin(async move {
            let query = format!("_{service}._{protocol}.{name}");
            let lookup = self
                .resolver
                .srv_lookup(query)
                .await
                .map_err(|source| lookup_error("SRV", name, source))?;
            let mut records = Vec::new();
            for record in lookup.answers() {
                let hickory_resolver::proto::rr::RData::SRV(record) = &record.data else {
                    continue;
                };
                ensure_below_limit(records.len(), maximum)?;
                records.push(SrvRecord {
                    target: record.target.to_utf8(),
                    port: record.port,
                    priority: record.priority,
                    weight: record.weight,
                });
            }
            sort_srv_records(&mut records)?;
            Ok(records)
        })
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn resolve_seeds(
    seeds: &[String],
    resolver: Option<&dyn Resolver>,
    limits: SeedLimits,
) -> Result<Vec<Endpoint>, SeedError> {
    if seeds.is_empty()
        || limits.max_seeds == 0
        || limits.max_addresses == 0
        || seeds.len() > limits.max_seeds as usize
    {
        return Err(SeedError::LimitExceeded);
    }

    let has_v2_seed = seeds.iter().any(|seed| !seed.trim().starts_with("v1:"));
    if !has_v2_seed {
        return Err(SeedError::UnsupportedVersion);
    }

    let system_resolver;
    let resolver = if let Some(resolver) = resolver {
        resolver
    } else {
        system_resolver = SystemResolver::new()?;
        &system_resolver
    };
    let mut endpoints = Vec::with_capacity(seeds.len().min(limits.max_addresses as usize));
    let mut seen = HashSet::new();
    let mut last_lookup_error = None;

    for seed in seeds {
        let trimmed_seed = seed.trim();
        if trimmed_seed.starts_with("v1:") {
            continue;
        }
        if let Some(name) = trimmed_seed.strip_prefix("dns-srv:") {
            let name = name.strip_suffix('.').unwrap_or(name);
            if name.is_empty() {
                return Err(SeedError::Malformed("empty monitor SRV name"));
            }
            let records = match resolver
                .lookup_srv("ceph-mon", "tcp", name, limits.max_addresses)
                .await
            {
                Ok(records) => records,
                Err(error @ SeedError::Lookup { .. }) => {
                    last_lookup_error = Some(error);
                    continue;
                }
                Err(error) => return Err(error),
            };
            if records.len() > limits.max_addresses as usize {
                return Err(SeedError::LimitExceeded);
            }
            for record in records {
                let host = record.target.strip_suffix('.').unwrap_or(&record.target);
                if let Err(error) = resolve_host(
                    resolver,
                    host,
                    record.port,
                    (record.priority, record.weight),
                    limits.max_addresses,
                    &mut endpoints,
                    &mut seen,
                )
                .await
                {
                    if matches!(error, SeedError::Lookup { .. }) {
                        last_lookup_error = Some(error);
                    } else {
                        return Err(error);
                    }
                }
            }
            continue;
        }

        let (host, port) = parse_seed(trimmed_seed)?;
        if let Ok(address) = host.parse::<IpAddr>() {
            append_endpoint(
                SocketAddr::new(normalize_ip(address), port),
                (0, 0),
                limits.max_addresses,
                &mut endpoints,
                &mut seen,
            )?;
        } else if let Err(error) = resolve_host(
            resolver,
            &host,
            port,
            (0, 0),
            limits.max_addresses,
            &mut endpoints,
            &mut seen,
        )
        .await
        {
            if matches!(error, SeedError::Lookup { .. }) {
                last_lookup_error = Some(error);
            } else {
                return Err(error);
            }
        }
    }

    if endpoints.is_empty() {
        return Err(last_lookup_error.unwrap_or(SeedError::Malformed(
            "monitor seeds resolved to no addresses",
        )));
    }
    Ok(endpoints)
}

fn parse_seed(seed: &str) -> Result<(String, u16), SeedError> {
    let mut seed = seed.trim();
    if let Some(value) = seed.strip_prefix("v2:") {
        seed = value;
    } else if seed.starts_with("v1:") {
        return Err(SeedError::UnsupportedVersion);
    }

    if let Some((endpoint, nonce)) = seed.rsplit_once('/') {
        if nonce.is_empty() || nonce.parse::<u32>().is_err() {
            return Err(SeedError::Malformed("invalid monitor nonce"));
        }
        seed = endpoint;
    }

    if let Ok(address) = seed.parse::<IpAddr>() {
        return Ok((address.to_string(), DEFAULT_MONITOR_V2_PORT));
    }
    if seed.starts_with('[') {
        let endpoint = seed
            .parse::<SocketAddr>()
            .map_err(|_| SeedError::Malformed("invalid monitor seed"))?;
        if endpoint.port() == 0 {
            return Err(SeedError::Malformed("invalid monitor port"));
        }
        return Ok((endpoint.ip().to_string(), endpoint.port()));
    }
    if let Some((host, port)) = seed.rsplit_once(':') {
        if host.is_empty() || host.contains(':') {
            return Err(SeedError::Malformed("invalid monitor seed"));
        }
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or(SeedError::Malformed("invalid monitor port"))?;
        return Ok((host.to_owned(), port));
    }
    if seed.is_empty() {
        return Err(SeedError::Malformed("invalid monitor seed"));
    }
    Ok((seed.to_owned(), DEFAULT_MONITOR_V2_PORT))
}

async fn resolve_host(
    resolver: &dyn Resolver,
    host: &str,
    port: u16,
    metadata: (u16, u16),
    maximum: u32,
    endpoints: &mut Vec<Endpoint>,
    seen: &mut HashSet<SocketAddr>,
) -> Result<(), SeedError> {
    let addresses = resolver.lookup_ip(host, maximum).await?;
    if addresses.len() > maximum as usize {
        return Err(SeedError::LimitExceeded);
    }
    for address in addresses {
        if address.is_unspecified() {
            continue;
        }
        append_endpoint(
            SocketAddr::new(normalize_ip(address), port),
            metadata,
            maximum,
            endpoints,
            seen,
        )?;
    }
    Ok(())
}

fn append_endpoint(
    address: SocketAddr,
    metadata: (u16, u16),
    maximum: u32,
    endpoints: &mut Vec<Endpoint>,
    seen: &mut HashSet<SocketAddr>,
) -> Result<(), SeedError> {
    if seen.contains(&address) {
        return Ok(());
    }
    if endpoints.len() >= maximum as usize {
        return Err(SeedError::LimitExceeded);
    }
    let entity_address = entity_address(address)?;
    seen.insert(address);
    endpoints.push(Endpoint {
        address,
        entity_address,
        priority: metadata.0,
        weight: metadata.1,
    });
    Ok(())
}

fn ensure_below_limit(length: usize, maximum: u32) -> Result<(), SeedError> {
    if length >= maximum as usize {
        return Err(SeedError::LimitExceeded);
    }
    Ok(())
}

fn sort_srv_records(records: &mut [SrvRecord]) -> Result<(), SeedError> {
    records.sort_by_key(|record| (record.priority, record.weight));
    let mut start = 0;
    while start < records.len() {
        let priority = records[start].priority;
        let end = records[start..]
            .iter()
            .position(|record| record.priority != priority)
            .map_or(records.len(), |offset| start + offset);
        shuffle_srv_weights(&mut records[start..end])?;
        start = end;
    }
    Ok(())
}

fn shuffle_srv_weights(records: &mut [SrvRecord]) -> Result<(), SeedError> {
    let mut total = records
        .iter()
        .map(|record| u64::from(record.weight))
        .sum::<u64>();
    let mut remaining = records;
    while total > 0 && remaining.len() > 1 {
        let selected = random_below(total)?;
        let mut cumulative = 0_u64;
        let index = remaining
            .iter()
            .position(|record| {
                cumulative += u64::from(record.weight);
                cumulative > selected
            })
            .unwrap_or(0);
        remaining.swap(0, index);
        total -= u64::from(remaining[0].weight);
        remaining = &mut remaining[1..];
    }
    Ok(())
}

fn random_below(upper: u64) -> Result<u64, SeedError> {
    let threshold = upper.wrapping_neg() % upper;
    loop {
        let mut bytes = [0_u8; 8];
        getrandom::fill(&mut bytes).map_err(|_| SeedError::Lookup {
            operation: "SRV ordering",
            name: "system random source".to_owned(),
            source: io::Error::other("random source unavailable"),
        })?;
        let value = u64::from_ne_bytes(bytes);
        if value >= threshold {
            return Ok(value % upper);
        }
    }
}

fn lookup_error(
    operation: &'static str,
    name: &str,
    source: impl std::error::Error + Send + Sync + 'static,
) -> SeedError {
    SeedError::Lookup {
        operation,
        name: name.to_owned(),
        source: io::Error::other(source),
    }
}

fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address @ IpAddr::V4(_) => address,
    }
}

fn entity_address(endpoint: SocketAddr) -> Result<EntityAddr, SeedError> {
    if endpoint.is_ipv4() {
        return EntityAddr::ipv4_v2(endpoint).map_err(map_wire_error);
    }

    let SocketAddr::V6(endpoint) = endpoint else {
        return Err(SeedError::Malformed("invalid monitor IP"));
    };
    if endpoint.scope_id() != 0 {
        return Err(SeedError::Malformed("zoned monitor IPv6 is unsupported"));
    }
    let mut socket_data = [0_u8; 26];
    socket_data[..2].copy_from_slice(&endpoint.port().to_be_bytes());
    socket_data[6..22].copy_from_slice(&endpoint.ip().octets());

    let mut encoder = Encoder::new(64);
    encoder.u8(1);
    encoder.versioned(1, 1, |payload| {
        payload.u32(2);
        payload.u32(0);
        payload.u32(28);
        payload.u16(10);
        payload.raw(&socket_data);
    });
    let bytes = encoder.finish().map_err(map_wire_error)?;
    EntityAddr::decode(&mut Decoder::new(&bytes, bytes.len())).map_err(map_wire_error)
}

fn map_wire_error(error: WireError) -> SeedError {
    match error {
        WireError::LimitExceeded => SeedError::LimitExceeded,
        WireError::Malformed | WireError::UnsupportedVersion { .. } => {
            SeedError::Malformed("invalid monitor IP")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct FakeResolver {
        ips: HashMap<String, Vec<IpAddr>>,
        failed_ips: HashSet<String>,
        srv: Vec<SrvRecord>,
        calls: Mutex<Vec<String>>,
    }

    impl Resolver for FakeResolver {
        fn lookup_ip<'a>(
            &'a self,
            host: &'a str,
            _maximum: u32,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, SeedError>> + Send + 'a>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(format!("ip:{host}"));
                if self.failed_ips.contains(host) {
                    return Err(SeedError::Lookup {
                        operation: "address",
                        name: host.to_owned(),
                        source: io::Error::other("scripted lookup failure"),
                    });
                }
                Ok(self.ips.get(host).cloned().unwrap_or_default())
            })
        }

        fn lookup_srv<'a>(
            &'a self,
            service: &'a str,
            protocol: &'a str,
            name: &'a str,
            _maximum: u32,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<SrvRecord>, SeedError>> + Send + 'a>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .unwrap()
                    .push(format!("srv:{service}:{protocol}:{name}"));
                Ok(self.srv.clone())
            })
        }
    }

    fn limits(max_seeds: u32, max_addresses: u32) -> SeedLimits {
        SeedLimits {
            max_seeds,
            max_addresses,
        }
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[tokio::test]
    async fn resolves_explicit_ip_host_and_srv_in_source_order() {
        let resolver = FakeResolver {
            ips: HashMap::from([
                ("mon.example".to_owned(), vec!["192.0.2.2".parse().unwrap()]),
                (
                    "srv.example".to_owned(),
                    vec!["2001:db8::2".parse().unwrap()],
                ),
            ]),
            srv: vec![SrvRecord {
                target: "srv.example.".to_owned(),
                port: 4400,
                priority: 9,
                weight: 10,
            }],
            ..FakeResolver::default()
        };
        let endpoints = resolve_seeds(
            &strings(&["v2:192.0.2.1:3300/7", "mon.example", "dns-srv:example."]),
            Some(&resolver),
            limits(4, 4),
        )
        .await
        .unwrap();

        assert_eq!(
            endpoints
                .iter()
                .map(|endpoint| endpoint.address.to_string())
                .collect::<Vec<_>>(),
            ["192.0.2.1:3300", "192.0.2.2:3300", "[2001:db8::2]:4400"]
        );
        assert_eq!((endpoints[2].priority, endpoints[2].weight), (9, 10));
        assert_eq!(
            *resolver.calls.lock().unwrap(),
            [
                "ip:mon.example",
                "srv:ceph-mon:tcp:example",
                "ip:srv.example"
            ]
        );
    }

    #[tokio::test]
    async fn lookup_failures_do_not_discard_usable_alternatives() {
        let resolver = FakeResolver {
            ips: HashMap::from([(
                "good.example".to_owned(),
                vec!["192.0.2.8".parse().unwrap()],
            )]),
            failed_ips: HashSet::from(["bad.example".to_owned(), "bad-srv.example".to_owned()]),
            srv: vec![
                SrvRecord {
                    target: "bad-srv.example".to_owned(),
                    port: 3300,
                    priority: 0,
                    weight: 0,
                },
                SrvRecord {
                    target: "good.example".to_owned(),
                    port: 4400,
                    priority: 0,
                    weight: 0,
                },
            ],
            ..FakeResolver::default()
        };
        let endpoints = resolve_seeds(
            &strings(&["bad.example", "dns-srv:example"]),
            Some(&resolver),
            limits(2, 4),
        )
        .await
        .expect("healthy alternatives");
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].address, "192.0.2.8:4400".parse().unwrap());

        assert!(matches!(
            resolve_seeds(&strings(&["bad.example"]), Some(&resolver), limits(1, 1)).await,
            Err(SeedError::Lookup { .. })
        ));
    }

    #[tokio::test]
    async fn parses_bracketed_ipv6_and_explicit_hostname_port() {
        let resolver = FakeResolver {
            ips: HashMap::from([("mon.example".to_owned(), vec!["192.0.2.8".parse().unwrap()])]),
            ..FakeResolver::default()
        };
        let endpoints = resolve_seeds(
            &strings(&["[2001:db8::1]:4400", "mon.example:5500"]),
            Some(&resolver),
            limits(2, 2),
        )
        .await
        .unwrap();
        assert_eq!(endpoints[0].address, "[2001:db8::1]:4400".parse().unwrap());
        assert_eq!(endpoints[1].address, "192.0.2.8:5500".parse().unwrap());
        assert_eq!(endpoints[0].entity_address.endpoint(), None);
    }

    #[tokio::test]
    async fn ignores_v1_in_mixed_vectors_but_rejects_v1_only() {
        let resolver = FakeResolver::default();
        let endpoints = resolve_seeds(
            &strings(&["v1:192.0.2.9:6789", "v2:192.0.2.1:3300"]),
            Some(&resolver),
            limits(2, 2),
        )
        .await
        .unwrap();
        assert_eq!(endpoints.len(), 1);
        assert!(matches!(
            resolve_seeds(
                &strings(&["v1:192.0.2.9:6789"]),
                Some(&resolver),
                limits(1, 1)
            )
            .await,
            Err(SeedError::UnsupportedVersion)
        ));
    }

    #[tokio::test]
    async fn deduplicates_in_first_seen_order_and_unmaps_ipv4() {
        let resolver = FakeResolver {
            ips: HashMap::from([(
                "mon.example".to_owned(),
                vec![
                    "::ffff:192.0.2.1".parse().unwrap(),
                    "192.0.2.2".parse().unwrap(),
                    "192.0.2.2".parse().unwrap(),
                ],
            )]),
            ..FakeResolver::default()
        };
        let endpoints = resolve_seeds(
            &strings(&["192.0.2.1", "mon.example"]),
            Some(&resolver),
            limits(2, 3),
        )
        .await
        .unwrap();
        assert_eq!(
            endpoints
                .iter()
                .map(|endpoint| endpoint.address)
                .collect::<Vec<_>>(),
            [
                SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 3300)),
                SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 3300)),
            ]
        );
    }

    #[tokio::test]
    async fn enforces_source_per_answer_and_aggregate_limits() {
        let resolver = FakeResolver {
            ips: HashMap::from([(
                "many".to_owned(),
                vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()],
            )]),
            ..FakeResolver::default()
        };
        assert!(matches!(
            resolve_seeds(&strings(&["a", "b"]), Some(&resolver), limits(1, 2)).await,
            Err(SeedError::LimitExceeded)
        ));
        assert!(matches!(
            resolve_seeds(&strings(&["many"]), Some(&resolver), limits(1, 1)).await,
            Err(SeedError::LimitExceeded)
        ));
        assert!(matches!(
            resolve_seeds(
                &strings(&["192.0.2.1", "192.0.2.2"]),
                Some(&resolver),
                limits(2, 1)
            )
            .await,
            Err(SeedError::LimitExceeded)
        ));
    }

    #[tokio::test]
    async fn rejects_malformed_ports_nonces_and_ip_literals() {
        let resolver = FakeResolver::default();
        for seed in [
            "192.0.2.1:0",
            "192.0.2.1:65536",
            "192.0.2.1:nope",
            "v2:192.0.2.1:3300/",
            "v2:192.0.2.1:3300/4294967296",
            "v2:192.0.2.1:3300/1/2",
            "[2001:db8::1",
            "[2001:db8::1]:65536",
        ] {
            assert!(
                matches!(
                    resolve_seeds(&strings(&[seed]), Some(&resolver), limits(1, 1)).await,
                    Err(SeedError::Malformed(_))
                ),
                "seed={seed:?}"
            );
        }
    }

    #[tokio::test]
    async fn numeric_addresses_do_not_invoke_dns() {
        let resolver = FakeResolver::default();
        resolve_seeds(
            &strings(&["192.0.2.1", "2001:db8::1"]),
            Some(&resolver),
            limits(2, 2),
        )
        .await
        .unwrap();
        assert!(resolver.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn skips_unspecified_answers_and_rejects_empty_results() {
        let resolver = FakeResolver {
            ips: HashMap::from([(
                "mon.example".to_owned(),
                vec![
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                ],
            )]),
            ..FakeResolver::default()
        };
        assert!(matches!(
            resolve_seeds(&strings(&["mon.example"]), Some(&resolver), limits(1, 2)).await,
            Err(SeedError::Malformed(_))
        ));
    }

    #[test]
    fn sorts_srv_records_by_priority_and_leaves_zero_weight_order_stable() {
        let mut records = vec![
            SrvRecord {
                target: "second".to_owned(),
                port: 3300,
                priority: 2,
                weight: 0,
            },
            SrvRecord {
                target: "first-a".to_owned(),
                port: 3300,
                priority: 1,
                weight: 0,
            },
            SrvRecord {
                target: "first-b".to_owned(),
                port: 3300,
                priority: 1,
                weight: 0,
            },
        ];
        sort_srv_records(&mut records).unwrap();
        assert_eq!(
            records
                .iter()
                .map(|record| record.target.as_str())
                .collect::<Vec<_>>(),
            ["first-a", "first-b", "second"]
        );
    }
}
