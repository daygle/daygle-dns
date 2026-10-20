//! Local root zone (RFC 8806, the console's "Secondary ROOT Zone").
//!
//! [`LocalRoot`] transfers the root zone from the configured servers,
//! accepts it only when [`crate::zonemd::verify_zone`] proves it intact and
//! authentic, keeps it in memory (and in a cache file so a restart does not
//! wait for a transfer), and serves it to the recursive resolver from a
//! loopback-only responder. The resolver points its root hints at that
//! responder, so root queries never leave the machine; referrals below the
//! root (to the TLD servers, including `arpa` and `root-servers.net`) still
//! go to the real servers.
//!
//! The copy is refreshed on the zone's SOA refresh interval and stops being
//! served when it is older than the SOA expire value, at which point the
//! resolver falls back to the real root servers.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use daygle_dns_core::config::{parse_master_addr, LocalRootSettings};
use daygle_dns_core::LocalRootView;
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{
    BinDecodable, BinDecoder, BinEncodable, BinEncoder, NameEncoding,
};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::transfer::XfrClient;
use crate::zonemd::{verify_zone, TrustAnchor};

/// A verified root zone, indexed for answering.
pub struct RootZone {
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    /// UNIX time the copy was last confirmed current with a source.
    checked_at: AtomicU64,
    records: Vec<Record>,
    /// Non-RRSIG RRsets by (lowercased owner, type).
    rrsets: HashMap<(Name, RecordType), Vec<Record>>,
    /// RRSIGs by (lowercased owner, covered type).
    signatures: HashMap<(Name, RecordType), Vec<Record>>,
    /// NSEC records by owner, in canonical order, for denial proofs.
    nsecs: BTreeMap<Name, Record>,
    /// Delegated top-level domains (lowercased single labels).
    tlds: HashSet<Name>,
}

impl RootZone {
    /// Index a verified record list. `checked_at` is when it was fetched.
    fn build(records: Vec<Record>, checked_at: u64) -> Result<Self, String> {
        let mut records = records;
        // An AXFR repeats the SOA at the end.
        if records.len() > 1 && records.first() == records.last() {
            records.pop();
        }

        let (serial, refresh, retry, expire) = records
            .iter()
            .find_map(|r| match &r.data {
                RData::SOA(soa) if r.name.is_root() => Some((
                    soa.serial,
                    soa.refresh.max(0) as u32,
                    soa.retry.max(0) as u32,
                    soa.expire.max(0) as u32,
                )),
                _ => None,
            })
            .ok_or("the zone has no SOA at the root")?;

        let mut rrsets: HashMap<(Name, RecordType), Vec<Record>> = HashMap::new();
        let mut signatures: HashMap<(Name, RecordType), Vec<Record>> = HashMap::new();
        let mut nsecs = BTreeMap::new();
        let mut tlds = HashSet::new();
        for record in &records {
            let owner = record.name.to_lowercase();
            match &record.data {
                RData::DNSSEC(DNSSECRData::RRSIG(sig)) => {
                    signatures
                        .entry((owner, sig.input().type_covered))
                        .or_default()
                        .push(record.clone());
                    continue;
                }
                RData::DNSSEC(DNSSECRData::NSEC(_)) => {
                    nsecs.insert(owner.clone(), record.clone());
                }
                RData::NS(_) if owner.num_labels() == 1 => {
                    tlds.insert(owner.clone());
                }
                _ => {}
            }
            rrsets
                .entry((owner, record.record_type()))
                .or_default()
                .push(record.clone());
        }
        Ok(Self {
            serial,
            refresh,
            retry,
            expire,
            checked_at: AtomicU64::new(checked_at),
            records,
            rrsets,
            signatures,
            nsecs,
            tlds,
        })
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn tld_count(&self) -> usize {
        self.tlds.len()
    }

    /// UNIX time after which the copy must not be used (RFC 8806 section
    /// 3: a copy that cannot be refreshed within SOA expire is stale).
    pub fn expires_at(&self) -> u64 {
        self.checked_at.load(Ordering::Relaxed) + u64::from(self.expire)
    }

    fn is_current(&self, now: u64) -> bool {
        now < self.expires_at()
    }

    pub fn has_tld(&self, tld: &str) -> bool {
        Name::from_ascii(format!("{}.", tld.trim_end_matches('.')))
            .map(|n| self.tlds.contains(&n.to_lowercase()))
            .unwrap_or(false)
    }

    fn rrset(&self, owner: &Name, rtype: RecordType) -> Option<&Vec<Record>> {
        self.rrsets.get(&(owner.clone(), rtype))
    }

    /// `rtype` at `owner` plus its signatures when `dnssec`.
    fn signed(&self, owner: &Name, rtype: RecordType, dnssec: bool) -> Vec<Record> {
        let mut out = self.rrset(owner, rtype).cloned().unwrap_or_default();
        if dnssec && !out.is_empty() {
            if let Some(sigs) = self.signatures.get(&(owner.clone(), rtype)) {
                out.extend(sigs.iter().cloned());
            }
        }
        out
    }

    /// The NSEC record covering `name` (the closest owner at or before it).
    fn covering_nsec(&self, name: &Name) -> Option<&Record> {
        self.nsecs
            .range(..=name.clone())
            .next_back()
            .map(|(_, r)| r)
    }

    /// Answer one query the way a root server would.
    pub fn answer(&self, query: &Message) -> Message {
        let mut response = Message::new(
            query.metadata.id,
            MessageType::Response,
            query.metadata.op_code,
        );
        response.metadata.recursion_desired = query.metadata.recursion_desired;
        let dnssec = query
            .edns
            .as_ref()
            .map(|e| e.flags().dnssec_ok)
            .unwrap_or(false);
        if query.edns.is_some() {
            let mut edns = Edns::new();
            edns.set_max_payload(1232).set_dnssec_ok(dnssec);
            response.set_edns(edns);
        }
        let Some(question) = query.queries.first() else {
            response.metadata.response_code = ResponseCode::FormErr;
            return response;
        };
        response.queries.push(question.clone());
        if query.metadata.op_code != OpCode::Query {
            response.metadata.response_code = ResponseCode::NotImp;
            return response;
        }
        if question.query_class() != DNSClass::IN {
            response.metadata.response_code = ResponseCode::Refused;
            return response;
        }

        let qname = question.name().to_lowercase();
        let qtype = question.query_type();
        let root = Name::root();
        let apex_negative = |response: &mut Message, nsec_for: &[Name]| {
            response
                .authorities
                .extend(self.signed(&root, RecordType::SOA, dnssec));
            if dnssec {
                let mut added = HashSet::new();
                for name in nsec_for {
                    if let Some(nsec) = self.covering_nsec(name) {
                        let owner = nsec.name.to_lowercase();
                        if added.insert(owner.clone()) {
                            response.authorities.extend(self.signed(
                                &owner,
                                RecordType::NSEC,
                                true,
                            ));
                        }
                    }
                }
            }
        };

        if qname.is_root() {
            response.metadata.authoritative = true;
            let answer = self.signed(&root, qtype, dnssec);
            if answer.is_empty() {
                apex_negative(&mut response, std::slice::from_ref(&root));
            } else {
                response.answers.extend(answer);
            }
            return response;
        }

        let tld = qname.trim_to(1);
        if !self.tlds.contains(&tld) {
            // NXDOMAIN: the NSEC covering the TLD, and the apex NSEC, which
            // covers the wildcard `*.` (nothing sorts between `.` and `*.`).
            response.metadata.authoritative = true;
            response.metadata.response_code = ResponseCode::NXDomain;
            let wildcard = Name::from_ascii("*.").expect("valid name");
            apex_negative(&mut response, &[tld, wildcard]);
            return response;
        }

        if qname == tld && qtype == RecordType::DS {
            // DS lives in the parent: answered here, authoritatively.
            response.metadata.authoritative = true;
            let answer = self.signed(&tld, RecordType::DS, dnssec);
            if answer.is_empty() {
                apex_negative(&mut response, &[tld]);
            } else {
                response.answers.extend(answer);
            }
            return response;
        }

        // Everything else at or below a TLD is a referral.
        let ns = self
            .rrset(&tld, RecordType::NS)
            .cloned()
            .unwrap_or_default();
        if dnssec {
            let ds = self.signed(&tld, RecordType::DS, true);
            if ds.is_empty() {
                response
                    .authorities
                    .extend(self.signed(&tld, RecordType::NSEC, true));
            } else {
                response.authorities.extend(ds);
            }
        }
        for record in &ns {
            if let RData::NS(target) = &record.data {
                let target = target.0.to_lowercase();
                for rtype in [RecordType::A, RecordType::AAAA] {
                    if let Some(glue) = self.rrset(&target, rtype) {
                        response.additionals.extend(glue.iter().cloned());
                    }
                }
            }
        }
        response.authorities.splice(0..0, ns);
        response
    }

    /// Serialize the zone for the cache file: magic, the fetch time, then the
    /// records in uncompressed wire format.
    fn encode(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::with_capacity(self.records.len() * 128);
        buf.extend_from_slice(CACHE_MAGIC);
        buf.extend_from_slice(&self.checked_at.load(Ordering::Relaxed).to_be_bytes());
        buf.extend_from_slice(&(self.records.len() as u32).to_be_bytes());
        // One encoder per record: an encoder's buffer is capped at 64 KiB.
        let mut wire = Vec::with_capacity(512);
        for record in &self.records {
            wire.clear();
            let mut encoder = BinEncoder::new(&mut wire);
            encoder.set_name_encoding(NameEncoding::Uncompressed);
            record.emit(&mut encoder).map_err(|e| e.to_string())?;
            buf.extend_from_slice(&wire);
        }
        Ok(buf)
    }

    /// Parse a cache file into `(fetched_at, records)`.
    fn decode(bytes: &[u8]) -> Result<(u64, Vec<Record>), String> {
        let header = CACHE_MAGIC.len() + 12;
        if bytes.len() < header || &bytes[..CACHE_MAGIC.len()] != CACHE_MAGIC {
            return Err("not a root zone cache file".to_string());
        }
        let at = CACHE_MAGIC.len();
        let fetched_at = u64::from_be_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
        let count = u32::from_be_bytes(bytes[at + 8..at + 12].try_into().expect("4 bytes"));
        let mut decoder = BinDecoder::new(bytes);
        decoder.read_slice(header).map_err(|e| e.to_string())?;
        let mut records = Vec::with_capacity(count as usize);
        for _ in 0..count {
            records.push(Record::read(&mut decoder).map_err(|e| e.to_string())?);
        }
        Ok((fetched_at, records))
    }
}

const CACHE_MAGIC: &[u8] = b"DAYGLE-ROOT-ZONE-1\n";

/// Status of the local root zone, for the API and the console.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LocalRootStatus {
    pub enabled: bool,
    /// A verified, unexpired copy is being served to the resolver.
    pub serving: bool,
    pub serial: Option<u32>,
    pub records: usize,
    pub tlds: usize,
    /// RFC 3339 time of the last successful transfer or serial check.
    pub last_checked: Option<String>,
    /// RFC 3339 time after which the copy is no longer used.
    pub expires: Option<String>,
    /// The server the current copy came from (or "cache" after a restart).
    pub source: Option<String>,
    pub last_error: Option<String>,
    /// RFC 3339 time of the last attempt that failed.
    pub last_error_at: Option<String>,
}

#[derive(Default)]
struct Progress {
    source: Option<String>,
    last_error: Option<String>,
    last_error_at: Option<u64>,
}

/// Keeps the local root zone current and serves it on loopback.
pub struct LocalRoot {
    settings: RwLock<LocalRootSettings>,
    zone: ArcSwapOption<RootZone>,
    progress: Mutex<Progress>,
    /// The loopback responder, bound on first use.
    addr: Mutex<Option<SocketAddr>>,
    cache_path: Option<PathBuf>,
    client: XfrClient,
    wake: tokio::sync::Notify,
}

impl LocalRoot {
    /// `cache_path` is where the verified zone is kept between restarts.
    pub fn new(settings: LocalRootSettings, cache_path: Option<PathBuf>) -> Self {
        Self {
            settings: RwLock::new(settings),
            zone: ArcSwapOption::empty(),
            progress: Mutex::new(Progress::default()),
            addr: Mutex::new(None),
            cache_path,
            // The root zone is ~2 MB: allow slow transfer servers.
            client: XfrClient::new(Duration::from_secs(30)),
            wake: tokio::sync::Notify::new(),
        }
    }

    /// Apply new settings (from the console or a config reload).
    pub fn set_settings(&self, settings: LocalRootSettings) {
        let mut current = self.settings.write().expect("local root lock poisoned");
        if *current == settings {
            return;
        }
        let disabled = !settings.enabled;
        *current = settings;
        drop(current);
        if disabled {
            self.zone.store(None);
            *self.progress.lock().expect("local root lock poisoned") = Progress::default();
            if let Some(path) = &self.cache_path {
                let _ = std::fs::remove_file(path);
            }
        }
        self.wake.notify_one();
    }

    /// Ask for an immediate refresh.
    pub fn refresh_now(&self) {
        self.wake.notify_one();
    }

    fn settings(&self) -> LocalRootSettings {
        self.settings
            .read()
            .expect("local root lock poisoned")
            .clone()
    }

    fn anchor(&self) -> TrustAnchor {
        match &self.settings().test_trust_anchor {
            Some(key) => TrustAnchor::Key(key.clone()),
            None => TrustAnchor::BuiltinRoot,
        }
    }

    pub fn status(&self) -> LocalRootStatus {
        let progress = self.progress.lock().expect("local root lock poisoned");
        let zone = self.zone.load_full();
        LocalRootStatus {
            enabled: self.settings().enabled,
            serving: self.serving_addr().is_some(),
            serial: zone.as_ref().map(|z| z.serial()),
            records: zone.as_ref().map(|z| z.record_count()).unwrap_or(0),
            tlds: zone.as_ref().map(|z| z.tld_count()).unwrap_or(0),
            last_checked: zone
                .as_ref()
                .map(|z| rfc3339(z.checked_at.load(Ordering::Relaxed))),
            expires: zone.as_ref().map(|z| rfc3339(z.expires_at())),
            source: progress.source.clone(),
            last_error: progress.last_error.clone(),
            last_error_at: progress.last_error_at.map(rfc3339),
        }
    }

    /// Keep the zone current until `shutdown`.
    pub async fn run_forever(self: Arc<Self>, shutdown: CancellationToken) {
        loop {
            let delay = if self.settings().enabled {
                if let Err(e) = self.ensure_listener().await {
                    self.record_error(format!("cannot start the local root responder: {e}"));
                }
                if self.zone.load().is_none() {
                    self.load_cache();
                }
                match self.refresh().await {
                    Ok(()) => self.zone.load().as_ref().map(|z| z.refresh).unwrap_or(1800),
                    Err(e) => {
                        warn!(error = %e, "local root zone refresh failed");
                        self.record_error(e);
                        self.zone.load().as_ref().map(|z| z.retry).unwrap_or(300)
                    }
                }
            } else {
                u32::MAX
            };
            let delay = Duration::from_secs(u64::from(delay.clamp(60, 86400)));
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }

    fn record_error(&self, error: String) {
        let mut progress = self.progress.lock().expect("local root lock poisoned");
        progress.last_error = Some(error);
        progress.last_error_at = Some(unix_now());
    }

    /// Check each source in turn; transfer when it has a newer serial.
    async fn refresh(&self) -> Result<(), String> {
        let sources = self.settings().effective_sources();
        let root = Name::root();
        let mut errors = Vec::new();
        for source in &sources {
            let addr = match parse_master_addr(source) {
                Ok(addr) => addr,
                Err(e) => {
                    errors.push(format!("{source}: {e}"));
                    continue;
                }
            };
            let current = self.zone.load_full();
            if let Some(zone) = &current {
                match self.client.query_soa(addr, &root).await {
                    Ok(Some(Record {
                        data: RData::SOA(soa),
                        ..
                    })) if !serial_newer(soa.serial, zone.serial) => {
                        // Still current: that resets the expiry clock.
                        zone.checked_at.store(unix_now(), Ordering::Relaxed);
                        self.write_cache(zone);
                        self.progress
                            .lock()
                            .expect("local root lock poisoned")
                            .last_error = None;
                        debug!(serial = zone.serial, %source, "local root zone is current");
                        return Ok(());
                    }
                    Ok(_) => {}
                    Err(e) => {
                        errors.push(format!("{source}: {e}"));
                        continue;
                    }
                }
            }
            match self.transfer(addr).await {
                Ok(zone) => {
                    info!(
                        serial = zone.serial,
                        records = zone.record_count(),
                        tlds = zone.tld_count(),
                        %source,
                        "local root zone transferred and verified"
                    );
                    self.write_cache(&zone);
                    self.zone.store(Some(Arc::new(zone)));
                    let mut progress = self.progress.lock().expect("local root lock poisoned");
                    progress.source = Some(source.clone());
                    progress.last_error = None;
                    return Ok(());
                }
                Err(e) => errors.push(format!("{source}: {e}")),
            }
        }
        Err(format!(
            "no server provided a valid root zone ({})",
            errors.join("; ")
        ))
    }

    async fn transfer(&self, addr: SocketAddr) -> Result<RootZone, String> {
        let records = self
            .client
            .axfr(addr, &Name::root())
            .await
            .map_err(|e| e.to_string())?;
        let now = unix_now();
        verify_zone(&Name::root(), &records, &self.anchor(), now)?;
        RootZone::build(records, now)
    }

    /// Load the cache file left by a previous run, if it still verifies and
    /// has not expired.
    fn load_cache(&self) {
        let Some(path) = &self.cache_path else {
            return;
        };
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        let now = unix_now();
        let loaded = RootZone::decode(&bytes).and_then(|(fetched_at, records)| {
            verify_zone(&Name::root(), &records, &self.anchor(), now)?;
            RootZone::build(records, fetched_at)
        });
        match loaded {
            Ok(zone) if zone.is_current(now) => {
                info!(serial = zone.serial, "local root zone loaded from cache");
                self.zone.store(Some(Arc::new(zone)));
                self.progress
                    .lock()
                    .expect("local root lock poisoned")
                    .source = Some("cache".to_string());
            }
            Ok(_) => debug!("cached local root zone has expired"),
            Err(e) => warn!(error = %e, "ignoring the local root zone cache"),
        }
    }

    fn write_cache(&self, zone: &RootZone) {
        let Some(path) = &self.cache_path else {
            return;
        };
        let result = zone.encode().and_then(|bytes| {
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, path).map_err(|e| e.to_string())
        });
        if let Err(e) = result {
            warn!(error = %e, path = %path.display(), "cannot write the local root zone cache");
        }
    }

    /// Bind the loopback responder (UDP and TCP on one port) once.
    async fn ensure_listener(self: &Arc<Self>) -> std::io::Result<()> {
        if self
            .addr
            .lock()
            .expect("local root lock poisoned")
            .is_some()
        {
            return Ok(());
        }
        let (udp, tcp) = bind_pair(IpAddr::V4(Ipv4Addr::LOCALHOST)).await?;
        let addr = udp.local_addr()?;
        tokio::spawn(serve_udp(Arc::downgrade(self), udp));
        tokio::spawn(serve_tcp(Arc::downgrade(self), tcp));
        debug!(%addr, "local root responder listening");
        *self.addr.lock().expect("local root lock poisoned") = Some(addr);
        Ok(())
    }

    fn current_zone(&self) -> Option<Arc<RootZone>> {
        // Runs for every resolver query: read the flag without cloning.
        if !self
            .settings
            .read()
            .expect("local root lock poisoned")
            .enabled
        {
            return None;
        }
        self.zone
            .load_full()
            .filter(|zone| zone.is_current(unix_now()))
    }

    /// Answer a query from the responder sockets, with the largest UDP
    /// response the requester accepts.
    fn handle(&self, bytes: &[u8]) -> Option<(Message, usize)> {
        let query = Message::from_vec(bytes).ok()?;
        if query.metadata.message_type != MessageType::Query {
            return None;
        }
        let udp_limit = query
            .edns
            .as_ref()
            .map(|e| e.max_payload().max(512))
            .unwrap_or(512) as usize;
        let response = match self.current_zone() {
            Some(zone) => zone.answer(&query),
            None => {
                let mut response = Message::new(
                    query.metadata.id,
                    MessageType::Response,
                    query.metadata.op_code,
                );
                response.queries = query.queries.clone();
                response.metadata.response_code = ResponseCode::ServFail;
                response
            }
        };
        Some((response, udp_limit))
    }
}

impl LocalRootView for LocalRoot {
    fn serving_addr(&self) -> Option<SocketAddr> {
        self.current_zone()?;
        *self.addr.lock().expect("local root lock poisoned")
    }

    fn tld_exists(&self, tld: &str) -> Option<bool> {
        self.current_zone().map(|zone| zone.has_tld(tld))
    }
}

/// Bind UDP and TCP on the same free loopback port.
async fn bind_pair(
    ip: IpAddr,
) -> std::io::Result<(tokio::net::UdpSocket, tokio::net::TcpListener)> {
    let mut last_error = None;
    for _ in 0..20 {
        let udp = tokio::net::UdpSocket::bind((ip, 0)).await?;
        let port = udp.local_addr()?.port();
        match tokio::net::TcpListener::bind((ip, port)).await {
            Ok(tcp) => return Ok((udp, tcp)),
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.unwrap_or_else(|| std::io::Error::other("no free port")))
}

async fn serve_udp(root: std::sync::Weak<LocalRoot>, socket: tokio::net::UdpSocket) {
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
            return;
        };
        let Some(root) = root.upgrade() else {
            return;
        };
        let Some((mut response, limit)) = root.handle(&buf[..len]) else {
            continue;
        };
        let mut bytes = response.to_vec().unwrap_or_default();
        if bytes.len() > limit {
            // Too big for UDP: the resolver retries over TCP.
            response.answers.clear();
            response.authorities.clear();
            response.additionals.clear();
            response.metadata.truncation = true;
            bytes = response.to_vec().unwrap_or_default();
        }
        let _ = socket.send_to(&bytes, peer).await;
    }
}

async fn serve_tcp(root: std::sync::Weak<LocalRoot>, listener: tokio::net::TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let root = root.clone();
        tokio::spawn(async move {
            loop {
                let mut len = [0u8; 2];
                let read =
                    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut len));
                if !matches!(read.await, Ok(Ok(_))) {
                    return;
                }
                let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
                if stream.read_exact(&mut buf).await.is_err() {
                    return;
                }
                let Some(root) = root.upgrade() else {
                    return;
                };
                let Some((response, _)) = root.handle(&buf) else {
                    return;
                };
                let Ok(bytes) = response.to_vec() else {
                    return;
                };
                let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&bytes);
                if stream.write_all(&framed).await.is_err() {
                    return;
                }
            }
        });
    }
}

fn serial_newer(candidate: u32, current: u32) -> bool {
    candidate != current && (candidate.wrapping_sub(current) as i32) > 0
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn rfc3339(unix: u64) -> String {
    chrono::DateTime::from_timestamp(unix as i64, 0)
        .map(|t| t.to_rfc3339())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zonemd::sign_test_zone;
    use hickory_proto::dnssec::rdata::{DS, NSEC};
    use hickory_proto::op::Query;
    use hickory_proto::rr::rdata::{A, NS, SOA};

    fn name(n: &str) -> Name {
        Name::from_ascii(n).unwrap()
    }

    fn nsec(owner: &str, next: &str, types: Vec<RecordType>) -> Record {
        Record::from_rdata(
            name(owner),
            86400,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(name(next), types))),
        )
    }

    /// A small root: `test.` (signed, with DS) and `example.` (no DS).
    fn test_root(now: u64) -> (Vec<Record>, Vec<u8>) {
        let records = vec![
            Record::from_rdata(
                Name::root(),
                86400,
                RData::SOA(SOA::new(
                    name("a.root."),
                    name("nstld.root."),
                    2026102000,
                    1800,
                    900,
                    604800,
                    86400,
                )),
            ),
            Record::from_rdata(Name::root(), 518400, RData::NS(NS(name("a.root.")))),
            Record::from_rdata(name("test."), 172800, RData::NS(NS(name("ns.test.")))),
            Record::from_rdata(name("ns.test."), 172800, RData::A(A::new(192, 0, 2, 53))),
            Record::from_rdata(
                name("test."),
                86400,
                RData::DNSSEC(DNSSECRData::DS(DS::new(
                    1234,
                    hickory_proto::dnssec::Algorithm::ECDSAP256SHA256,
                    hickory_proto::dnssec::DigestType::SHA256,
                    vec![0xab; 32],
                ))),
            ),
            Record::from_rdata(name("example."), 172800, RData::NS(NS(name("ns.example.")))),
            nsec(".", "example.", vec![RecordType::NS, RecordType::SOA]),
            nsec("example.", "test.", vec![RecordType::NS]),
            nsec("test.", ".", vec![RecordType::NS, RecordType::DS]),
        ];
        sign_test_zone(&Name::root(), records, now)
    }

    fn query(qname: &str, qtype: RecordType, dnssec: bool) -> Message {
        let mut msg = Message::new(7, MessageType::Query, OpCode::Query);
        msg.queries.push(Query::query(name(qname), qtype));
        let mut edns = Edns::new();
        edns.set_dnssec_ok(dnssec);
        msg.set_edns(edns);
        msg
    }

    fn types(records: &[Record]) -> Vec<RecordType> {
        records.iter().map(|r| r.record_type()).collect()
    }

    #[test]
    fn answers_like_a_root_server() {
        let now = unix_now();
        let (records, _) = test_root(now);
        let zone = RootZone::build(records, now).unwrap();
        assert_eq!(zone.tld_count(), 2);
        assert!(zone.has_tld("TEST"));
        assert!(!zone.has_tld("nope"));

        // Referral with glue and the DS (plus its signature only when DO).
        let r = zone.answer(&query("www.test.", RecordType::A, false));
        assert!(!r.metadata.authoritative);
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert_eq!(types(&r.authorities), vec![RecordType::NS]);
        assert_eq!(types(&r.additionals), vec![RecordType::A]);
        let r = zone.answer(&query("www.test.", RecordType::A, true));
        assert_eq!(types(&r.authorities), vec![RecordType::NS, RecordType::DS]);

        // Unsigned delegation: the NSEC proves there is no DS.
        let r = zone.answer(&query("example.", RecordType::NS, true));
        assert_eq!(
            types(&r.authorities),
            vec![RecordType::NS, RecordType::NSEC]
        );

        // DS is answered authoritatively by the parent.
        let r = zone.answer(&query("test.", RecordType::DS, false));
        assert!(r.metadata.authoritative);
        assert_eq!(types(&r.answers), vec![RecordType::DS]);

        // Apex data, signed when DO is set.
        let r = zone.answer(&query(".", RecordType::DNSKEY, true));
        assert!(r.metadata.authoritative);
        assert_eq!(
            types(&r.answers),
            vec![RecordType::DNSKEY, RecordType::RRSIG]
        );

        // A TLD that does not exist.
        let r = zone.answer(&query("host.nope.", RecordType::A, true));
        assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
        assert!(r.metadata.authoritative);
        assert_eq!(r.authorities[0].record_type(), RecordType::SOA);
        // The NSEC covering "nope." is example. -> test.; the apex NSEC
        // covers the wildcard.
        let nsec_owners: Vec<String> = r
            .authorities
            .iter()
            .filter(|r| r.record_type() == RecordType::NSEC)
            .map(|r| r.name.to_string())
            .collect();
        assert_eq!(nsec_owners, vec!["example.".to_string(), ".".to_string()]);
    }

    #[test]
    fn cache_file_round_trips() {
        let now = unix_now();
        let (records, anchor) = test_root(now);
        let zone = RootZone::build(records, now - 60).unwrap();
        let (fetched_at, decoded) = RootZone::decode(&zone.encode().unwrap()).unwrap();
        assert_eq!(fetched_at, now - 60);
        assert_eq!(decoded.len(), zone.record_count());
        verify_zone(&Name::root(), &decoded, &TrustAnchor::Key(anchor), now).unwrap();
        assert!(RootZone::decode(b"garbage").is_err());
    }

    #[test]
    fn expired_copy_is_not_served() {
        let now = unix_now();
        let (records, _) = test_root(now);
        let zone = RootZone::build(records, now - 604800).unwrap();
        assert!(!zone.is_current(now));
        let zone = RootZone::build(zone.records.clone(), now - 600).unwrap();
        assert!(zone.is_current(now));
    }
}
