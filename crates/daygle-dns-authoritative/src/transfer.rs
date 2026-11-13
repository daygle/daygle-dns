//! Zone-transfer client (AXFR/IXFR) used by secondary zones.
//!
//! DNS zone transfers run over TCP with the standard two-byte length prefix.
//! A full transfer (AXFR) streams every record of a zone; the answer section
//! begins and ends with the zone SOA. IXFR requests can be answered with a
//! single SOA (no change, or "ask again with AXFR"), a full transfer, or
//! incremental deltas. As a server Daygle answers IXFR with deltas from the
//! zone's change journal, falling back to a full transfer when the journal
//! cannot reach the client's serial; as a client it applies the deltas and
//! falls back to AXFR for anything it does not apply.
//!
//! With a TSIG key the request is signed and every reply message must
//! verify, chained from the request (RFC 8945).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use daygle_dns_core::error::{DaygleError, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use daygle_dns_core::config::TransferMaster;

use crate::tsig::{ResponseVerifier, TsigKey};

/// Minimal DNS-over-TCP transfer client.
#[derive(Clone)]
pub struct XfrClient {
    /// Per-read timeout for the transfer connection.
    timeout: Duration,
    /// Extra XoT trust anchors (from `authoritative.xot_ca_certs`), on top of
    /// the public roots. Swappable so a console change applies without a
    /// restart.
    xot_ca: Arc<arc_swap::ArcSwap<Vec<rustls::pki_types::CertificateDer<'static>>>>,
}

impl std::fmt::Debug for XfrClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XfrClient")
            .field("timeout", &self.timeout)
            .field("xot_ca_certs", &self.xot_ca.load().len())
            .finish()
    }
}

/// Load PEM certificate files as XoT trust anchors.
///
/// These are trusted *in addition to* the public roots: a private CA for an
/// internal master. A missing or unreadable file is an error, so a typo is
/// reported where the setting is saved rather than as a failed transfer.
pub fn load_xot_ca_certs(
    paths: &[String],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;

    let mut certs = Vec::new();
    for path in paths {
        let path = path.trim();
        if path.is_empty() {
            continue;
        }
        let entries = rustls::pki_types::CertificateDer::pem_file_iter(path)
            .map_err(|e| DaygleError::Config(format!("cannot read XoT CA file '{path}': {e}")))?;
        let mut found = 0;
        for entry in entries {
            certs.push(entry.map_err(|e| {
                DaygleError::Tls(format!("cannot parse a certificate in '{path}': {e}"))
            })?);
            found += 1;
        }
        if found == 0 {
            return Err(DaygleError::Config(format!(
                "no PEM certificates found in XoT CA file '{path}'"
            )));
        }
    }
    Ok(certs)
}

impl Default for XfrClient {
    fn default() -> Self {
        Self::new(Duration::from_secs(10))
    }
}

/// Anything a transfer can be sent to: a plain address, or a master whose
/// entry asked for TLS (XoT, RFC 9103).
pub trait TransferTarget {
    fn target(&self) -> TransferMaster;
}

impl TransferTarget for SocketAddr {
    fn target(&self) -> TransferMaster {
        TransferMaster {
            addr: *self,
            tls_name: None,
        }
    }
}

impl TransferTarget for TransferMaster {
    fn target(&self) -> TransferMaster {
        self.clone()
    }
}

impl TransferTarget for &TransferMaster {
    fn target(&self) -> TransferMaster {
        (*self).clone()
    }
}

/// The ALPN protocol identifier for zone transfers over TLS (RFC 9103).
const XOT_ALPN: &[u8] = b"xot";

/// Boxed transfer stream: plain TCP, or TLS when the master asked for it.
type TransferIo = Box<dyn TransferStream>;

trait TransferStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TransferStream for T {}

/// The client TLS configuration for XoT: public roots plus `ca`, and the
/// `xot` ALPN.
fn xot_client_config(
    ca: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<rustls::ClientConfig> {
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in ca {
        roots
            .add(cert.clone())
            .map_err(|e| DaygleError::Tls(format!("cannot use an XoT CA certificate: {e}")))?;
    }
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| DaygleError::Tls(format!("TLS client setup failed: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![XOT_ALPN.to_vec()];
    Ok(config)
}

impl XfrClient {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            xot_ca: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
        }
    }

    /// Trust the PEM certificates in `paths` for XoT masters, replacing any
    /// previous extra anchors. The public roots stay trusted either way.
    pub fn set_xot_ca_certs(&self, paths: &[String]) -> Result<()> {
        self.xot_ca.store(Arc::new(load_xot_ca_certs(paths)?));
        Ok(())
    }

    /// Query the SOA record of `zone` from `master`.
    ///
    /// Returns `None` when the response carries no SOA (e.g. an error or an
    /// authoritative NXDOMAIN).
    pub async fn query_soa(
        &self,
        master: impl TransferTarget,
        zone: &Name,
    ) -> Result<Option<Record>> {
        self.query_soa_signed(master, zone, None).await
    }

    /// [`Self::query_soa`], signed with `tsig` when given.
    pub async fn query_soa_signed(
        &self,
        master: impl TransferTarget,
        zone: &Name,
        tsig: Option<&TsigKey>,
    ) -> Result<Option<Record>> {
        let master = master.target();
        let msg = build_query(zone, RecordType::SOA);
        let records = self.request(&master, &msg, 1, tsig, true).await?;
        Ok(records
            .iter()
            .find(|r| r.record_type() == RecordType::SOA && r.name == *zone)
            .cloned())
    }

    /// Perform a full AXFR of `zone` from `master`.
    ///
    /// Returns every record in the transfer (including the SOA that both
    /// opens and closes the transfer). Records from multi-message transfers
    /// are concatenated in order.
    pub async fn axfr(&self, master: impl TransferTarget, zone: &Name) -> Result<Vec<Record>> {
        self.axfr_signed(master, zone, None).await
    }

    /// [`Self::axfr`], signed with `tsig` when given.
    pub async fn axfr_signed(
        &self,
        master: impl TransferTarget,
        zone: &Name,
        tsig: Option<&TsigKey>,
    ) -> Result<Vec<Record>> {
        let master = master.target();
        let msg = build_query(zone, RecordType::AXFR);
        let records = self
            .request(&master, &msg, u16::MAX as usize, tsig, false)
            .await?;
        validate_axfr(zone, &records)?;
        Ok(records)
    }

    /// Synchronize `zone` from `master` with IXFR from `current_serial`.
    ///
    /// The master answers with the whole zone (RFC 1995 §4 permits that), with
    /// difference sequences, or with a single SOA when this copy is current.
    pub async fn ixfr(
        &self,
        master: impl TransferTarget,
        zone: &Name,
        current_serial: u32,
        tsig: Option<&TsigKey>,
    ) -> Result<Ixfr> {
        let master = master.target();
        let mut query = build_query(zone, RecordType::IXFR);
        // IXFR carries the client's current serial in the authority section.
        query.add_authority(soa_record(zone, current_serial));
        let answers = self
            .request(&master, &query, u16::MAX as usize, tsig, true)
            .await?;
        match parse_ixfr(zone, current_serial, &answers)? {
            // A lone newer SOA means "too big for IXFR here, use AXFR"
            // (RFC 1995 §4): fetch the zone in full.
            ParsedIxfr::AskForFull => self.axfr_signed(&master, zone, tsig).await.map(Ixfr::Full),
            ParsedIxfr::UpToDate => Ok(Ixfr::UpToDate),
            ParsedIxfr::Full(records) => Ok(Ixfr::Full(records)),
            ParsedIxfr::Delta(deltas) => Ok(Ixfr::Delta(deltas)),
        }
    }

    /// Open a TCP connection and perform a query, reading up to `max_messages`
    /// response messages. Returns the concatenated answer records.
    ///
    /// `lone_soa_ends`: a first message holding just the SOA is the whole
    /// reply (SOA queries, IXFR "no change"). For AXFR it is only the start:
    /// some servers send the opening SOA in a message of its own.
    async fn request(
        &self,
        master: &TransferMaster,
        query: &Message,
        max_messages: usize,
        tsig: Option<&TsigKey>,
        lone_soa_ends: bool,
    ) -> Result<Vec<Record>> {
        let master = master.clone();
        let mut stream = self.connect(&master).await?;

        let (bytes, mut verifier) = match tsig {
            Some(key) => {
                let (wire, mac) = crate::tsig::sign_request_with_mac(query, key)
                    .map_err(|e| DaygleError::Proto(format!("sign query: {e}")))?;
                (wire, Some(ResponseVerifier::new(key.clone(), mac)))
            }
            None => (
                query
                    .to_vec()
                    .map_err(|e| DaygleError::Proto(format!("encode query: {e}")))?,
                None,
            ),
        };
        let mut framed = Vec::with_capacity(bytes.len() + 2);
        framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        framed.extend_from_slice(&bytes);
        tokio::time::timeout(self.timeout, stream.write_all(&framed))
            .await
            .map_err(|_| DaygleError::Proto("write query timed out".to_string()))?
            .map_err(|e| DaygleError::Proto(format!("write query: {e}")))?;

        // For AXFR/IXFR the transfer can span many messages; the terminating
        // SOA is the last record of the last message. We keep reading until we
        // see a message whose final answer record is an SOA.
        let mut all_answers = Vec::new();
        let mut start_soa_serial: Option<u32> = None;
        let mut messages = 0;
        loop {
            messages += 1;
            if messages > max_messages {
                return Err(DaygleError::Proto(format!(
                    "transfer from {master} exceeded {max_messages} messages"
                )));
            }

            let (raw, message) = self.read_message(&mut stream).await?;
            if let Some(verifier) = verifier.as_mut() {
                verifier.verify(&raw).map_err(|e| {
                    DaygleError::Proto(format!("TSIG check of the reply from {master} failed: {e}"))
                })?;
            }
            if message.metadata.message_type != MessageType::Response
                || message.metadata.op_code != query.metadata.op_code
                || message.metadata.id != query.metadata.id
                || (!message.queries.is_empty() && message.queries != query.queries)
            {
                return Err(DaygleError::Proto(format!(
                    "response from {master} does not match the query"
                )));
            }
            if message.metadata.response_code != hickory_proto::op::ResponseCode::NoError {
                return Err(DaygleError::Proto(format!(
                    "master {master} answered {}",
                    message.metadata.response_code
                )));
            }
            if message.metadata.truncation {
                return Err(DaygleError::Proto(format!(
                    "truncated transfer from {master}"
                )));
            }

            let answers = message.answers;
            // Remember the serial of the opening SOA so we can detect the
            // closing SOA that terminates the transfer.
            if start_soa_serial.is_none() {
                start_soa_serial = answers
                    .iter()
                    .find(|r| r.record_type() == RecordType::SOA)
                    .and_then(|r| match &r.data {
                        RData::SOA(soa) => Some(soa.serial),
                        _ => None,
                    });
            }
            // The transfer ends when the last record of a message is an SOA
            // with the same serial as the opening SOA. A message with no
            // answers at all (e.g. NXDOMAIN with the SOA in the authority
            // section) also ends the exchange.
            let seen = all_answers.len() + answers.len();
            let is_terminal = answers.is_empty()
                || answers.last().is_some_and(|last| {
                    last.record_type() == RecordType::SOA
                        && match (&last.data, start_soa_serial) {
                            (RData::SOA(soa), Some(start)) => soa.serial == start,
                            _ => false,
                        }
                        && (seen > 1 || lone_soa_ends)
                });
            all_answers.extend(answers);

            if is_terminal {
                break;
            }
        }
        if let Some(verifier) = &verifier {
            verifier.finish().map_err(|e| {
                DaygleError::Proto(format!("TSIG check of the reply from {master} failed: {e}"))
            })?;
        }

        Ok(all_answers)
    }

    /// Open the transfer connection: plain TCP, or TLS when the master asked
    /// for it (RFC 9103), verified against its name and public roots.
    async fn connect(&self, master: &TransferMaster) -> Result<TransferIo> {
        let stream =
            tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(master.addr))
                .await
                .map_err(|_| {
                    DaygleError::Proto(format!("connect to master {} timed out", master.addr))
                })?
                .map_err(|e| {
                    DaygleError::Proto(format!("cannot connect to master {}: {e}", master.addr))
                })?;
        let Some(name) = master.tls_name.as_deref() else {
            return Ok(Box::new(stream));
        };
        let server_name = rustls::pki_types::ServerName::try_from(name.to_string())
            .map_err(|e| DaygleError::Proto(format!("bad master name '{name}': {e}")))?;
        let anchors = self.xot_ca.load_full();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(xot_client_config(&anchors)?));
        let stream = tokio::time::timeout(self.timeout, connector.connect(server_name, stream))
            .await
            .map_err(|_| {
                DaygleError::Proto(format!("TLS handshake with {} timed out", master.addr))
            })?
            .map_err(|e| {
                DaygleError::Proto(format!("TLS handshake with {} failed: {e}", master.addr))
            })?;
        Ok(Box::new(stream))
    }

    async fn read_message(&self, stream: &mut TransferIo) -> Result<(Vec<u8>, Message)> {
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| DaygleError::Proto("read length timed out".to_string()))?
            .map_err(|e| DaygleError::Proto(format!("read length: {e}")))?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut body))
            .await
            .map_err(|_| DaygleError::Proto("read message timed out".to_string()))?
            .map_err(|e| DaygleError::Proto(format!("read message: {e}")))?;
        let message = Message::from_vec(&body)
            .map_err(|e| DaygleError::Proto(format!("decode message: {e}")))?;
        Ok((body, message))
    }
}

/// What an IXFR exchange produced.
#[derive(Debug, Clone, PartialEq)]
pub enum Ixfr {
    /// The master's copy is not newer: nothing to do.
    UpToDate,
    /// The whole zone, SOA first and last.
    Full(Vec<Record>),
    /// Difference sequences, oldest first.
    Delta(Vec<IxfrDelta>),
}

/// One difference sequence (RFC 1995 §4): the records removed and added
/// between two consecutive SOA serials, with the SOA of the newer version.
#[derive(Debug, Clone, PartialEq)]
pub struct IxfrDelta {
    pub from_serial: u32,
    pub to_serial: u32,
    pub new_soa: Record,
    pub deleted: Vec<Record>,
    pub added: Vec<Record>,
}

enum ParsedIxfr {
    UpToDate,
    AskForFull,
    Full(Vec<Record>),
    Delta(Vec<IxfrDelta>),
}

fn soa_serial(record: &Record) -> Option<u32> {
    match &record.data {
        RData::SOA(soa) => Some(soa.serial),
        _ => None,
    }
}

/// Read an IXFR answer (RFC 1995 §4).
///
/// The answer is either one SOA (nothing to send, or "ask again with AXFR"),
/// a full zone (SOA, records, SOA), or the current SOA followed by difference
/// sequences and a closing copy of the current SOA.
fn parse_ixfr(zone: &Name, current_serial: u32, answers: &[Record]) -> Result<ParsedIxfr> {
    let Some(first) = answers.first() else {
        return Err(DaygleError::Proto("empty IXFR response".to_string()));
    };
    if first.name != *zone || first.dns_class != hickory_proto::rr::DNSClass::IN {
        return Err(DaygleError::Proto(
            "IXFR SOA does not match the requested zone".to_string(),
        ));
    }
    let Some(target) = soa_serial(first) else {
        return Err(DaygleError::Proto(
            "IXFR response does not start with an SOA".to_string(),
        ));
    };

    if answers.len() == 1 {
        return Ok(if crate::secondary::serial_newer(target, current_serial) {
            ParsedIxfr::AskForFull
        } else {
            ParsedIxfr::UpToDate
        });
    }
    // A full transfer repeats the SOA at both ends and starts with records.
    if soa_serial(&answers[1]).is_none() {
        validate_axfr(zone, answers)?;
        return Ok(ParsedIxfr::Full(answers.to_vec()));
    }

    let mut deltas = Vec::new();
    let mut i = 1;
    let mut expected_from = current_serial;
    while i < answers.len() {
        // The closing copy of the master's current SOA ends the answer.
        if soa_serial(&answers[i]) == Some(target) && i + 1 == answers.len() {
            break;
        }
        let Some(from_serial) = soa_serial(&answers[i]) else {
            return Err(DaygleError::Proto(
                "IXFR difference sequence does not start with an SOA".to_string(),
            ));
        };
        if from_serial != expected_from {
            return Err(DaygleError::Proto(format!(
                "IXFR difference sequence starts at serial {from_serial}, expected {expected_from}"
            )));
        }
        i += 1;
        let mut deleted = Vec::new();
        while i < answers.len() && soa_serial(&answers[i]).is_none() {
            deleted.push(answers[i].clone());
            i += 1;
        }
        let Some(new_soa) = answers.get(i).cloned() else {
            return Err(DaygleError::Proto(
                "IXFR difference sequence has no closing SOA".to_string(),
            ));
        };
        let Some(to_serial) = soa_serial(&new_soa) else {
            return Err(DaygleError::Proto(
                "IXFR difference sequence does not end with an SOA".to_string(),
            ));
        };
        i += 1;
        let mut added = Vec::new();
        while i < answers.len() && soa_serial(&answers[i]).is_none() {
            added.push(answers[i].clone());
            i += 1;
        }
        if !crate::secondary::serial_newer(to_serial, from_serial) {
            return Err(DaygleError::Proto(format!(
                "IXFR difference sequence {from_serial} -> {to_serial} does not advance"
            )));
        }
        expected_from = to_serial;
        deltas.push(IxfrDelta {
            from_serial,
            to_serial,
            new_soa,
            deleted,
            added,
        });
    }
    if deltas.is_empty() {
        return Err(DaygleError::Proto(
            "IXFR response carried no difference sequences".to_string(),
        ));
    }
    if expected_from != target {
        return Err(DaygleError::Proto(format!(
            "IXFR difference sequences end at serial {expected_from}, not {target}"
        )));
    }
    Ok(ParsedIxfr::Delta(deltas))
}

/// Reject incomplete or out-of-zone AXFR data before any caller applies it.
fn validate_axfr(zone: &Name, records: &[Record]) -> Result<()> {
    let valid = records.len() >= 2
        && records.first().is_some_and(|first| {
            first.name == *zone
                && matches!(&first.data, RData::SOA(_))
                && records
                    .last()
                    .is_some_and(|last| last.name == first.name && last.data == first.data)
        })
        && records.iter().all(|record| {
            record.dns_class == hickory_proto::rr::DNSClass::IN && zone.zone_of(&record.name)
        });
    if valid {
        Ok(())
    } else {
        Err(DaygleError::Proto(format!("invalid AXFR for zone {zone}")))
    }
}

/// Build a synthetic SOA record carrying `serial` (for the IXFR authority
/// section). The names are placeholders; only the serial is consulted.
fn soa_record(zone: &Name, serial: u32) -> Record {
    let soa = hickory_proto::rr::rdata::SOA::new(
        zone.clone(),
        zone.clone(),
        serial,
        3600,
        600,
        86400,
        3600,
    );
    Record::from_rdata(zone.clone(), 3600, RData::SOA(soa))
}

fn build_query(zone: &Name, rtype: RecordType) -> Message {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(zone.clone(), rtype));
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn axfr_requires_matching_zone_and_soa_data() {
        let zone: Name = "example.com.".parse().unwrap();
        let soa = soa_record(&zone, 7);
        let a = Record::from_rdata(
            Name::from_ascii("www.example.com.").unwrap(),
            60,
            RData::A(hickory_proto::rr::rdata::A::new(192, 0, 2, 1)),
        );
        assert!(validate_axfr(&zone, &[soa.clone(), a.clone(), soa.clone()]).is_ok());
        let foreign =
            Record::from_rdata(Name::from_ascii("other.test.").unwrap(), 60, a.data.clone());
        assert!(validate_axfr(&zone, &[soa.clone(), foreign, soa.clone()]).is_err());
        let wrong_zone: Name = "other.test.".parse().unwrap();
        let other_soa = soa_record(&wrong_zone, 7);
        assert!(validate_axfr(&zone, &[other_soa.clone(), other_soa]).is_err());
        let mut changed = soa.clone();
        if let RData::SOA(ref mut data) = changed.data {
            data.minimum += 1;
        }
        assert!(validate_axfr(&zone, &[soa.clone(), changed]).is_err());
        assert!(validate_axfr(&zone, &[soa]).is_err());
    }

    #[tokio::test]
    async fn rejects_a_response_with_the_wrong_transaction_id() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).await.unwrap();
            let mut body = vec![0; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut body).await.unwrap();
            let query = Message::from_vec(&body).unwrap();
            let mut response = Message::new(
                query.metadata.id.wrapping_add(1),
                MessageType::Response,
                OpCode::Query,
            );
            response.add_query(query.queries[0].clone());
            response.add_answer(soa_record(query.queries[0].name(), 1));
            let wire = response.to_vec().unwrap();
            stream
                .write_all(&(wire.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&wire).await.unwrap();
        });
        let zone = Name::from_ascii("example.com.").unwrap();
        assert!(XfrClient::default().query_soa(addr, &zone).await.is_err());
        server.await.unwrap();
    }

    #[test]
    fn ixfr_query_includes_serial_in_authority() {
        let zone: Name = "example.com.".parse().unwrap();
        let mut query = build_query(&zone, RecordType::IXFR);
        query.add_authority(soa_record(&zone, 42));

        let bytes = query.to_vec().unwrap();
        let decoded = Message::from_vec(&bytes).unwrap();
        assert_eq!(decoded.queries.len(), 1);
        assert_eq!(decoded.queries[0].query_type(), RecordType::IXFR);
        let soa = decoded
            .authorities
            .iter()
            .find(|r| r.record_type() == RecordType::SOA)
            .expect("SOA in authority");
        match &soa.data {
            RData::SOA(soa) => assert_eq!(soa.serial, 42),
            _ => panic!("expected SOA"),
        }
    }

    #[test]
    fn soa_record_roundtrip() {
        let zone: Name = "example.com.".parse().unwrap();
        let record = soa_record(&zone, 7);
        match &record.data {
            RData::SOA(soa) => assert_eq!(soa.serial, 7),
            _ => panic!("expected SOA"),
        }
    }
}
