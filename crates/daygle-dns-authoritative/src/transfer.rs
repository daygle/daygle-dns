//! Zone-transfer client (AXFR/IXFR) used by secondary zones.
//!
//! DNS zone transfers run over TCP with the standard two-byte length prefix.
//! A full transfer (AXFR) streams every record of a zone; the answer section
//! begins and ends with the zone SOA. IXFR requests can be answered with a
//! single SOA (no change, or "ask again with AXFR"), a full transfer, or
//! incremental deltas; Daygle answers IXFR with a full transfer (always
//! valid per RFC 1995), and this client falls back to AXFR when it gets
//! anything it does not apply.
//!
//! With a TSIG key the request is signed and every reply message must
//! verify, chained from the request (RFC 8945).

use std::net::SocketAddr;
use std::time::Duration;

use daygle_dns_core::error::{DaygleError, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::tsig::{ResponseVerifier, TsigKey};

/// Minimal DNS-over-TCP transfer client.
#[derive(Debug, Clone)]
pub struct XfrClient {
    /// Per-read timeout for the transfer connection.
    timeout: Duration,
}

impl Default for XfrClient {
    fn default() -> Self {
        Self::new(Duration::from_secs(10))
    }
}

impl XfrClient {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Query the SOA record of `zone` from `master`.
    ///
    /// Returns `None` when the response carries no SOA (e.g. an error or an
    /// authoritative NXDOMAIN).
    pub async fn query_soa(&self, master: SocketAddr, zone: &Name) -> Result<Option<Record>> {
        self.query_soa_signed(master, zone, None).await
    }

    /// [`Self::query_soa`], signed with `tsig` when given.
    pub async fn query_soa_signed(
        &self,
        master: SocketAddr,
        zone: &Name,
        tsig: Option<&TsigKey>,
    ) -> Result<Option<Record>> {
        let msg = build_query(zone, RecordType::SOA);
        let records = self.request(master, &msg, 1, tsig, true).await?;
        Ok(records
            .iter()
            .find(|r| r.record_type() == RecordType::SOA)
            .cloned())
    }

    /// Perform a full AXFR of `zone` from `master`.
    ///
    /// Returns every record in the transfer (including the SOA that both
    /// opens and closes the transfer). Records from multi-message transfers
    /// are concatenated in order.
    pub async fn axfr(&self, master: SocketAddr, zone: &Name) -> Result<Vec<Record>> {
        self.axfr_signed(master, zone, None).await
    }

    /// [`Self::axfr`], signed with `tsig` when given.
    pub async fn axfr_signed(
        &self,
        master: SocketAddr,
        zone: &Name,
        tsig: Option<&TsigKey>,
    ) -> Result<Vec<Record>> {
        let msg = build_query(zone, RecordType::AXFR);
        self.request(master, &msg, u16::MAX as usize, tsig, false)
            .await
    }

    /// Synchronize `zone` from `master`, preferring IXFR from
    /// `current_serial`.
    ///
    /// Returns the full zone (SOA first and last), or `None` when the master
    /// says this copy is current.
    pub async fn ixfr_or_axfr(
        &self,
        master: SocketAddr,
        zone: &Name,
        current_serial: u32,
        tsig: Option<&TsigKey>,
    ) -> Result<Option<Vec<Record>>> {
        let mut query = build_query(zone, RecordType::IXFR);
        // IXFR carries the client's current serial in the authority section.
        query.add_authority(soa_record(zone, current_serial));
        let answers = self
            .request(master, &query, u16::MAX as usize, tsig, true)
            .await?;

        let soas: Vec<u32> = answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::SOA(soa) => Some(soa.serial),
                _ => None,
            })
            .collect();
        match soas.as_slice() {
            // A lone SOA no newer than ours: nothing to do. A lone newer SOA
            // means "too big for IXFR here, use AXFR" (RFC 1995 §4).
            [serial] if answers.len() == 1 => {
                if crate::secondary::serial_newer(*serial, current_serial) {
                    self.axfr_signed(master, zone, tsig).await.map(Some)
                } else {
                    Ok(None)
                }
            }
            // A full transfer: SOA opens and closes, records in between.
            [_, _] => Ok(Some(answers)),
            // Incremental deltas we do not apply: fall back to AXFR.
            _ => {
                debug!(%zone, %master, "IXFR returned an incremental response; falling back to AXFR");
                self.axfr_signed(master, zone, tsig).await.map(Some)
            }
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
        master: SocketAddr,
        query: &Message,
        max_messages: usize,
        tsig: Option<&TsigKey>,
        lone_soa_ends: bool,
    ) -> Result<Vec<Record>> {
        let mut stream = tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(master))
            .await
            .map_err(|_| DaygleError::Proto(format!("connect to master {master} timed out")))?
            .map_err(|e| DaygleError::Proto(format!("cannot connect to master {master}: {e}")))?;

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

    async fn read_message(&self, stream: &mut tokio::net::TcpStream) -> Result<(Vec<u8>, Message)> {
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
