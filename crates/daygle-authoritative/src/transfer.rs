//! Zone-transfer client (AXFR/IXFR) used by secondary zones.
//!
//! DNS zone transfers run over TCP with the standard two-byte length prefix.
//! A full transfer (AXFR) streams every record of a zone; the answer section
//! begins and ends with the zone SOA. IXFR requests can be answered with a
//! single SOA (no change), a full transfer, or incremental deltas; Daygle
//! answers IXFR with a full transfer (always valid per RFC 1995), and this
//! client falls back to AXFR when it detects an incremental response it does
//! not apply.

use std::net::SocketAddr;
use std::time::Duration;

use daygle_core::error::{DaygleError, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

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
        let msg = build_query(zone, RecordType::SOA);
        let records = self.request(master, &msg, 1).await?;
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
        let msg = build_query(zone, RecordType::AXFR);
        self.request(master, &msg, u16::MAX as usize).await
    }

    /// Synchronize `zone` from `master`, preferring IXFR when `current_serial`
    /// is known.
    ///
    /// Returns the records to apply: empty when the master reports no changes
    /// (single SOA), or the full zone when the master answered with a full
    /// transfer. If the master sends incremental deltas (more than two SOA
    /// records), this client falls back to a plain AXFR.
    pub async fn ixfr_or_axfr(
        &self,
        master: SocketAddr,
        zone: &Name,
        current_serial: Option<u32>,
    ) -> Result<Vec<Record>> {
        let mut query = build_query(zone, RecordType::IXFR);
        // IXFR carries the client's current serial in the authority section.
        if let Some(serial) = current_serial {
            if let Ok(soa) = soa_record(zone, serial) {
                query.add_authority(soa);
            }
        }
        let answers = self.request(master, &query, u16::MAX as usize).await?;

        let soa_count = answers
            .iter()
            .filter(|r| r.record_type() == RecordType::SOA)
            .count();

        match soa_count {
            // No changes: a single SOA, no other records.
            1 if answers.len() == 1 => Ok(vec![]),
            // Full transfer: SOA opens and closes, records in between.
            2 => Ok(answers),
            // Incremental deltas we do not apply: fall back to AXFR.
            _ => {
                debug!(%zone, %master, "IXFR returned an incremental response; falling back to AXFR");
                self.axfr(master, zone).await
            }
        }
    }

    /// Open a TCP connection and perform a query, reading up to `max_messages`
    /// response messages. Returns the concatenated answer records.
    async fn request(
        &self,
        master: SocketAddr,
        query: &Message,
        max_messages: usize,
    ) -> Result<Vec<Record>> {
        let mut stream = tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(master))
            .await
            .map_err(|_| DaygleError::Proto(format!("connect to master {master} timed out")))?
            .map_err(|e| DaygleError::Proto(format!("cannot connect to master {master}: {e}")))?;

        let bytes = query
            .to_vec()
            .map_err(|e| DaygleError::Proto(format!("encode query: {e}")))?;
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

            let message = self.read_message(&mut stream).await?;
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
            let is_terminal = answers.is_empty()
                || answers.last().is_some_and(|last| {
                    last.record_type() == RecordType::SOA
                        && match (&last.data, start_soa_serial) {
                            (RData::SOA(soa), Some(start)) => soa.serial == start,
                            _ => false,
                        }
                });
            all_answers.extend(answers);

            if is_terminal {
                break;
            }
        }

        Ok(all_answers)
    }

    async fn read_message(
        &self,
        stream: &mut tokio::net::TcpStream,
    ) -> Result<Message> {
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
        Message::from_vec(&body).map_err(|e| DaygleError::Proto(format!("decode message: {e}")))
    }
}

/// Build a synthetic SOA record carrying `serial` (for the IXFR authority
/// section). The names are placeholders; only the serial is consulted.
fn soa_record(zone: &Name, serial: u32) -> Result<Record> {
    let soa = hickory_proto::rr::rdata::SOA::new(
        zone.clone(),
        zone.clone(),
        serial,
        3600,
        600,
        86400,
        3600,
    );
    Ok(Record::from_rdata(zone.clone(), 3600, RData::SOA(soa)))
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
        query.add_authority(soa_record(&zone, 42).unwrap());

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
        let record = soa_record(&zone, 7).unwrap();
        match &record.data {
            RData::SOA(soa) => assert_eq!(soa.serial, 7),
            _ => panic!("expected SOA"),
        }
    }
}
