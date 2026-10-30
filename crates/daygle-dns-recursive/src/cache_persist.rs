//! Forward-cache persistence: the resolver's cache assistant snapshots
//! (answers with their remaining TTLs, and cached failures) written to a
//! file on shutdown and reloaded on startup, so a restart does not begin
//! with an empty cache (and no serve-stale safety net while it re-warms).
//!
//! The file format is the one the local root zone's cache file uses
//! (`crate`-adjacent `root_zone` pattern in daygle-dns-authoritative): a
//! magic header, then uncompressed wire-encoded records. An entry is
//! ordered fields on top of the record list, so a partial or damaged file
//! is rejected wholesale instead of silently restoring half a cache.

use std::io;
use std::path::Path;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use hickory_proto::op::Query;
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_proto::serialize::binary::{
    BinDecodable, BinDecoder, BinEncodable, BinEncoder, NameEncoding,
};
use tracing::{debug, info, warn};

use crate::cache_assist::{CacheAssistant, PersistedEntry};

/// Marks the file and its layout version.
const SNAPSHOT_MAGIC: &[u8] = b"DAYGLE-CACHE-1\n";

/// Fixed overhead of one entry: scalars only (name and records are added
/// variably and always longer than 11 octets together with them).
const ENTRY_OVERHEAD: usize = 2 + 2 + 2 + 8 + 8 + 8;

/// Write `entries` as a snapshot file, replacing any previous one
/// atomically (temp file + rename, neither readers nor a crash can observe
/// a half-written one). Returns the number of entries written.
pub fn write_snapshot(path: &Path, entries: &[PersistedEntry]) -> io::Result<usize> {
    let mut buf = Vec::with_capacity(
        entries.len().saturating_mul(ENTRY_OVERHEAD + 128) + SNAPSHOT_MAGIC.len() + 4,
    );
    buf.extend_from_slice(SNAPSHOT_MAGIC);
    buf.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for entry in entries {
        encode_entry(&mut buf, entry);
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &buf)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(entries.len())
}

/// One entry: scope, type, the (case-preserved) query name, answer and
/// failure expiries, the optional failure SOA and the answer records.
fn encode_entry(buf: &mut Vec<u8>, entry: &PersistedEntry) {
    buf.extend_from_slice(&entry.key.scope.to_be_bytes());
    buf.extend_from_slice(&entry.key.rtype.to_be_bytes());
    buf.extend_from_slice(&entry.valid_through_secs.to_be_bytes());
    buf.extend_from_slice(&entry.failure_through_secs.to_be_bytes());
    buf.push(u8::from(entry.failure_code.is_some()));
    if let Some(code) = entry.failure_code {
        buf.extend_from_slice(&code.to_be_bytes());
    }
    encode_name(buf, &entry.query.name().to_string());
    // The failure SOA, if any (also wire-encoded like every record).
    buf.push(u8::from(entry.failure_soa.is_some()));
    let records = entry.failure_soa.as_slice();
    for record in records {
        encode_record(buf, record);
    }
    buf.extend_from_slice(&(entry.answers.len() as u16).to_be_bytes());
    for record in &entry.answers {
        encode_record(buf, record);
    }
}

fn encode_name(buf: &mut Vec<u8>, name: &str) {
    let Ok(name) = Name::from_utf8(name) else {
        return;
    };
    let mut wire = Vec::with_capacity(name.len() + 1);
    let mut encoder = BinEncoder::new(&mut wire);
    encoder.set_name_encoding(NameEncoding::Uncompressed);
    if name.emit(&mut encoder).is_ok() {
        drop(encoder);
        buf.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        buf.extend_from_slice(&wire);
    } else {
        // Never happens for valid cache names; encode nothing rather than
        // corrupt the stream.
        buf.extend_from_slice(&0u16.to_be_bytes());
    }
}

fn encode_record(buf: &mut Vec<u8>, record: &Record) {
    // One encoder per record: an encoder's buffer is capped at 64 KiB.
    let mut wire = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut wire);
    encoder.set_name_encoding(NameEncoding::Uncompressed);
    if record.emit(&mut encoder).is_ok() {
        drop(encoder);
        buf.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        buf.extend_from_slice(&wire);
    } else {
        buf.extend_from_slice(&0u16.to_be_bytes());
    }
}

#[derive(Debug)]
pub struct DecodeError(String);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Parse a snapshot file. A damaged file is reported as an error once, then
/// treated as absent (nothing is restored, nothing is trusted).
pub fn read_snapshot(path: &Path) -> Result<Vec<PersistedEntry>, DecodeError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(Vec::new()); // first boot or the file was removed: fine
        }
        Err(e) => return Err(DecodeError(format!("cannot read: {e}"))),
    };
    let header = SNAPSHOT_MAGIC.len() + 4;
    if bytes.len() < header || &bytes[..SNAPSHOT_MAGIC.len()] != SNAPSHOT_MAGIC {
        return Err(DecodeError(
            "not a forward-cache snapshot file".to_string(),
        ));
    }
    let count = u32::from_be_bytes(
        bytes[header - 4..header]
            .try_into()
            .expect("4 byte count"),
    );
    // The count comes from the file: a damaged one must not make us
    // reserve gigabytes up front (an entry is at least a few dozen bytes).
    let mut entries =
        Vec::with_capacity((count as usize).min(bytes.len() / (ENTRY_OVERHEAD + 4)));
    let mut decoder = BinDecoder::new(&bytes);
    decoder
        .read_slice(header)
        .map_err(|e| DecodeError(format!("bad header: {e}")))?;

    for _ in 0..count {
        entries.push(decode_entry(&mut decoder)?);
    }
    Ok(entries)
}

fn read_u16(decoder: &mut BinDecoder) -> Result<u16, DecodeError> {
    let slice = decoder
        .read_slice(2)
        .map_err(|e| DecodeError(format!("truncated u16: {e}")))?
        .unverified();
    Ok(u16::from_be_bytes(slice.try_into().expect("2 bytes")))
}

fn read_u64(decoder: &mut BinDecoder) -> Result<u64, DecodeError> {
    let slice = decoder
        .read_slice(8)
        .map_err(|e| DecodeError(format!("truncated u64: {e}")))?
        .unverified();
    Ok(u64::from_be_bytes(slice.try_into().expect("8 bytes")))
}

fn read_name(decoder: &mut BinDecoder) -> Result<Name, DecodeError> {
    let wire_len = read_u16(decoder)? as usize;
    if wire_len == 0 {
        return Err(DecodeError("empty name".to_string()));
    }
    let slice = decoder
        .read_slice(wire_len)
        .map_err(|e| DecodeError(format!("truncated name: {e}")))?
        .unverified();
    let mut name_decoder = BinDecoder::new(slice);
    Name::read(&mut name_decoder).map_err(|e| DecodeError(format!("bad name: {e}")))
}

fn read_records(decoder: &mut BinDecoder, count: usize) -> Result<Vec<Record>, DecodeError> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let wire_len = read_u16(decoder)? as usize;
        if wire_len == 0 {
            return Err(DecodeError("empty record".to_string()));
        }        let slice = decoder
        .read_slice(wire_len)
        .map_err(|e| DecodeError(format!("truncated record: {e}")))?
        .unverified();
        let mut record_decoder = BinDecoder::new(slice);
        records.push(
            Record::read(&mut record_decoder)
                .map_err(|e| DecodeError(format!("bad record: {e}")))?,
        );
    }
    Ok(records)
}

fn decode_entry(decoder: &mut BinDecoder) -> Result<PersistedEntry, DecodeError> {
    let scope = read_u16(decoder)?;
    let rtype = read_u16(decoder)?;
    let valid_through_secs = read_u64(decoder)?;
    let failure_through_secs = read_u64(decoder)?;
    let failure_code = if read_flag(decoder)? {
        Some(read_u16(decoder)?)
    } else {
        None
    };
    let name = read_name(decoder)?;
    let failure_soa = if read_flag(decoder)? {
        Some(
            read_records(decoder, 1)?
                .pop()
                .ok_or_else(|| DecodeError("missing failure SOA".to_string()))?,
        )
    } else {
        None
    };
    let count = read_u16(decoder)? as usize;
    let answers = read_records(decoder, count)?;
    Ok(PersistedEntry {
        key: crate::cache_assist::CacheKey {
            name: name.to_string().to_ascii_lowercase(),
            rtype,
            scope,
        },
        query: Query::query(name, RecordType::from(rtype)),
        answers,
        valid_through_secs,
        failure_through_secs,
        failure_code,
        failure_soa,
    })
}

/// Read a single flag byte.
fn read_flag(decoder: &mut BinDecoder) -> Result<bool, DecodeError> {
    let slice: &[u8] = decoder
        .read_slice(1)
        .map_err(|e| DecodeError(format!("truncated flag: {e}")))?
        .unverified();
    Ok(slice[0] != 0)
}

/// Restore `path`'s snapshot into `assistant`, logging (not failing) on any
/// problem: a snapshot is a startup optimization, never a requirement.
pub fn load_cache_assistant(assistant: &CacheAssistant, path: &Path) {
    match read_snapshot(path) {
        Ok(entries) if entries.is_empty() => {
            debug!(path = %path.display(), "no forward-cache snapshot to restore");
        }
        Ok(entries) => {
            let restored = assistant.import_persisted(entries);
            info!(
                path = %path.display(),
                entries = restored,
                "forward-cache snapshot restored"
            );
        }
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "dropping unusable forward-cache snapshot"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache_assist::{cache_key, MAX_TRACKED_ENTRIES};
    use std::time::Duration;

    fn entry_a() -> PersistedEntry {
        let name = Name::from_utf8("Example.Com.").unwrap();
        let query = hickory_proto::op::Query::query(name.clone(), hickory_proto::rr::RecordType::A);
        let answers = vec![hickory_proto::rr::Record::from_rdata(
            name.clone(),
            300,
            hickory_proto::rr::RData::A(hickory_proto::rr::rdata::a::A(
                std::net::Ipv4Addr::new(192, 0, 2, 1),
            )),
        )];
        let soa_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        PersistedEntry {
            key: cache_key(&name, hickory_proto::rr::RecordType::A).scoped(7),
            query,
            answers,
            valid_through_secs: soa_at + 240,
            failure_through_secs: 0,
            failure_code: None,
            failure_soa: None,
        }
    }

    fn entry_failure() -> PersistedEntry {
        let name = Name::from_utf8("gone.example.").unwrap();
        let query = hickory_proto::op::Query::query(name.clone(), hickory_proto::rr::RecordType::AAAA);
        let soa = hickory_proto::rr::Record::from_rdata(
            Name::from_utf8("zone.example.").unwrap(),
            60,
            hickory_proto::rr::RData::SOA(hickory_proto::rr::rdata::soa::SOA::new(
                Name::from_utf8("ns.zone.example.").unwrap(),
                Name::from_utf8("host.zone.example.").unwrap(),
                1,
                7200,
                900,
                1_209_600,
                60,
            )),
        );
        PersistedEntry {
            key: cache_key(&name, hickory_proto::rr::RecordType::AAAA).scoped(0),
            query,
            answers: Vec::new(),
            valid_through_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .saturating_sub(10),
            failure_through_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 5,
            failure_code: Some(3),
            failure_soa: Some(soa),
        }
    }

    #[test]
    fn snapshot_round_trips() {
        let dir = tempdir();
        let path = dir.path().join("resolver-cache.bin");
        let entries = vec![entry_a(), entry_failure()];
        let written = write_snapshot(&path, &entries).unwrap();
        assert_eq!(written, 2);
        let restored = read_snapshot(&path).unwrap();
        assert_eq!(restored.len(), 2);
        for (a, b) in entries.iter().zip(restored.iter()) {
            assert_eq!(a.key, b.key);
            assert_eq!(a.query.name(), b.query.name());
            assert_eq!(a.valid_through_secs, b.valid_through_secs);
            assert_eq!(a.failure_through_secs, b.failure_through_secs);
            assert_eq!(a.failure_code, b.failure_code);
            assert_eq!(a.answers.len(), b.answers.len());
            assert_eq!(a.failure_soa.as_ref().map(|r| r.data.to_string()),
                       b.failure_soa.as_ref().map(|r| r.data.to_string()));
        }
    }

    #[test]
    fn missing_file_is_empty() {
        let dir = tempdir();
        assert!(read_snapshot(&dir.path().join("nope.bin")).unwrap().is_empty());
    }

    #[test]
    fn truncated_file_is_rejected() {
        let dir = tempdir();
        let path = dir.path().join("resolver-cache.bin");
        let entries = vec![entry_a(), entry_failure()];
        write_snapshot(&path, &entries).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        // Cut the file inside the second entry: framing must catch it.
        std::fs::write(&path, &bytes[..bytes.len() - 5]).unwrap();
        assert!(
            read_snapshot(&path).is_err(),
            "a torn file must not decode silently"
        );

        // A flipped magic is not a snapshot either.
        let mut bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        bytes[0] = b'X';
        std::fs::write(&path, &bytes).unwrap();
        assert!(read_snapshot(&path).is_err());
    }

    #[test]
    fn garbage_is_rejected() {
        let dir = tempdir();
        let path = dir.path().join("resolver-cache.bin");
        std::fs::write(&path, b"a handful of bytes").unwrap();
        assert!(read_snapshot(&path).is_err());
    }

    #[test]
    fn import_restores_and_prunes() {
        let assistant = CacheAssistant::new(crate::cache_assist::PrefetchConfig {
            enabled: true,
            ttl_fraction_pct: 10,
            min_queries: 1,
            window: Duration::from_secs(60),
            serve_stale_secs: 86400,
            max_cache_ttl: 0,
            failure_cache_ttl: 10,
        });
        let mut live = entry_a();
        live.key = live.key.clone().scoped(1);
        let restored = assistant.import_persisted(vec![entry_a(), live, entry_failure()]);
        assert_eq!(restored, 3);
        // A fresh answer is servable right away, keyed under its scope.
        let key = entry_a().key;
        let answer = assistant.fresh_answer(&key).expect("fresh answer");
        assert_eq!(answer.answers().len(), 1);
        // Failure replay survives the snapshot too.
        assert_eq!(assistant.cached_failure_code(&entry_failure().key), Some(3));
        // And a far-future entry is a clock anomaly, dropped.
        let mut far = entry_a();
        far.valid_through_secs += 90 * 24 * 60 * 60;
        assert_eq!(assistant.import_persisted(vec![far]), 0);
        assert!(assistant.tracked_names() >= 3);
        assert!(MAX_TRACKED_ENTRIES > 0);
    }

    fn tempdir() -> tempfile_stub::Dir {
        tempfile_stub::Dir::new()
    }

    /// Minimal scratch directory for these tests (no external dependency):
    /// unique dirs under the system temp path.
    mod tempfile_stub {
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU64, Ordering};

        pub struct Dir {
            path: PathBuf,
        }

        impl Dir {
            pub fn new() -> Self {
                static SEQ: AtomicU64 = AtomicU64::new(0);
                let path = std::env::temp_dir().join(format!(
                    "daygle-cache-persist-{}-{}",
                    std::process::id(),
                    SEQ.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&path).unwrap();
                Self { path }
            }

            pub fn path(&self) -> &Path {
                &self.path
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }
}
