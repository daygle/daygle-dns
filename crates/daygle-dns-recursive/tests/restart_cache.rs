//! Restart survival: a cache snapshot written from one resolver must keep
//! answering (and keep a flaky upstream un-bothered) after being loaded
//! into a fresh one, exactly as a restart would.
//!
//! The stub counts the queries it sees, so a lookup answered from a
//! restored cache entry is distinguishable from one that traveled.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use daygle_dns_core::config::RecursiveSettings;
use daygle_dns_core::Metrics;
use daygle_dns_recursive::persistence::read_snapshot;
use daygle_dns_recursive::RecursiveResolver;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_resolver::lookup::Lookup;

/// A UDP DNS stub answering `host.<zone>.` with a fixed A record and
/// NXDOMAIN for everything else, counting the queries it receives.
async fn spawn_stub(zone: &str, ip: &str) -> (SocketAddr, Arc<AtomicUsize>) {
    let suffix = format!(".{zone}.");
    let ip: std::net::Ipv4Addr = ip.parse().unwrap();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let counters = queries.clone();
    let mut buf = vec![0u8; 4096];

    tokio::spawn(async move {
        loop {
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(_) => return,
            };
            let Ok(query) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            counters.fetch_add(1, Ordering::SeqCst);
            let mut response = Message::new(
                query.metadata.id,
                MessageType::Response,
                query.metadata.op_code,
            );
            response.metadata.recursion_available = true;
            for q in query.queries.iter() {
                let qname = q.name().to_string();
                response.queries.push(q.clone());
                if qname.ends_with(&suffix) {
                    response.metadata.response_code = ResponseCode::NoError;
                    let record = Record::from_rdata(q.name().clone(), 60, RData::A(ip.into()));
                    response.answers.push(record);
                } else {
                    response.metadata.response_code = ResponseCode::NXDomain;
                }
            }
            let bytes = response.to_vec().unwrap();
            if socket.send_to(&bytes, peer).await.is_err() {
                return;
            }
        }
    });

    (addr, queries)
}

fn settings(upstream: SocketAddr) -> RecursiveSettings {
    RecursiveSettings {
        enabled: true,
        use_system_config: false,
        upstreams: vec![upstream.to_string()],
        dnssec_validate: false,
        attempts: 2,
        timeout_secs: 3,
        persist_cache: true,
        ..Default::default()
    }
}

fn scratch_file(tag: &str) -> std::path::PathBuf {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "daygle-restart-cache-{}-{}-{tag}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    path
}

fn first_ip(lookup: &Lookup) -> String {
    lookup
        .answers()
        .first()
        .expect("at least one record")
        .data
        .to_string()
}

#[tokio::test]
async fn snapshot_warms_a_fresh_resolver() {
    let (upstream, queries) = spawn_stub("restart.test", "198.51.100.10").await;
    let snapshot = scratch_file("warm");

    // First run: resolve once (one upstream trip), then shut down.
    let resolver =
        RecursiveResolver::build(&settings(upstream), Arc::new(Metrics::default()), &[], None)
            .unwrap();
    let answer = resolver
        .lookup("host.restart.test.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(first_ip(&answer), "198.51.100.10");
    assert_eq!(queries.load(Ordering::SeqCst), 1);

    let persisted = resolver.persist_cache(&snapshot).unwrap();
    assert!(persisted >= 1, "the answered name must be in the snapshot");
    drop(resolver);

    // Second run (the restart): a fresh resolver reloads the snapshot.
    let restart =
        RecursiveResolver::build(&settings(upstream), Arc::new(Metrics::default()), &[], None)
            .unwrap();
    restart.load_cache(&snapshot);

    let answer = restart
        .lookup("host.restart.test.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(first_ip(&answer), "198.51.100.10");
    // The stub saw exactly one query across both runs: the restart served
    // from the snapshot instead of asking upstream again.
    assert_eq!(queries.load(Ordering::SeqCst), 1);

    // Cold cache behavior must stay intact: a name that was never asked
    // before the restart goes upstream (one trip), comes back NXDOMAIN and
    // surfaces as an error.
    let missing = restart.lookup("gone.restart.test.", RecordType::AAAA).await;
    assert!(missing.is_err(), "a nonexistent name must not resolve");
    // Warm answer trip + this NXDOMAIN trip: exactly two upstream visits.
    assert_eq!(queries.load(Ordering::SeqCst), 2);

    let _ = std::fs::remove_file(&snapshot);
}

#[tokio::test]
async fn sustained_entries_keep_their_ttl_budget() {
    // A higher-TTL answer survives a simulated delay between snapshot and
    // restore: expiry is absolute, so the TTL remaining shrinks with the
    // downtime instead of being reborn.
    let (upstream, queries) = spawn_stub("slow.test", "203.0.113.5").await;
    let snapshot = scratch_file("ttl");

    let resolver =
        RecursiveResolver::build(&settings(upstream), Arc::new(Metrics::default()), &[], None)
            .unwrap();
    let answer = resolver
        .lookup("host.slow.test.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(first_ip(&answer), "203.0.113.5");
    resolver.persist_cache(&snapshot).unwrap();
    drop(resolver);
    assert_eq!(queries.load(Ordering::SeqCst), 1);

    // Stand-in for the downtime before the next boot.
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // Load the file directly (as `load_cache` would) and check that time
    // kept passing: the entry must still be valid but older than before.
    let entries = read_snapshot(&snapshot).expect("the snapshot decodes");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let entry = entries
        .iter()
        .find(|e| e.key.name.ends_with("host.slow.test."))
        .expect("the name is snapshotted");
    assert!(entry.valid_through_secs > now, "still within its TTL");

    let restart =
        RecursiveResolver::build(&settings(upstream), Arc::new(Metrics::default()), &[], None)
            .unwrap();
    restart.load_cache(&snapshot);
    let answer = restart
        .lookup("host.slow.test.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(first_ip(&answer), "203.0.113.5");
    // Reloaded from the file, not from upstream.
    assert_eq!(queries.load(Ordering::SeqCst), 1);
    // And served with the TTL time actually left, not the original TTL.
    let ttl = answer.answers().first().unwrap().ttl;
    assert!(ttl < 60, "restored TTL {ttl} must be below the original 60");
    // The downtime and load overhead kept the answer nearly fresh.
    assert!(ttl > 55, "still nearly fresh (got {ttl})");

    let _ = std::fs::remove_file(&snapshot);
}

#[tokio::test]
async fn persist_cache_off_writes_nothing() {
    let (upstream, queries) = spawn_stub("off.test", "203.0.113.9").await;
    let snapshot = scratch_file("off");

    let mut cfg = settings(upstream);
    cfg.persist_cache = false;
    let resolver = RecursiveResolver::build(&cfg, Arc::new(Metrics::default()), &[], None).unwrap();
    resolver
        .lookup("host.off.test.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(queries.load(Ordering::SeqCst), 1);

    // The setting is off, so both directions are no-ops.
    assert_eq!(resolver.persist_cache(&snapshot).unwrap(), 0);
    assert!(!snapshot.exists(), "no file is written");
    drop(resolver);

    let restart = RecursiveResolver::build(&cfg, Arc::new(Metrics::default()), &[], None).unwrap();
    std::fs::write(&snapshot, b"junk-that-nobody-wrote").unwrap();
    restart.load_cache(&snapshot); // not even consulted
    let answer = restart
        .lookup("host.off.test.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(first_ip(&answer), "203.0.113.9");
    // No cache to answer from, so the stub is asked again.
    assert!(queries.load(Ordering::SeqCst) >= 2);

    let _ = std::fs::remove_file(&snapshot);
}
