//! Integration test: full recursive resolution (stub → recursive resolver →
//! upstream authoritative server) without requiring internet access.

mod common;

use common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

#[tokio::test]
async fn recursively_resolves_through_local_upstream() {
    let dir = tempfile::tempdir().unwrap();
    let upstream_db = dir.path().join("upstream.db");
    let upstream = spawn_upstream(&upstream_db, "upstream.test", "198.51.100.9").await;

    let mut config = base_config(&dir.path().join("daygle.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    config.recursive.attempts = 2;
    config.recursive.timeout_secs = 3;

    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    // Cold miss → recursive → upstream.
    let msg = udp_query(udp, "host.upstream.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.9"));
    assert!(msg.recursion_available);
    assert_eq!(server.metrics.snapshot().recursive, 1);

    shutdown(server).await;
}
