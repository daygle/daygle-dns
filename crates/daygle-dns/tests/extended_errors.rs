//! Integration test: responses carry an Extended DNS Error (RFC 8914) that
//! says why (blocked, filtered, refused, failed upstream), for clients that
//! sent EDNS; clients that did not get no OPT record at all.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use daygle_dns_core::config::{RecursionAccess, ResolutionMode};
use hickory_proto::op::{Edns, Message, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::RecordType;

/// Send `name`/`rtype` over UDP with EDNS and return the response.
async fn query_edns(addr: SocketAddr, name: &str, rtype: RecordType) -> Message {
    let mut msg = query_message(name, rtype);
    msg.metadata.recursion_desired = true;
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    msg.set_edns(edns);
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&msg.to_vec().unwrap(), addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut buf))
        .await
        .expect("answer in time")
        .unwrap();
    Message::from_vec(&buf[..n]).unwrap()
}

/// The EDE info code and text in a response, if any.
fn ede(msg: &Message) -> Option<(u16, String)> {
    match msg.edns.as_ref()?.option(EdnsCode::Unknown(15))? {
        EdnsOption::Unknown(15, data) if data.len() >= 2 => Some((
            u16::from_be_bytes([data[0], data[1]]),
            String::from_utf8_lossy(&data[2..]).into_owned(),
        )),
        _ => None,
    }
}

#[tokio::test]
async fn responses_explain_themselves() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    cfg.policy.blocklist = vec!["*.ads.example".to_string()];
    cfg.policy.filter_aaaa = true;
    let server = spawn(cfg).await;
    let udp = server.udp_addr.unwrap();

    // Blocked by the blocklist: NXDOMAIN, EDE 15 (Blocked) with the reason.
    let msg = query_edns(udp, "banner.ads.example.", RecordType::A).await;
    assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
    let (code, text) = ede(&msg).expect("EDE on a blocked answer");
    assert_eq!(code, 15);
    assert!(!text.is_empty());
    // The response offers EDNS back, echoing the client's.
    assert!(msg.edns.as_ref().unwrap().max_payload() >= 512);

    // AAAA filtering: NODATA, EDE 17 (Filtered).
    let msg = query_edns(udp, "dual.example.", RecordType::AAAA).await;
    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    assert_eq!(ede(&msg).map(|e| e.0), Some(17));

    // Recursion off and not authoritative: REFUSED, EDE 20 (Not
    // Authoritative).
    let msg = query_edns(udp, "example.com.", RecordType::A).await;
    assert_eq!(msg.metadata.response_code, ResponseCode::Refused);
    assert_eq!(ede(&msg).map(|e| e.0), Some(20));

    // A client that sent no EDNS gets no OPT record.
    let msg = udp_query(udp, "banner.ads.example.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);
    assert!(msg.edns.is_none());
    shutdown(server).await;

    // Recursion not allowed for this client: EDE 18 (Prohibited). An
    // upstream that never answers: SERVFAIL, EDE 22 (No Reachable
    // Authority).
    let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    cfg.recursive.enabled = true;
    cfg.recursive.mode = Some(ResolutionMode::Forwarding);
    cfg.recursive.upstreams = vec![dead.local_addr().unwrap().to_string()];
    cfg.recursive.timeout_secs = 1;
    cfg.recursive.attempts = 1;
    cfg.recursive.dnssec_validate = false;
    cfg.recursive.serve_stale_secs = 0;
    cfg.server.client_timeout_ms = 1500;
    cfg.recursive.recursion_access = RecursionAccess::Custom;
    cfg.recursive.recursion_networks = vec!["127.0.0.1/32".to_string()];
    let server = spawn(cfg).await;
    let udp = server.udp_addr.unwrap();
    let msg = query_edns(udp, "nowhere.example.", RecordType::A).await;
    assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(ede(&msg).map(|e| e.0), Some(22));
    let mut other = query_message("nowhere.example.", RecordType::A);
    other.set_edns(Edns::new());
    let socket = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
    socket.send_to(&other.to_vec().unwrap(), udp).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let msg = Message::from_vec(&buf[..n]).unwrap();
    assert_eq!(msg.metadata.response_code, ResponseCode::Refused);
    assert_eq!(ede(&msg).map(|e| e.0), Some(18));
    shutdown(server).await;
    drop(dead);
}
