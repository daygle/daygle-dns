//! Integration test: DNS cookies (RFC 7873). Clients that send a cookie get
//! a server cookie back (on authoritative answers too), a malformed cookie
//! gets FORMERR, and a client whose server cookie checks out gets a larger,
//! but still finite, per-client rate limit.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use hickory_proto::op::{Edns, Message, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::RecordType;

async fn query(addr: SocketAddr, name: &str, cookie: Option<Vec<u8>>) -> Message {
    let mut msg = query_message(name, RecordType::A);
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    if let Some(cookie) = cookie {
        edns.options_mut()
            .insert(EdnsOption::Unknown(u16::from(EdnsCode::Cookie), cookie));
    }
    msg.set_edns(edns);
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&msg.to_vec().unwrap(), addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .expect("answer in time")
        .unwrap();
    Message::from_vec(&buf[..n]).unwrap()
}

fn cookie_of(msg: &Message) -> Option<Vec<u8>> {
    match msg.edns.as_ref()?.option(EdnsCode::Cookie)? {
        EdnsOption::Unknown(_, data) => Some(data.clone()),
        _ => None,
    }
}

#[tokio::test]
async fn cookies_are_answered_and_trusted() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    cfg.rate_limit.enabled = true;
    cfg.rate_limit.exempt_loopback = false;
    cfg.rate_limit.client_max_queries = 3;
    cfg.rate_limit.client_window_secs = 60;
    cfg.rate_limit.domain_max_queries = 1000;
    let server = spawn(cfg).await;
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "cookie.test".into(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "www".into(),
                rtype: "A".into(),
                content: "192.0.2.53".into(),
                ttl: 60,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();
    let udp = server.udp_addr.unwrap();
    let client_cookie = vec![9, 8, 7, 6, 5, 4, 3, 2];

    // First contact: client cookie only. The (authoritative) answer brings
    // our client cookie back with a server cookie.
    let msg = query(udp, "www.cookie.test.", Some(client_cookie.clone())).await;
    assert_eq!(msg.answers.len(), 1);
    let cookie = cookie_of(&msg).expect("server cookie");
    assert_eq!(cookie.len(), 24);
    assert_eq!(&cookie[..8], &client_cookie[..]);

    // With the server cookie, the client gets ten times the limit of 3 a
    // minute (the window is shared with its other queries).
    for _ in 0..6 {
        let msg = query(udp, "www.cookie.test.", Some(cookie.clone())).await;
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert!(cookie_of(&msg).is_some());
    }
    // Without one it does.
    let mut codes = Vec::new();
    for _ in 0..5 {
        codes.push(
            query(udp, "www.cookie.test.", None)
                .await
                .metadata
                .response_code,
        );
    }
    assert!(codes.contains(&ResponseCode::ServFail), "{codes:?}");
    // ... and a made-up server cookie does not help.
    let mut forged = cookie.clone();
    forged[23] ^= 0xff;
    let msg = query(udp, "www.cookie.test.", Some(forged)).await;
    assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);

    // The larger allowance (30 a minute here) still ends: keep querying with
    // the cookie and it is refused before another 30 get through.
    let mut admitted = 0;
    let refused = loop {
        let msg = query(udp, "www.cookie.test.", Some(cookie.clone())).await;
        if msg.metadata.response_code == ResponseCode::ServFail {
            break true;
        }
        admitted += 1;
        if admitted > 30 {
            break false;
        }
    };
    assert!(refused, "a valid cookie must not lift the limit entirely");

    // A cookie of an impossible length: FORMERR.
    let msg = query(udp, "www.cookie.test.", Some(vec![1; 9])).await;
    assert_eq!(msg.metadata.response_code, ResponseCode::FormErr);
    shutdown(server).await;
}
