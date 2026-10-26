//! Integration test: recursive mode. A fake DNS hierarchy runs on three
//! loopback addresses sharing one unprivileged port - a root server
//! (127.0.0.2), a `test.` TLD server (127.0.0.3) and an `example.test.`
//! authoritative server (127.0.0.4) - and Daygle must walk root -> TLD ->
//! authoritative to answer. Also covers recursion access control and NODATA
//! in forwarding mode.

mod common;

use std::net::{Ipv4Addr, SocketAddr};

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use daygle_dns_core::config::{
    ClientPolicyAction, ClientPolicyConfig, ConditionalZoneConfig, DaygleConfig, IpVersions,
    RecursionAccess, ResolutionMode,
};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{NS, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

const ROOT: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const TLD: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
const AUTH: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);

/// What a fake server does with one question.
enum Reply {
    /// Authoritative answer records.
    Answer(Vec<Record>),
    /// Referral: NS records in the authority section plus glue.
    Referral(Vec<Record>, Vec<Record>),
    /// Authoritative NODATA (NOERROR, no answers) with the zone SOA.
    NoData(Record),
    /// Authoritative NXDOMAIN with the zone SOA.
    NxDomain(Record),
}

fn name(n: &str) -> Name {
    Name::from_ascii(n).unwrap()
}

fn ns(owner: &str, target: &str) -> Record {
    Record::from_rdata(name(owner), 300, RData::NS(NS(name(target))))
}

fn a(owner: &str, ip: Ipv4Addr) -> Record {
    Record::from_rdata(name(owner), 300, RData::A(ip.into()))
}

fn soa(zone: &str) -> Record {
    Record::from_rdata(
        name(zone),
        300,
        RData::SOA(SOA::new(
            name(&format!("ns.{}", zone.trim_start_matches('.'))),
            name("hostmaster.example."),
            1,
            3600,
            600,
            86400,
            60,
        )),
    )
}

fn is_under(qname: &str, zone: &str) -> bool {
    qname == zone || qname.ends_with(&format!(".{zone}"))
}

/// The root zone: delegates `test.` and knows nothing else.
fn root_server(qname: &str, qtype: RecordType) -> Reply {
    if qname == "." {
        return match qtype {
            RecordType::NS => Reply::Answer(vec![ns(".", "a.root.test.")]),
            _ => Reply::NoData(soa(".")),
        };
    }
    if is_under(qname, "test.") {
        return Reply::Referral(vec![ns("test.", "ns.test.")], vec![a("ns.test.", TLD)]);
    }
    Reply::NxDomain(soa("."))
}

/// The `test.` TLD: delegates `example.test.`.
fn tld_server(qname: &str, qtype: RecordType) -> Reply {
    if qname == "test." {
        return match qtype {
            RecordType::NS => Reply::Answer(vec![ns("test.", "ns.test.")]),
            _ => Reply::NoData(soa("test.")),
        };
    }
    if qname == "ns.test." && qtype == RecordType::A {
        return Reply::Answer(vec![a("ns.test.", TLD)]);
    }
    if is_under(qname, "example.test.") {
        return Reply::Referral(
            vec![ns("example.test.", "ns.example.test.")],
            vec![a("ns.example.test.", AUTH)],
        );
    }
    Reply::NxDomain(soa("test."))
}

/// The `example.test.` zone itself.
fn auth_server(qname: &str, qtype: RecordType) -> Reply {
    match (qname, qtype) {
        ("example.test.", RecordType::NS) => {
            Reply::Answer(vec![ns("example.test.", "ns.example.test.")])
        }
        ("example.test.", RecordType::SOA) => Reply::Answer(vec![soa("example.test.")]),
        ("ns.example.test.", RecordType::A) => Reply::Answer(vec![a("ns.example.test.", AUTH)]),
        ("www.example.test.", RecordType::A) => {
            Reply::Answer(vec![a("www.example.test.", Ipv4Addr::new(198, 51, 100, 7))])
        }
        ("www.example.test." | "example.test." | "ns.example.test.", _) => {
            Reply::NoData(soa("example.test."))
        }
        _ => Reply::NxDomain(soa("example.test.")),
    }
}

/// Serve `handler` over UDP on `ip:port` until the test ends.
fn spawn_fake(socket: tokio::net::UdpSocket, handler: fn(&str, RecordType) -> Reply) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let mut response = Message::new(
                query.metadata.id,
                MessageType::Response,
                query.metadata.op_code,
            );
            response.metadata.recursion_desired = query.metadata.recursion_desired;
            for q in query.queries.iter() {
                response.queries.push(q.clone());
                let qname = q.name().to_ascii().to_ascii_lowercase();
                match handler(&qname, q.query_type()) {
                    Reply::Answer(records) => {
                        response.metadata.authoritative = true;
                        response.answers.extend(records);
                    }
                    Reply::Referral(authority, glue) => {
                        response.authorities.extend(authority);
                        response.additionals.extend(glue);
                    }
                    Reply::NoData(soa) => {
                        response.metadata.authoritative = true;
                        response.authorities.push(soa);
                    }
                    Reply::NxDomain(soa) => {
                        response.metadata.authoritative = true;
                        response.metadata.response_code = ResponseCode::NXDomain;
                        response.authorities.push(soa);
                    }
                }
            }
            if socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .is_err()
            {
                return;
            }
        }
    });
}

/// Bind the three fake servers on one port free on all three addresses.
async fn spawn_hierarchy() -> u16 {
    loop {
        let root = tokio::net::UdpSocket::bind((ROOT, 0)).await.unwrap();
        let port = root.local_addr().unwrap().port();
        let (Ok(tld), Ok(auth)) = (
            tokio::net::UdpSocket::bind((TLD, port)).await,
            tokio::net::UdpSocket::bind((AUTH, port)).await,
        ) else {
            continue;
        };
        spawn_fake(root, root_server);
        spawn_fake(tld, tld_server);
        spawn_fake(auth, auth_server);
        return port;
    }
}

fn recursive_config(dir: &tempfile::TempDir, port: u16) -> DaygleConfig {
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.mode = Some(ResolutionMode::Recursive);
    config.recursive.root_hints = vec![ROOT.to_string()];
    config.recursive.test_outbound_port = Some(port);
    // The fake hierarchy is unsigned; the built-in root trust anchor would
    // (correctly) reject it.
    config.recursive.dnssec_validate = false;
    config.recursive.timeout_secs = 2;
    config
}

#[tokio::test]
async fn recursive_mode_walks_root_tld_authoritative() {
    let port = spawn_hierarchy().await;
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(recursive_config(&dir, port)).await;
    let udp = server.udp_addr.unwrap();

    // A real answer, three delegation levels down.
    let msg = udp_query(udp, "www.example.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.7"));
    assert!(msg.recursion_available);

    // NODATA: the name exists, the type does not. Must not be NXDOMAIN.
    let msg = udp_query(udp, "www.example.test.", RecordType::AAAA).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert!(msg.answers.is_empty());

    // NXDOMAIN from the authoritative server and from the root.
    let msg = udp_query(udp, "missing.example.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);
    let msg = udp_query(udp, "host.no-such-tld.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);

    shutdown(server).await;
}

#[tokio::test]
async fn conditional_forwarder_overrides_recursive_mode() {
    let port = spawn_hierarchy().await;
    let forwarder = spawn_upstream_answering("corp.internal.", Ipv4Addr::new(10, 1, 2, 3)).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = recursive_config(&dir, port);
    config.recursive.conditional_zones = vec![ConditionalZoneConfig {
        name: "corp.internal".to_string(),
        upstreams: vec![forwarder.to_string()],
    }];
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    let msg = udp_query(udp, "host.corp.internal.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("10.1.2.3"));
    // Everything else still recurses.
    let msg = udp_query(udp, "www.example.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.7"));

    shutdown(server).await;
}

#[tokio::test]
async fn recursion_access_refuses_clients_outside_allowed_networks() {
    let port = spawn_hierarchy().await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = recursive_config(&dir, port);
    // The test client is 127.0.0.1, outside this list.
    config.recursive.recursion_access = RecursionAccess::Custom;
    config.recursive.recursion_networks = vec!["10.0.0.0/8".to_string()];
    let server = spawn(config).await;
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "local.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "host".to_string(),
                rtype: "A".to_string(),
                content: "192.0.2.9".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();
    let udp = server.udp_addr.unwrap();

    // Recursion is refused...
    let msg = udp_query(udp, "www.example.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::Refused);
    // ...but this server's own zones are answered for everyone.
    let msg = udp_query(udp, "host.local.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.9"));

    shutdown(server).await;
}

// A console save that changes Recursion Access applies to live traffic
// immediately, without a restart: the replacement resolver is built during
// the save and swapped in after the config is published, so the published
// settings and the serving resolver always move together.
#[tokio::test]
async fn save_applies_recursion_access_without_restart() {
    let upstream = spawn_upstream_answering("fwd.test.", Ipv4Addr::new(198, 51, 100, 55)).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.mode = Some(ResolutionMode::Forwarding);
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    config.recursive.timeout_secs = 2;
    // Deny from the start: recursion is served to nobody.
    config.recursive.recursion_access = RecursionAccess::Deny;
    // Real ports: validation rejects port 0, and that pre-existing error
    // would otherwise mask the result this test expects from the save.
    config.server.port = free_port();
    config.api.port = free_port();
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();
    let api = format!("http://{}/api/config", server.api_addr);
    let client = reqwest::Client::new();

    // Deny: only authoritative zones are answered, recursion is REFUSED.
    let msg = udp_query(udp, "host.fwd.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::Refused);

    // The console save that opens recursion up ("Recursion Access:
    // Allow").
    let ok = client
        .put(&api)
        .json(&serde_json::json!({ "recursive": { "recursion_access": "allow" } }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    // The next query already recurses to the upstream - no restart.
    let msg = udp_query(udp, "host.fwd.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.55"));

    // And a save that closes it applies immediately too: the upstream is
    // unreachable in test terms anyway, but the client is refused before any
    // upstream traffic.
    let ok = client
        .put(&api)
        .json(&serde_json::json!({ "recursive": { "recursion_access": "deny" } }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    let msg = udp_query(udp, "fresh.fwd.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::Refused);

    shutdown(server).await;
}

#[tokio::test]
async fn forwarding_mode_passes_nodata_through_as_noerror() {
    // The upstream knows v4only.test (A only): AAAA is NODATA, not NXDOMAIN.
    let upstream = spawn_upstream_answering("v4only.test.", Ipv4Addr::new(192, 0, 2, 44)).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.mode = Some(ResolutionMode::Forwarding);
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    let msg = udp_query(udp, "v4only.test.", RecordType::AAAA).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert!(msg.answers.is_empty());
    let msg = udp_query(udp, "v4only.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.44"));

    shutdown(server).await;
}

#[tokio::test]
async fn outbound_ip_versions_choose_which_servers_are_asked() {
    // IPv4 only: an IPv6 root hint is ignored and the IPv4 hierarchy answers.
    let port = spawn_hierarchy().await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = recursive_config(&dir, port);
    config.recursive.outbound_ip_versions = IpVersions::Ipv4;
    config.recursive.root_hints = vec!["2001:db8::53".to_string(), ROOT.to_string()];
    let server = spawn(config).await;
    let msg = udp_query(server.udp_addr.unwrap(), "www.example.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.7"));
    shutdown(server).await;

    // IPv6 only: the IPv4 root server is never asked, so nothing resolves
    // (the only IPv6 root hint has no server behind it).
    let dir = tempfile::tempdir().unwrap();
    let mut config = recursive_config(&dir, port);
    config.recursive.outbound_ip_versions = IpVersions::Ipv6;
    config.recursive.root_hints = vec![ROOT.to_string(), "::1".to_string()];
    let server = spawn(config).await;
    let msg = udp_query(server.udp_addr.unwrap(), "www.example.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::ServFail);
    shutdown(server).await;

    // Forwarding: a change that leaves no upstream of an allowed version is
    // refused; one that keeps some is applied.
    let upstream = spawn_upstream_answering("v4only.test.", Ipv4Addr::new(192, 0, 2, 44)).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.mode = Some(ResolutionMode::Forwarding);
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string(), "[2001:db8::53]:53".to_string()];
    config.recursive.dnssec_validate = false;
    let server = spawn(config).await;
    let client = reqwest::Client::new();
    let put = |versions: &'static str| {
        client
            .put(format!("http://{}/api/config", server.api_addr))
            .json(&serde_json::json!({
                "recursive": { "upstreams": ["[2001:db8::53]:53"], "outbound_ip_versions": versions }
            }))
            .send()
    };
    let resp = put("ipv4").await.unwrap();
    assert_eq!(resp.status(), 400);
    assert!(resp.text().await.unwrap().contains("IPv4"));
    let resp = client
        .put(format!("http://{}/api/config", server.api_addr))
        .json(&serde_json::json!({ "recursive": { "outbound_ip_versions": "ipv4" } }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let config: serde_json::Value = client
        .get(format!("http://{}/api/config", server.api_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(config["recursive"]["outbound_ip_versions"], "ipv4");
    let msg = udp_query(server.udp_addr.unwrap(), "v4only.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.44"));
    shutdown(server).await;
}

/// A second client address on loopback (the tests' default client is
/// 127.0.0.1).
const OTHER_CLIENT: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 5);

fn policy(
    name: &str,
    client: Ipv4Addr,
    action: ClientPolicyAction,
    upstreams: Vec<String>,
) -> ClientPolicyConfig {
    ClientPolicyConfig {
        name: name.to_string(),
        enabled: true,
        clients: vec![format!("{client}/32")],
        action,
        upstreams,
        modified_at: None,
    }
}

async fn resolver_stats(server: &daygle_dns::BoundServer) -> serde_json::Value {
    reqwest::get(format!("http://{}/api/resolver", server.api_addr))
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn client_policies_route_forward_and_refuse_per_client() {
    // Default clients forward to one upstream; the policy client to another.
    let default_upstream = spawn_upstream_answering("test.", Ipv4Addr::new(192, 0, 2, 1)).await;
    let family_upstream = spawn_upstream_answering("test.", Ipv4Addr::new(192, 0, 2, 2)).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.mode = Some(ResolutionMode::Forwarding);
    config.recursive.upstreams = vec![default_upstream.to_string()];
    config.recursive.dnssec_validate = false;
    config.recursive.client_policies = vec![policy(
        "kids",
        OTHER_CLIENT,
        ClientPolicyAction::Forward,
        vec![family_upstream.to_string()],
    )];
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    // The same name, answered per client - and not from the other's cache.
    for _ in 0..2 {
        let msg = udp_query(udp, "www.site.test.", RecordType::A).await;
        assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.1"));
        let msg = udp_query_from(OTHER_CLIENT.into(), udp, "www.site.test.", RecordType::A).await;
        assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.2"));
    }

    let stats = resolver_stats(&server).await;
    assert_eq!(stats["client_policies"], 1);
    assert_eq!(stats["stats"]["routes"]["client_policy"], 2);
    assert_eq!(stats["stats"]["routes"]["forwarding"], 2);
    assert_eq!(stats["stats"]["outcomes"]["noerror"], 4);
    let latency: u64 = stats["stats"]["latency"]["counts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_u64().unwrap())
        .sum();
    assert_eq!(latency, 4);
    shutdown(server).await;

    // A refuse policy turns the client away; everyone else still resolves.
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.mode = Some(ResolutionMode::Forwarding);
    config.recursive.upstreams = vec![default_upstream.to_string()];
    config.recursive.dnssec_validate = false;
    config.recursive.client_policies = vec![policy(
        "guests",
        OTHER_CLIENT,
        ClientPolicyAction::Refuse,
        vec![],
    )];
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();
    let msg = udp_query_from(OTHER_CLIENT.into(), udp, "www.site.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::Refused);
    let msg = udp_query(udp, "www.site.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.1"));
    shutdown(server).await;
}

#[tokio::test]
async fn recursive_client_policy_while_the_default_forwards() {
    let port = spawn_hierarchy().await;
    let upstream = spawn_upstream_answering("example.test.", Ipv4Addr::new(192, 0, 2, 9)).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = recursive_config(&dir, port);
    config.recursive.mode = Some(ResolutionMode::Forwarding);
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.client_policies = vec![policy(
        "lab",
        OTHER_CLIENT,
        ClientPolicyAction::Recursive,
        vec![],
    )];
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    // The policy client walks the fake hierarchy; others use the upstream.
    let msg = udp_query_from(OTHER_CLIENT.into(), udp, "www.example.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.7"));
    let msg = udp_query(udp, "www.example.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.9"));
    shutdown(server).await;
}

async fn cache_counters(server: &daygle_dns::BoundServer) -> (u64, u64) {
    let metrics: serde_json::Value =
        reqwest::get(format!("http://{}/api/metrics", server.api_addr))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    (
        metrics["cache_hits"].as_u64().unwrap(),
        metrics["cache_misses"].as_u64().unwrap(),
    )
}

#[tokio::test]
async fn cache_hits_and_misses_are_counted_in_both_modes() {
    // Recursive: the first lookup walks the hierarchy, the repeat is cached.
    let port = spawn_hierarchy().await;
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(recursive_config(&dir, port)).await;
    let udp = server.udp_addr.unwrap();
    let msg = udp_query(udp, "www.example.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.7"));
    assert_eq!(cache_counters(&server).await, (0, 1));
    let msg = udp_query(udp, "www.example.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.7"));
    assert_eq!(cache_counters(&server).await, (1, 1));
    shutdown(server).await;

    // Forwarding: the same through an upstream.
    let upstream = spawn_upstream_answering("site.test.", Ipv4Addr::new(192, 0, 2, 1)).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.mode = Some(ResolutionMode::Forwarding);
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();
    for expected in [(0, 1), (1, 1), (2, 1)] {
        let msg = udp_query(udp, "www.site.test.", RecordType::A).await;
        assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.1"));
        assert_eq!(cache_counters(&server).await, expected);
    }
    shutdown(server).await;
}

async fn flush_name(
    server: &daygle_dns::BoundServer,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{}/api/cache/flush", server.api_addr))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or_default())
}

#[tokio::test]
async fn flushing_one_name_drops_it_from_the_cache() {
    let upstream = spawn_upstream_answering("site.test.", Ipv4Addr::new(192, 0, 2, 1)).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.mode = Some(ResolutionMode::Forwarding);
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    for name in ["www.site.test.", "other.site.test.", "www.site.test."] {
        udp_query(udp, name, RecordType::A).await;
    }
    assert_eq!(cache_counters(&server).await, (1, 2));

    // Flushing www (all types, as typed without the trailing dot) makes the
    // next query go upstream again; other.site.test stays cached.
    let (status, body) = flush_name(&server, serde_json::json!({ "name": "WWW.site.test" })).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["complete"], true);
    udp_query(udp, "www.site.test.", RecordType::A).await;
    assert_eq!(cache_counters(&server).await, (1, 3));
    udp_query(udp, "other.site.test.", RecordType::A).await;
    assert_eq!(cache_counters(&server).await, (2, 3));

    // One type only, and input errors.
    let (status, _) = flush_name(
        &server,
        serde_json::json!({ "name": "www.site.test", "type": "aaaa" }),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = flush_name(
        &server,
        serde_json::json!({ "name": "www.site.test", "type": "NOPE" }),
    )
    .await;
    assert_eq!(status, 400);
    let (status, _) = flush_name(&server, serde_json::json!({ "name": " " })).await;
    assert_eq!(status, 400);
    shutdown(server).await;

    // Recursive mode cannot drop one entry from the recursor's cache.
    let port = spawn_hierarchy().await;
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(recursive_config(&dir, port)).await;
    let (status, body) =
        flush_name(&server, serde_json::json!({ "name": "www.example.test" })).await;
    assert_eq!(status, 200);
    assert_eq!(body["complete"], false);
    shutdown(server).await;
}

#[tokio::test]
async fn opportunistic_encryption_falls_back_to_plain_dns() {
    // The fake servers speak no TLS: probes fail and resolution carries on
    // over UDP.
    let port = spawn_hierarchy().await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = recursive_config(&dir, port);
    config.recursive.opportunistic_encryption = true;
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    let msg = udp_query(udp, "www.example.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.7"));
    let stats = resolver_stats(&server).await;
    assert_eq!(stats["opportunistic_encryption"], true);
    assert_eq!(stats["mode"], "recursive");
    assert!(
        stats["stats"]["connections"]["udp"].as_u64().unwrap() > 0,
        "{stats}"
    );
    assert!(
        stats["stats"]["routes"]["recursive"].as_u64().unwrap() >= 1,
        "{stats}"
    );
    shutdown(server).await;
}

/// A recursive upstream stub: answers A for `owner` (and names below it),
/// NODATA for other types there, NXDOMAIN elsewhere.
async fn spawn_upstream_answering(owner: &'static str, ip: Ipv4Addr) -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let mut response = Message::new(
                query.metadata.id,
                MessageType::Response,
                query.metadata.op_code,
            );
            response.metadata.recursion_available = true;
            response.metadata.recursion_desired = query.metadata.recursion_desired;
            for q in query.queries.iter() {
                response.queries.push(q.clone());
                let qname = q.name().to_ascii().to_ascii_lowercase();
                if is_under(&qname, owner) {
                    if q.query_type() == RecordType::A {
                        response.answers.push(a(&qname, ip));
                    } else {
                        response.authorities.push(soa(owner));
                    }
                } else {
                    response.metadata.response_code = ResponseCode::NXDomain;
                }
            }
            if socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .is_err()
            {
                return;
            }
        }
    });
    addr
}
