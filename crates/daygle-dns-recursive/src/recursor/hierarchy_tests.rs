//! The recursor against small fake DNS hierarchies on loopback: one UDP
//! server per address, all on one port, which outbound queries are
//! redirected to (see `test_outbound_port`).
//!
//! These cover the patched walk in `vendor/hickory-resolver` and validator
//! in `vendor/hickory-net` (see `vendor/README.md`).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use daygle_dns_core::config::RecursiveSettings;
use daygle_dns_core::Metrics;
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME, NS};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use super::{build, lookup, trace_queries, RecursorSlot, TraceStep};

fn name(n: &str) -> Name {
    Name::from_ascii(n).unwrap()
}

/// What one fake server sends back for a question.
enum Reply {
    /// Nothing, as a dead name server on stale glue.
    Silent,
    Message(Message),
}

type Handler = Arc<dyn Fn(&Query) -> Reply + Send + Sync>;

/// A referral to `zone`, with glue for the name servers given an address.
fn referral(zone: &str, servers: &[(&str, Option<Ipv4Addr>)]) -> Reply {
    let mut message = Message::query();
    for (ns, address) in servers {
        message.add_authority(Record::from_rdata(name(zone), 300, RData::NS(NS(name(ns)))));
        if let Some(address) = address {
            message.add_additional(Record::from_rdata(name(ns), 300, RData::A(A(*address))));
        }
    }
    Reply::Message(message)
}

/// An authoritative answer of `records` (empty: no data).
fn answer(records: Vec<Record>) -> Reply {
    let mut message = Message::query();
    message.metadata.authoritative = true;
    message.add_answers(records);
    Reply::Message(message)
}

fn nxdomain() -> Reply {
    let mut message = Message::query();
    message.metadata.authoritative = true;
    message.metadata.response_code = ResponseCode::NXDomain;
    Reply::Message(message)
}

fn a(owner: &str, address: Ipv4Addr) -> Record {
    Record::from_rdata(name(owner), 300, RData::A(A(address)))
}

fn cname(owner: &str, target: &str) -> Record {
    Record::from_rdata(name(owner), 300, RData::CNAME(CNAME(name(target))))
}

/// `owner` (lower case, with the trailing dot) of `query`, and whether it is
/// `zone` or a name under it.
fn owner(query: &Query) -> String {
    query.name().to_ascii().to_ascii_lowercase()
}

fn under(owner: &str, zone: &str) -> bool {
    owner == zone || owner.ends_with(&format!(".{zone}"))
}

/// Serve `servers` on one port of their loopback addresses (127.0.0.2 is
/// the root), retrying on a port another test holds.
async fn spawn_hierarchy(servers: Vec<(Ipv4Addr, Handler)>) -> u16 {
    'retry: loop {
        let mut sockets = Vec::new();
        let mut port = 0;
        for (address, handler) in &servers {
            match tokio::net::UdpSocket::bind((*address, port)).await {
                Ok(socket) => {
                    port = socket.local_addr().unwrap().port();
                    sockets.push((socket, handler.clone()));
                }
                Err(_) => continue 'retry,
            }
        }
        for (socket, handler) in sockets {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                        return;
                    };
                    let Ok(query) = Message::from_vec(&buf[..len]) else {
                        continue;
                    };
                    let Some(question) = query.queries.first().cloned() else {
                        continue;
                    };
                    let Reply::Message(mut response) = handler(&question) else {
                        continue;
                    };
                    response.metadata.id = query.metadata.id;
                    response.metadata.message_type = MessageType::Response;
                    response.metadata.op_code = query.metadata.op_code;
                    response.queries.push(question);
                    if let Ok(bytes) = response.to_vec() {
                        let _ = socket.send_to(&bytes, peer).await;
                    }
                }
            });
        }
        return port;
    }
}

const ROOT: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const TLD: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);

/// The root: refers everything to `test.` at [`TLD`].
fn root() -> (Ipv4Addr, Handler) {
    (
        ROOT,
        Arc::new(|_: &Query| referral("test.", &[("ns.test.", Some(TLD))])),
    )
}

/// The `test.` TLD: refers each zone in `zones` (name, its name servers)
/// and denies everything else.
/// A zone the TLD delegates: its name and its name servers, with their glue.
type Delegation = (&'static str, Vec<(&'static str, Option<Ipv4Addr>)>);

fn tld(zones: Vec<Delegation>) -> (Ipv4Addr, Handler) {
    (
        TLD,
        Arc::new(move |query: &Query| {
            let owner = owner(query);
            for (zone, servers) in &zones {
                if under(&owner, zone) {
                    return referral(zone, servers);
                }
            }
            nxdomain()
        }),
    )
}

/// An authoritative server answering from `records`: the records at the
/// name and type asked, a CNAME at the name for any type, no data for
/// other names under `zone` listed in `names` (empty non-terminals
/// included), and NXDOMAIN for the rest.
fn authority(
    address: Ipv4Addr,
    zone: &'static str,
    records: Vec<Record>,
    names: Vec<&'static str>,
) -> (Ipv4Addr, Handler) {
    let mut by_name: HashMap<String, Vec<Record>> = HashMap::new();
    for record in records {
        by_name
            .entry(record.name.to_ascii().to_ascii_lowercase())
            .or_default()
            .push(record);
    }
    (
        address,
        Arc::new(move |query: &Query| {
            let owner = owner(query);
            if !under(&owner, zone) {
                return Reply::Silent;
            }
            if let Some(records) = by_name.get(&owner) {
                let cnames: Vec<Record> = records
                    .iter()
                    .filter(|r| r.record_type() == RecordType::CNAME)
                    .cloned()
                    .collect();
                if !cnames.is_empty() && query.query_type() != RecordType::CNAME {
                    return answer(cnames);
                }
                return answer(
                    records
                        .iter()
                        .filter(|r| r.record_type() == query.query_type())
                        .cloned()
                        .collect(),
                );
            }
            if owner == zone || names.contains(&owner.as_str()) {
                return answer(Vec::new());
            }
            nxdomain()
        }),
    )
}

fn settings(port: u16, dnssec_validate: bool) -> RecursiveSettings {
    RecursiveSettings {
        dnssec_validate,
        root_hints: vec![ROOT.to_string()],
        test_outbound_port: Some(port),
        timeout_secs: 5,
        ..RecursiveSettings::default()
    }
}

async fn resolve(
    settings: &RecursiveSettings,
    qname: &str,
) -> (
    daygle_dns_core::error::Result<hickory_resolver::lookup::Lookup>,
    Vec<TraceStep>,
) {
    let recursor = build(settings, None, Arc::new(Metrics::default())).expect("a recursor");
    let slot = RecursorSlot::new(recursor, None, settings);
    trace_queries(lookup(&slot, name(qname), RecordType::A)).await
}

fn asked<'a>(trace: &'a [TraceStep], qname: &str, record_type: &str) -> Vec<&'a TraceStep> {
    trace
        .iter()
        .filter(|s| s.name.eq_ignore_ascii_case(qname) && s.record_type == record_type)
        .collect()
}

fn answer_ips(
    result: &daygle_dns_core::error::Result<hickory_resolver::lookup::Lookup>,
) -> Vec<String> {
    match result {
        Ok(lookup) => lookup
            .answers()
            .iter()
            .filter(|r| r.record_type() == RecordType::A)
            .map(|r| r.data.to_string())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// A zone the parent gives glue for only one name server (the others are
/// named in another zone) still resolves when that server never answers:
/// the other name servers' addresses are looked up too. `0.datadog.pool.ntp.org`
/// was answered SERVFAIL so: `ntp.org` has glue only for `ns1.everett.org`
/// in `.org`, and one DS query it did not answer within 1.7s left the
/// validator nothing else to ask.
#[tokio::test]
async fn a_zone_whose_only_glued_name_server_is_silent_resolves_from_another() {
    const SILENT: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);
    const OTHER_TEST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 5);
    const ALIVE: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 6);
    let port = spawn_hierarchy(vec![
        root(),
        tld(vec![
            (
                "pool.test.",
                vec![("ns1.pool.test.", Some(SILENT)), ("ns2.other.test.", None)],
            ),
            ("other.test.", vec![("ns.other.test.", Some(OTHER_TEST))]),
        ]),
        (SILENT, Arc::new(|_: &Query| Reply::Silent)),
        authority(
            OTHER_TEST,
            "other.test.",
            vec![a("ns2.other.test.", ALIVE)],
            Vec::new(),
        ),
        authority(
            ALIVE,
            "pool.test.",
            vec![a("www.pool.test.", Ipv4Addr::new(198, 51, 100, 7))],
            Vec::new(),
        ),
    ])
    .await;

    let started = Instant::now();
    let (result, trace) = resolve(&settings(port, false), "www.pool.test.").await;
    assert_eq!(
        answer_ips(&result),
        ["198.51.100.7"],
        "{result:?}\n{trace:#?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}\n{trace:#?}",
        started.elapsed()
    );
    assert!(
        !asked(&trace, "ns2.other.test.", "A").is_empty(),
        "the glueless name server was looked up\n{trace:#?}"
    );
}

/// While proving an answer insecure, the validator looks for the zone cut
/// above each name with NS queries; a CNAME at one of those names (here
/// `ut.ex.test`, as at `ut.taobao.com`) shows it is no cut, and its target
/// is not resolved. `h-adashx4ae.ut.taobao.com` spent 4.3s of its 13s
/// resolving `shop.taobao.com` that way.
#[tokio::test]
async fn the_validator_does_not_follow_a_cname_while_looking_for_a_zone_cut() {
    const EX: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);
    let port = spawn_hierarchy(vec![
        root(),
        tld(vec![("ex.test.", vec![("ns.ex.test.", Some(EX))])]),
        authority(
            EX,
            "ex.test.",
            vec![
                cname("ut.ex.test.", "detour.ex.test."),
                a("h.ut.ex.test.", Ipv4Addr::new(198, 51, 100, 8)),
                a("detour.ex.test.", Ipv4Addr::new(198, 51, 100, 9)),
            ],
            Vec::new(),
        ),
    ])
    .await;

    let (result, trace) = resolve(&settings(port, true), "h.ut.ex.test.").await;
    assert_eq!(
        answer_ips(&result),
        ["198.51.100.8"],
        "{result:?}\n{trace:#?}"
    );
    assert!(
        !asked(&trace, "ut.ex.test.", "NS").is_empty(),
        "the validator (or the walk) probed the alias for a zone cut\n{trace:#?}"
    );
    let detour: Vec<&TraceStep> = trace
        .iter()
        .filter(|s| s.name.eq_ignore_ascii_case("detour.ex.test."))
        .collect();
    assert!(detour.is_empty(), "the alias was followed: {detour:#?}");
}

/// A zone whose servers wrongly answer NXDOMAIN for empty non-terminals:
/// after the first such answer the walk asks the full name (RFC 9156
/// section 3) instead of each name on the way down. `global.cainiao.com`
/// and `h-adashx4ae.ut.taobao.com` walked several of these, about 0.3s
/// each.
#[tokio::test]
async fn an_nxdomain_for_an_empty_non_terminal_moves_the_walk_to_the_full_name() {
    const DEEP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);
    let port = spawn_hierarchy(vec![
        root(),
        tld(vec![("deep.test.", vec![("ns.deep.test.", Some(DEEP))])]),
        // No `names`: every empty non-terminal is (wrongly) NXDOMAIN.
        authority(
            DEEP,
            "deep.test.",
            vec![a("x.d.c.b.deep.test.", Ipv4Addr::new(198, 51, 100, 10))],
            Vec::new(),
        ),
    ])
    .await;

    let (result, trace) = resolve(&settings(port, false), "x.d.c.b.deep.test.").await;
    assert_eq!(
        answer_ips(&result),
        ["198.51.100.10"],
        "{result:?}\n{trace:#?}"
    );
    assert_eq!(asked(&trace, "b.deep.test.", "NS").len(), 1, "{trace:#?}");
    for skipped in ["c.b.deep.test.", "d.c.b.deep.test."] {
        assert!(
            asked(&trace, skipped, "NS").is_empty(),
            "{skipped} was probed after the NXDOMAIN\n{trace:#?}"
        );
    }
}

/// When the walk passes over a name that is a zone cut, the parent's
/// servers answer the deeper probe with a referral to it, which the walk
/// follows: here `sub.deep.test` is (wrongly) NXDOMAIN, so the walk jumps
/// to the full name and is referred to `z.sub.deep.test`, which it never
/// probed.
#[tokio::test]
async fn a_referral_to_a_cut_the_walk_passed_over_is_followed() {
    const DEEP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);
    const Z: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 5);
    let deep = authority(DEEP, "deep.test.", Vec::new(), Vec::new()).1;
    let port = spawn_hierarchy(vec![
        root(),
        tld(vec![("deep.test.", vec![("ns.deep.test.", Some(DEEP))])]),
        (
            DEEP,
            Arc::new(move |query: &Query| {
                if under(&owner(query), "z.sub.deep.test.") {
                    referral("z.sub.deep.test.", &[("ns.z.sub.deep.test.", Some(Z))])
                } else {
                    deep(query)
                }
            }),
        ),
        authority(
            Z,
            "z.sub.deep.test.",
            vec![a("www.z.sub.deep.test.", Ipv4Addr::new(198, 51, 100, 11))],
            Vec::new(),
        ),
    ])
    .await;

    let (result, trace) = resolve(&settings(port, false), "www.z.sub.deep.test.").await;
    assert_eq!(
        answer_ips(&result),
        ["198.51.100.11"],
        "{result:?}\n{trace:#?}"
    );
    assert!(
        asked(&trace, "z.sub.deep.test.", "NS").is_empty(),
        "the cut was found from the referral, not probed\n{trace:#?}"
    );
    let from_z = trace
        .iter()
        .any(|s| s.server == IpAddr::V4(Z) && s.name.eq_ignore_ascii_case("www.z.sub.deep.test."));
    assert!(from_z, "the name was asked of the cut's server\n{trace:#?}");
}

/// A long name under one zone is walked in at most ten probes (RFC 9156
/// section 2.3): one label at a time for the first four, then several.
/// Empty non-terminals answer no data here, as they should.
#[tokio::test]
async fn a_long_name_is_walked_in_at_most_ten_probes() {
    const LONG: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);
    const QNAME: &str = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.long.test.";
    let mut names = Vec::new();
    let labels: Vec<&str> = QNAME.trim_end_matches('.').split('.').collect();
    for start in 1..labels.len() - 2 {
        let suffix: String = labels[start..].iter().map(|l| format!("{l}.")).collect();
        names.push(&*Box::leak(suffix.into_boxed_str()));
    }
    let port = spawn_hierarchy(vec![
        root(),
        tld(vec![("long.test.", vec![("ns.long.test.", Some(LONG))])]),
        authority(
            LONG,
            "long.test.",
            vec![a(QNAME, Ipv4Addr::new(198, 51, 100, 12))],
            names,
        ),
    ])
    .await;

    let (result, trace) = resolve(&settings(port, false), QNAME).await;
    assert_eq!(
        answer_ips(&result),
        ["198.51.100.12"],
        "{result:?}\n{trace:#?}"
    );
    let probes = trace.iter().filter(|s| s.record_type == "NS").count();
    assert!(probes <= 10, "{probes} probes\n{trace:#?}");
    assert_eq!(
        asked(&trace, QNAME, "NS").len(),
        1,
        "the walk ends at the full name\n{trace:#?}"
    );
}

/// Two zones served by the same glueless name server, chained by a CNAME:
/// the server's address is looked up for the first zone and found in the
/// cache for the second. `email-static.useinsider.com` passes through two
/// Huawei Cloud CDN zones that share `ns3`/`ns33.cdnhwc10.cn`, and looked
/// both addresses up twice, a second each, in a lookup that took 15 s.
#[tokio::test]
async fn a_shared_glueless_name_server_is_looked_up_once() {
    const DNS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);
    const CDN: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 5);
    let port = spawn_hierarchy(vec![
        root(),
        tld(vec![
            ("dns.test.", vec![("ns.dns.test.", Some(DNS))]),
            ("one.test.", vec![("cdn.dns.test.", None)]),
            ("two.test.", vec![("cdn.dns.test.", None)]),
        ]),
        authority(DNS, "dns.test.", vec![a("cdn.dns.test.", CDN)], Vec::new()),
        (
            CDN,
            Arc::new(|query: &Query| match owner(query).as_str() {
                "www.one.test." => answer(vec![cname("www.one.test.", "www.two.test.")]),
                "www.two.test." if query.query_type() == RecordType::A => {
                    answer(vec![a("www.two.test.", Ipv4Addr::new(198, 51, 100, 9))])
                }
                _ => answer(Vec::new()),
            }),
        ),
    ])
    .await;

    let (result, trace) = resolve(&settings(port, false), "www.one.test.").await;
    assert_eq!(
        answer_ips(&result),
        ["198.51.100.9"],
        "{result:?}\n{trace:#?}"
    );
    assert_eq!(
        asked(&trace, "cdn.dns.test.", "A").len(),
        1,
        "the shared name server's address was looked up once\n{trace:#?}"
    );
}

/// An NS question answered "no records" by a zone whose SOA allows only a
/// second of negative caching is still remembered for the next lookup:
/// every name on the way down that is not a zone cut gets that answer, and
/// Huawei Cloud's CDN zones (SOA minimum 10 s) had the same questions asked
/// again within one lookup of `email-static.useinsider.com`.
#[tokio::test]
async fn an_ns_nodata_with_a_short_soa_minimum_is_not_asked_again() {
    use hickory_proto::rr::rdata::SOA;

    const CDN: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);
    let port = spawn_hierarchy(vec![
        root(),
        tld(vec![("cdn.test.", vec![("ns.cdn.test.", Some(CDN))])]),
        (
            CDN,
            Arc::new(|query: &Query| {
                let owner = owner(query);
                if query.query_type() == RecordType::A && owner.ends_with(".edge.cdn.test.") {
                    return answer(vec![a(&owner, Ipv4Addr::new(198, 51, 100, 11))]);
                }
                // No data, with an SOA whose minimum is one second.
                let mut message = Message::query();
                message.metadata.authoritative = true;
                message.add_authority(Record::from_rdata(
                    name("cdn.test."),
                    1,
                    RData::SOA(SOA::new(
                        name("ns.cdn.test."),
                        name("hostmaster.cdn.test."),
                        1,
                        3600,
                        600,
                        86400,
                        1,
                    )),
                ));
                Reply::Message(message)
            }),
        ),
    ])
    .await;

    let settings = settings(port, false);
    let recursor = build(&settings, None, Arc::new(Metrics::default())).expect("a recursor");
    let slot = RecursorSlot::new(recursor, None, &settings);
    let (first, trace) =
        trace_queries(lookup(&slot, name("a.edge.cdn.test."), RecordType::A)).await;
    assert!(first.is_ok(), "{first:?}\n{trace:#?}");
    assert_eq!(asked(&trace, "edge.cdn.test.", "NS").len(), 1, "{trace:#?}");

    // Past the zone's own one second.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let (second, trace) =
        trace_queries(lookup(&slot, name("b.edge.cdn.test."), RecordType::A)).await;
    assert!(second.is_ok(), "{second:?}\n{trace:#?}");
    assert!(
        asked(&trace, "edge.cdn.test.", "NS").is_empty(),
        "the NODATA for edge.cdn.test. NS came from the cache\n{trace:#?}"
    );
}
