//! DHCPv6 (RFC 8415): the protocol logic, independent of sockets. Stateful
//! scopes hand out addresses (IA_NA); every scope answers with its DNS
//! settings. Prefix delegation and temporary addresses are not offered:
//! routers advertise the prefix themselves.

use std::net::{IpAddr, Ipv6Addr};

use daygle_dns_core::dhcp::{normalize_duid, Dhcp6Scope};
use dhcproto::v6::{
    DhcpOption, DhcpOptions, IAAddr, Message, MessageType, OptionCode, Status, StatusCode, IANA,
};

use crate::leases::{self, Leases, BOUND, DECLINED, OFFERED, RELEASED};

/// How many addresses of a range are tried before giving up.
const PROBES: u128 = 4096;

/// What a request is answered for.
pub struct Context<'a> {
    pub scope: &'a Dhcp6Scope,
    pub net: ipnet::Ipv6Net,
    /// This server's DUID.
    pub server_duid: &'a [u8],
    /// The DNS server handed out when the scope names none: this server's
    /// address on the client's network.
    pub dns_default: Option<Ipv6Addr>,
    /// UNIX seconds.
    pub now: i64,
}

fn client_duid(msg: &Message) -> Option<String> {
    match msg.opts().get(OptionCode::ClientId) {
        Some(DhcpOption::ClientId(id)) if !id.is_empty() => Some(leases::hex(id)),
        _ => None,
    }
}

fn server_duid(msg: &Message) -> Option<&[u8]> {
    match msg.opts().get(OptionCode::ServerId) {
        Some(DhcpOption::ServerId(id)) => Some(id),
        _ => None,
    }
}

/// The lease key of one of a client's address associations.
fn lease_client(duid: &str, iaid: u32) -> String {
    format!("{duid}/{iaid:08x}")
}

/// The host name from the client FQDN option (39): a flags byte, then the
/// name in wire format. Only its first label is used.
fn hostname(msg: &Message) -> String {
    let Some(DhcpOption::Unknown(opt)) = msg.opts().get(OptionCode::ClientFqdn) else {
        return String::new();
    };
    let data = opt.data();
    let Some(&len) = data.get(1) else {
        return String::new();
    };
    data.get(2..2 + usize::from(len))
        .map(|label| leases::clean_hostname(&String::from_utf8_lossy(label)))
        .unwrap_or_default()
}

fn ia_nas(msg: &Message) -> Vec<IANA> {
    msg.opts()
        .get_all(OptionCode::IANA)
        .unwrap_or_default()
        .iter()
        .filter_map(|o| match o {
            DhcpOption::IANA(ia) => Some(ia.clone()),
            _ => None,
        })
        .collect()
}

fn ia_addresses(ia: &IANA) -> Vec<Ipv6Addr> {
    ia.opts
        .get_all(OptionCode::IAAddr)
        .unwrap_or_default()
        .iter()
        .filter_map(|o| match o {
            DhcpOption::IAAddr(a) => Some(a.addr),
            _ => None,
        })
        .collect()
}

/// The address reserved for this DUID, with its name.
fn reservation(scope: &Dhcp6Scope, duid: &str) -> Option<(Ipv6Addr, String)> {
    scope
        .reservations
        .iter()
        .find(|r| normalize_duid(&r.client).as_deref() == Some(duid))
        .and_then(|r| {
            Some((
                r.address.trim().parse().ok()?,
                leases::clean_hostname(&r.hostname),
            ))
        })
}

fn reserved_for_other(scope: &Dhcp6Scope, ip: Ipv6Addr, duid: &str) -> bool {
    scope.reservations.iter().any(|r| {
        r.address.trim().parse::<Ipv6Addr>().ok() == Some(ip)
            && normalize_duid(&r.client).as_deref() != Some(duid)
    })
}

fn usable(ctx: &Context<'_>, leases: &Leases, ip: Ipv6Addr, duid: &str, id: &str) -> bool {
    let in_range = ctx.scope.range().is_some_and(|(start, end)| {
        (u128::from(start)..=u128::from(end)).contains(&u128::from(ip))
    });
    let reserved_here = reservation(ctx.scope, duid).is_some_and(|(r, _)| r == ip);
    (in_range || reserved_here)
        && ctx.net.contains(&ip)
        && Some(ip) != ctx.dns_default
        && !reserved_for_other(ctx.scope, ip, duid)
        && leases.free_for(&IpAddr::V6(ip), id, ctx.now)
}

/// A stable starting point in the range for `id`, so a client tends to get
/// the same address back.
fn spread(id: &str) -> u128 {
    // FNV-1a.
    id.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    }) as u128
}

/// The address for one association: the reservation (for the first one),
/// the current lease, an address the client asked for, or a free one.
fn choose(
    ctx: &Context<'_>,
    leases: &Leases,
    duid: &str,
    id: &str,
    first: bool,
    asked: &[Ipv6Addr],
) -> Option<Ipv6Addr> {
    if first {
        if let Some((ip, _)) = reservation(ctx.scope, duid) {
            if usable(ctx, leases, ip, duid, id) {
                return Some(ip);
            }
        }
    }
    if let Some(IpAddr::V6(ip)) = leases
        .of_client(&ctx.scope.name, id, ctx.now)
        .map(|l| l.address)
    {
        if usable(ctx, leases, ip, duid, id) {
            return Some(ip);
        }
    }
    if let Some(ip) = asked.iter().find(|ip| usable(ctx, leases, **ip, duid, id)) {
        return Some(*ip);
    }
    let (start, end) = ctx.scope.range()?;
    let (start, end) = (u128::from(start), u128::from(end));
    let size = end - start + 1;
    let base = spread(id) % size;
    (0..size.min(PROBES))
        .map(|i| Ipv6Addr::from(start + (base + i) % size))
        .find(|ip| usable(ctx, leases, *ip, duid, id))
}

fn status(code: Status, msg: &str) -> DhcpOption {
    DhcpOption::StatusCode(StatusCode {
        status: code,
        msg: msg.to_string(),
    })
}

/// A reply of `kind` to `request`, with both DUIDs and the DNS settings.
fn reply(ctx: &Context<'_>, request: &Message, kind: MessageType) -> Message {
    let mut msg = Message::new_with_id(kind, request.xid());
    let opts = msg.opts_mut();
    if let Some(DhcpOption::ClientId(id)) = request.opts().get(OptionCode::ClientId) {
        opts.insert(DhcpOption::ClientId(id.clone()));
    }
    opts.insert(DhcpOption::ServerId(ctx.server_duid.to_vec()));
    let mut dns: Vec<Ipv6Addr> = ctx
        .scope
        .dns_servers
        .iter()
        .filter_map(|d| d.trim().parse().ok())
        .collect();
    if dns.is_empty() {
        dns.extend(ctx.dns_default);
    }
    if !dns.is_empty() {
        opts.insert(DhcpOption::DomainNameServers(dns));
    }
    let search: Vec<hickory_proto::rr::Name> = ctx
        .scope
        .domain_search
        .iter()
        .filter_map(|d| {
            let d = d.trim().trim_end_matches('.');
            hickory_proto::rr::Name::from_ascii(format!("{d}.")).ok()
        })
        .collect();
    if !search.is_empty() {
        opts.insert(DhcpOption::DomainSearchList(search));
    }
    msg
}

/// An association holding `addresses` with the scope's lifetimes; the
/// ones in `dropped` are listed with zero lifetimes so the client stops
/// using them.
fn ia_with(ctx: &Context<'_>, iaid: u32, address: Option<Ipv6Addr>, dropped: &[Ipv6Addr]) -> IANA {
    let preferred = ctx.scope.preferred_secs;
    let valid = ctx.scope.valid_secs;
    let mut opts = DhcpOptions::new();
    match address {
        Some(addr) => opts.insert(DhcpOption::IAAddr(IAAddr {
            addr,
            preferred_life: preferred,
            valid_life: valid,
            opts: DhcpOptions::new(),
        })),
        None => opts.insert(status(Status::NoAddrsAvail, "no addresses available")),
    }
    for addr in dropped.iter().filter(|a| Some(**a) != address) {
        opts.insert(DhcpOption::IAAddr(IAAddr {
            addr: *addr,
            preferred_life: 0,
            valid_life: 0,
            opts: DhcpOptions::new(),
        }));
    }
    let (t1, t2) = if address.is_some() {
        (preferred / 2, preferred / 5 * 4)
    } else {
        (0, 0)
    };
    IANA {
        id: iaid,
        t1,
        t2,
        opts,
    }
}

/// Bind (or, for an advertisement, offer) an address to every association
/// in `request`.
fn assign(
    ctx: &Context<'_>,
    request: &Message,
    leases: &mut Leases,
    duid: &str,
    bind: bool,
    msg: &mut Message,
) {
    let name = reservation(ctx.scope, duid)
        .map(|(_, name)| name)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| hostname(request));
    let scope_name = ctx.scope.name.as_str();
    for (i, ia) in ia_nas(request).iter().enumerate() {
        let id = lease_client(duid, ia.id);
        let asked = ia_addresses(ia);
        let chosen = choose(ctx, leases, duid, &id, i == 0, &asked);
        if let Some(ip) = chosen {
            let address = IpAddr::V6(ip);
            // An older lease of this association on another address goes.
            if let Some(old) = leases
                .of_client(scope_name, &id, ctx.now)
                .map(|l| l.address)
            {
                if old != address {
                    leases.update(&old, |l| {
                        l.state = RELEASED.to_string();
                        l.expires = ctx.now;
                    });
                }
            }
            // Only the first association carries the DNS name.
            let lease_name = if i == 0 { name.as_str() } else { "" };
            let current = leases.get(&address).filter(|l| l.client_id == id).cloned();
            if bind {
                let expires = ctx.now + i64::from(ctx.scope.valid_secs);
                match current {
                    Some(l) if l.state == BOUND && l.hostname == lease_name => {
                        leases.update(&address, |l| {
                            l.expires = expires;
                            l.updated_at = chrono::Utc::now().to_rfc3339();
                        });
                    }
                    old => {
                        let mut lease = leases::lease(
                            address, scope_name, &id, duid, lease_name, BOUND, expires,
                        );
                        if let Some(old) = old {
                            lease.dns_name = old.dns_name;
                            lease.dns_records = old.dns_records;
                        }
                        leases.put(lease);
                    }
                }
            } else if current.is_none_or(|l| l.state != BOUND || l.expires <= ctx.now) {
                leases.put(leases::lease(
                    address,
                    scope_name,
                    &id,
                    duid,
                    lease_name,
                    OFFERED,
                    ctx.now + leases::OFFER_SECS,
                ));
            }
        }
        msg.opts_mut()
            .insert(DhcpOption::IANA(ia_with(ctx, ia.id, chosen, &asked)));
    }
}

/// Answer `request`; `None` when nothing is sent back.
pub fn handle(ctx: &Context<'_>, request: &Message, leases: &mut Leases) -> Option<Message> {
    let duid = client_duid(request);
    let ours = server_duid(request).map(|id| id == ctx.server_duid);
    match request.msg_type() {
        MessageType::Solicit => {
            let duid = duid?;
            if ctx.scope.stateless() || ours.is_some() || ia_nas(request).is_empty() {
                return None;
            }
            let rapid = request.opts().get(OptionCode::RapidCommit).is_some();
            let kind = if rapid {
                MessageType::Reply
            } else {
                MessageType::Advertise
            };
            let mut msg = reply(ctx, request, kind);
            if rapid {
                msg.opts_mut().insert(DhcpOption::RapidCommit);
            }
            assign(ctx, request, leases, &duid, rapid, &mut msg);
            Some(msg)
        }
        MessageType::Request | MessageType::Renew | MessageType::Rebind => {
            let duid = duid?;
            // Request and Renew name their server; Rebind goes to any.
            if request.msg_type() != MessageType::Rebind && ours != Some(true) {
                return None;
            }
            if ctx.scope.stateless() {
                return None;
            }
            let mut msg = reply(ctx, request, MessageType::Reply);
            assign(ctx, request, leases, &duid, true, &mut msg);
            Some(msg)
        }
        MessageType::Release | MessageType::Decline => {
            let duid = duid?;
            if ours != Some(true) {
                return None;
            }
            let decline = request.msg_type() == MessageType::Decline;
            for ia in ia_nas(request) {
                let id = lease_client(&duid, ia.id);
                for ip in ia_addresses(&ia) {
                    let address = IpAddr::V6(ip);
                    if leases.get(&address).is_some_and(|l| l.client_id == id) {
                        leases.update(&address, |l| {
                            if decline {
                                l.state = DECLINED.to_string();
                                l.client_id = "declined".to_string();
                                l.expires = ctx.now + leases::DECLINE_SECS;
                            } else {
                                l.state = RELEASED.to_string();
                                l.expires = ctx.now;
                            }
                        });
                    }
                }
            }
            let mut msg = reply(ctx, request, MessageType::Reply);
            msg.opts_mut().insert(status(Status::Success, ""));
            Some(msg)
        }
        MessageType::Confirm => {
            duid.as_ref()?;
            let addresses: Vec<Ipv6Addr> = ia_nas(request).iter().flat_map(ia_addresses).collect();
            if addresses.is_empty() || ctx.scope.stateless() {
                return None;
            }
            let on_link = addresses.iter().all(|a| ctx.net.contains(a));
            let mut msg = reply(ctx, request, MessageType::Reply);
            msg.opts_mut().insert(if on_link {
                status(Status::Success, "")
            } else {
                status(Status::NotOnLink, "not on this link")
            });
            Some(msg)
        }
        MessageType::InformationRequest => {
            if ours == Some(false) {
                return None;
            }
            Some(reply(ctx, request, MessageType::Reply))
        }
        _ => None,
    }
}

/// A new server DUID (DUID-UUID, RFC 6355).
pub fn new_server_duid() -> Vec<u8> {
    let mut duid = vec![0, 4];
    duid.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    duid
}

#[cfg(test)]
mod tests {
    use super::*;
    use daygle_dns_core::dhcp::DhcpReservation;

    const SERVER: &[u8] = &[0, 4, 1, 2, 3, 4];

    fn scope() -> Dhcp6Scope {
        Dhcp6Scope {
            name: "lan6".to_string(),
            prefix: "fd00:1::/64".to_string(),
            range_start: "fd00:1::1000".to_string(),
            range_end: "fd00:1::1001".to_string(),
            domain_search: vec!["home.arpa".to_string()],
            reservations: vec![DhcpReservation {
                client: "00:01:00:01:aa:bb".to_string(),
                address: "fd00:1::50".to_string(),
                hostname: "nas".to_string(),
                description: String::new(),
            }],
            ..Dhcp6Scope::default()
        }
    }

    fn ctx(scope: &Dhcp6Scope) -> Context<'_> {
        Context {
            scope,
            net: scope.net().unwrap(),
            server_duid: SERVER,
            dns_default: Some("fd00:1::1".parse().unwrap()),
            now: 1_000,
        }
    }

    fn request(kind: MessageType, duid: &[u8], iaid: u32, server: Option<&[u8]>) -> Message {
        let mut msg = Message::new(kind);
        msg.opts_mut().insert(DhcpOption::ClientId(duid.to_vec()));
        if let Some(server) = server {
            msg.opts_mut().insert(DhcpOption::ServerId(server.to_vec()));
        }
        msg.opts_mut().insert(DhcpOption::IANA(IANA {
            id: iaid,
            t1: 0,
            t2: 0,
            opts: DhcpOptions::new(),
        }));
        msg
    }

    fn address(msg: &Message) -> Option<Ipv6Addr> {
        let Some(DhcpOption::IANA(ia)) = msg.opts().get(OptionCode::IANA) else {
            return None;
        };
        ia_addresses(ia).first().copied()
    }

    #[test]
    fn solicit_request_binds_and_reservations_win() {
        let scope = scope();
        let ctx = ctx(&scope);
        let mut leases = Leases::default();
        let client = [0, 1, 0, 1, 0xcc, 0xdd];
        let mut solicit = request(MessageType::Solicit, &client, 7, None);
        // Option 39: flags, then "laptop" in wire format.
        let mut fqdn = vec![0, 6];
        fqdn.extend_from_slice(b"laptop");
        fqdn.push(0);
        solicit
            .opts_mut()
            .insert(DhcpOption::Unknown(dhcproto::v6::UnknownOption::new(
                OptionCode::ClientFqdn,
                fqdn.clone(),
            )));
        let adv = handle(&ctx, &solicit, &mut leases).unwrap();
        assert_eq!(adv.msg_type(), MessageType::Advertise);
        let offered = address(&adv).unwrap();
        assert!(ctx
            .scope
            .range()
            .is_some_and(|(s, e)| offered >= s && offered <= e));
        assert!(
            matches!(adv.opts().get(OptionCode::DomainNameServers), Some(DhcpOption::DomainNameServers(d)) if d == &vec!["fd00:1::1".parse::<Ipv6Addr>().unwrap()])
        );
        assert_eq!(leases.get(&IpAddr::V6(offered)).unwrap().state, OFFERED);

        // A Request to another server is not ours.
        let mut req = request(MessageType::Request, &client, 7, Some(&[9, 9]));
        assert!(handle(&ctx, &req, &mut leases).is_none());
        req = request(MessageType::Request, &client, 7, Some(SERVER));
        req.opts_mut()
            .insert(DhcpOption::Unknown(dhcproto::v6::UnknownOption::new(
                OptionCode::ClientFqdn,
                fqdn,
            )));
        let rep = handle(&ctx, &req, &mut leases).unwrap();
        assert_eq!(address(&rep), Some(offered));
        let lease = leases.get(&IpAddr::V6(offered)).unwrap();
        assert_eq!(
            (lease.state.as_str(), lease.hostname.as_str()),
            (BOUND, "laptop")
        );
        assert_eq!(lease.hw_address, "00010001ccdd");

        // The reserved client gets its address (and name) with Rapid Commit.
        let mut rapid = request(MessageType::Solicit, &[0, 1, 0, 1, 0xaa, 0xbb], 1, None);
        rapid.opts_mut().insert(DhcpOption::RapidCommit);
        let rep = handle(&ctx, &rapid, &mut leases).unwrap();
        assert_eq!(rep.msg_type(), MessageType::Reply);
        assert_eq!(address(&rep), Some("fd00:1::50".parse().unwrap()));
        let lease = leases.get(&"fd00:1::50".parse().unwrap()).unwrap();
        assert_eq!(
            (lease.state.as_str(), lease.hostname.as_str()),
            (BOUND, "nas")
        );

        // The range holds two; a third client gets none after a second.
        handle(
            &ctx,
            &request(MessageType::Request, &[0, 1, 2], 1, Some(SERVER)),
            &mut leases,
        )
        .unwrap();
        let rep = handle(
            &ctx,
            &request(MessageType::Request, &[0, 1, 3], 1, Some(SERVER)),
            &mut leases,
        )
        .unwrap();
        assert_eq!(address(&rep), None);
    }

    #[test]
    fn release_confirm_and_information() {
        let scope = scope();
        let ctx = ctx(&scope);
        let mut leases = Leases::default();
        let client = [0, 1, 5];
        let rep = handle(
            &ctx,
            &request(MessageType::Request, &client, 1, Some(SERVER)),
            &mut leases,
        )
        .unwrap();
        let ip = address(&rep).unwrap();

        let mut release = request(MessageType::Release, &client, 1, Some(SERVER));
        release
            .opts_mut()
            .insert(DhcpOption::IANA(ia_with(&ctx, 1, Some(ip), &[])));
        assert!(handle(&ctx, &release, &mut leases).is_some());
        assert_eq!(leases.get(&IpAddr::V6(ip)).unwrap().state, RELEASED);

        let mut confirm = Message::new(MessageType::Confirm);
        confirm
            .opts_mut()
            .insert(DhcpOption::ClientId(client.to_vec()));
        confirm.opts_mut().insert(DhcpOption::IANA(ia_with(
            &ctx,
            1,
            Some("fd00:2::5".parse().unwrap()),
            &[],
        )));
        let rep = handle(&ctx, &confirm, &mut leases).unwrap();
        assert!(
            matches!(rep.opts().get(OptionCode::StatusCode), Some(DhcpOption::StatusCode(s)) if s.status == Status::NotOnLink)
        );

        let mut info = Message::new(MessageType::InformationRequest);
        info.opts_mut()
            .insert(DhcpOption::ClientId(client.to_vec()));
        let rep = handle(&ctx, &info, &mut leases).unwrap();
        assert!(rep.opts().get(OptionCode::DomainSearchList).is_some());
        assert!(rep.opts().get(OptionCode::IANA).is_none());

        // A stateless scope only answers Information-requests.
        let stateless = Dhcp6Scope {
            range_start: String::new(),
            range_end: String::new(),
            ..scope.clone()
        };
        let ctx = Context {
            scope: &stateless,
            ..ctx
        };
        assert!(handle(
            &ctx,
            &request(MessageType::Solicit, &client, 1, None),
            &mut leases
        )
        .is_none());
        assert!(handle(&ctx, &info, &mut leases).is_some());
    }
}
