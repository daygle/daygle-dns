//! DHCPv4 (RFC 2131/2132): the protocol logic, independent of sockets.
//! [`handle`] takes a request and the scope it arrived for and returns the
//! reply, updating the lease table.

use std::net::{IpAddr, Ipv4Addr};

use daygle_dns_core::dhcp::{custom_option_bytes, normalize_mac, DhcpScope};
use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode, OptionCode, UnknownOption};

use crate::leases::{self, Leases, BOUND, DECLINED, OFFERED, RELEASED};

/// What a request is answered for.
pub struct Context<'a> {
    pub scope: &'a DhcpScope,
    pub net: ipnet::Ipv4Net,
    /// This server's address on the client's network (the server
    /// identifier, and the default DNS server).
    pub server_ip: Ipv4Addr,
    /// UNIX seconds.
    pub now: i64,
}

/// The client's identity: its client identifier (option 61) if it sent
/// one, else its hardware address.
pub fn client_id(msg: &Message) -> String {
    match msg.opts().get(OptionCode::ClientIdentifier) {
        Some(DhcpOption::ClientIdentifier(id)) if !id.is_empty() => leases::hex(id),
        _ => leases::hex(msg.chaddr()),
    }
}

/// The client's MAC address, when its hardware is Ethernet-like.
pub fn mac(msg: &Message) -> String {
    let chaddr = msg.chaddr();
    if chaddr.len() == 6 {
        normalize_mac(&leases::hex(chaddr)).unwrap_or_default()
    } else {
        String::new()
    }
}

/// The host name the client gave (option 12, or the client FQDN).
fn hostname(msg: &Message) -> String {
    match msg.opts().get(OptionCode::Hostname) {
        Some(DhcpOption::Hostname(name)) => leases::clean_hostname(name),
        _ => match msg.opts().get(OptionCode::ClientFQDN) {
            Some(DhcpOption::ClientFQDN(fqdn)) => leases::clean_hostname(&fqdn.domain().to_ascii()),
            _ => String::new(),
        },
    }
}

/// The address reserved for this client in the scope, with its name.
fn reservation(scope: &DhcpScope, mac: &str) -> Option<(Ipv4Addr, String)> {
    if mac.is_empty() {
        return None;
    }
    scope
        .reservations
        .iter()
        .find(|r| normalize_mac(&r.client).as_deref() == Some(mac))
        .and_then(|r| {
            Some((
                r.address.trim().parse().ok()?,
                leases::clean_hostname(&r.hostname),
            ))
        })
}

/// Whether `ip` is reserved for a client other than `mac`.
fn reserved_for_other(scope: &DhcpScope, ip: Ipv4Addr, mac: &str) -> bool {
    scope.reservations.iter().any(|r| {
        r.address.trim().parse::<Ipv4Addr>().ok() == Some(ip)
            && normalize_mac(&r.client).as_deref() != Some(mac)
    })
}

/// Whether `ip` may be handed to `client` (identified by `id` and `mac`).
fn usable(ctx: &Context<'_>, leases: &Leases, ip: Ipv4Addr, id: &str, mac: &str) -> bool {
    let in_range = ctx
        .scope
        .range()
        .is_some_and(|(start, end)| (u32::from(start)..=u32::from(end)).contains(&u32::from(ip)));
    let reserved_here = reservation(ctx.scope, mac).is_some_and(|(r, _)| r == ip);
    (in_range || reserved_here)
        && ctx.net.contains(&ip)
        && ip != ctx.net.network()
        && ip != ctx.net.broadcast()
        && ip != ctx.server_ip
        && ctx.scope.router.trim().parse::<Ipv4Addr>().ok() != Some(ip)
        && !reserved_for_other(ctx.scope, ip, mac)
        && leases.free_for(&IpAddr::V4(ip), id, ctx.now)
}

/// The address to offer: the client's reservation, its current lease, the
/// address it asked for, or the first free one.
fn choose(
    ctx: &Context<'_>,
    leases: &Leases,
    id: &str,
    mac: &str,
    requested: Option<Ipv4Addr>,
) -> Option<Ipv4Addr> {
    if let Some((ip, _)) = reservation(ctx.scope, mac) {
        if usable(ctx, leases, ip, id, mac) {
            return Some(ip);
        }
    }
    if let Some(IpAddr::V4(ip)) = leases
        .of_client(&ctx.scope.name, id, ctx.now)
        .map(|l| l.address)
    {
        if usable(ctx, leases, ip, id, mac) {
            return Some(ip);
        }
    }
    if let Some(ip) = requested {
        if usable(ctx, leases, ip, id, mac) {
            return Some(ip);
        }
    }
    let (start, end) = ctx.scope.range()?;
    (u32::from(start)..=u32::from(end))
        .map(Ipv4Addr::from)
        .find(|ip| usable(ctx, leases, *ip, id, mac))
}

/// A reply to `request` of `kind`, with the server identifier.
fn reply(ctx: &Context<'_>, request: &Message, kind: MessageType, yiaddr: Ipv4Addr) -> Message {
    let mut msg = Message::new_with_id(
        request.xid(),
        if kind == MessageType::Nak {
            Ipv4Addr::UNSPECIFIED
        } else {
            request.ciaddr()
        },
        yiaddr,
        Ipv4Addr::UNSPECIFIED,
        request.giaddr(),
        request.chaddr(),
    );
    msg.set_opcode(Opcode::BootReply);
    msg.set_htype(request.htype());
    let mut flags = request.flags();
    if kind == MessageType::Nak && !request.giaddr().is_unspecified() {
        flags = flags.set_broadcast();
    }
    msg.set_flags(flags);
    msg.opts_mut().insert(DhcpOption::MessageType(kind));
    msg.opts_mut()
        .insert(DhcpOption::ServerIdentifier(ctx.server_ip));
    msg
}

/// Add the scope's configuration options (and, for a lease, its times).
fn add_options(ctx: &Context<'_>, msg: &mut Message, lease_secs: Option<u32>) {
    let scope = ctx.scope;
    let opts = msg.opts_mut();
    opts.insert(DhcpOption::SubnetMask(ctx.net.netmask()));
    opts.insert(DhcpOption::BroadcastAddr(ctx.net.broadcast()));
    if let Ok(router) = scope.router.trim().parse::<Ipv4Addr>() {
        opts.insert(DhcpOption::Router(vec![router]));
    }
    let dns: Vec<Ipv4Addr> = scope
        .dns_servers
        .iter()
        .filter_map(|d| d.trim().parse().ok())
        .collect();
    opts.insert(DhcpOption::DomainNameServer(if dns.is_empty() {
        vec![ctx.server_ip]
    } else {
        dns
    }));
    let domain = scope.domain_name.trim().trim_end_matches('.');
    if !domain.is_empty() {
        opts.insert(DhcpOption::DomainName(domain.to_string()));
        if let Ok(name) = hickory_proto::rr::Name::from_ascii(format!("{domain}.")) {
            opts.insert(DhcpOption::DomainSearch(vec![name]));
        }
    }
    let ntp: Vec<Ipv4Addr> = scope
        .ntp_servers
        .iter()
        .filter_map(|n| n.trim().parse().ok())
        .collect();
    if !ntp.is_empty() {
        opts.insert(DhcpOption::NtpServers(ntp));
    }
    if let Some(secs) = lease_secs {
        opts.insert(DhcpOption::AddressLeaseTime(secs));
        opts.insert(DhcpOption::Renewal(secs / 2));
        opts.insert(DhcpOption::Rebinding(secs / 8 * 7));
    }
    for custom in &scope.options {
        if let Ok(bytes) = custom_option_bytes(&custom.value) {
            opts.insert(DhcpOption::Unknown(UnknownOption::new(
                OptionCode::from(custom.code),
                bytes,
            )));
        }
    }
}

fn requested_ip(msg: &Message) -> Option<Ipv4Addr> {
    match msg.opts().get(OptionCode::RequestedIpAddress) {
        Some(DhcpOption::RequestedIpAddress(ip)) => Some(*ip),
        _ => None,
    }
}

fn server_id(msg: &Message) -> Option<Ipv4Addr> {
    match msg.opts().get(OptionCode::ServerIdentifier) {
        Some(DhcpOption::ServerIdentifier(ip)) => Some(*ip),
        _ => None,
    }
}

/// Answer `request`; `None` when nothing is sent back.
pub fn handle(ctx: &Context<'_>, request: &Message, leases: &mut Leases) -> Option<Message> {
    if request.opcode() != Opcode::BootRequest {
        return None;
    }
    let kind = request.opts().msg_type()?;
    let id = client_id(request);
    let mac = mac(request);
    let scope_name = ctx.scope.name.as_str();
    match kind {
        MessageType::Discover => {
            let ip = choose(ctx, leases, &id, &mac, requested_ip(request))?;
            // Drop an older offer to this client for another address.
            if let Some(old) = leases
                .of_client(scope_name, &id, ctx.now)
                .map(|l| l.address)
            {
                if old != IpAddr::V4(ip) && leases.get(&old).is_some_and(|l| l.state == OFFERED) {
                    leases.remove(&old);
                }
            }
            let bound = leases
                .get(&IpAddr::V4(ip))
                .is_some_and(|l| l.state == BOUND && l.client_id == id && l.expires > ctx.now);
            if !bound {
                leases.put(leases::lease(
                    IpAddr::V4(ip),
                    scope_name,
                    &id,
                    &mac,
                    &hostname(request),
                    OFFERED,
                    ctx.now + leases::OFFER_SECS,
                ));
            }
            let mut offer = reply(ctx, request, MessageType::Offer, ip);
            add_options(ctx, &mut offer, Some(ctx.scope.lease_secs));
            Some(offer)
        }
        MessageType::Request => {
            if let Some(sid) = server_id(request) {
                if sid != ctx.server_ip {
                    // The client took another server's offer.
                    if let Some(lease) = leases.of_client(scope_name, &id, ctx.now) {
                        if lease.state == OFFERED {
                            let address = lease.address;
                            leases.remove(&address);
                        }
                    }
                    return None;
                }
            }
            let wanted = requested_ip(request)
                .or_else(|| (!request.ciaddr().is_unspecified()).then_some(request.ciaddr()));
            let Some(ip) = wanted else {
                return Some(reply(ctx, request, MessageType::Nak, Ipv4Addr::UNSPECIFIED));
            };
            if !usable(ctx, leases, ip, &id, &mac) {
                return Some(reply(ctx, request, MessageType::Nak, Ipv4Addr::UNSPECIFIED));
            }
            let name = reservation(ctx.scope, &mac)
                .map(|(_, name)| name)
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| hostname(request));
            let expires = ctx.now + i64::from(ctx.scope.lease_secs);
            let address = IpAddr::V4(ip);
            let renewal = leases
                .get(&address)
                .is_some_and(|l| l.client_id == id && l.state == BOUND && l.hostname == name);
            if renewal {
                leases.update(&address, |l| {
                    l.expires = expires;
                    l.updated_at = chrono::Utc::now().to_rfc3339();
                });
            } else {
                // A changed name re-registers: keep the old records so the
                // service can remove them.
                let old = leases.get(&address).filter(|l| l.client_id == id).cloned();
                let mut lease =
                    leases::lease(address, scope_name, &id, &mac, &name, BOUND, expires);
                if let Some(old) = old {
                    lease.dns_name = old.dns_name;
                    lease.dns_records = old.dns_records;
                }
                leases.put(lease);
            }
            let mut ack = reply(ctx, request, MessageType::Ack, ip);
            add_options(ctx, &mut ack, Some(ctx.scope.lease_secs));
            Some(ack)
        }
        MessageType::Decline => {
            if let Some(ip) = requested_ip(request) {
                let address = IpAddr::V4(ip);
                if leases.get(&address).is_some_and(|l| l.client_id == id) {
                    leases.update(&address, |l| {
                        l.state = DECLINED.to_string();
                        l.client_id = "declined".to_string();
                        l.expires = ctx.now + leases::DECLINE_SECS;
                    });
                }
            }
            None
        }
        MessageType::Release => {
            let address = IpAddr::V4(request.ciaddr());
            if leases.get(&address).is_some_and(|l| l.client_id == id) {
                leases.update(&address, |l| {
                    l.state = RELEASED.to_string();
                    l.expires = ctx.now;
                });
            }
            None
        }
        MessageType::Inform => {
            let mut ack = reply(ctx, request, MessageType::Ack, Ipv4Addr::UNSPECIFIED);
            add_options(ctx, &mut ack, None);
            Some(ack)
        }
        _ => None,
    }
}

/// Where a reply goes (RFC 2131 §4.1): to the relay, to the client's
/// address, or broadcast on the client's network.
#[derive(Debug, PartialEq, Eq)]
pub enum Destination {
    Relay(Ipv4Addr),
    Unicast(Ipv4Addr),
    Broadcast,
}

pub fn destination(request: &Message, reply: &Message) -> Destination {
    if !request.giaddr().is_unspecified() {
        return Destination::Relay(request.giaddr());
    }
    let nak = reply.opts().has_msg_type(MessageType::Nak);
    if !request.ciaddr().is_unspecified() && !nak {
        return Destination::Unicast(request.ciaddr());
    }
    Destination::Broadcast
}

/// Set the broadcast flag (for building test requests).
pub fn broadcast_flags() -> Flags {
    Flags::default().set_broadcast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use daygle_dns_core::dhcp::DhcpReservation;

    fn scope() -> DhcpScope {
        DhcpScope {
            name: "lan".to_string(),
            subnet: "192.168.1.0/24".to_string(),
            range_start: "192.168.1.100".to_string(),
            range_end: "192.168.1.102".to_string(),
            router: "192.168.1.1".to_string(),
            domain_name: "home.arpa".to_string(),
            reservations: vec![DhcpReservation {
                client: "02:00:00:00:00:99".to_string(),
                address: "192.168.1.50".to_string(),
                hostname: "printer".to_string(),
                description: String::new(),
            }],
            ..DhcpScope::default()
        }
    }

    fn ctx(scope: &DhcpScope) -> Context<'_> {
        Context {
            scope,
            net: scope.net().unwrap(),
            server_ip: "192.168.1.2".parse().unwrap(),
            now: 1_000,
        }
    }

    fn request(kind: MessageType, mac: u8) -> Message {
        let mut msg = Message::new_with_id(
            7,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &[2, 0, 0, 0, 0, mac],
        );
        msg.opts_mut().insert(DhcpOption::MessageType(kind));
        msg.opts_mut()
            .insert(DhcpOption::Hostname("Kids-iPad".to_string()));
        msg
    }

    fn yiaddr_of(reply: &Option<Message>) -> Ipv4Addr {
        reply.as_ref().expect("a reply").yiaddr()
    }

    #[test]
    fn discover_request_ack_binds_a_lease() {
        let scope = scope();
        let ctx = ctx(&scope);
        let mut leases = Leases::default();
        let offer = handle(&ctx, &request(MessageType::Discover, 1), &mut leases);
        let ip = yiaddr_of(&offer);
        assert_eq!(ip, "192.168.1.100".parse::<Ipv4Addr>().unwrap());
        let offer = offer.unwrap();
        assert!(offer.opts().has_msg_type(MessageType::Offer));
        assert!(
            matches!(offer.opts().get(OptionCode::Router), Some(DhcpOption::Router(r)) if r == &vec!["192.168.1.1".parse::<Ipv4Addr>().unwrap()])
        );
        assert!(
            matches!(offer.opts().get(OptionCode::DomainNameServer), Some(DhcpOption::DomainNameServer(d)) if d == &vec![ctx.server_ip])
        );

        let mut req = request(MessageType::Request, 1);
        req.opts_mut().insert(DhcpOption::RequestedIpAddress(ip));
        req.opts_mut()
            .insert(DhcpOption::ServerIdentifier(ctx.server_ip));
        let ack = handle(&ctx, &req, &mut leases).unwrap();
        assert!(ack.opts().has_msg_type(MessageType::Ack));
        let lease = leases.get(&IpAddr::V4(ip)).unwrap();
        assert_eq!(lease.state, BOUND);
        assert_eq!(lease.hostname, "kids-ipad");
        assert_eq!(lease.hw_address, "02:00:00:00:00:01");
        assert_eq!(lease.expires, 1_000 + 86_400);

        // A second client gets the next address; the same client the same.
        assert_eq!(
            yiaddr_of(&handle(
                &ctx,
                &request(MessageType::Discover, 2),
                &mut leases
            )),
            "192.168.1.101".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            yiaddr_of(&handle(
                &ctx,
                &request(MessageType::Discover, 1),
                &mut leases
            )),
            ip
        );
    }

    #[test]
    fn reservations_and_exhaustion() {
        let scope = scope();
        let ctx = ctx(&scope);
        let mut leases = Leases::default();
        assert_eq!(
            yiaddr_of(&handle(
                &ctx,
                &request(MessageType::Discover, 0x99),
                &mut leases
            )),
            "192.168.1.50".parse::<Ipv4Addr>().unwrap()
        );
        for mac in 1..=3 {
            assert!(handle(&ctx, &request(MessageType::Discover, mac), &mut leases).is_some());
        }
        // Three addresses in the range: the fourth client gets nothing.
        assert!(handle(&ctx, &request(MessageType::Discover, 4), &mut leases).is_none());
        // Someone else asking for the reserved address is refused.
        let mut req = request(MessageType::Request, 5);
        req.opts_mut().insert(DhcpOption::RequestedIpAddress(
            "192.168.1.50".parse().unwrap(),
        ));
        let nak = handle(&ctx, &req, &mut leases).unwrap();
        assert!(nak.opts().has_msg_type(MessageType::Nak));
    }

    #[test]
    fn release_decline_inform_and_other_servers() {
        let scope = scope();
        let ctx = ctx(&scope);
        let mut leases = Leases::default();
        let ip = yiaddr_of(&handle(
            &ctx,
            &request(MessageType::Discover, 1),
            &mut leases,
        ));
        // The client picked another server's offer: ours is withdrawn.
        let mut req = request(MessageType::Request, 1);
        req.opts_mut()
            .insert(DhcpOption::ServerIdentifier("192.168.1.3".parse().unwrap()));
        assert!(handle(&ctx, &req, &mut leases).is_none());
        assert!(leases.get(&IpAddr::V4(ip)).is_none());
        // Bind, then release.
        let mut req = request(MessageType::Request, 1);
        req.opts_mut().insert(DhcpOption::RequestedIpAddress(ip));
        handle(&ctx, &req, &mut leases).unwrap();
        let mut release = request(MessageType::Release, 1);
        release.set_ciaddr(ip);
        assert!(handle(&ctx, &release, &mut leases).is_none());
        assert_eq!(leases.get(&IpAddr::V4(ip)).unwrap().state, RELEASED);
        // Decline: the address is set aside.
        let mut req = request(MessageType::Request, 1);
        req.opts_mut().insert(DhcpOption::RequestedIpAddress(ip));
        handle(&ctx, &req, &mut leases).unwrap();
        let mut decline = request(MessageType::Decline, 1);
        decline
            .opts_mut()
            .insert(DhcpOption::RequestedIpAddress(ip));
        handle(&ctx, &decline, &mut leases);
        assert_eq!(leases.get(&IpAddr::V4(ip)).unwrap().state, DECLINED);
        assert_ne!(
            yiaddr_of(&handle(
                &ctx,
                &request(MessageType::Discover, 1),
                &mut leases
            )),
            ip
        );
        // Inform: options only.
        let mut inform = request(MessageType::Inform, 7);
        inform.set_ciaddr("192.168.1.20".parse::<Ipv4Addr>().unwrap());
        let ack = handle(&ctx, &inform, &mut leases).unwrap();
        assert!(ack.yiaddr().is_unspecified());
        assert!(ack.opts().get(OptionCode::AddressLeaseTime).is_none());
        assert_eq!(
            destination(&inform, &ack),
            Destination::Unicast("192.168.1.20".parse().unwrap())
        );
    }
}
