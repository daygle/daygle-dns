//! DNS cookies (RFC 7873), with server cookies in the interoperable
//! layout of RFC 9018: version 1, three reserved bytes, a timestamp and an
//! 8-byte SipHash-2-4 of the client cookie, those fields and the client's
//! address, keyed by a secret made at start-up.
//!
//! A client that sends a cookie gets its client cookie back with a fresh
//! server cookie on every response. A request whose server cookie checks
//! out comes from the address it claims (a spoofed source could not have
//! received the cookie), so it is not held to the per-client rate limit.
//! Requests without a cookie, or with a stale one, are answered as usual.

use std::hash::Hasher;
use std::net::IpAddr;

use hickory_proto::op::Edns;
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::Record;
use hickory_server::net::NetError;
use hickory_server::server::{ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponse;
use siphasher::sip::SipHasher24;

/// Server cookies older than this are no longer accepted (RFC 9018 §4.3).
const MAX_AGE_SECS: u32 = 3600;
/// ... nor ones dated more than this far in the future.
const MAX_FUTURE_SECS: u32 = 300;

/// The server-cookie secret and whether cookies are on.
pub struct Cookies {
    enabled: bool,
    secret: [u8; 16],
}

/// What a request's COOKIE option says.
#[derive(Debug, PartialEq, Eq)]
pub enum CookieCheck {
    /// No cookie (or cookies are off).
    Absent,
    /// A COOKIE option of the wrong length: FORMERR (RFC 7873 §5.2.2).
    Malformed,
    /// A client cookie, and whether the server cookie with it was ours and
    /// fresh. `reply` is the COOKIE option to send back.
    Present { valid: bool, reply: Vec<u8> },
}

fn random_secret() -> [u8; 16] {
    let mut secret = [0u8; 16];
    if getrandom::fill(&mut secret).is_err() {
        panic!("no OS CSPRNG available for the DNS cookie secret");
    }
    secret
}

impl Cookies {
    /// Cookies keyed by this process's secret, which stays the same across
    /// listener rebuilds (so clients' cookies keep working after a reload).
    pub fn new(enabled: bool) -> Self {
        static SECRET: std::sync::OnceLock<[u8; 16]> = std::sync::OnceLock::new();
        Self {
            enabled,
            secret: *SECRET.get_or_init(random_secret),
        }
    }

    #[cfg(test)]
    fn with_random_secret(enabled: bool) -> Self {
        Self {
            enabled,
            secret: random_secret(),
        }
    }

    fn hash(&self, client_cookie: &[u8], header: &[u8; 8], client: IpAddr) -> [u8; 8] {
        let mut hasher = SipHasher24::new_with_key(&self.secret);
        hasher.write(client_cookie);
        hasher.write(header);
        match client {
            IpAddr::V4(v4) => hasher.write(&v4.octets()),
            IpAddr::V6(v6) => hasher.write(&v6.octets()),
        }
        hasher.finish().to_be_bytes()
    }

    /// Our server cookie for this client at `now`.
    fn server_cookie(&self, client_cookie: &[u8], client: IpAddr, now: u32) -> [u8; 16] {
        let mut header = [0u8; 8];
        header[0] = 1;
        header[4..].copy_from_slice(&now.to_be_bytes());
        let mut cookie = [0u8; 16];
        cookie[..8].copy_from_slice(&header);
        cookie[8..].copy_from_slice(&self.hash(client_cookie, &header, client));
        cookie
    }

    fn valid(&self, client_cookie: &[u8], server: &[u8], client: IpAddr, now: u32) -> bool {
        if server.len() != 16 || server[0] != 1 {
            return false;
        }
        let header: [u8; 8] = server[..8].try_into().expect("length checked");
        let stamp = u32::from_be_bytes(header[4..].try_into().expect("length checked"));
        let fresh = if stamp <= now {
            now - stamp <= MAX_AGE_SECS
        } else {
            stamp - now <= MAX_FUTURE_SECS
        };
        fresh
            && daygle_dns_core::auth::constant_time_eq(
                &server[8..],
                &self.hash(client_cookie, &header, client),
            )
    }

    /// Read the request's COOKIE option (`client` canonical, `now` UNIX
    /// seconds).
    pub fn check(&self, edns: Option<&Edns>, client: IpAddr, now: u32) -> CookieCheck {
        if !self.enabled {
            return CookieCheck::Absent;
        }
        let Some(EdnsOption::Unknown(_, data)) = edns.and_then(|e| e.option(EdnsCode::Cookie))
        else {
            return CookieCheck::Absent;
        };
        // 8 bytes of client cookie, then nothing or 8-32 bytes of server
        // cookie.
        if data.len() < 8 || (data.len() > 8 && data.len() < 16) || data.len() > 40 {
            return CookieCheck::Malformed;
        }
        let (client_cookie, server) = data.split_at(8);
        let valid = !server.is_empty() && self.valid(client_cookie, server, client, now);
        let mut reply = client_cookie.to_vec();
        reply.extend_from_slice(&self.server_cookie(client_cookie, client, now));
        CookieCheck::Present { valid, reply }
    }
}

/// Re-type a response for a shorter-lived OPT record (the queries and OPT
/// it borrows only have to outlive the send).
fn with_edns<'q, 'e, 'a, A, B, C, D>(
    response: MessageResponse<'q, 'a, A, B, C, D>,
    edns: &'e Edns,
) -> MessageResponse<'e, 'a, A, B, C, D>
where
    'q: 'e,
    A: Iterator<Item = &'a Record> + Send + 'a,
    B: Iterator<Item = &'a Record> + Send + 'a,
    C: Iterator<Item = &'a Record> + Send + 'a,
    D: Iterator<Item = &'a Record> + Send + 'a,
{
    let mut response: MessageResponse<'e, 'a, A, B, C, D> = response;
    response.set_edns(edns);
    response
}

/// Adds the COOKIE option to whatever response goes out (from the
/// dispatcher or the authoritative catalog) when the request had a cookie.
#[derive(Clone)]
pub struct CookieResponder<R> {
    inner: R,
    reply: Option<Vec<u8>>,
}

impl<R> CookieResponder<R> {
    pub fn new(inner: R, reply: Option<Vec<u8>>) -> Self {
        Self { inner, reply }
    }
}

#[async_trait::async_trait]
impl<R: ResponseHandler> ResponseHandler for CookieResponder<R> {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        // Only responses that carry an OPT record (the client sent EDNS,
        // which it must to send a cookie) get one.
        let edns = match (&self.reply, response.edns()) {
            (Some(reply), Some(edns)) => {
                let mut edns = edns.clone();
                // Replace any cookie already there (the catalog echoes the
                // request's options).
                edns.options_mut()
                    .as_mut()
                    .retain(|(code, _)| *code != EdnsCode::Cookie);
                edns.options_mut().insert(EdnsOption::Unknown(
                    u16::from(EdnsCode::Cookie),
                    reply.clone(),
                ));
                Some(edns)
            }
            _ => None,
        };
        match &edns {
            Some(edns) => self.inner.send_response(with_edns(response, edns)).await,
            None => self.inner.send_response(response).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edns_with_cookie(data: Vec<u8>) -> Edns {
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Unknown(u16::from(EdnsCode::Cookie), data));
        edns
    }

    #[test]
    fn server_cookies_round_trip_and_expire() {
        let cookies = Cookies::new(true);
        let client: IpAddr = "192.0.2.7".parse().unwrap();
        let client_cookie = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let now = 1_800_000_000;

        // First contact: no server cookie yet; one comes back.
        let CookieCheck::Present { valid, reply } =
            cookies.check(Some(&edns_with_cookie(client_cookie.clone())), client, now)
        else {
            panic!("cookie expected");
        };
        assert!(!valid);
        assert_eq!(reply.len(), 24);
        assert_eq!(&reply[..8], &client_cookie[..]);
        assert_eq!(reply[8], 1, "RFC 9018 version");

        // Sending it back checks out, from the same address only, and only
        // while fresh.
        let check =
            |ip: IpAddr, at: u32| cookies.check(Some(&edns_with_cookie(reply.clone())), ip, at);
        assert!(matches!(
            check(client, now + 60),
            CookieCheck::Present { valid: true, .. }
        ));
        assert!(matches!(
            check("192.0.2.8".parse().unwrap(), now),
            CookieCheck::Present { valid: false, .. }
        ));
        assert!(matches!(
            check(client, now + MAX_AGE_SECS + 1),
            CookieCheck::Present { valid: false, .. }
        ));
        assert!(matches!(
            check(client, now - MAX_FUTURE_SECS - 1),
            CookieCheck::Present { valid: false, .. }
        ));
        // Tampering is caught.
        let mut forged = reply.clone();
        forged[23] ^= 1;
        assert!(matches!(
            cookies.check(Some(&edns_with_cookie(forged)), client, now),
            CookieCheck::Present { valid: false, .. }
        ));
        // Another server's secret does not validate ours.
        assert!(matches!(
            Cookies::with_random_secret(true).check(
                Some(&edns_with_cookie(reply.clone())),
                client,
                now
            ),
            CookieCheck::Present { valid: false, .. }
        ));
    }

    #[test]
    fn malformed_absent_and_disabled() {
        let cookies = Cookies::new(true);
        let client: IpAddr = "2001:db8::1".parse().unwrap();
        for len in [0, 7, 9, 15, 41] {
            assert_eq!(
                cookies.check(Some(&edns_with_cookie(vec![0; len])), client, 0),
                CookieCheck::Malformed,
                "length {len}"
            );
        }
        assert_eq!(
            cookies.check(Some(&Edns::new()), client, 0),
            CookieCheck::Absent
        );
        assert_eq!(cookies.check(None, client, 0), CookieCheck::Absent);
        assert_eq!(
            Cookies::new(false).check(Some(&edns_with_cookie(vec![0; 8])), client, 0),
            CookieCheck::Absent
        );
    }
}
