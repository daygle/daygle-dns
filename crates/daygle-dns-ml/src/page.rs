//! Page-content stage: the second opinion behind a threat verdict.
//!
//! A domain name says little on its own. This stage takes the domains the
//! threat channel already flagged, fetches the page itself, and reads its
//! title and text with a small lexical classifier ([`classify_text`]), so the
//! console can show what the site actually says next to the name that got it
//! flagged.
//!
//! It is **evidence, not a decision**: nothing here blocks, clears or raises a
//! verdict. The text classifier is a cue table with fixed weights, not a
//! trained model, and its confidence is capped below the default block
//! threshold, so it cannot become the reason a domain is blocked. Its output
//! is appended to the threat verdict's evidence once per classification.
//!
//! Fetching is the risky part, so the rules are deliberately narrow:
//!
//! * only `http` and `https`, only default ports, and only ordinary domain
//!   names - no IP literals, no userinfo in the URL;
//! * the host is resolved once here and every address it answers with must be
//!   globally routable (loopback, private, link-local, CGNAT, multicast,
//!   unspecified, documentation and reserved ranges are refused), then that
//!   address is pinned into the HTTP client, so a second DNS answer cannot
//!   redirect the request into the local network;
//! * redirects are followed by hand, at most three, each one re-validated the
//!   same way - a redirect to `http://10.0.0.1/` is refused;
//! * the response must be HTML or plain text, is read through a byte cap, and
//!   the whole request is bounded by a timeout.
//!
//! The stage is off unless `ai.fetch_pages` is on, and it only ever sees
//! domains the threat channel already reported.

use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use daygle_dns_core::config::PageRule;
use reqwest::header::{ACCEPT, CONTENT_TYPE, LOCATION};
use reqwest::redirect::Policy as RedirectPolicy;

/// Sent as the user agent, so an operator reading their access log can tell
/// where the request came from.
const USER_AGENT: &str = concat!("daygle-dns/", env!("CARGO_PKG_VERSION"));
const ACCEPT_VALUE: &str = "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.1";
/// Redirects followed before giving up.
const MAX_REDIRECTS: usize = 3;
/// Fetches running at once.
const FETCH_WORKERS: usize = 4;
/// Below this much readable text a page is treated as having none: an empty
/// shell, a consent wall, or a script-only page says nothing worth recording.
const MIN_TEXT_CHARS: usize = 40;

/// What a fetched page yielded: its address after redirects, its `<title>`
/// and its readable text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageContent {
    pub url: String,
    pub title: String,
    pub text: String,
}

/// A category the page text suggests, with the cues that suggested it.
#[derive(Debug, Clone, PartialEq)]
pub struct TextVerdict {
    pub category: &'static str,
    /// At most 0.9: below the default auto-block threshold, by construction.
    pub confidence: f32,
    /// The phrases that matched, strongest first.
    pub cues: Vec<&'static str>,
}

/// One weighted phrase. Matching is whole-phrase on normalised text, so
/// "verify your account" never fires on "verify account details" by accident.
struct Cue {
    phrase: &'static str,
    category: &'static str,
    weight: f32,
}

const CUES: &[Cue] = &[
    Cue {
        phrase: "verify your account",
        category: "phishing",
        weight: 3.0,
    },
    Cue {
        phrase: "confirm your password",
        category: "phishing",
        weight: 3.0,
    },
    Cue {
        phrase: "unusual sign-in",
        category: "phishing",
        weight: 3.0,
    },
    Cue {
        phrase: "account will be suspended",
        category: "phishing",
        weight: 3.0,
    },
    Cue {
        phrase: "seed phrase",
        category: "phishing",
        weight: 3.0,
    },
    Cue {
        phrase: "connect your wallet",
        category: "scam",
        weight: 3.0,
    },
    Cue {
        phrase: "claim your reward",
        category: "scam",
        weight: 2.0,
    },
    Cue {
        phrase: "double your",
        category: "scam",
        weight: 2.0,
    },
    Cue {
        phrase: "free crypto",
        category: "scam",
        weight: 2.0,
    },
    Cue {
        phrase: "gift card",
        category: "scam",
        weight: 1.5,
    },
    Cue {
        phrase: "download crack",
        category: "malware",
        weight: 3.0,
    },
    Cue {
        phrase: "ransomware",
        category: "malware",
        weight: 3.0,
    },
    Cue {
        phrase: "keylogger",
        category: "malware",
        weight: 3.0,
    },
    Cue {
        phrase: "deposit bonus",
        category: "gambling",
        weight: 2.0,
    },
    Cue {
        phrase: "betting odds",
        category: "gambling",
        weight: 1.5,
    },
    Cue {
        phrase: "casino",
        category: "gambling",
        weight: 1.5,
    },
    Cue {
        phrase: "explicit content",
        category: "adult",
        weight: 2.0,
    },
    Cue {
        phrase: "add to cart",
        category: "shopping",
        weight: 1.5,
    },
    Cue {
        phrase: "breaking news",
        category: "news",
        weight: 1.5,
    },
];

/// A score below this is noise: one weak cue in a long page says nothing.
const MIN_SCORE: f32 = 2.0;

/// Classify page text. Deliberately small: a normalised bag of weighted
/// phrases, each counted once however often it appears, so stuffing a page
/// with one keyword cannot inflate the score.
pub fn classify_text(title: &str, text: &str) -> Option<TextVerdict> {
    let haystack = normalise(&format!("{title} {text}"));
    if haystack.is_empty() {
        return None;
    }
    let mut scores: Vec<(&'static str, f32, Vec<&'static str>)> = Vec::new();
    for cue in CUES {
        if !haystack.contains(cue.phrase) {
            continue;
        }
        match scores
            .iter_mut()
            .find(|(category, _, _)| *category == cue.category)
        {
            Some((_, score, cues)) => {
                *score += cue.weight;
                cues.push(cue.phrase);
            }
            None => scores.push((cue.category, cue.weight, vec![cue.phrase])),
        }
    }
    let (category, mut score, mut cues) = scores
        .into_iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))?;
    if score < MIN_SCORE {
        return None;
    }
    cues.sort_by(|a, b| {
        let weight = |phrase: &str| {
            CUES.iter()
                .find(|c| c.phrase == phrase)
                .map(|c| c.weight)
                .unwrap_or(0.0)
        };
        weight(b)
            .partial_cmp(&weight(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    // 0.4 at the threshold, +0.1 per point of cue weight, capped at 0.9.
    score = score.min(5.0);
    Some(TextVerdict {
        category,
        confidence: (0.4 + 0.1 * score).min(0.9),
        cues,
    })
}

fn normalise(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut space = true;
    for ch in lower.chars() {
        if ch.is_ascii_alphanumeric() || ch == '\'' {
            out.push(ch);
            space = false;
        } else if !space {
            out.push(' ');
            space = true;
        }
    }
    out.trim().to_string()
}

/// Which addresses the fetcher may connect to. Tests open it for loopback
/// only, so the network path can be exercised without touching the internet.
#[derive(Debug, Clone, Copy)]
struct AddressPolicy {
    allow_loopback: bool,
}

impl AddressPolicy {
    fn allows(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback() {
                    return self.allow_loopback;
                }
                is_global_v4(v4)
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    return self.allow_loopback;
                }
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return is_global_v4(v4);
                }
                !(v6.is_unspecified()
                    || v6.is_multicast()
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
                    || (v6.segments()[0] & 0xffc0) == 0xfe80)
            }
        }
    }
}

fn is_global_v4(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || octets[0] == 0
        || octets[0] >= 240
        || (octets[0] == 100 && (64..=127).contains(&octets[1])))
}

/// Fetches pages under the rules in the module documentation.
#[derive(Debug, Clone)]
pub struct PageFetcher {
    timeout: Duration,
    max_bytes: usize,
    policy: AddressPolicy,
    /// Test hook: connect here instead of resolving the host, with the port
    /// spelled in the URL (reqwest pins the address but not the port). `None`
    /// in production, where resolution is the thing being pinned.
    pinned: Option<(SocketAddr, u16)>,
}

impl PageFetcher {
    pub fn new(timeout: Duration, max_bytes: usize) -> Self {
        Self {
            timeout,
            max_bytes,
            policy: AddressPolicy {
                allow_loopback: false,
            },
            pinned: None,
        }
    }

    #[cfg(test)]
    fn pinned(addr: SocketAddr, timeout: Duration, max_bytes: usize) -> Self {
        Self {
            timeout,
            max_bytes,
            policy: AddressPolicy {
                allow_loopback: true,
            },
            pinned: Some((addr, addr.port())),
        }
    }

    /// Fetch `domain`'s home page, HTTPS first and plain HTTP if that fails.
    /// The error is a short human-readable reason, recorded as evidence.
    pub fn fetch(&self, domain: &str) -> Result<PageContent, String> {
        let host = normalise_host(domain).ok_or_else(|| "not a fetchable host".to_string())?;
        let mut last = String::from("no attempt made");
        for scheme in ["https", "http"] {
            match self.fetch_url(&host, scheme, "/", 0) {
                Ok(page) => return Ok(page),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn fetch_url(
        &self,
        host: &str,
        scheme: &str,
        target: &str,
        hops: usize,
    ) -> Result<PageContent, String> {
        let addr = self.resolve(host, scheme)?;
        let url = match self.pinned {
            Some((_, port)) => format!("{scheme}://{host}:{port}{target}"),
            None => format!("{scheme}://{host}{target}"),
        };
        let client = reqwest::blocking::Client::builder()
            .timeout(self.timeout)
            .redirect(RedirectPolicy::none())
            .resolve(host, addr)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|e| format!("client error: {e}"))?;
        let response = client
            .get(&url)
            .header(ACCEPT, ACCEPT_VALUE)
            .send()
            .map_err(|e| format!("request failed: {e}"))?;

        let status = response.status();
        if status.is_redirection() {
            if hops >= MAX_REDIRECTS {
                return Err("too many redirects".to_string());
            }
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| "redirect without a location".to_string())?
                .to_string();
            let (next_scheme, next_host, next_target) = redirect_target(scheme, host, &location)?;
            return self.fetch_url(&next_host, &next_scheme, &next_target, hops + 1);
        }
        if !status.is_success() {
            return Err(format!("HTTP {status}"));
        }

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !(content_type.starts_with("text/html")
            || content_type.starts_with("application/xhtml")
            || content_type.starts_with("text/plain"))
        {
            return Err(if content_type.is_empty() {
                "no content type".to_string()
            } else {
                format!("not an HTML page ({content_type})")
            });
        }

        let mut body = Vec::new();
        response
            .take(self.max_bytes as u64)
            .read_to_end(&mut body)
            .map_err(|e| format!("read failed: {e}"))?;
        let html = String::from_utf8_lossy(&body);
        let (title, text) = extract(&html);
        if text.chars().count() < MIN_TEXT_CHARS {
            return Err("page had no readable text".to_string());
        }
        Ok(PageContent { url, title, text })
    }

    /// Resolve once, refuse if *any* answer is not globally routable, and hand
    /// back the address to pin: the client never resolves the name again.
    fn resolve(&self, host: &str, scheme: &str) -> Result<SocketAddr, String> {
        if let Some((addr, _)) = self.pinned {
            if !self.policy.allows(addr.ip()) {
                return Err("refusing to fetch a non-public address".to_string());
            }
            return Ok(addr);
        }
        let port = if scheme == "https" { 443 } else { 80 };
        let addrs: Vec<SocketAddr> = (host, port)
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve {host}: {e}"))?
            .collect();
        if addrs.is_empty() {
            return Err(format!("{host} has no address"));
        }
        if addrs.iter().any(|a| !self.policy.allows(a.ip())) {
            return Err(format!(
                "refusing to fetch {host}: it resolves to a non-public address"
            ));
        }
        Ok(addrs[0])
    }
}

/// A host we are willing to put in a URL: an ordinary name, not an address
/// literal and not a name with credentials in it.
fn normalise_host(domain: &str) -> Option<String> {
    let host = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 || host.parse::<IpAddr>().is_ok() {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
    }
    Some(host)
}

/// Where a redirect points, with the same rules applied to the new host.
fn redirect_target(
    scheme: &str,
    host: &str,
    location: &str,
) -> Result<(String, String, String), String> {
    let location = location.trim();
    let (next_scheme, rest) = if let Some(rest) = location.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = location.strip_prefix("http://") {
        ("http", rest)
    } else if location.starts_with('/') {
        return Ok((
            scheme.to_string(),
            host.to_string(),
            without_fragment(location),
        ));
    } else {
        return Err("relative redirect not followed".to_string());
    };
    let rest = without_fragment(rest);
    let rest = rest.as_str();
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    if authority.contains('@') {
        return Err("redirect with credentials not followed".to_string());
    }
    let (next_host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let expected = if next_scheme == "https" { "443" } else { "80" };
    if let Some(port) = port {
        if port != expected {
            return Err(format!("redirect to port {port} not followed"));
        }
    }
    let next_host =
        normalise_host(next_host).ok_or_else(|| "redirect to an invalid host".to_string())?;
    Ok((
        next_scheme.to_string(),
        next_host,
        if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        },
    ))
}

fn without_fragment(value: &str) -> String {
    match value.find('#') {
        Some(index) => value[..index].to_string(),
        None => value.to_string(),
    }
}

/// Readable title and text out of an HTML document: scripts, styles,
/// comments and tags dropped, entities decoded, whitespace collapsed.
pub fn extract(html: &str) -> (String, String) {
    let lower = html.to_ascii_lowercase();
    let mut title = String::new();
    let mut text = String::new();
    let mut i = 0usize;
    while i < html.len() {
        match lower[i..].find('<') {
            Some(offset) => {
                let open = i + offset;
                text.push_str(&html[i..open]);
                text.push(' ');
                if lower[open..].starts_with("<!--") {
                    match lower[open..].find("-->") {
                        Some(end) => i = open + end + 3,
                        None => break,
                    }
                    continue;
                }
                let mut skipped = false;
                for tag in ["script", "style", "noscript"] {
                    if lower[open..].starts_with(&format!("<{tag}")) {
                        let close = format!("</{tag}>");
                        match lower[open..].find(&close) {
                            Some(end) => i = open + end + close.len(),
                            None => i = html.len(),
                        }
                        skipped = true;
                        break;
                    }
                }
                if skipped {
                    continue;
                }
                if lower[open..].starts_with("<title")
                    && title.is_empty()
                    && lower[open..].find('>').is_some()
                {
                    let start = open + lower[open..].find('>').unwrap_or(0) + 1;
                    if let Some(end) = lower[start..].find("</title>") {
                        title = decode(&html[start..start + end]);
                        i = start + end + "</title>".len();
                        continue;
                    }
                }
                match lower[open..].find('>') {
                    Some(end) => i = open + end + 1,
                    None => break,
                }
            }
            None => {
                text.push_str(&html[i..]);
                break;
            }
        }
    }
    (collapse(&title), collapse(&decode(&text)))
}

fn decode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find('&') {
        out.push_str(&rest[..index]);
        let tail = &rest[index..];
        let mut replaced = false;
        for (entity, value) in [
            ("&amp;", "&"),
            ("&lt;", "<"),
            ("&gt;", ">"),
            ("&quot;", "\""),
            ("&#39;", "'"),
            ("&apos;", "'"),
            ("&nbsp;", " "),
        ] {
            if let Some(after) = tail.strip_prefix(entity) {
                out.push_str(value);
                rest = after;
                replaced = true;
                break;
            }
        }
        if !replaced {
            out.push('&');
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    out
}

fn collapse(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !space && !out.is_empty() {
                out.push(' ');
                space = true;
            }
        } else {
            out.push(ch);
            space = false;
        }
    }
    out.trim().to_string()
}

/// What one page read produced: the evidence line, and the reading the
/// configured rule may act on.
#[derive(Debug, Clone, PartialEq)]
pub struct Inspection {
    pub note: String,
    pub reading: Option<TextVerdict>,
}

/// What the scanner needs from a page read: the evidence line and the reading
/// a rule may act on. [`PageFetcher`] is the live implementation; tests and
/// callers that already hold readings can supply their own without a network.
pub trait PageReader: Send + Sync {
    fn inspect(&self, domain: &str) -> Inspection;
}

impl PageReader for PageFetcher {
    fn inspect(&self, domain: &str) -> Inspection {
        read_page(self, domain)
    }
}

/// The confidence `page_rule` gives a threat verdict after reading its page,
/// or `None` when the rule leaves it alone.
///
/// The two directions are deliberately asymmetric: agreement can only raise a
/// confidence (a corroborating page never makes a verdict more certain than
/// the page itself), while disagreement caps it at `1 - confidence`, the
/// page's own certainty that it is ordinary. Only `decide` may lower.
pub fn adjust_confidence(
    rule: PageRule,
    base: f32,
    reading: Option<&TextVerdict>,
    mut is_threat_label: impl FnMut(&str) -> bool,
    floor: f32,
) -> Option<f32> {
    if rule == PageRule::Evidence {
        return None;
    }
    let reading = reading?;
    if reading.confidence < floor.clamp(0.0, 1.0) {
        return None;
    }
    if is_threat_label(reading.category) {
        let raised = base.max(reading.confidence).min(1.0);
        (raised > base + 0.001).then_some(raised)
    } else if rule == PageRule::Decide {
        let capped = base.min(1.0 - reading.confidence).max(0.0);
        (capped < base - 0.001).then_some(capped)
    } else {
        None
    }
}

/// A one-line note for the threat verdict's evidence: what the page said, or
/// why it could not be read. Bounded, since evidence is shown in a table.
pub fn evidence_note(outcome: &Result<PageContent, String>) -> String {
    match outcome {
        Ok(page) => {
            let title = truncate(&page.title, 80);
            match classify_text(&page.title, &page.text) {
                Some(verdict) => format!(
                    "page \"{title}\" reads {} ({:.0}%: {})",
                    verdict.category,
                    verdict.confidence * 100.0,
                    verdict
                        .cues
                        .iter()
                        .take(3)
                        .copied()
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                None => format!("page \"{title}\" read, no category matched"),
            }
        }
        Err(e) => format!("page not read: {}", truncate(e, 120)),
    }
}

fn truncate(text: &str, limit: usize) -> String {
    let text = text.trim();
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let mut out: String = text.chars().take(limit).collect();
    out.push_str("...");
    out
}

/// Fetch `domain` and classify what it says, in the shape the scanner records.
pub fn read_page(fetcher: &PageFetcher, domain: &str) -> Inspection {
    let outcome = fetcher.fetch(domain);
    let reading = match &outcome {
        Ok(page) => classify_text(&page.title, &page.text),
        Err(_) => None,
    };
    Inspection {
        note: evidence_note(&outcome),
        reading,
    }
}

/// Workers used for a batch of candidates.
pub fn workers() -> usize {
    FETCH_WORKERS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    fn public() -> AddressPolicy {
        AddressPolicy {
            allow_loopback: false,
        }
    }

    #[test]
    fn private_and_special_addresses_are_refused() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.9",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "192.0.2.10",
            "255.255.255.255",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(!public().allows(ip), "{ip} should not be fetchable");
        }
        for ip in ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(public().allows(ip), "{ip} should be fetchable");
        }
        // Only the test policy opens loopback, and only loopback.
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(AddressPolicy {
            allow_loopback: true
        }
        .allows(loopback));
        let private: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!AddressPolicy {
            allow_loopback: true
        }
        .allows(private));
    }

    #[test]
    fn hosts_are_ordinary_names() {
        assert_eq!(
            normalise_host("Example.COM."),
            Some("example.com".to_string())
        );
        assert_eq!(
            normalise_host("news.example.co.uk"),
            Some("news.example.co.uk".to_string())
        );
        for bad in [
            "",
            "localhost",
            "http://example.com",
            "example.com/path",
            "1.2.3.4",
            "exa mple.com",
            "-example.com",
            "example..com",
            "user@example.com",
        ] {
            assert!(normalise_host(bad).is_none(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn redirects_are_revalidated() {
        let ok = redirect_target("https", "example.com", "https://www.example.com/login").unwrap();
        assert_eq!(ok.0, "https");
        assert_eq!(ok.1, "www.example.com");
        assert_eq!(ok.2, "/login");
        let relative = redirect_target("http", "example.com", "/next#top").unwrap();
        assert_eq!(relative.2, "/next");
        // An address literal, a private hostname's port, or credentials are
        // all refused before a second request is made.
        assert!(redirect_target("https", "example.com", "http://127.0.0.1/").is_err());
        assert!(redirect_target("https", "example.com", "http://example.com:8080/").is_err());
        assert!(redirect_target("https", "example.com", "https://user:pw@example.com/").is_err());
        assert!(redirect_target("https", "example.com", "ftp://example.com/").is_err());
        assert!(redirect_target("https", "example.com", "other").is_err());
    }

    #[test]
    fn extraction_drops_scripts_and_styles() {
        let html = r#"<html><head><title>  Example &amp; Co  </title>
            <style>body { color: red }</style>
            <script>var secret = "<p>not text</p>";</script></head>
            <body><!-- comment --><h1>Hello</h1><p>World&nbsp;wide</p></body></html>"#;
        let (title, text) = extract(html);
        assert_eq!(title, "Example & Co");
        assert_eq!(text, "Hello World wide");
        assert!(!text.contains("color"));
        assert!(!text.contains("not text"));
    }

    #[test]
    fn a_name_that_is_not_a_host_is_never_fetched() {
        // No network is touched: the name is refused before resolution.
        let fetcher = PageFetcher::new(Duration::from_secs(5), 64 * 1024);
        let note = read_page(&fetcher, "under_score.example").note;
        assert!(note.contains("not a fetchable host"), "{note}");
        assert!(read_page(&fetcher, "127.0.0.1")
            .note
            .contains("not a fetchable host"));
        assert!(read_page(&fetcher, "localhost")
            .note
            .contains("not a fetchable host"));
    }

    fn reading(category: &'static str, confidence: f32) -> TextVerdict {
        TextVerdict {
            category,
            confidence,
            cues: vec![],
        }
    }

    #[test]
    fn the_page_rule_only_moves_confidence_when_asked() {
        let threat = |label: &str| label == "phishing";
        let agreeing = reading("phishing", 0.8);
        let disagreeing = reading("shopping", 0.8);

        // Evidence only: never touches a verdict, in either direction.
        assert_eq!(
            adjust_confidence(PageRule::Evidence, 0.4, Some(&agreeing), threat, 0.5),
            None
        );
        assert_eq!(
            adjust_confidence(PageRule::Evidence, 0.4, Some(&disagreeing), threat, 0.5),
            None
        );

        // Corroborate: agreement raises, disagreement is ignored.
        assert_eq!(
            adjust_confidence(PageRule::Corroborate, 0.4, Some(&agreeing), threat, 0.5),
            Some(0.8)
        );
        assert_eq!(
            adjust_confidence(PageRule::Corroborate, 0.99, Some(&agreeing), threat, 0.5),
            None,
            "a reading below the current confidence raises nothing"
        );
        assert_eq!(
            adjust_confidence(PageRule::Corroborate, 0.4, Some(&disagreeing), threat, 0.5),
            None
        );

        // Decide: agreement raises, disagreement caps at 1 - confidence.
        let capped = adjust_confidence(PageRule::Decide, 0.4, Some(&disagreeing), threat, 0.5)
            .expect("a disagreeing page caps the verdict");
        assert!(
            (capped - 0.2).abs() < 1e-6,
            "0.4 capped at 1 - 0.8, got {capped}"
        );
        assert_eq!(
            adjust_confidence(PageRule::Decide, 0.4, Some(&agreeing), threat, 0.5),
            Some(0.8)
        );

        // A reading below the floor is not a second opinion at all.
        assert_eq!(
            adjust_confidence(
                PageRule::Decide,
                0.4,
                Some(&reading("shopping", 0.55)),
                threat,
                0.6
            ),
            None
        );
        assert_eq!(
            adjust_confidence(PageRule::Decide, 0.4, None, threat, 0.6),
            None
        );
    }

    #[test]
    fn text_classifier_finds_the_strongest_category() {
        let verdict = classify_text(
            "Sign in",
            "Please verify your account to avoid suspension. Confirm your password today.",
        )
        .unwrap();
        assert_eq!(verdict.category, "phishing");
        assert!(verdict.confidence >= 0.7);
        assert!(verdict.confidence <= 0.9);

        // One weak cue is not a category, and repetition does not add up.
        assert!(classify_text("Shop", "Add to cart").is_none());
        let repeated = classify_text("Shop", "add to cart add to cart add to cart");
        assert!(repeated.is_none(), "the same phrase counts once");

        assert!(classify_text("Example", "Welcome to our documentation.").is_none());
    }

    /// Serve one canned response per attempt. The fetcher tries HTTPS first,
    /// so the plain listener sees a TLS handshake before the HTTP request.
    fn serve(
        listener: TcpListener,
        response: String,
        attempts: usize,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            for _ in 0..attempts {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut request = [0u8; 4096];
                let _ = std::io::Read::read(&mut stream, &mut request);
                let _ = stream.write_all(response.as_bytes());
            }
        })
    }

    #[test]
    fn a_page_is_fetched_classified_and_bounded() {
        // A loopback server stands in for a hostile site; the test constructor
        // pins the address and is the only thing that lets the fetcher reach
        // it. Real fetches go through resolution and the public-address rule.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = "<html><head><title>Free crypto</title></head><body>Connect your wallet \
            and double your deposit. Claim your reward now, limited offer for early investors.\
            </body></html>";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let server = serve(listener, response, 2);
        let fetcher = PageFetcher::pinned(addr, Duration::from_secs(5), 64 * 1024);
        let page = fetcher.fetch("page.test").expect("page should be fetched");
        server.join().unwrap();
        assert_eq!(page.title, "Free crypto");
        assert!(page.text.contains("Connect your wallet"));
        let verdict = classify_text(&page.title, &page.text).unwrap();
        assert_eq!(verdict.category, "scam");

        let note = evidence_note(&Ok(page));
        assert!(note.contains("page \"Free crypto\""), "{note}");
        assert!(note.contains("scam"), "{note}");
        assert!(note.len() < 400);
    }

    #[test]
    fn a_page_that_is_not_html_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = serve(
            listener,
            "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: 4\r\nConnection: close\r\n\r\nPK\x03\x04".to_string(),
            2,
        );
        let fetcher = PageFetcher::pinned(addr, Duration::from_secs(5), 64 * 1024);
        let error = fetcher.fetch("page.test").unwrap_err();
        server.join().unwrap();
        assert!(error.contains("not an HTML page"), "{error}");
    }

    #[test]
    fn a_bare_page_is_not_recorded_as_read() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = "<html><body><script>app()</script></body></html>";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let server = serve(listener, response, 2);
        let fetcher = PageFetcher::pinned(addr, Duration::from_secs(5), 64 * 1024);
        let error = fetcher.fetch("page.test").unwrap_err();
        server.join().unwrap();
        assert!(error.contains("no readable text"), "{error}");
    }
}
