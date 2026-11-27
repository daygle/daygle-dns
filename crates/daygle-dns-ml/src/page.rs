//! Page-content stage: the second opinion behind a threat verdict.
//!
//! A domain name says little on its own. This stage takes the domains the
//! threat channel already flagged, fetches the page itself, and reads its
//! title and text with a small lexical classifier ([`classify_text`]), so the
//! console can show what the site actually says next to the name that got it
//! flagged.
//!
//! What the reading may do is `ai.page_rule`'s decision:
//!
//! * `evidence` (the default) only records it: nothing here blocks, clears or
//!   raises a verdict;
//! * `corroborate` lets a page that agrees raise the threat confidence, never
//!   above the reading's own confidence (at most 0.9, below the default block
//!   threshold);
//! * `decide` also lets a page that reads as an ordinary category cap the
//!   confidence - but only when no threat cue appears anywhere on the page.
//!   The page is written by the site being judged, so this direction can be
//!   gamed by a site that serves harmless-looking text to a fetcher; it is an
//!   opt-in for networks that accept that trade.
//!
//! The text classifier is a cue table with fixed weights, not a trained
//! model. Its output is appended to the threat verdict's evidence once per
//! classification.
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
//! `ai.fetch_pages` enables validation of existing threat candidates.
//! `ai.monitor_page_discovery` also inspects uncertain threat results.

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
pub(crate) const DISCOVERY_ENFORCEMENT_FLOOR: f32 = 0.95;

/// What a fetched page yielded: its address after redirects, its `<title>`
/// and its readable text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageContent {
    pub url: String,
    pub title: String,
    pub text: String,
    complete: bool,
    has_password_form: bool,
    has_sensitive_form: bool,
    redirects: RedirectEvidence,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RedirectEvidence {
    cross_site_hops: usize,
    downgraded: bool,
}

impl RedirectEvidence {
    fn record(&mut self, host: &str, scheme: &str, next_host: &str, next_scheme: &str) {
        if psl::domain_str(host).unwrap_or(host) != psl::domain_str(next_host).unwrap_or(next_host)
        {
            self.cross_site_hops += 1;
        }
        self.downgraded |= scheme == "https" && next_scheme == "http";
    }
}

/// A category the page text suggests, with the cues that suggested it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TextVerdict {
    pub category: &'static str,
    /// At most 0.9: below the default auto-block threshold, by construction.
    pub confidence: f32,
    /// The phrases that matched, strongest first.
    pub cues: Vec<&'static str>,
    /// Every other category a cue matched, however weakly. A page that reads
    /// as shopping but also says "verify your account" is not evidence that
    /// a threat verdict was wrong.
    pub also: Vec<&'static str>,
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
    // Ordinary categories need two cues to clear `MIN_SCORE`: one shop
    // phrase on a phishing page is not a reading.
    Cue {
        phrase: "add to cart",
        category: "shopping",
        weight: 1.5,
    },
    Cue {
        phrase: "free shipping",
        category: "shopping",
        weight: 1.0,
    },
    Cue {
        phrase: "shopping cart",
        category: "shopping",
        weight: 1.0,
    },
    Cue {
        phrase: "returns policy",
        category: "shopping",
        weight: 1.0,
    },
    Cue {
        phrase: "breaking news",
        category: "news",
        weight: 1.5,
    },
    Cue {
        phrase: "latest news",
        category: "news",
        weight: 1.0,
    },
    Cue {
        phrase: "top stories",
        category: "news",
        weight: 1.0,
    },
    Cue {
        phrase: "editorial",
        category: "news",
        weight: 1.0,
    },
];

/// A score below this is noise: one weak cue in a long page says nothing.
const MIN_SCORE: f32 = 2.0;

/// Classify page text. Deliberately small: a normalised bag of weighted
/// phrases, each counted once however often it appears, so stuffing a page
/// with one keyword cannot inflate the score.
pub fn classify_text(title: &str, text: &str) -> Option<TextVerdict> {
    classify_with(CUES, title, text)
}

/// What an ordinary page is about, for a domain the categorizer is unsure
/// of: the strongest category in [`CATEGORY_CUES`], or `None`. Only ordinary
/// categories are in that table, so this never reads a threat; threats are
/// [`classify_text`]'s job, on its own table, so cues added here cannot
/// outvote a threat reading.
pub fn classify_category(title: &str, text: &str) -> Option<TextVerdict> {
    classify_with(CATEGORY_CUES, title, text)
}

const fn cue(phrase: &'static str, category: &'static str, weight: f32) -> Cue {
    Cue {
        phrase,
        category,
        weight,
    }
}

/// Phrases that say what an ordinary site is, by the categorizer's labels.
/// Like the ordinary cues in [`CUES`], one phrase alone never clears
/// `MIN_SCORE`: a reading takes two, or one strong and one weak. Phrases
/// are chosen to be specific; words every site has ("menu", "contact us")
/// are left out.
const CATEGORY_CUES: &[Cue] = &[
    cue("breaking news", "news", 1.5),
    cue("latest news", "news", 1.0),
    cue("top stories", "news", 1.0),
    cue("editorial", "news", 1.0),
    cue("opinion", "news", 0.5),
    cue("add to cart", "shopping", 1.5),
    cue("free shipping", "shopping", 1.0),
    cue("shopping cart", "shopping", 1.0),
    cue("returns policy", "shopping", 1.0),
    cue("in stock", "shopping", 1.0),
    cue("casino", "gambling", 1.5),
    cue("sportsbook", "gambling", 1.5),
    cue("free spins", "gambling", 1.5),
    cue("deposit bonus", "gambling", 1.5),
    cue("betting odds", "gambling", 1.5),
    cue("explicit content", "adult", 2.0),
    cue("adults only", "adult", 1.5),
    cue("porn", "adult", 1.5),
    cue("job openings", "jobs", 1.5),
    cue("job search", "jobs", 1.5),
    cue("post a job", "jobs", 1.5),
    cue("apply now", "jobs", 0.5),
    cue("salary", "jobs", 1.0),
    cue("online courses", "education", 1.5),
    cue("enrol", "education", 1.0),
    cue("admissions", "education", 1.0),
    cue("curriculum", "education", 1.0),
    cue("online banking", "finance", 1.5),
    cue("interest rate", "finance", 1.0),
    cue("savings account", "finance", 1.5),
    cue("mortgage", "finance", 1.0),
    cue("credit card", "finance", 0.5),
    cue("official website of", "government", 1.5),
    cue("department of", "government", 1.0),
    cue("ministry of", "government", 1.0),
    cue("public services", "government", 1.0),
    cue("multiplayer", "gaming", 1.5),
    cue("gameplay", "gaming", 1.0),
    cue("play now", "gaming", 0.5),
    cue("leaderboard", "gaming", 1.0),
    cue("live scores", "sports", 1.5),
    cue("league table", "sports", 1.5),
    cue("fixtures", "sports", 1.0),
    cue("match report", "sports", 1.0),
    cue("recipes", "food", 1.5),
    cue("ingredients", "food", 1.0),
    cue("order food", "food", 1.5),
    cue("restaurant", "food", 1.0),
    cue("tv shows", "streaming", 1.5),
    cue("watch now", "streaming", 1.0),
    cue("episodes", "streaming", 1.0),
    cue("movies", "streaming", 0.5),
    cue("followers", "social", 1.0),
    cue("share photos", "social", 1.5),
    cue("connect with friends", "social", 1.5),
    cue("find your match", "dating", 1.5),
    cue("singles", "dating", 1.0),
    cue("online dating", "dating", 1.5),
    cue("homes for sale", "real-estate", 1.5),
    cue("property for sale", "real-estate", 1.5),
    cue("for rent", "real-estate", 1.0),
    cue("bedrooms", "real-estate", 1.0),
    cue("used cars", "auto", 1.5),
    cue("test drive", "auto", 1.5),
    cue("new cars", "auto", 1.0),
    cue("dealership", "auto", 1.0),
    cue("bitcoin", "crypto", 1.0),
    cue("ethereum", "crypto", 1.0),
    cue("blockchain", "crypto", 1.0),
    cue("cryptocurrency", "crypto", 1.0),
    cue("api reference", "developer", 1.5),
    cue("documentation", "developer", 1.0),
    cue("open source", "developer", 1.0),
    cue("sdk", "developer", 1.0),
    cue("webmail", "email", 1.5),
    cue("compose", "email", 0.5),
    cue("inbox", "email", 1.0),
    cue("virtual machines", "cloud", 1.5),
    cue("cloud hosting", "cloud", 1.5),
    cue("object storage", "cloud", 1.0),
    cue("no logs", "vpn-proxy", 1.5),
    cue("hide your ip", "vpn-proxy", 1.5),
    cue("vpn", "vpn-proxy", 1.0),
    cue("proxy server", "vpn-proxy", 1.0),
];

fn classify_with(table: &[Cue], title: &str, text: &str) -> Option<TextVerdict> {
    let haystack = normalise(&format!("{title} {text}"));
    if haystack.is_empty() {
        return None;
    }
    let mut scores: Vec<(&'static str, f32, Vec<&'static str>)> = Vec::new();
    for cue in table {
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
    let winner = scores
        .iter()
        .enumerate()
        .max_by(|a, b| {
            a.1 .1
                .partial_cmp(&b.1 .1)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|(index, _)| index)?;
    let (category, mut score, mut cues) = scores.swap_remove(winner);
    let also: Vec<&'static str> = scores.iter().map(|(category, ..)| *category).collect();
    if score < MIN_SCORE {
        return None;
    }
    cues.sort_by(|a, b| {
        let weight = |phrase: &str| {
            table
                .iter()
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
        also,
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
                let s = v6.segments();
                // Translation prefixes carry an IPv4 address: judge that.
                // NAT64 (64:ff9b::/96) in the low 32 bits, 6to4 (2002::/16)
                // in bits 16-48.
                if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
                    let v4 = std::net::Ipv4Addr::new(
                        (s[6] >> 8) as u8,
                        s[6] as u8,
                        (s[7] >> 8) as u8,
                        s[7] as u8,
                    );
                    return is_global_v4(v4);
                }
                if s[0] == 0x2002 {
                    let v4 = std::net::Ipv4Addr::new(
                        (s[1] >> 8) as u8,
                        s[1] as u8,
                        (s[2] >> 8) as u8,
                        s[2] as u8,
                    );
                    return is_global_v4(v4);
                }
                !(v6.is_unspecified()
                    || v6.is_multicast()
                    // IPv4-compatible (::a.b.c.d, deprecated) and the rest of ::/96.
                    || s[..6] == [0, 0, 0, 0, 0, 0]
                    // Unique local fc00::/7, link-local fe80::/10, the old
                    // site-local fec0::/10.
                    || (s[0] & 0xfe00) == 0xfc00
                    || (s[0] & 0xffc0) == 0xfe80
                    || (s[0] & 0xffc0) == 0xfec0
                    // Documentation 2001:db8::/32, Teredo 2001::/32 and the
                    // discard-only 100::/64.
                    || (s[0] == 0x2001 && (s[1] == 0x0db8 || s[1] == 0))
                    || (s[0] == 0x0100 && s[1..4] == [0, 0, 0]))
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
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        // IETF protocol assignments 192.0.0.0/24 and benchmarking 198.18.0.0/15.
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 198 && (octets[1] & 0xfe) == 18))
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
        self.fetch_page(domain, false)
    }

    fn fetch_page(&self, domain: &str, inspect_forms: bool) -> Result<PageContent, String> {
        let host = normalise_host(domain).ok_or_else(|| "not a fetchable host".to_string())?;
        let mut last = String::from("no attempt made");
        for scheme in ["https", "http"] {
            match self.fetch_url(&host, scheme, "/", 0, inspect_forms) {
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
        inspect_forms: bool,
    ) -> Result<PageContent, String> {
        let addr = self.resolve(host, scheme)?;
        let url = match self.pinned {
            Some((_, port)) => format!("{scheme}://{host}:{port}{target}"),
            None => format!("{scheme}://{host}{target}"),
        };
        let client = reqwest::blocking::Client::builder()
            .timeout(self.timeout)
            .redirect(RedirectPolicy::none())
            // A proxy from the environment would resolve and connect for
            // us, past the address check and the pin.
            .no_proxy()
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
            let mut page = self.fetch_url(
                &next_host,
                &next_scheme,
                &next_target,
                hops + 1,
                inspect_forms,
            )?;
            page.redirects
                .record(host, scheme, &next_host, &next_scheme);
            return Ok(page);
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
        let (title, text, has_password_form, has_sensitive_form) =
            extract_page(&html, inspect_forms && content_type != "text/plain");
        if text.chars().count() < MIN_TEXT_CHARS {
            return Err("page had no readable text".to_string());
        }
        Ok(PageContent {
            url,
            title,
            text,
            complete: body.len() < self.max_bytes,
            has_password_form,
            has_sensitive_form,
            redirects: RedirectEvidence::default(),
        })
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
    // Schemes are case-insensitive (`HTTPS://` is valid), and a
    // protocol-relative `//host/path` keeps the current scheme but names a
    // new host: it must be validated as one, not fetched as a path on this
    // host.
    let strip_scheme = |prefix: &str| {
        location
            .get(..prefix.len())
            .filter(|head| head.eq_ignore_ascii_case(prefix))
            .map(|_| &location[prefix.len()..])
    };
    let (next_scheme, rest) = if let Some(rest) = strip_scheme("https://") {
        ("https", rest)
    } else if let Some(rest) = strip_scheme("http://") {
        ("http", rest)
    } else if let Some(rest) = location.strip_prefix("//") {
        (if scheme == "https" { "https" } else { "http" }, rest)
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
    // The authority ends at the path or, with no path, at the query.
    let (authority, path) = match rest.find(['/', '?']) {
        Some(index) if rest[index..].starts_with('?') => {
            (&rest[..index], format!("/{}", &rest[index..]))
        }
        Some(index) => (&rest[..index], rest[index..].to_string()),
        None => (rest, "/".to_string()),
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
            path
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
    let (title, text, _, _) = extract_page(html, false);
    (title, text)
}

fn extract_page(html: &str, inspect_forms: bool) -> (String, String, bool, bool) {
    let lower = html.to_ascii_lowercase();
    let mut title = String::new();
    let mut text = String::new();
    let mut i = 0usize;
    let mut in_form = false;
    let mut has_password_form = false;
    let mut has_sensitive_form = false;
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
                // Static strings: building them per `<` allocated six times
                // for every tag on the page.
                for (opening, close) in [
                    ("<script", "</script>"),
                    ("<style", "</style>"),
                    ("<noscript", "</noscript>"),
                ] {
                    if lower[open..].starts_with(opening) {
                        match lower[open..].find(close) {
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
                if inspect_forms {
                    for (opening, close) in
                        [("<template", "</template>"), ("<textarea", "</textarea>")]
                    {
                        if lower[open..].starts_with(opening) {
                            i = lower[open..]
                                .find(close)
                                .map_or(html.len(), |end| open + end + close.len());
                            skipped = true;
                            break;
                        }
                    }
                    if skipped {
                        continue;
                    }
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
                let tail = &lower[open + 1..];
                let end = if inspect_forms {
                    tag_end(tail)
                } else {
                    tail.find('>')
                };
                match end {
                    Some(end) => {
                        if inspect_forms {
                            let tag = &tail[..end];
                            let split = tag.find(|c: char| c.is_ascii_whitespace() || c == '/');
                            let name = &tag[..split.unwrap_or(tag.len())];
                            if tag.trim_end() == "/form" {
                                in_form = false;
                            } else if name == "form" {
                                in_form = true;
                            } else if name == "input" && in_form {
                                let (password, sensitive) = form_input(&tag[name.len()..]);
                                has_password_form |= password;
                                has_sensitive_form |= sensitive;
                            }
                        }
                        i = open + end + 2;
                    }
                    None => break,
                }
            }
            None => {
                text.push_str(&html[i..]);
                break;
            }
        }
    }
    (
        collapse(&title),
        collapse(&decode(&text)),
        has_password_form,
        has_sensitive_form,
    )
}

fn tag_end(tag: &str) -> Option<usize> {
    let mut quote = None;
    for (index, byte) in tag.bytes().enumerate() {
        match quote {
            Some(end) if byte == end => quote = None,
            Some(_) => {}
            None if matches!(byte, b'\'' | b'"') => quote = Some(byte),
            None if byte == b'>' => return Some(index),
            None => {}
        }
    }
    None
}

fn form_input(mut rest: &str) -> (bool, bool) {
    let mut input_type = None;
    let mut sensitive = false;
    while !rest.trim_start().is_empty() {
        rest = rest.trim_start();
        let end = rest
            .find(|c: char| c.is_ascii_whitespace() || c == '=')
            .unwrap_or(rest.len());
        let (name, tail) = rest.split_at(end);
        let Some(value) = tail.trim_start().strip_prefix('=') else {
            rest = tail;
            continue;
        };
        let value = value.trim_start();
        let (actual, tail) = match value.as_bytes().first() {
            Some(b'\'' | b'"') => {
                let Some((actual, tail)) = value[1..].split_once(value.as_bytes()[0] as char)
                else {
                    return (false, false);
                };
                (actual, tail)
            }
            _ => value.split_at(value.find(char::is_whitespace).unwrap_or(value.len())),
        };
        match name {
            "type" if input_type.is_none() => input_type = Some(actual),
            "autocomplete" => {
                sensitive |= matches!(
                    actual.split_ascii_whitespace().last(),
                    Some(
                        "cc-number"
                            | "cc-csc"
                            | "cc-exp"
                            | "cc-exp-month"
                            | "cc-exp-year"
                            | "one-time-code"
                    )
                );
            }
            "name" => {
                sensitive |= matches!(
                    actual,
                    "ssn"
                        | "social_security_number"
                        | "tax_id"
                        | "national_id"
                        | "passport_number"
                        | "routing_number"
                        | "bank_account_number"
                        | "card_number"
                        | "cvv"
                )
            }
            _ => {}
        }
        rest = tail;
    }
    (
        input_type == Some("password"),
        sensitive && input_type != Some("hidden"),
    )
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
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Inspection {
    pub note: String,
    pub reading: Option<TextVerdict>,
    /// The page's title and text, when it was read: kept for the page-text
    /// model ([`crate::page_model`]).
    pub page: Option<(String, String)>,
}

/// What the scanner needs from a page read: the evidence line and the reading
/// a rule may act on. [`PageFetcher`] is the live implementation; tests and
/// callers that already hold readings can supply their own without a network.
pub trait PageReader: Send + Sync {
    fn inspect(&self, domain: &str) -> Inspection;

    fn inspect_for_discovery(&self, _domain: &str, _floor: f32) -> DiscoveryReading {
        DiscoveryReading::unknown(None, "discovery inspection unavailable")
    }
}

/// A review finding sourced only from the inspected page.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiscoveryReading {
    pub final_host: Option<String>,
    pub category: Option<String>,
    pub confidence: Option<f32>,
    pub evidence: String,
}

impl DiscoveryReading {
    fn unknown(final_host: Option<String>, evidence: &str) -> Self {
        Self {
            final_host,
            category: None,
            confidence: None,
            evidence: truncate(evidence, 160),
        }
    }
}

impl PageReader for PageFetcher {
    fn inspect(&self, domain: &str) -> Inspection {
        read_page(self, domain)
    }

    fn inspect_for_discovery(&self, domain: &str, floor: f32) -> DiscoveryReading {
        match self.fetch_page(domain, true) {
            Ok(page) => discovery_reading(domain, &page, floor),
            Err(_) => DiscoveryReading::unknown(None, "page could not be inspected"),
        }
    }
}

fn discovery_reading(domain: &str, page: &PageContent, floor: f32) -> DiscoveryReading {
    let final_host = reqwest::Url::parse(&page.url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned));
    if !page.complete {
        return DiscoveryReading::unknown(final_host, "page reached the response-size limit");
    }
    let Some(registered) = final_host.as_deref().and_then(psl::domain_str) else {
        return DiscoveryReading::unknown(final_host, "page hostname could not be assessed");
    };
    let crosses_sites =
        Some(registered) != psl::domain_str(domain) || page.redirects.cross_site_hops > 0;
    let mut reading = discovery_destination(page, registered, final_host.clone(), floor);
    if crosses_sites || page.redirects.downgraded {
        let chain = format!(
            "redirect chain: {} cross-site hop(s){}",
            page.redirects.cross_site_hops,
            if page.redirects.downgraded {
                ", HTTPS downgraded to HTTP"
            } else {
                ""
            }
        );
        // A redirect alone is common for legitimate sign-in and payment flows.
        // Keep the destination's evidence, with monitor-only authority for the chain.
        if reading.confidence.is_some_and(|score| score >= 0.9) && floor <= 0.9 {
            reading.confidence = Some(0.9);
            reading.evidence = format!("{chain}; destination: {}", reading.evidence);
            return reading;
        }
        return DiscoveryReading::unknown(
            final_host,
            &format!("{chain}; no strong destination finding"),
        );
    }
    reading
}

fn discovery_destination(
    page: &PageContent,
    registered: &str,
    final_host: Option<String>,
    floor: f32,
) -> DiscoveryReading {
    // These are narrow title claims, not general brand mentions. Shared identity
    // providers need their own entries when adding another brand here.
    let title = normalise(&page.title);
    let text = format!(" {title} {} ", normalise(&page.text));
    let pressures_password =
        text.contains(" account will be suspended ") && text.contains(" confirm your password ");
    let brand = [
        ("paypal", &["paypal.com"][..]),
        (
            "microsoft",
            &["microsoft.com", "microsoftonline.com", "live.com"][..],
        ),
        ("apple", &["apple.com", "icloud.com"][..]),
    ]
    .into_iter()
    .find(|(brand, _)| title.split_whitespace().next() == Some(*brand));
    if let Some((brand, official)) = brand {
        if official.contains(&registered) {
            return DiscoveryReading::unknown(final_host, "page is on the named brand's site");
        }
        let title = format!(" {title} ");
        let sign_in = [" sign in ", " sign into ", " log in ", " login "]
            .iter()
            .any(|phrase| title.contains(phrase));
        let confidence = if pressures_password {
            DISCOVERY_ENFORCEMENT_FLOOR
        } else {
            0.9
        };
        if page.has_password_form && sign_in && floor <= confidence {
            return DiscoveryReading {
                final_host,
                category: Some("phishing".to_owned()),
                confidence: Some(confidence),
                evidence: if pressures_password {
                    format!("{brand} sign-in title on a different site, password form, and password-confirmation demand under threat of suspension")
                } else {
                    format!("{brand} sign-in title on a different site with a password form")
                },
            };
        }
    }
    let reward = text.contains(" claim your reward ") || text.contains(" claim your prize ");
    if page.has_sensitive_form && reward && text.contains(" processing fee ") && floor <= 0.9 {
        return DiscoveryReading {
            final_host,
            category: Some("scam".to_string()),
            confidence: Some(0.9),
            evidence: "reward claim with a processing fee and a payment or identity form"
                .to_string(),
        };
    }
    // A form requesting sensitive fields is normal on many sites. Pair it
    // with a deceptive request and coercive context before surfacing a finding.
    let pressured = [
        " account will be suspended ",
        " account will be closed ",
        " avoid account closure ",
        " avoid suspension ",
    ]
    .iter()
    .any(|phrase| text.contains(phrase));
    let verification = [
        " verify your identity ",
        " reconfirm your payment details ",
        " verify your card ",
        " enter your verification code ",
        " confirm your bank details ",
    ]
    .iter()
    .any(|phrase| text.contains(phrase));
    if page.has_sensitive_form && pressured && verification && floor <= 0.9 {
        return DiscoveryReading {
            final_host,
            category: Some("phishing".to_string()),
            confidence: Some(0.9),
            evidence: "sensitive payment, identity, or verification form paired with a pressured verification request".to_string(),
        };
    }
    let reading = classify_text(&page.title, &page.text).filter(|reading| {
        reading.confidence >= floor.max(0.8)
            && reading.cues.len() >= 2
            && daygle_dns_core::config::THREAT_FAMILIES.contains(&reading.category)
            && (reading.category != "phishing"
                || (page.has_password_form
                    && reading.cues.contains(&"account will be suspended")
                    && reading.cues.contains(&"confirm your password")))
    });
    match reading {
        Some(reading) => DiscoveryReading {
            final_host,
            category: Some(reading.category.to_owned()),
            confidence: Some(reading.confidence),
            evidence: reading
                .cues
                .into_iter()
                .take(3)
                .chain((reading.category == "phishing").then_some("password form"))
                .collect::<Vec<_>>()
                .join(", "),
        },
        None => DiscoveryReading::unknown(final_host, "no strong threat reading from page text"),
    }
}

#[cfg(test)]
#[test]
fn discovery_requires_multiple_threat_cues_and_a_complete_response() {
    let mut page = PageContent {
        url: "https://accounts.example/login".to_owned(),
        title: "Account sign-in".to_owned(),
        text: "Verify your account. Verify your account. Verify your account.".to_owned(),
        complete: true,
        has_password_form: true,
        has_sensitive_form: false,
        redirects: RedirectEvidence::default(),
    };
    assert!(discovery_reading("accounts.example", &page, 0.5)
        .category
        .is_none());
    page.text.push_str(" Confirm your password.");
    assert!(discovery_reading("accounts.example", &page, 0.5)
        .category
        .is_none());
    page.text.push_str(" Your account will be suspended.");
    let finding = discovery_reading("accounts.example", &page, 0.5);
    assert_eq!(finding.category.as_deref(), Some("phishing"));
    assert_eq!(finding.final_host.as_deref(), Some("accounts.example"));
    page.has_password_form = false;
    assert!(discovery_reading("accounts.example", &page, 0.5)
        .category
        .is_none());
    page.has_password_form = true;
    page.complete = false;
    assert!(discovery_reading("accounts.example", &page, 0.5)
        .confidence
        .is_none());
}

#[cfg(test)]
#[test]
fn discovery_checks_password_forms_and_brand_claims() {
    let signed_in = r#"<form><input title="a > b" TYPE = 'Password'></form>"#;
    let html = format!("<title>PayPal sign in</title>{signed_in}");
    let (title, text, has_password_form, has_sensitive_form) = extract_page(&html, true);
    assert!(has_password_form);
    let mut page = PageContent {
        url: "https://accounts.example/".to_owned(),
        title,
        text,
        complete: true,
        has_password_form,
        has_sensitive_form,
        redirects: RedirectEvidence::default(),
    };
    assert_eq!(
        discovery_reading("accounts.example", &page, 0.6)
            .category
            .as_deref(),
        Some("phishing")
    );
    page.redirects
        .record("redirect.example", "https", "accounts.example", "http");
    let redirected = discovery_reading("redirect.example", &page, 0.6);
    assert_eq!(redirected.category.as_deref(), Some("phishing"));
    assert_eq!(redirected.confidence, Some(0.9));
    assert!(redirected.evidence.contains("HTTPS downgraded to HTTP"));
    page.text = "Confirm your password or your account will be suspended.".to_owned();
    page.redirects
        .record("accounts.example", "http", "redirect.example", "https");
    assert_eq!(
        discovery_reading("accounts.example", &page, 0.6).confidence,
        Some(0.9)
    );
    page.text.clear();
    page.url = "https://www.paypal.com/signin".to_owned();
    assert!(discovery_reading("redirect.example", &page, 0.6)
        .category
        .is_none());
    page.redirects = RedirectEvidence::default();
    assert!(discovery_reading("www.paypal.com", &page, 0.6)
        .category
        .is_none());
    page.url = "https://accounts.example/".to_owned();
    page.title = "Sign in to your account".to_owned();
    assert!(discovery_reading("accounts.example", &page, 0.6)
        .category
        .is_none());

    for html in [
        r#"<!-- <form><input type=password></form> -->"#,
        r#"<script>'<form><input type=password></form>'</script>"#,
        r#"<template><form><input type=password></form></template>"#,
        r#"<textarea><form><input type=password></form></textarea>"#,
        r#"<form><input data-note="type=password" type=email></form>"#,
        r#"<form></form><input type=password>"#,
    ] {
        assert!(
            !extract_page(html, true).2,
            "unexpected password form: {html}"
        );
    }
}

#[cfg(test)]
#[test]
fn discovery_distinguishes_sensitive_form_scams_from_ordinary_pages() {
    for (title, text, input, expected) in [
        (
            "Checkout",
            "Pay the processing fee for this order.",
            "autocomplete=cc-number",
            None,
        ),
        (
            "Tax form",
            "Enter your identity details to complete your tax return.",
            "name=ssn",
            None,
        ),
        (
            "Prize announcement",
            "Claim your prize and pay a processing fee.",
            "type=hidden name=ssn",
            None,
        ),
        (
            "Prize claim",
            "Claim your prize and pay a processing fee.",
            "autocomplete='billing cc-number'",
            Some("scam"),
        ),
        (
            "Prize claim",
            "Claim your reward after you pay the processing fee.",
            "name=social_security_number",
            Some("scam"),
        ),
        (
            "PayPal Login",
            "Sign in to continue. Confirm your password or your account will be suspended.",
            "type=password",
            Some("phishing"),
        ),
        (
            "Account check",
            "Verify your identity to avoid account closure.",
            "name=passport_number",
            Some("phishing"),
        ),
        (
            "Payment check",
            "Reconfirm your payment details or your account will be suspended.",
            "name=bank_account_number",
            Some("phishing"),
        ),
        (
            "Account recovery",
            "Enter your verification code or your account will be closed.",
            "autocomplete=one-time-code",
            Some("phishing"),
        ),
        (
            "Two-factor sign in",
            "Enter your verification code to sign in.",
            "autocomplete=one-time-code",
            None,
        ),
    ] {
        let html = format!("<title>{title}</title>{text}<form><input {input}></form>");
        let (title, text, has_password_form, has_sensitive_form) = extract_page(&html, true);
        let reading = discovery_reading(
            "ordinary.example",
            &PageContent {
                url: "https://ordinary.example/".to_owned(),
                title,
                text,
                complete: true,
                has_password_form,
                has_sensitive_form,
                redirects: RedirectEvidence::default(),
            },
            0.6,
        );
        assert_eq!(reading.category.as_deref(), expected, "{html}");
        if expected == Some("phishing") {
            assert_eq!(
                reading.confidence,
                Some(if html.contains("PayPal Login") {
                    DISCOVERY_ENFORCEMENT_FLOOR
                } else {
                    0.9
                })
            );
        }
    }
}

/// The confidence `page_rule` gives a threat verdict after reading its page,
/// or `None` when the rule leaves it alone.
///
/// The two directions are deliberately asymmetric: agreement can only raise a
/// confidence (a corroborating page never makes a verdict more certain than
/// the page itself), while disagreement caps it at `1 - confidence`, the
/// page's own certainty that it is ordinary. Only `decide` may lower, and
/// only for a page with no threat cue anywhere on it: a site cannot talk its
/// way out of a verdict by adding a paragraph about casinos.
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
    } else if rule == PageRule::Decide && !reading.also.iter().any(|c| is_threat_label(c)) {
        let capped = base.min(1.0 - reading.confidence).max(0.0);
        (capped < base - 0.001).then_some(capped)
    } else {
        None
    }
}

/// A one-line note for the threat verdict's evidence: what the page said, or
/// why it could not be read. Bounded, since evidence is shown in a table.
pub fn evidence_note(outcome: &Result<PageContent, String>) -> String {
    let reading = outcome
        .as_ref()
        .ok()
        .and_then(|page| classify_text(&page.title, &page.text));
    note_for(outcome, reading.as_ref())
}

/// [`evidence_note`] for a page already classified, so a read classifies
/// its text once rather than once for the note and again for the rule.
fn note_for(outcome: &Result<PageContent, String>, reading: Option<&TextVerdict>) -> String {
    match outcome {
        Ok(page) => {
            let title = truncate(&page.title, 80);
            match reading {
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
        note: note_for(&outcome, reading.as_ref()),
        reading,
        page: outcome.ok().map(|page| (page.title, page.text)),
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
        // Scheme case does not matter.
        let upper = redirect_target("http", "example.com", "HTTPS://www.example.com/a").unwrap();
        assert_eq!(
            upper,
            ("https".into(), "www.example.com".into(), "/a".into())
        );
        // Protocol-relative: a new host under the current scheme, validated.
        let relative = redirect_target("https", "example.com", "//cdn.example.net/x").unwrap();
        assert_eq!(
            relative,
            ("https".into(), "cdn.example.net".into(), "/x".into())
        );
        assert!(redirect_target("https", "example.com", "//127.0.0.1/").is_err());
        // A query with no path still names a valid host.
        let query = redirect_target("https", "example.com", "https://example.org?a=1").unwrap();
        assert_eq!(
            query,
            ("https".into(), "example.org".into(), "/?a=1".into())
        );
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
            also: vec![],
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

    #[test]
    fn decide_never_lowers_a_page_that_also_reads_as_a_threat() {
        let mixed = TextVerdict {
            category: "gambling",
            confidence: 0.8,
            cues: vec!["casino", "deposit bonus"],
            also: vec!["phishing"],
        };
        let is_threat = |label: &str| label == "phishing";
        assert_eq!(
            adjust_confidence(PageRule::Decide, 0.95, Some(&mixed), is_threat, 0.6),
            None,
            "a threat cue anywhere on the page keeps the verdict"
        );
        let plain = TextVerdict {
            also: vec![],
            ..mixed
        };
        assert!(adjust_confidence(PageRule::Decide, 0.95, Some(&plain), is_threat, 0.6).is_some());
    }

    #[test]
    fn ordinary_categories_can_be_read() {
        let shop = classify_text("Shop", "add to cart - free shipping on every order").unwrap();
        assert_eq!(shop.category, "shopping");
        let news = classify_text("Daily", "latest news and top stories from today").unwrap();
        assert_eq!(news.category, "news");
        let mixed =
            classify_text("Shop", "add to cart, free shipping, verify your account").unwrap();
        assert!(mixed.also.contains(&"shopping") || mixed.also.contains(&"phishing"));
    }

    #[test]
    fn translated_and_special_ipv6_addresses_are_refused() {
        for ip in [
            "64:ff9b::a00:1",   // NAT64 of 10.0.0.1
            "2002:c0a8:101::1", // 6to4 of 192.168.1.1
            "fec0::1",          // site-local
            "2001:db8::1",      // documentation
            "::a00:1",          // IPv4-compatible
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(!public().allows(ip), "{ip} must be refused");
        }
        for ip in ["64:ff9b::808:808", "2606:4700::1111"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(public().allows(ip), "{ip} is public");
        }
    }
}
