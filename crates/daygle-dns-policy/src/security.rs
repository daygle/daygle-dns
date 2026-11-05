//! Security categories: kinds of infrastructure that attackers favour
//! (free hosting subdomains, dynamic DNS hostnames, tunnels, paste and
//! webhook drops, IPFS gateways, mining pools, high-risk TLDs), each a
//! built-in list a filtering group can block with one tick.
//!
//! Entries use the blocklist syntax ([`crate::Blocklist`]): `*.example.com`
//! blocks the subdomains of `example.com` but not the name itself, an exact
//! name blocks only that name, and `@@name` is an exception that is never
//! blocked by the category (a provider's own website or update API).
//!
//! Also here: the per-group TLD block list, which turns `zip` into `*.zip`.

use serde::Serialize;

/// One security category.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct SecurityCategory {
    /// Stable identifier stored in a group's `blocked_security`.
    pub id: &'static str,
    /// Display name.
    pub name: &'static str,
    /// What the category blocks and what it leaves alone, for the console.
    pub description: &'static str,
    /// The console section the category is listed in.
    pub section: Section,
    /// The detector that decides membership, for categories judged by
    /// examining the name or its answer instead of a list.
    pub detector: Option<Detector>,
    /// Blocklist entries (`*.suffix`, exact names, `@@` exceptions); empty
    /// for a detector.
    pub entries: &'static [&'static str],
}

/// Where the console lists a category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    /// Threats: malware, phishing and their infrastructure.
    Security,
    /// Tracking.
    Privacy,
}

/// A category decided by examining a name rather than by a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Detector {
    /// Internationalized names imitating Latin ones ([`crate::detect`]).
    Homograph,
    /// Names made up by malware's domain generation algorithms.
    Dga,
    /// Domains whose name servers belong to a parking service; decided once
    /// the name servers are known, after resolution.
    Parked,
    /// Names imitating a well-known brand with a typo, look-alike
    /// characters or a phishing word ([`crate::detect::typosquat`]).
    Typosquat,
    /// Domains registered less than 30 days ago; decided once the
    /// registration date is known ([`crate::rdap`]), after resolution.
    NewlyRegistered,
    /// Names on Google Safe Browsing's lists ([`crate::safe_browsing`]),
    /// checked after resolution.
    SafeBrowsing,
    /// Names whose addresses all belong to consumer ISPs
    /// ([`crate::residential`]), checked after resolution.
    ResidentialHosting,
    /// Answers whose CNAME chain leads to a third-party tracker
    /// ([`crate::cname_trackers`]), checked after resolution.
    CnameTracker,
}

impl Detector {
    /// Whether the dispatcher decides it after resolution, from data it
    /// looks up in the background, rather than the engine from the name.
    pub fn after_resolution(self) -> bool {
        matches!(
            self,
            Self::Parked
                | Self::NewlyRegistered
                | Self::SafeBrowsing
                | Self::ResidentialHosting
                | Self::CnameTracker
        )
    }
}

/// Every known security category.
pub const SECURITY_CATEGORIES: &[SecurityCategory] = &[
    SecurityCategory {
        id: "free_hosting",
        name: "Free Hosting Domains",
        description: "Default subdomains handed out by free web hosts and site builders \
            (*.pages.dev, *.vercel.app, *.netlify.app, ...), heavily abused for phishing. \
            Sites on these hosts that use their own domain name are not affected.",
        section: Section::Security,
        detector: None,
        entries: &[
            "*.pages.dev",
            "*.vercel.app",
            "*.netlify.app",
            "*.github.io",
            "*.gitlab.io",
            "*.web.app",
            "*.firebaseapp.com",
            "*.glitch.me",
            "*.onrender.com",
            "*.replit.app",
            "*.repl.co",
            "*.workers.dev",
            "*.surge.sh",
            "*.000webhostapp.com",
            "*.weebly.com",
            "*.wixsite.com",
            "*.webflow.io",
            "*.framer.website",
            "*.carrd.co",
            "*.square.site",
            "*.godaddysites.com",
            "@@www.weebly.com",
            "@@www.000webhostapp.com",
            "@@www.carrd.co",
        ],
    },
    SecurityCategory {
        id: "dynamic_dns",
        name: "Dynamic DNS Hostnames",
        description: "Hostnames from free dynamic DNS services (DuckDNS, No-IP, Dynu, \
            FreeDNS, ...), which need no identity check and are common in phishing. The \
            services' own websites and update APIs stay reachable; allow your own DDNS \
            hostname under Custom Allow if you use one.",
        section: Section::Security,
        detector: None,
        entries: &[
            // DuckDNS
            "*.duckdns.org",
            "@@www.duckdns.org",
            // No-IP
            "*.ddns.net",
            "*.hopto.org",
            "*.zapto.org",
            "*.sytes.net",
            "*.servebeer.com",
            "*.serveftp.com",
            "*.servehttp.com",
            "*.myftp.biz",
            "*.myftp.org",
            "*.redirectme.net",
            "*.bounceme.net",
            "*.no-ip.biz",
            "*.no-ip.info",
            "*.no-ip.org",
            "*.ddnsking.com",
            "*.3utilities.com",
            // Dynu
            "*.dynu.net",
            "*.ddnsfree.com",
            "*.freeddns.org",
            "*.mywire.org",
            "*.webredirect.org",
            "*.ddnsgeek.com",
            "*.giize.com",
            "*.gleeze.com",
            "*.kozow.com",
            "*.loseyourip.com",
            "*.ooguy.com",
            "*.theworkpc.com",
            "*.camdvr.org",
            "*.accesscam.org",
            // FreeDNS (afraid.org)
            "*.afraid.org",
            "*.mooo.com",
            "*.us.to",
            "*.chickenkiller.com",
            "*.crabdance.com",
            "*.strangled.net",
            "*.ignorelist.com",
            "*.jumpingcrab.com",
            "*.twilightparadox.com",
            "@@www.afraid.org",
            "@@freedns.afraid.org",
            "@@sync.afraid.org",
            // Dyn
            "*.dyndns.org",
            "*.dyndns.biz",
            "*.homeip.net",
            "*.dnsalias.com",
            "*.dnsalias.net",
            "*.dnsalias.org",
            "@@www.dyndns.org",
            "@@members.dyndns.org",
            "@@checkip.dyndns.org",
            // dynv6, deSEC, YDNS, nsupdate.info, dnsHome, spDYN
            "*.dynv6.net",
            "*.dedyn.io",
            "@@update.dedyn.io",
            "@@update6.dedyn.io",
            "*.ydns.eu",
            "*.nsupdate.info",
            "@@www.nsupdate.info",
            "@@ipv4.nsupdate.info",
            "@@ipv6.nsupdate.info",
            "*.dnshome.de",
            "@@www.dnshome.de",
            "*.spdns.de",
            "@@www.spdns.de",
            "@@update.spdns.de",
        ],
    },
    SecurityCategory {
        id: "tunneling",
        name: "Tunneling Endpoints",
        description: "Public endpoints of services that expose a local port to the \
            internet (ngrok, Cloudflare quick tunnels, localtunnel, ...), used to host \
            phishing pages behind random subdomains. Named Cloudflare Tunnels on your own \
            domain are not affected.",
        section: Section::Security,
        detector: None,
        entries: &[
            "*.ngrok.io",
            "*.ngrok.app",
            "*.ngrok.dev",
            "*.ngrok-free.app",
            "*.ngrok-free.dev",
            "*.trycloudflare.com",
            "*.loca.lt",
            "serveo.net",
            "*.serveo.net",
            "*.lhr.life",
            "*.pinggy.link",
            "*.loclx.io",
            "*.tunnelto.dev",
            "*.share.zrok.io",
            "*.devtunnels.ms",
            "*.sharedwithexpose.com",
        ],
    },
    SecurityCategory {
        id: "data_drop",
        name: "Data Drop Services",
        description: "Paste sites, anonymous file drops, webhook and request catchers and \
            out-of-band DNS loggers, used to stage payloads and collect stolen data. This \
            blocks legitimate use of these services too.",
        section: Section::Security,
        detector: None,
        entries: &[
            // Paste sites
            "pastebin.com",
            "*.pastebin.com",
            "paste.ee",
            "*.paste.ee",
            "hastebin.com",
            "*.hastebin.com",
            "rentry.co",
            "*.rentry.co",
            "rentry.org",
            "*.rentry.org",
            "controlc.com",
            "*.controlc.com",
            "justpaste.it",
            "*.justpaste.it",
            "privatebin.net",
            "*.privatebin.net",
            "dpaste.org",
            "*.dpaste.org",
            "dpaste.com",
            "*.dpaste.com",
            "paste.rs",
            "termbin.com",
            "*.termbin.com",
            // File drops
            "transfer.sh",
            "*.transfer.sh",
            "file.io",
            "*.file.io",
            "0x0.st",
            "temp.sh",
            "tmpfiles.org",
            "*.tmpfiles.org",
            "catbox.moe",
            "*.catbox.moe",
            "gofile.io",
            "*.gofile.io",
            "pixeldrain.com",
            "*.pixeldrain.com",
            // JSON stores
            "jsonbin.io",
            "*.jsonbin.io",
            "npoint.io",
            "*.npoint.io",
            // Webhook and request catchers
            "webhook.site",
            "*.webhook.site",
            "requestbin.com",
            "*.requestbin.com",
            "*.m.pipedream.net",
            "beeceptor.com",
            "*.beeceptor.com",
            "requestcatcher.com",
            "*.requestcatcher.com",
            "hookbin.com",
            "*.hookbin.com",
            // Out-of-band interaction and DNS loggers
            "*.interact.sh",
            "*.oast.pro",
            "*.oast.live",
            "*.oast.site",
            "*.oast.online",
            "*.oast.fun",
            "*.oast.me",
            "*.oastify.com",
            "*.burpcollaborator.net",
            "*.dnslog.cn",
            "*.ceye.io",
            "canarytokens.com",
            "*.canarytokens.com",
        ],
    },
    SecurityCategory {
        id: "decentralized_gateways",
        name: "Decentralized Web Gateways",
        description: "Public gateways that serve IPFS and ENS content to ordinary browsers, \
            used to host phishing pages that cannot be taken down.",
        section: Section::Security,
        detector: None,
        entries: &[
            "ipfs.io",
            "*.ipfs.io",
            "dweb.link",
            "*.dweb.link",
            "cf-ipfs.com",
            "*.cf-ipfs.com",
            "cloudflare-ipfs.com",
            "*.cloudflare-ipfs.com",
            "w3s.link",
            "*.w3s.link",
            "nftstorage.link",
            "*.nftstorage.link",
            "*.mypinata.cloud",
            "gateway.pinata.cloud",
            "4everland.link",
            "*.4everland.link",
            "infura-ipfs.io",
            "*.infura-ipfs.io",
            "*.on.fleek.co",
            "eth.limo",
            "*.eth.limo",
            "eth.link",
            "*.eth.link",
        ],
    },
    SecurityCategory {
        id: "crypto_mining",
        name: "Cryptocurrency Mining",
        description: "In-browser miners and mining pools, so a compromised device or page \
            cannot mine cryptocurrency (cryptojacking). This also stops intentional mining.",
        section: Section::Security,
        detector: None,
        entries: &[
            // In-browser miners
            "coinhive.com",
            "*.coinhive.com",
            "coin-hive.com",
            "*.coin-hive.com",
            "authedmine.com",
            "*.authedmine.com",
            "crypto-loot.com",
            "*.crypto-loot.com",
            "cryptoloot.pro",
            "*.cryptoloot.pro",
            "webmine.cz",
            "*.webmine.cz",
            "webminepool.com",
            "*.webminepool.com",
            "minero.cc",
            "*.minero.cc",
            "coinimp.com",
            "*.coinimp.com",
            "jsecoin.com",
            "*.jsecoin.com",
            "monerominer.rocks",
            "*.monerominer.rocks",
            "ppoi.org",
            "*.ppoi.org",
            // Mining pools
            "supportxmr.com",
            "*.supportxmr.com",
            "minexmr.com",
            "*.minexmr.com",
            "moneroocean.stream",
            "*.moneroocean.stream",
            "nanopool.org",
            "*.nanopool.org",
            "2miners.com",
            "*.2miners.com",
            "f2pool.com",
            "*.f2pool.com",
            "hashvault.pro",
            "*.hashvault.pro",
            "xmrpool.eu",
            "*.xmrpool.eu",
            "c3pool.com",
            "*.c3pool.com",
            "herominers.com",
            "*.herominers.com",
            "unmineable.com",
            "*.unmineable.com",
            "minergate.com",
            "*.minergate.com",
            "nicehash.com",
            "*.nicehash.com",
            "antpool.com",
            "*.antpool.com",
        ],
    },
    SecurityCategory {
        id: "high_risk_tlds",
        name: "High-Risk TLDs",
        description: "Top-level domains dominated by abuse in published phishing and spam \
            reports (.zip, .mov, .top, .cfd, .sbs, the former Freenom TLDs, ...). The list \
            is curated and updated with each release; allow a site you need under Custom \
            Allow.",
        section: Section::Security,
        detector: None,
        entries: &[
            "*.zip",
            "*.mov",
            "*.top",
            "*.cfd",
            "*.sbs",
            "*.bond",
            "*.icu",
            "*.cyou",
            "*.rest",
            "*.buzz",
            "*.quest",
            "*.monster",
            "*.cam",
            "*.lol",
            "*.mom",
            "*.boats",
            "*.autos",
            "*.yachts",
            "*.hair",
            "*.beauty",
            "*.makeup",
            "*.skin",
            "*.tk",
            "*.ml",
            "*.ga",
            "*.cf",
            "*.gq",
        ],
    },
    SecurityCategory {
        id: "idn_homographs",
        name: "IDN Homographs",
        description: "Internationalized names that imitate a familiar one with look-alike \
            letters from another alphabet (a Cyrillic 'а' in pаypal.com). Genuine names in \
            other languages, such as bücher.de or яндекс.рф, are not affected.",
        section: Section::Security,
        detector: Some(Detector::Homograph),
        entries: &[],
    },
    SecurityCategory {
        id: "dga_domains",
        name: "DGA Domains",
        description: "Random-looking names that malware generates to find its command-and-control \
            servers (xjkqpwzvbnmtrd.com). Judged by how unlike real names the letters are; a \
            rare genuine site may be caught, so allow it under Custom Allow.",
        section: Section::Security,
        detector: Some(Detector::Dga),
        entries: &[],
    },
    SecurityCategory {
        id: "parked_domains",
        name: "Parked Domains",
        description:
            "Domains served by parking services (Sedo, Bodis, ParkingCrew, ...) that show \
            ads and redirects instead of a site. The name servers are looked up the first time \
            a domain is seen, so that first visit is not blocked.",
        section: Section::Security,
        detector: Some(Detector::Parked),
        entries: &[],
    },
    SecurityCategory {
        id: "typosquatting",
        name: "Typosquatting",
        description:
            "Names that imitate a brand phishing often targets (PayPal, Apple, Microsoft, banks, \
            delivery companies, ...) with a typo (gooogle.com), look-alike characters \
            (paypa1.com) or a phishing word (paypal-login.com). The brands' own sites are \
            not affected.",
        section: Section::Security,
        detector: Some(Detector::Typosquat),
        entries: &[],
    },
    SecurityCategory {
        id: "newly_registered",
        name: "Newly Registered Domains",
        description:
            "Domains registered less than 30 days ago, which threat actors favour for new \
            campaigns. Registration dates are looked up over RDAP the first time a domain is \
            seen (so that first visit is not blocked), which tells the domain's registry the \
            name, though not who asked; TLDs without RDAP are never blocked.",
        section: Section::Security,
        detector: Some(Detector::NewlyRegistered),
        entries: &[],
    },
    SecurityCategory {
        id: "google_safe_browsing",
        name: "Google Safe Browsing",
        description:
            "Malware and phishing sites on Google Safe Browsing's lists. The lists are kept on \
            this server; Google is asked only when a name's hash matches one of them, and then \
            only for a hash prefix shared with many names, never with your address. Needs a \
            Safe Browsing API key under Filtering → Response Filters (the API is for \
            non-commercial use only). Lists of single pages on a site cannot be checked by DNS.",
        section: Section::Security,
        detector: Some(Detector::SafeBrowsing),
        entries: &[],
    },
    SecurityCategory {
        id: "residential_hosting",
        name: "Residential Hosting",
        description:
            "Names whose addresses all belong to home internet providers rather than data \
            centres, as botnet command servers and phishing proxies on compromised routers do. \
            Networks are identified with Team Cymru's IP-to-ASN service and PeeringDB, looked up \
            in the background (so the first visits are not blocked); CDN caches inside ISPs are \
            not affected. Services run from a home connection, including your ISP's own portal \
            and your own home server, are blocked: allow them under Custom Allow.",
        section: Section::Security,
        detector: Some(Detector::ResidentialHosting),
        entries: &[],
    },
    SecurityCategory {
        id: "disguised_trackers",
        name: "Disguised Third-Party Trackers",
        description: "Trackers and ad servers hidden behind a site's own subdomain with a CNAME \
            (metrics.shop.example pointing to a tracking company), which lets them read the \
            site's cookies and slip past browsers' third-party protections. Uses AdGuard's \
            catalogue of tracking companies' CNAME targets.",
        section: Section::Privacy,
        detector: Some(Detector::CnameTracker),
        entries: &[],
    },
];

/// Name-server suffixes of domain parking services: a domain whose name
/// servers are under one of these is parked.
pub const PARKING_NAME_SERVERS: &[&str] = &[
    "sedoparking.com",
    "bodis.com",
    "parkingcrew.net",
    "above.com",
    "parklogic.com",
    "fabulous.com",
    "cashparking.com",
    "hugedomainsdns.com",
    "dan.com",
    "undeveloped.com",
    "afternic.com",
    "namedrive.com",
    "voodoo.com",
];

/// Whether a name server (lowercase, no trailing dot) belongs to a parking
/// service.
pub fn is_parking_name_server(ns: &str) -> bool {
    PARKING_NAME_SERVERS.iter().any(|suffix| {
        ns == *suffix
            || ns
                .strip_suffix(suffix)
                .is_some_and(|rest| rest.ends_with('.'))
    })
}

/// The security category with id `id` (any case).
pub fn find(id: &str) -> Option<&'static SecurityCategory> {
    SECURITY_CATEGORIES
        .iter()
        .find(|c| c.id.eq_ignore_ascii_case(id.trim()))
}

/// A TLD as a group stores it: lowercase, in punycode, without dots or a
/// `*.` prefix (`.ZIP` and `*.zip` become `zip`). `None` when `raw` is not a
/// single valid DNS label.
pub fn normalize_tld(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let trimmed = trimmed.strip_prefix("*.").unwrap_or(trimmed);
    let trimmed = trimmed.trim_matches('.');
    if trimmed.is_empty() || trimmed.contains('.') {
        return None;
    }
    let tld = daygle_dns_core::config::normalize_domains([trimmed.to_string()])
        .into_iter()
        .next()?;
    let valid = tld.len() <= 63
        && tld.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !tld.starts_with('-')
        && !tld.ends_with('-')
        // A TLD is never all digits (that would read as an address).
        && !tld.bytes().all(|b| b.is_ascii_digit());
    valid.then_some(tld)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Blocklist;

    #[test]
    fn ids_are_unique_and_entries_valid() {
        let mut ids = std::collections::HashSet::new();
        for category in SECURITY_CATEGORIES {
            assert!(ids.insert(category.id), "duplicate id {}", category.id);
            assert_eq!(
                category.entries.is_empty(),
                category.detector.is_some(),
                "{}",
                category.id
            );
            let mut seen = std::collections::HashSet::new();
            for entry in category.entries {
                assert!(seen.insert(entry), "{}: duplicate {entry}", category.id);
                let pattern = entry.strip_prefix("@@").unwrap_or(entry);
                if category.id == "high_risk_tlds" {
                    let tld = pattern
                        .strip_prefix("*.")
                        .expect("TLD entries are wildcards");
                    assert_eq!(normalize_tld(tld).as_deref(), Some(tld));
                } else {
                    daygle_dns_core::config::validate_domain_pattern(pattern)
                        .unwrap_or_else(|e| panic!("{}: {entry}: {e}", category.id));
                }
            }
        }
        assert_eq!(
            find("Dynamic_DNS").map(|c| c.name),
            Some("Dynamic DNS Hostnames")
        );
        assert!(find("nope").is_none());
    }

    #[test]
    fn exceptions_keep_provider_sites_reachable() {
        let ddns = find("dynamic_dns").unwrap();
        let list = Blocklist::from_lines(ddns.entries.iter().copied());
        assert!(list.contains("phish.duckdns.org"));
        assert!(!list.contains("duckdns.org"));
        assert!(!list.contains("www.duckdns.org"));
        assert!(!list.contains("freedns.afraid.org"));
        assert!(list.contains("evil.mooo.com"));
    }

    #[test]
    fn parking_name_servers() {
        assert!(is_parking_name_server("ns1.sedoparking.com"));
        assert!(is_parking_name_server("ns2.bodis.com"));
        assert!(!is_parking_name_server("ns1.notbodis.com"));
        assert!(!is_parking_name_server("ns1.example.com"));
    }

    #[test]
    fn tlds_normalize() {
        assert_eq!(normalize_tld(" .ZIP ").as_deref(), Some("zip"));
        assert_eq!(normalize_tld("*.mov").as_deref(), Some("mov"));
        assert_eq!(normalize_tld("рф").as_deref(), Some("xn--p1ai"));
        assert_eq!(normalize_tld("xn--p1ai").as_deref(), Some("xn--p1ai"));
        assert_eq!(normalize_tld("co.uk"), None);
        assert_eq!(normalize_tld(""), None);
        assert_eq!(normalize_tld("a_b"), None);
        assert_eq!(normalize_tld("123"), None);
    }
}
