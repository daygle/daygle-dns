//! Security and privacy categories a filtering group can block with one
//! tick. Each is either an exact check the server performs itself (a
//! [`Detector`]) or a maintained public list ([`Feed`]) the server
//! downloads and refreshes on a schedule ([`crate::feeds`]); none is a
//! hand-written list or a guess.
//!
//! Also here: the per-group TLD block list, which turns `zip` into `*.zip`.

use serde::Serialize;

/// One security or privacy category.
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
    /// The check that decides membership, for categories judged by
    /// examining the answer or looking the domain up.
    pub detector: Option<Detector>,
    /// The maintained list the category blocks (or, with a detector, the
    /// data the detector uses).
    pub feed: Option<Feed>,
}

/// A maintained public list a category is built from.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Feed {
    /// Who maintains it, for the console.
    pub source: &'static str,
    /// Where it is downloaded from.
    pub url: &'static str,
    /// How it is written.
    pub format: FeedFormat,
    /// A list of names the maintainer says to let through despite the
    /// main list (reputable sites under an abused TLD), in the same format.
    pub allow_url: Option<&'static str>,
}

/// How a feed is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedFormat {
    /// One name per line, each covering its subdomains (HaGeZi's wildcard
    /// "onlydomains" lists; a bare TLD covers the whole TLD).
    Wildcard,
    /// One name per line, each covering only itself.
    Domains,
    /// AdGuard's cname-trackers catalogue (JSON): the `tracker` and `ad`
    /// companies' CNAME targets, each covering its subdomains.
    AdguardCnameTrackers,
    /// IPFS's public gateway list (JSON array of gateway URLs): each
    /// gateway's host and its subdomains.
    IpfsGateways,
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

/// A category decided by a check rather than by a list alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Detector {
    /// Domains registered less than 30 days ago; decided once the
    /// registration date is known ([`crate::rdap`]), after resolution.
    NewlyRegistered,
    /// Names on Google Safe Browsing's lists ([`crate::safe_browsing`]),
    /// checked after resolution.
    SafeBrowsing,
    /// Names whose addresses all belong to consumer ISPs
    /// ([`crate::residential`]), checked after resolution.
    ResidentialHosting,
    /// Answers whose CNAME chain leads to a third-party tracker on the
    /// category's feed ([`crate::cname_trackers`]), checked after
    /// resolution.
    CnameTracker,
}

impl Detector {
    /// Whether the dispatcher decides it after resolution (every detector
    /// does: they need the answer or a lookup).
    pub fn after_resolution(self) -> bool {
        true
    }
}

/// Category ids that existed in earlier versions and were retired (they
/// were heuristics, or hand-written lists without a maintained source).
/// Groups that still name them keep working: the ids are dropped when the
/// group is saved and ignored until then.
pub const RETIRED: &[&str] = &[
    "free_hosting",
    "tunneling",
    "data_drop",
    "parked_domains",
    "allow_tracking_links",
    "idn_homographs",
    "dga_domains",
    "typosquatting",
    "native_sonos",
    "native_vizio",
];

/// Whether `id` names a retired category.
pub fn is_retired(id: &str) -> bool {
    RETIRED.iter().any(|r| r.eq_ignore_ascii_case(id.trim()))
}

/// Every known category.
pub const SECURITY_CATEGORIES: &[SecurityCategory] = &[
    SecurityCategory {
        id: "dynamic_dns",
        name: "Dynamic DNS Hostnames",
        description:
            "Dynamic DNS services, whose free hostnames need no identity check and are heavily \
            used in phishing. Their own websites are blocked too; if you use one, allow your \
            hostname and the provider's update address under Custom Allow.",
        section: Section::Security,
        detector: None,
        feed: Some(Feed {
            source: "HaGeZi DynDNS",
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dyndns-onlydomains.txt",
            format: FeedFormat::Wildcard,
            allow_url: None,
        }),
    },
    SecurityCategory {
        id: "decentralized_gateways",
        name: "Decentralized Web Gateways",
        description:
            "Public gateways that serve IPFS content to ordinary browsers, used to host \
            phishing pages that cannot be taken down.",
        section: Section::Security,
        detector: None,
        feed: Some(Feed {
            source: "IPFS public gateway list",
            url: "https://raw.githubusercontent.com/ipfs/public-gateway-checker/main/gateways.json",
            format: FeedFormat::IpfsGateways,
            allow_url: None,
        }),
    },
    SecurityCategory {
        id: "crypto_mining",
        name: "Cryptocurrency Mining",
        description:
            "In-browser miners and mining pools, so a compromised device or page cannot mine \
            cryptocurrency (cryptojacking). This also stops intentional mining.",
        section: Section::Security,
        detector: None,
        feed: Some(Feed {
            source: "The Block List Project (Crypto)",
            url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/crypto-nl.txt",
            format: FeedFormat::Domains,
            allow_url: None,
        }),
    },
    SecurityCategory {
        id: "high_risk_tlds",
        name: "High-Risk TLDs",
        description:
            "Top-level domains dominated by spam, scams and phishing (from Cloudflare Radar, \
            Netcraft and Spamhaus data). This blocks whole TLDs, so some legitimate sites are \
            caught; reputable ones on the maintainer's allowlist stay reachable, and you can \
            allow others under Custom Allow.",
        section: Section::Security,
        detector: None,
        feed: Some(Feed {
            source: "HaGeZi Most Abused TLDs",
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/spam-tlds-onlydomains.txt",
            format: FeedFormat::Wildcard,
            allow_url: Some("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/spam-tlds-allow-onlydomains.txt"),
        }),
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
        feed: None,
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
        feed: None,
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
        feed: None,
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
        feed: Some(Feed {
            source: "AdGuard cname-trackers",
            url: "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/script/src/cloaked-trackers.json",
            format: FeedFormat::AdguardCnameTrackers,
            allow_url: None,
        }),
    },
    SecurityCategory {
        id: "native_apple",
        name: "Native Tracking: Apple",
        description: "Analytics, diagnostics and ad attribution that iPhones, iPads and Macs send by themselves.",
        section: Section::Privacy,
        detector: None,
        feed: Some(Feed {
            source: "HaGeZi Native Tracker (Apple)",
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.apple-onlydomains.txt",
            format: FeedFormat::Wildcard,
            allow_url: None,
        }),
    },
    SecurityCategory {
        id: "native_samsung",
        name: "Native Tracking: Samsung",
        description: "Ads, usage analytics and smart-TV content recognition from Samsung phones and TVs.",
        section: Section::Privacy,
        detector: None,
        feed: Some(Feed {
            source: "HaGeZi Native Tracker (Samsung)",
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.samsung-onlydomains.txt",
            format: FeedFormat::Wildcard,
            allow_url: None,
        }),
    },
    SecurityCategory {
        id: "native_xiaomi",
        name: "Native Tracking: Xiaomi",
        description: "Usage statistics and system ads from Xiaomi, Redmi and POCO devices.",
        section: Section::Privacy,
        detector: None,
        feed: Some(Feed {
            source: "HaGeZi Native Tracker (Xiaomi)",
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.xiaomi-onlydomains.txt",
            format: FeedFormat::Wildcard,
            allow_url: None,
        }),
    },
    SecurityCategory {
        id: "native_huawei",
        name: "Native Tracking: Huawei",
        description: "Usage metrics and log uploads from Huawei and Honor devices.",
        section: Section::Privacy,
        detector: None,
        feed: Some(Feed {
            source: "HaGeZi Native Tracker (Huawei)",
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.huawei-onlydomains.txt",
            format: FeedFormat::Wildcard,
            allow_url: None,
        }),
    },
    SecurityCategory {
        id: "native_windows",
        name: "Native Tracking: Windows & Office",
        description: "Windows and Office diagnostic data (telemetry) and error reporting.",
        section: Section::Privacy,
        detector: None,
        feed: Some(Feed {
            source: "HaGeZi Native Tracker (Windows & Office)",
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.winoffice-onlydomains.txt",
            format: FeedFormat::Wildcard,
            allow_url: None,
        }),
    },
    SecurityCategory {
        id: "native_amazon",
        name: "Native Tracking: Amazon",
        description: "Device metrics and usage logs from Echo, Fire TV and Kindle devices.",
        section: Section::Privacy,
        detector: None,
        feed: Some(Feed {
            source: "HaGeZi Native Tracker (Amazon)",
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.amazon-onlydomains.txt",
            format: FeedFormat::Wildcard,
            allow_url: None,
        }),
    },
    SecurityCategory {
        id: "native_roku",
        name: "Native Tracking: Roku",
        description: "Usage logs and ads from Roku players and TVs.",
        section: Section::Privacy,
        detector: None,
        feed: Some(Feed {
            source: "HaGeZi Native Tracker (Roku)",
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.roku-onlydomains.txt",
            format: FeedFormat::Wildcard,
            allow_url: None,
        }),
    },
    SecurityCategory {
        id: "native_lg",
        name: "Native Tracking: LG webOS",
        description: "Ads and viewing data from LG smart TVs.",
        section: Section::Privacy,
        detector: None,
        feed: Some(Feed {
            source: "HaGeZi Native Tracker (LG webOS)",
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.lgwebos-onlydomains.txt",
            format: FeedFormat::Wildcard,
            allow_url: None,
        }),
    },
    SecurityCategory {
        id: "native_vivo",
        name: "Native Tracking: Vivo",
        description: "Usage analytics and system ads from Vivo phones.",
        section: Section::Privacy,
        detector: None,
        feed: Some(Feed {
            source: "HaGeZi Native Tracker (Vivo)",
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.vivo-onlydomains.txt",
            format: FeedFormat::Wildcard,
            allow_url: None,
        }),
    },
    SecurityCategory {
        id: "native_oppo",
        name: "Native Tracking: OPPO & Realme",
        description: "Usage analytics and system ads from OPPO, Realme and OnePlus (ColorOS) phones.",
        section: Section::Privacy,
        detector: None,
        feed: Some(Feed {
            source: "HaGeZi Native Tracker (OPPO & Realme)",
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.oppo-realme-onlydomains.txt",
            format: FeedFormat::Wildcard,
            allow_url: None,
        }),
    },
    SecurityCategory {
        id: "native_tiktok",
        name: "Native Tracking: TikTok",
        description: "Analytics and tracking built into the TikTok app.",
        section: Section::Privacy,
        detector: None,
        feed: Some(Feed {
            source: "HaGeZi Native Tracker (TikTok)",
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.tiktok-onlydomains.txt",
            format: FeedFormat::Wildcard,
            allow_url: None,
        }),
    },
];

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

    #[test]
    fn ids_are_unique_and_every_category_is_backed() {
        let mut ids = std::collections::HashSet::new();
        for category in SECURITY_CATEGORIES {
            assert!(ids.insert(category.id), "duplicate id {}", category.id);
            assert!(!is_retired(category.id), "{} is retired", category.id);
            // Every category is an exact check or a maintained list.
            assert!(
                category.detector.is_some() || category.feed.is_some(),
                "{}",
                category.id
            );
            if let Some(feed) = category.feed {
                assert!(feed.url.starts_with("https://"), "{}", category.id);
            }
        }
        assert_eq!(
            find("Dynamic_DNS").map(|c| c.name),
            Some("Dynamic DNS Hostnames")
        );
        assert!(find("nope").is_none());
        assert!(is_retired("DGA_domains"));
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
