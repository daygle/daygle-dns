//! Safe Search and YouTube Restricted Mode.
//!
//! The search engines offer a "safe" address that forces their strictest
//! filtering whatever the user's account or browser settings say. Answering
//! a search engine's name with that address (as a CNAME to it) turns Safe
//! Search on for every device using this server, the same way schools and
//! routers do it.

/// Google's forced Safe Search address.
pub const GOOGLE_SAFE: &str = "forcesafesearch.google.com";
/// Bing's strict mode address.
pub const BING_SAFE: &str = "strict.bing.com";
/// DuckDuckGo's strict mode address.
pub const DUCKDUCKGO_SAFE: &str = "safe.duckduckgo.com";
/// YouTube's strict Restricted Mode address.
pub const YOUTUBE_RESTRICTED: &str = "restrict.youtube.com";

/// The YouTube names Google lists for DNS-enforced Restricted Mode.
const YOUTUBE_NAMES: [&str; 5] = [
    "www.youtube.com",
    "m.youtube.com",
    "youtubei.googleapis.com",
    "youtube.googleapis.com",
    "www.youtube-nocookie.com",
];

/// The safe address `qname` (lowercase, no trailing dot) is answered with,
/// given which of the two switches is on; `None` leaves it alone.
pub fn safe_target(qname: &str, safe_search: bool, youtube: bool) -> Option<&'static str> {
    if youtube && YOUTUBE_NAMES.contains(&qname) {
        return Some(YOUTUBE_RESTRICTED);
    }
    if !safe_search {
        return None;
    }
    match qname {
        "bing.com" | "www.bing.com" => Some(BING_SAFE),
        "duckduckgo.com" | "www.duckduckgo.com" | "start.duckduckgo.com" => Some(DUCKDUCKGO_SAFE),
        _ if is_google_search(qname) => Some(GOOGLE_SAFE),
        _ => None,
    }
}

/// Whether `qname` is Google's search front page in some country:
/// `google.com`, `google.de`, `google.co.uk`, `google.com.au`, with or
/// without `www.`.
fn is_google_search(qname: &str) -> bool {
    let name = qname.strip_prefix("www.").unwrap_or(qname);
    let Some(tld) = name.strip_prefix("google.") else {
        return false;
    };
    let cc = |s: &str| s.len() == 2 && s.bytes().all(|b| b.is_ascii_lowercase());
    match tld.split_once('.') {
        None => tld == "com" || cc(tld),
        Some(("co", rest)) | Some(("com", rest)) => cc(rest),
        Some(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_engines_map_to_their_safe_addresses() {
        for name in [
            "google.com",
            "www.google.com",
            "www.google.de",
            "google.co.uk",
            "www.google.com.au",
        ] {
            assert_eq!(safe_target(name, true, false), Some(GOOGLE_SAFE), "{name}");
        }
        for name in [
            "mail.google.com",
            "google.example.com",
            "www.google.com.evil.test",
            "google.co.uk.evil.test",
            "forcesafesearch.google.com",
            "googleapis.com",
        ] {
            assert_eq!(safe_target(name, true, false), None, "{name}");
        }
        assert_eq!(safe_target("www.bing.com", true, false), Some(BING_SAFE));
        assert_eq!(
            safe_target("duckduckgo.com", true, false),
            Some(DUCKDUCKGO_SAFE)
        );
        // Off: nothing changes.
        assert_eq!(safe_target("www.google.com", false, true), None);
    }

    #[test]
    fn youtube_has_its_own_switch() {
        assert_eq!(
            safe_target("www.youtube.com", false, true),
            Some(YOUTUBE_RESTRICTED)
        );
        assert_eq!(
            safe_target("m.youtube.com", true, true),
            Some(YOUTUBE_RESTRICTED)
        );
        assert_eq!(safe_target("www.youtube.com", true, false), None);
        assert_eq!(safe_target("music.youtube.com", false, true), None);
    }
}
