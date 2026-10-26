//! Recent blocks, so the block page can say why a site was blocked: the
//! dispatcher records each block it answers with the block page's address,
//! and the page looks the visitor's (address, host name) up.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Most entries kept; older ones are forgotten first.
const CAPACITY: usize = 4096;
/// How long a block is remembered (the page loads right after the lookup).
const KEEP_FOR: Duration = Duration::from_secs(600);

/// The recent blocks.
#[derive(Debug, Default)]
pub struct BlockLog {
    entries: Mutex<HashMap<(IpAddr, String), (String, Instant)>>,
}

impl BlockLog {
    /// Remember that `name` was blocked for `client`, and why.
    pub fn record(&self, client: IpAddr, name: &str, reason: &str) {
        let mut entries = self.entries.lock();
        if entries.len() >= CAPACITY {
            let now = Instant::now();
            entries.retain(|_, (_, at)| now.duration_since(*at) < KEEP_FOR);
            if entries.len() >= CAPACITY {
                entries.clear();
            }
        }
        entries.insert(
            (
                client.to_canonical(),
                name.trim_end_matches('.').to_ascii_lowercase(),
            ),
            (reason.to_string(), Instant::now()),
        );
    }

    /// Why `name` was blocked for `client`, if it was recently.
    pub fn reason(&self, client: IpAddr, name: &str) -> Option<String> {
        let entries = self.entries.lock();
        entries
            .get(&(
                client.to_canonical(),
                name.trim_end_matches('.').to_ascii_lowercase(),
            ))
            .filter(|(_, at)| at.elapsed() < KEEP_FOR)
            .map(|(reason, _)| reason.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_are_looked_up_per_client_and_name() {
        let log = BlockLog::default();
        let client: IpAddr = "192.168.1.7".parse().unwrap();
        log.record(client, "Ads.Example.", "on blocklist 'Ads'");
        assert_eq!(
            log.reason(client, "ads.example").as_deref(),
            Some("on blocklist 'Ads'")
        );
        assert_eq!(
            log.reason("192.168.1.8".parse().unwrap(), "ads.example"),
            None
        );
        assert_eq!(log.reason(client, "other.example"), None);
    }
}
