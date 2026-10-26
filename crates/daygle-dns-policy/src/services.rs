//! Blocked services: well-known apps and sites, each a set of domains, that
//! a filtering group can block with one tick ("block TikTok") instead of a
//! hand-made list. Every domain covers its subdomains.

use serde::Serialize;

/// One service.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Service {
    /// Stable identifier stored in a group's `blocked_services`.
    pub id: &'static str,
    /// Display name.
    pub name: &'static str,
    /// Display category.
    pub category: &'static str,
    /// The service's domains (each covering its subdomains).
    pub domains: &'static [&'static str],
}

const SOCIAL: &str = "Social Media";
const MESSAGING: &str = "Messaging";
const VIDEO: &str = "Video and Streaming";
const GAMING: &str = "Gaming";
const AI: &str = "AI Chatbots";
const DATING: &str = "Dating";

/// Every known service, grouped by category.
pub const SERVICES: &[Service] = &[
    Service {
        id: "facebook",
        name: "Facebook",
        category: SOCIAL,
        domains: &[
            "facebook.com",
            "facebook.net",
            "fbcdn.net",
            "fb.com",
            "fb.me",
            "fbsbx.com",
        ],
    },
    Service {
        id: "instagram",
        name: "Instagram",
        category: SOCIAL,
        domains: &["instagram.com", "cdninstagram.com", "ig.me"],
    },
    Service {
        id: "tiktok",
        name: "TikTok",
        category: SOCIAL,
        domains: &[
            "tiktok.com",
            "tiktokv.com",
            "tiktokcdn.com",
            "tiktokcdn-us.com",
            "tiktokv.us",
            "tiktokw.us",
            "byteoversea.com",
            "ibytedtos.com",
            "ibyteimg.com",
            "musical.ly",
        ],
    },
    Service {
        id: "snapchat",
        name: "Snapchat",
        category: SOCIAL,
        domains: &[
            "snapchat.com",
            "snap.com",
            "sc-cdn.net",
            "snapkit.com",
            "snapads.com",
            "sc-static.net",
        ],
    },
    Service {
        id: "twitter",
        name: "X (Twitter)",
        category: SOCIAL,
        domains: &["twitter.com", "x.com", "twimg.com", "t.co"],
    },
    Service {
        id: "threads",
        name: "Threads",
        category: SOCIAL,
        domains: &["threads.net", "threads.com"],
    },
    Service {
        id: "reddit",
        name: "Reddit",
        category: SOCIAL,
        domains: &[
            "reddit.com",
            "redd.it",
            "redditmedia.com",
            "redditstatic.com",
        ],
    },
    Service {
        id: "pinterest",
        name: "Pinterest",
        category: SOCIAL,
        domains: &["pinterest.com", "pinimg.com"],
    },
    Service {
        id: "tumblr",
        name: "Tumblr",
        category: SOCIAL,
        domains: &["tumblr.com"],
    },
    Service {
        id: "bereal",
        name: "BeReal",
        category: SOCIAL,
        domains: &["bereal.com", "bere.al"],
    },
    Service {
        id: "whatsapp",
        name: "WhatsApp",
        category: MESSAGING,
        domains: &["whatsapp.com", "whatsapp.net", "wa.me"],
    },
    Service {
        id: "messenger",
        name: "Messenger",
        category: MESSAGING,
        domains: &["messenger.com", "m.me"],
    },
    Service {
        id: "telegram",
        name: "Telegram",
        category: MESSAGING,
        domains: &["telegram.org", "telegram.me", "t.me", "telesco.pe"],
    },
    Service {
        id: "discord",
        name: "Discord",
        category: MESSAGING,
        domains: &[
            "discord.com",
            "discord.gg",
            "discordapp.com",
            "discordapp.net",
            "discord.media",
            "discordcdn.com",
        ],
    },
    Service {
        id: "youtube",
        name: "YouTube",
        category: VIDEO,
        domains: &[
            "youtube.com",
            "youtu.be",
            "ytimg.com",
            "googlevideo.com",
            "youtube-nocookie.com",
            "youtubei.googleapis.com",
            "youtube.googleapis.com",
            "yt.be",
        ],
    },
    Service {
        id: "twitch",
        name: "Twitch",
        category: VIDEO,
        domains: &[
            "twitch.tv",
            "twitchcdn.net",
            "ttvnw.net",
            "jtvnw.net",
            "twitchsvc.net",
        ],
    },
    Service {
        id: "kick",
        name: "Kick",
        category: VIDEO,
        domains: &["kick.com"],
    },
    Service {
        id: "netflix",
        name: "Netflix",
        category: VIDEO,
        domains: &[
            "netflix.com",
            "netflix.net",
            "nflxext.com",
            "nflximg.com",
            "nflximg.net",
            "nflxso.net",
            "nflxvideo.net",
        ],
    },
    Service {
        id: "disneyplus",
        name: "Disney+",
        category: VIDEO,
        domains: &[
            "disneyplus.com",
            "disney-plus.net",
            "dssott.com",
            "bamgrid.com",
        ],
    },
    Service {
        id: "primevideo",
        name: "Prime Video",
        category: VIDEO,
        domains: &["primevideo.com", "aiv-cdn.net", "aiv-delivery.net"],
    },
    Service {
        id: "spotify",
        name: "Spotify",
        category: VIDEO,
        domains: &["spotify.com", "scdn.co", "spotifycdn.com"],
    },
    Service {
        id: "roblox",
        name: "Roblox",
        category: GAMING,
        domains: &["roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com"],
    },
    Service {
        id: "fortnite",
        name: "Fortnite and Epic Games",
        category: GAMING,
        domains: &["epicgames.com", "epicgames.dev", "fortnite.com"],
    },
    Service {
        id: "minecraft",
        name: "Minecraft",
        category: GAMING,
        domains: &["minecraft.net", "mojang.com", "minecraftservices.com"],
    },
    Service {
        id: "steam",
        name: "Steam",
        category: GAMING,
        domains: &[
            "steampowered.com",
            "steamcommunity.com",
            "steamstatic.com",
            "steamcontent.com",
            "steamserver.net",
            "steamgames.com",
        ],
    },
    Service {
        id: "xbox",
        name: "Xbox Live",
        category: GAMING,
        domains: &["xboxlive.com", "xbox.com"],
    },
    Service {
        id: "playstation",
        name: "PlayStation Network",
        category: GAMING,
        domains: &[
            "playstation.com",
            "playstation.net",
            "sonyentertainmentnetwork.com",
        ],
    },
    Service {
        id: "chatgpt",
        name: "ChatGPT",
        category: AI,
        domains: &[
            "chatgpt.com",
            "openai.com",
            "oaistatic.com",
            "oaiusercontent.com",
        ],
    },
    Service {
        id: "claude",
        name: "Claude",
        category: AI,
        domains: &["claude.ai", "claude.com"],
    },
    Service {
        id: "gemini",
        name: "Gemini",
        category: AI,
        domains: &["gemini.google.com", "bard.google.com"],
    },
    Service {
        id: "copilot",
        name: "Microsoft Copilot",
        category: AI,
        domains: &["copilot.microsoft.com"],
    },
    Service {
        id: "characterai",
        name: "Character.AI",
        category: AI,
        domains: &["character.ai"],
    },
    Service {
        id: "perplexity",
        name: "Perplexity",
        category: AI,
        domains: &["perplexity.ai"],
    },
    Service {
        id: "tinder",
        name: "Tinder",
        category: DATING,
        domains: &["tinder.com", "gotinder.com"],
    },
    Service {
        id: "bumble",
        name: "Bumble",
        category: DATING,
        domains: &["bumble.com", "bumble.app"],
    },
];

/// The service with id `id` (any case).
pub fn find(id: &str) -> Option<&'static Service> {
    SERVICES
        .iter()
        .find(|s| s.id.eq_ignore_ascii_case(id.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_domains_valid() {
        let mut ids = std::collections::HashSet::new();
        for service in SERVICES {
            assert!(ids.insert(service.id), "duplicate id {}", service.id);
            assert!(!service.domains.is_empty(), "{}", service.id);
            for domain in service.domains {
                daygle_dns_core::config::validate_domain_pattern(domain)
                    .unwrap_or_else(|e| panic!("{}: {domain}: {e}", service.id));
            }
        }
        assert_eq!(find("TikTok").map(|s| s.name), Some("TikTok"));
        assert!(find("nope").is_none());
    }
}
