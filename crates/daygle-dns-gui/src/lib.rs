//! # daygle-gui
//!
//! Embeds the compiled web GUI (a Svelte app) into the server binary so the
//! REST API can serve the dashboard with no external web server.
//!
//! The build output lives in `web/dist`; building the Svelte app is optional -
//! a minimal fallback `index.html` is committed so the workspace always
//! compiles. Run `npm install && npm run build` in `web/` to refresh the
//! embedded bundle.

use rust_embed::RustEmbed;

/// Embedded GUI assets from `web/dist` (resolved relative to this crate).
#[derive(RustEmbed)]
#[folder = "../../web/dist"]
pub struct GuiAssets;

/// A resolved asset: MIME type, raw bytes, and the embedded file that
/// satisfied the request (used to pick a cache policy).
pub struct Asset {
    pub content_type: &'static str,
    pub bytes: Vec<u8>,
    /// Embedded file served (e.g. `index.html`, `assets/index-abc123.js`).
    /// Empty, directory-style and unknown SPA routes resolve to `index.html`.
    pub served_path: String,
}

impl Asset {
    /// HTTP `Cache-Control` value for this asset.
    pub fn cache_control(&self) -> &'static str {
        cache_control(&self.served_path)
    }
}

/// Cache-Control policy for a served embedded file.
///
/// The app shell (`index.html`) is served at a stable URL, so it must be
/// revalidated on every load (`no-cache`): after an upgrade the server
/// embeds a new shell pointing at new hashed bundles, and a browser holding
/// a stale cached shell would keep requesting removed assets until a hard
/// refresh.
///
/// Everything Vite emits under `assets/` is content-hashed - the filename
/// changes whenever the bytes change - so those responses are safe to cache
/// for a year as immutable.
///
/// Any other file (e.g. an un-hashed asset at the dist root) cannot be
/// proven stable across rebuilds, so it falls back to `no-cache`.
pub fn cache_control(served_path: &str) -> &'static str {
    if served_path == "index.html" {
        "no-cache"
    } else if served_path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

/// Look up an asset by request path (e.g. `index.html`, `assets/index.js`).
///
/// An empty path or a directory-style path resolves to `index.html`, which
/// also serves as the fallback for single-page-app routes.
pub fn lookup(path: &str) -> Option<Asset> {
    let path = path.trim_start_matches('/');
    let path = if path.is_empty() || path.ends_with('/') {
        "index.html"
    } else {
        path
    };

    // SPA fallback: unknown paths without a file extension serve the shell.
    let (served, file) = match GuiAssets::get(path) {
        Some(file) => (path, file),
        None => {
            if path.contains('.') {
                return None;
            }
            ("index.html", GuiAssets::get("index.html")?)
        }
    };

    Some(Asset {
        content_type: content_type(served),
        bytes: file.data.to_vec(),
        served_path: served.to_string(),
    })
}

/// Best-effort MIME type for an asset path.
pub fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html",
        Some("js" | "mjs") => "text/javascript",
        Some("css") => "text/css",
        Some("svg") => "image/svg+xml",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("map") => "application/json",
        _ => "application/octet-stream",
    }
}

/// Whether any GUI assets are embedded (always true; present for clarity).
pub fn is_available() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_index_at_root() {
        let asset = lookup("/").expect("index.html is embedded");
        assert!(asset.content_type.starts_with("text/html"));
        assert!(!asset.bytes.is_empty());
        assert_eq!(asset.served_path, "index.html");
        // The shell is revalidated on every load.
        assert_eq!(asset.cache_control(), "no-cache");
    }

    #[test]
    fn serves_spa_fallback() {
        let asset = lookup("/zones/abc").expect("SPA fallback works");
        assert!(asset.content_type.starts_with("text/html"));
        assert_eq!(asset.served_path, "index.html");
    }

    #[test]
    fn cache_policy_for_shell_and_hashed_assets() {
        // The shell must never be cached long-term.
        assert_eq!(cache_control("index.html"), "no-cache");
        // Content-hashed Vite bundles are immutable.
        assert_eq!(
            cache_control("assets/index-abc123.js"),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(
            cache_control("assets/index-abc123.css"),
            "public, max-age=31536000, immutable"
        );
        // Un-hashed files at the dist root cannot be proven stable.
        assert_eq!(cache_control("favicon.ico"), "no-cache");
    }
}
