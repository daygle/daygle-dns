//! # daygle-gui
//!
//! Embeds the compiled web GUI (a Svelte app) into the server binary so the
//! REST API can serve the dashboard with no external web server.
//!
//! The build output lives in `web/dist` and is committed, so the workspace
//! compiles without Node. Run `npm ci && npm run build` in `web/` to refresh
//! the embedded bundle after changing `web/src`.

use std::borrow::Cow;
use std::sync::OnceLock;

use rust_embed::RustEmbed;

/// Embedded GUI assets from `web/dist` (resolved relative to this crate).
#[derive(RustEmbed)]
#[folder = "../../web/dist"]
pub struct GuiAssets;

/// A resolved asset: MIME type, raw bytes, and the embedded file that
/// satisfied the request (used to pick a cache policy).
pub struct Asset {
    pub content_type: &'static str,
    /// Borrowed straight from the binary in release builds (no per-request
    /// copy); owned only when rust-embed reads from disk in debug builds.
    pub bytes: Cow<'static, [u8]>,
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
/// revalidated on every load (`no-cache`): after an update the server
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

/// The Vite entry bundle referenced by the embedded `index.html`
/// (e.g. `index-abc123`), without directory or extension - or `None` when it
/// cannot be parsed.
///
/// The console polls `/api/health`, which exposes this as `console_build`,
/// and compares it with the bundle file it is actually running, so a page
/// left open across a server update can tell that the server now embeds a
/// newer build and ask for a reload. The bundle name is content-hashed by
/// Vite, so it changes whenever the console build changes - even when the
/// workspace version does not (releases build from `main` with the version
/// pinned at 1.0.0, so a version comparison would never fire).
pub fn entry_bundle_name() -> Option<&'static str> {
    static ENTRY: OnceLock<Option<String>> = OnceLock::new();
    ENTRY
        .get_or_init(|| {
            let html = GuiAssets::get("index.html")?.data;
            let html = std::str::from_utf8(&html).ok()?;
            // The shell has exactly one module script, emitted by Vite as
            // `<script type="module" crossorigin src="/assets/index-<hash>.js">`.
            let script = html.find("<script type=\"module\"")?;
            let src = script + html[script..].find("src=\"")? + 5;
            let end = src + html[src..].find('"')?;
            let url = &html[src..end];
            let file = url.rsplit('/').next()?;
            let file = file.strip_suffix(".js")?;
            Some(file.to_string())
        })
        .as_deref()
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
        bytes: file.data,
        served_path: served.to_string(),
    })
}

/// Best-effort MIME type for an asset path.
pub fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
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
    fn serves_favicon() {
        let asset = lookup("/favicon.svg").expect("favicon is embedded");
        assert_eq!(asset.content_type, "image/svg+xml");
        assert!(!asset.bytes.is_empty());
        // Un-hashed at the dist root: revalidated on every load.
        assert_eq!(asset.cache_control(), "no-cache");
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

    #[test]
    fn entry_bundle_name_matches_the_embedded_shell() {
        // Committed dist shells reference a Vite-hashed entry bundle.
        let name = entry_bundle_name().expect("the shell's module script is parseable");
        assert!(name.starts_with("index-"), "unexpected entry name: {name}");
        assert!(!name.contains('/'), "entry name must be a bare file stem");
    }
}
