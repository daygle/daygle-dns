//! # daygle-gui
//!
//! Embeds the compiled web GUI (a Svelte app) into the server binary so the
//! REST API can serve the dashboard with no external web server.
//!
//! The build output lives in `web/dist`; building the Svelte app is optional —
//! a minimal fallback `index.html` is committed so the workspace always
//! compiles. Run `npm install && npm run build` in `web/` to refresh the
//! embedded bundle.

use rust_embed::RustEmbed;

/// Embedded GUI assets from `web/dist` (resolved relative to this crate).
#[derive(RustEmbed)]
#[folder = "../../web/dist"]
pub struct GuiAssets;

/// A resolved asset: MIME type and raw bytes.
pub struct Asset {
    pub content_type: &'static str,
    pub bytes: Vec<u8>,
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
    }

    #[test]
    fn serves_spa_fallback() {
        let asset = lookup("/zones/abc").expect("SPA fallback works");
        assert!(asset.content_type.starts_with("text/html"));
    }
}
