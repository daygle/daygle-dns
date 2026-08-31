//! A small, forgiving parser for BIND-style zone files.
//!
//! Supported syntax:
//! - `$ORIGIN example.com.` and `$TTL 3600`
//! - records with optional TTL and class: `www 300 IN A 192.0.2.1`
//! - `@` as the origin shorthand
//! - `;` comments and blank lines
//! - parentheses `(` `)` for multi-line RDATA
//! - quoted strings for TXT records
//!
//! The parser returns [`crate::model::RecordInput`] values which can be fed
//! into [`crate::store::ZoneStore::replace_records`].

use crate::model::RecordInput;
use daygle_dns_core::error::{DaygleError, Result};

/// Parse a zone file into record inputs plus the inferred origin.
pub fn parse_zone_file(text: &str) -> Result<Vec<RecordInput>> {
    let mut records = Vec::new();
    let mut origin = String::new();
    let mut default_ttl: u32 = 3600;

    let logical_lines = logical_lines(text);
    let mut last_owner = String::new();

    for raw in logical_lines {
        // Keep leading whitespace: it marks continuation lines. Only trim the
        // trailing whitespace and skip blanks/comments.
        let line = raw.trim_end();
        if line.trim().is_empty() || line.trim_start().starts_with(';') {
            continue;
        }

        // Directives (allow optional leading whitespace).
        let upper = line.trim_start().to_ascii_uppercase();
        if let Some(rest) = upper.strip_prefix("$ORIGIN") {
            origin = rest.trim().trim_end_matches('.').to_ascii_lowercase();
            continue;
        }
        if let Some(rest) = upper.strip_prefix("$TTL") {
            default_ttl = rest
                .trim()
                .parse()
                .map_err(|_| DaygleError::InvalidRecord(format!("bad $TTL in '{line}'")))?;
            continue;
        }
        if let Some(rest) = upper.strip_prefix("$INCLUDE") {
            return Err(DaygleError::InvalidRecord(format!(
                "$INCLUDE is not supported: '{rest}'"
            )));
        }

        let (owner, mut rest) = split_owner(&line, &origin, &last_owner)?;
        last_owner = owner.clone();

        // Optional TTL.
        let mut ttl = default_ttl;
        let (first, remainder) = split_first(&rest);
        if first
            .as_deref()
            .map(|t| t.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or(false)
        {
            ttl = first.unwrap().parse().unwrap_or(default_ttl);
            rest = remainder;
        }

        // Optional class (IN / CH / HS). Only IN is served; still accept and
        // skip it.
        if let (Some(first), remainder) = split_first(&rest) {
            if matches!(
                first.to_ascii_uppercase().as_str(),
                "IN" | "CH" | "HS" | "CLASS1" | "CLASS3" | "CLASS4"
            ) {
                rest = remainder;
            }
        }

        // Now: TYPE RDATA
        let (rtype, rdata) = rest
            .split_once(char::is_whitespace)
            .ok_or_else(|| DaygleError::InvalidRecord(format!("missing rdata in '{line}'")))?;
        let rtype = rtype.trim().to_ascii_uppercase();
        let content = rdata.trim().to_string();

        if rtype != "SOA" && rtype != "TXT" {
            // sanity: drop stray comments already handled by logical_lines
        }

        records.push(RecordInput {
            name: owner,
            rtype,
            content,
            ttl,
            priority: 0,
            disabled: false,
        });
    }

    Ok(records)
}

/// Split `owner [ttl] [class] type rdata`, returning (owner, rest).
fn split_owner(line: &str, origin: &str, last_owner: &str) -> Result<(String, String)> {
    // A line that starts with whitespace inherits the previous owner.
    if line.starts_with(char::is_whitespace) {
        let rest = line.trim_start();
        if last_owner.is_empty() {
            return Err(DaygleError::InvalidRecord(
                "continuation line without a previous owner".to_string(),
            ));
        }
        return Ok((last_owner.to_string(), rest.to_string()));
    }

    let (owner, rest) = line
        .split_once(char::is_whitespace)
        .ok_or_else(|| DaygleError::InvalidRecord(format!("cannot parse '{line}'")))?;
    let owner = owner.trim();

    let owner = if owner == "@" {
        if origin.is_empty() {
            return Err(DaygleError::InvalidRecord(
                "@ used before $ORIGIN was set".to_string(),
            ));
        }
        origin.to_string()
    } else if owner.contains('.') {
        // Either FQDN (trailing dot) or relative-with-dots; resolve against origin.
        if owner.ends_with('.') {
            owner.trim_end_matches('.').to_ascii_lowercase()
        } else if !origin.is_empty() && !owner.ends_with(&format!(".{origin}")) {
            format!("{owner}.{origin}")
        } else {
            owner.to_ascii_lowercase()
        }
    } else {
        // Bare label: relative to origin.
        if origin.is_empty() {
            owner.to_ascii_lowercase()
        } else {
            format!("{owner}.{origin}")
        }
    };

    Ok((owner, rest.trim_start().to_string()))
}

/// Split the first whitespace-delimited token from the rest.
fn split_first(s: &str) -> (Option<String>, String) {
    let s = s.trim_start();
    match s.split_once(char::is_whitespace) {
        Some((first, rest)) => (Some(first.to_string()), rest.trim_start().to_string()),
        None => {
            if s.is_empty() {
                (None, String::new())
            } else {
                (Some(s.to_string()), String::new())
            }
        }
    }
}

/// Combine physical lines, honoring parentheses and stripping comments.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;

    for raw in text.lines() {
        let mut line = raw;
        // Strip comments (naive but adequate for zone files; `;` inside quoted
        // TXT strings is rare and can be escaped).
        let mut in_quotes = false;
        let mut filtered = String::new();
        for ch in line.chars() {
            if ch == '"' {
                in_quotes = !in_quotes;
                filtered.push(ch);
            } else if ch == ';' && !in_quotes {
                break;
            } else {
                filtered.push(ch);
            }
        }
        line = filtered.as_str();

        for ch in line.chars() {
            if ch == '(' {
                depth += 1;
                current.push(' ');
            } else if ch == ')' {
                depth = depth.saturating_sub(1);
                current.push(' ');
            } else {
                current.push(ch);
            }
        }

        if depth == 0 {
            // Preserve leading whitespace (it marks continuation lines) but
            // drop trailing whitespace.
            let trimmed = current.trim_end();
            if !trimmed.is_empty() {
                out.push(trimmed.to_string());
            }
            current.clear();
        }
    }
    let remaining = current.trim_end();
    if !remaining.is_empty() {
        out.push(remaining.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_zone() {
        let text = r#"
$ORIGIN example.com.
$TTL 3600
@    IN SOA ns1.example.com. admin.example.com. 1 3600 600 86400 3600
     IN NS  ns1.example.com.
ns1  IN A   192.0.2.1
www  IN A   192.0.2.2
mail IN MX  10 mail.example.com.
txt  IN TXT "hello world"
"#;
        let records = parse_zone_file(text).unwrap();
        assert_eq!(records.len(), 6);

        let soa = records.iter().find(|r| r.rtype == "SOA").unwrap();
        assert_eq!(soa.name, "example.com");

        let ns = records.iter().find(|r| r.rtype == "NS").unwrap();
        assert_eq!(ns.name, "example.com"); // inherited owner

        let www = records.iter().find(|r| r.rtype == "A" && r.name == "www.example.com").unwrap();
        assert_eq!(www.content, "192.0.2.2");
        assert_eq!(www.ttl, 3600);

        let mx = records.iter().find(|r| r.rtype == "MX").unwrap();
        assert_eq!(mx.content, "10 mail.example.com.");
    }

    #[test]
    fn handles_multiline_rdata() {
        let text = r#"
$ORIGIN example.com.
example.com. IN TXT (
    "line one"
    "line two"
)
"#;
        let records = parse_zone_file(text).unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].content.contains("line one"));
    }

    #[test]
    fn comments_are_stripped() {
        let text = "$ORIGIN example.com.\nwww 60 IN A 192.0.2.9 ; a comment\n";
        let records = parse_zone_file(text).unwrap();
        assert_eq!(records[0].content, "192.0.2.9");
        assert_eq!(records[0].ttl, 60);
    }
}
