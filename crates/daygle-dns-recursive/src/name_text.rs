//! Turning a name in its text form back into a [`Name`].
//!
//! The dispatcher hands the resolver each query name as text: the wire name
//! in its ASCII presentation form ([`Name::to_ascii`]), with any byte that is
//! not a plain letter, digit or hyphen-in-the-middle escaped (`\-`, `\000`).
//! [`Name::from_utf8`] applies IDNA's rules to that text, and rejects labels
//! that are perfectly legal on the wire: one starting with a hyphen
//! (`-keyid-...-v2.microsoftaik.azure.net`, asked by Windows TPM
//! attestation) or holding a zero byte (the `...dnsotls-ds.metric.gstatic.com`
//! probes Android sends). Those queries were answered SERVFAIL at once,
//! without ever being resolved.

use hickory_proto::rr::Name;
use hickory_proto::ProtoError;

/// Parse a query name from its text form.
///
/// Tries [`Name::from_utf8`] first, so every name that parsed before (a
/// Unicode name typed in the console included) parses exactly as before.
/// When that fails and the text is ASCII, it is read as a presentation-form
/// name instead: labels split on unescaped dots, `\X` and `\DDD` escapes
/// decoded to their bytes, and the labels taken as they are on the wire.
pub(crate) fn parse_name(text: &str) -> Result<Name, ProtoError> {
    let error = match Name::from_utf8(text) {
        Ok(name) => return Ok(name),
        Err(e) => e,
    };
    if !text.is_ascii() {
        return Err(error);
    }
    presentation_labels(text)
        .and_then(|(labels, fqdn)| {
            let mut name = Name::from_labels(labels).ok()?;
            name.set_fqdn(fqdn);
            Some(name)
        })
        .ok_or(error)
}

/// The labels of a presentation-form name and whether it ends in a dot, or
/// `None` for a malformed escape or an empty label.
fn presentation_labels(text: &str) -> Option<(Vec<Vec<u8>>, bool)> {
    if text == "." {
        return Some((Vec::new(), true));
    }
    let bytes = text.as_bytes();
    let mut labels = Vec::new();
    let mut label = Vec::new();
    let mut fqdn = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                let digits = bytes.get(i + 1..i + 4);
                match digits {
                    Some(d) if d.iter().all(u8::is_ascii_digit) => {
                        let value = d.iter().fold(0u16, |v, &b| v * 10 + u16::from(b - b'0'));
                        label.push(u8::try_from(value).ok()?);
                        i += 4;
                    }
                    _ => {
                        label.push(*bytes.get(i + 1)?);
                        i += 2;
                    }
                }
                continue;
            }
            b'.' => {
                if label.is_empty() {
                    return None;
                }
                labels.push(std::mem::take(&mut label));
                fqdn = i + 1 == bytes.len();
            }
            b => label.push(b),
        }
        i += 1;
    }
    if !label.is_empty() {
        labels.push(label);
        fqdn = false;
    }
    (!labels.is_empty()).then_some((labels, fqdn))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(labels: &[&[u8]]) -> Name {
        let mut name = Name::from_labels(labels.iter().copied()).unwrap();
        name.set_fqdn(true);
        name
    }

    #[test]
    fn ordinary_names_parse_as_before() {
        for text in ["example.com", "example.com.", "xn--bcher-kva.example.", "."] {
            assert_eq!(parse_name(text).unwrap(), Name::from_utf8(text).unwrap());
        }
        assert_eq!(
            parse_name("bücher.example.").unwrap(),
            Name::from_utf8("bücher.example.").unwrap()
        );
    }

    #[test]
    fn a_label_starting_with_a_hyphen_round_trips() {
        let name = wire(&[b"-keyid-45ce-v2", b"microsoftaik", b"azure", b"net"]);
        let text = name.to_ascii();
        assert!(Name::from_utf8(&text).is_err());
        assert_eq!(parse_name(&text).unwrap(), name);
        // As the dispatcher passes it: no trailing dot.
        let parsed = parse_name(text.trim_end_matches('.')).unwrap();
        assert_eq!(parsed.to_ascii(), text.trim_end_matches('.'));
        assert!(!parsed.is_fqdn());
    }

    #[test]
    fn escaped_bytes_round_trip() {
        let name = wire(&[b"3o\x004az-dnsotls-ds", b"metric", b"gstatic", b"com"]);
        let text = name.to_ascii();
        assert!(Name::from_utf8(&text).is_err());
        assert_eq!(parse_name(&text).unwrap(), name);
        // The cache key's form (`Display`) parses back too.
        assert_eq!(parse_name(&name.to_string()).unwrap(), name);
        let dotted = wire(&[b"a.b", b"example"]);
        assert_eq!(parse_name(&dotted.to_ascii()).unwrap(), dotted);
    }

    #[test]
    fn malformed_text_is_rejected_by_the_fallback() {
        for text in ["a..b", "bad\\", "bad\\999.example", "..", "", ".a"] {
            assert!(presentation_labels(text).is_none(), "{text:?}");
        }
        assert!(parse_name("a..b").is_err());
    }
}
