//! RFC 2136 dynamic update (UPDATE) support.
//!
//! UPDATE messages for hosted primary zones are parsed here: the zone section
//! is validated, prerequisites are evaluated against the current zone data,
//! and the resulting additions/deletions are written through to SQLite in a
//! single transaction before the in-memory catalog is reloaded so the changes
//! go live immediately. A successful update bumps the zone serial unless the
//! update explicitly rewrites the SOA record.

use std::net::IpAddr;

use hickory_proto::op::{Edns, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use hickory_server::server::{Request, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::{MessageResponseBuilder, UpdateRequest};
use tracing::{debug, info, warn};

use crate::catalog::AuthorityCatalog;
use crate::model::{DeleteSpec, DynamicUpdate, Record as DbRecord, RecordInput, SoaUpdate, Zone};
use daygle_dns_core::error::DaygleError;

/// Handle an RFC 2136 UPDATE message against the authoritative catalog.
///
/// On success the zone data has been persisted to SQLite and the catalog
/// reloaded, so the next query sees the new records. The response uses the
/// all-zero format described in RFC 2136 §3.8 (no answer sections), which is
/// what update clients expect.
pub async fn handle_update<R: ResponseHandler>(
    catalog: &AuthorityCatalog,
    update: &Request,
    response_edns: Option<&Edns>,
    response_handle: R,
) -> ResponseInfo {
    handle_update_with_notify(catalog, update, response_edns, response_handle, None).await
}

/// Like [`handle_update`], but sends RFC 1996 NOTIFY to `notify` targets when
/// the update is applied successfully. Passing `None` keeps the update silent
/// (used by tests and deployments without configured secondaries).
pub async fn handle_update_with_notify<R: ResponseHandler>(
    catalog: &AuthorityCatalog,
    update: &Request,
    response_edns: Option<&Edns>,
    response_handle: R,
    notify: Option<&crate::notify::NotifySender>,
) -> ResponseInfo {
    let store = catalog.store();
    let settings = catalog.settings();

    // -- Zone section (RFC 2136 §2.3) ------------------------------------
    // Exactly one zone query, ZTYPE = SOA, ZCLASS = the zone's class (IN).
    let zone_query = match update.zone() {
        Ok(zone) => zone,
        Err(_) => {
            warn!("dynamic update rejected: zone section must contain exactly one record");
            return respond(update, response_edns, response_handle, ResponseCode::FormErr)
                .await;
        }
    };
    if zone_query.query_type() != RecordType::SOA {
        warn!("dynamic update rejected: zone type must be SOA");
        return respond(update, response_edns, response_handle, ResponseCode::FormErr).await;
    }
    if zone_query.query_class() != DNSClass::IN {
        return respond(update, response_edns, response_handle, ResponseCode::Refused).await;
    }
    let zone_name = lower_name(&zone_query.name().to_string());

    // -- Policy gate ------------------------------------------------------
    if !settings.allow_dynamic_updates
        || !update_client_allowed(&settings.update_networks, update.src().ip())
    {
        debug!(
            zone = %zone_name,
            client = %update.src(),
            "dynamic update refused by policy"
        );
        return respond(update, response_edns, response_handle, ResponseCode::Refused).await;
    }

    // -- TSIG gate (RFC 8945) ---------------------------------------------
    // When the zone requires a signed update, verify the request signature
    // before any zone state is read or modified.
    if let Some(required) = catalog.tsig_update_key(&zone_name) {
        match crate::tsig::verify_request(
            &crate::tsig::TsigKeyRing::from_configs(&settings.tsig_keys)
                .unwrap_or_default(),
            update.as_slice(),
            update.metadata.id,
        ) {
            crate::tsig::TsigVerifyOutcome::Valid { key, .. } if key.name == required.name => {
                debug!(zone = %zone_name, "dynamic update TSIG verified");
            }
            crate::tsig::TsigVerifyOutcome::Valid { .. } => {
                debug!(zone = %zone_name, "dynamic update signed with wrong TSIG key");
                return respond(update, response_edns, response_handle, ResponseCode::Refused).await;
            }
            crate::tsig::TsigVerifyOutcome::Invalid(failure) => {
                debug!(zone = %zone_name, ?failure, "dynamic update TSIG verification failed");
                return respond(update, response_edns, response_handle, ResponseCode::Refused).await;
            }
            crate::tsig::TsigVerifyOutcome::Unsigned => {
                debug!(zone = %zone_name, "dynamic update requires TSIG");
                return respond(update, response_edns, response_handle, ResponseCode::Refused).await;
            }
        }
    }

    // -- Zone must exist and be a primary zone ----------------------------
    let zone = match store.find_zone_by_name(&zone_name) {
        Ok(Some(zone)) => zone,
        Ok(None) => {
            debug!(zone = %zone_name, "dynamic update for unhosted zone");
            return respond(update, response_edns, response_handle, ResponseCode::NotAuth).await;
        }
        Err(e) => {
            warn!(zone = %zone_name, error = %e, "zone lookup failed for update");
            return respond(update, response_edns, response_handle, ResponseCode::ServFail).await;
        }
    };

    let secondary_ids = match store.list_secondary() {
        Ok(list) => list,
        Err(e) => {
            warn!(error = %e, "secondary-zone lookup failed for update");
            return respond(update, response_edns, response_handle, ResponseCode::ServFail).await;
        }
    };
    if secondary_ids.iter().any(|s| s.zone_id == zone.id) {
        debug!(zone = %zone.name, "dynamic update rejected for secondary zone");
        return respond(update, response_edns, response_handle, ResponseCode::Refused).await;
    }

    let records = match store.list_records(&zone.id) {
        Ok(records) => records,
        Err(e) => {
            warn!(zone = %zone.name, error = %e, "record lookup failed for update");
            return respond(update, response_edns, response_handle, ResponseCode::ServFail).await;
        }
    };

    // -- Prerequisites (RFC 2136 §2.4) ------------------------------------
    for prereq in update.prerequisites() {
        let name = lower_name(&prereq.name.to_string());
        if !name_in_zone(&name, &zone.name) {
            return respond(update, response_edns, response_handle, ResponseCode::NotZone).await;
        }
        if let Err(code) = check_prerequisite(&zone, &records, prereq, &name) {
            debug!(
                zone = %zone.name,
                prereq = %name,
                code = %code,
                "prerequisite failed"
            );
            return respond(update, response_edns, response_handle, code).await;
        }
    }

    // -- Build the update plan (RFC 2136 §2.5) ----------------------------
    let mut plan = DynamicUpdate::default();
    for record in update.updates() {
        let name = lower_name(&record.name.to_string());
        if !name_in_zone(&name, &zone.name) {
            return respond(update, response_edns, response_handle, ResponseCode::NotZone).await;
        }
        if let Err(code) = build_update(&zone, &name, record, &mut plan) {
            return respond(update, response_edns, response_handle, code).await;
        }
    }

    // RFC 2136 §3.4.2.4: the server must not delete the zone's last NS
    // record; refuse such updates rather than leaving a broken zone.
    if would_remove_last_apex_ns(&zone, &records, &plan) {
        debug!(zone = %zone.name, "update refused: would delete last apex NS");
        return respond(update, response_edns, response_handle, ResponseCode::Refused).await;
    }

    // -- Apply atomically, then reload the catalog -------------------------
    if let Err(e) = store.apply_dynamic_updates(&zone.id, &plan) {
        let code = match &e {
            DaygleError::InvalidRecord(_) => ResponseCode::Refused,
            _ => ResponseCode::ServFail,
        };
        warn!(zone = %zone.name, error = %e, "dynamic update apply failed");
        return respond(update, response_edns, response_handle, code).await;
    }
    if let Err(e) = catalog.reload() {
        warn!(zone = %zone.name, error = %e, "catalog reload after update failed");
        return respond(update, response_edns, response_handle, ResponseCode::ServFail).await;
    }

    info!(
        zone = %zone.name,
        adds = plan.adds.len(),
        deletes = plan.deletes.len(),
        soa = plan.soa.is_some(),
        "dynamic update applied"
    );
    if let Some(sender) = notify {
        // Fire-and-forget: NOTIFYs must not delay the update response (a
        // dead secondary can cost up to the NOTIFY timeout per target).
        let sender = sender.clone();
        let zone_name = zone.name.clone();
        tokio::spawn(async move {
            sender.notify_zone(&zone_name).await;
        });
    }
    respond(update, response_edns, response_handle, ResponseCode::NoError).await
}

/// Evaluate one prerequisite record against the current zone data.
///
/// The three forms are distinguished by the record's class and RDATA, per
/// RFC 2136 §2.4: class NONE = "does not exist", class ANY = "exists (value
/// independent)", class IN = "exists (value dependent)".
fn check_prerequisite(
    zone: &Zone,
    records: &[DbRecord],
    prereq: &Record,
    name: &str,
) -> std::result::Result<(), ResponseCode> {
    let rtype = prereq.record_type();
    match prereq.dns_class {
        DNSClass::NONE => {
            if rtype == RecordType::ANY {
                if name_has_records(zone, records, name) {
                    Err(ResponseCode::YXDomain)
                } else {
                    Ok(())
                }
            } else if rrset_exists(zone, records, name, rtype) {
                Err(ResponseCode::YXRRSet)
            } else {
                Ok(())
            }
        }
        DNSClass::ANY => {
            if rtype == RecordType::ANY {
                if name_has_records(zone, records, name) {
                    Ok(())
                } else {
                    Err(ResponseCode::NXDomain)
                }
            } else if rrset_exists(zone, records, name, rtype) {
                Ok(())
            } else {
                Err(ResponseCode::NXRRSet)
            }
        }
        DNSClass::IN => {
            if rtype == RecordType::ANY {
                if name_has_records(zone, records, name) {
                    Ok(())
                } else {
                    Err(ResponseCode::NXDomain)
                }
            } else if rdata_matches(zone, records, name, rtype, &prereq.data) {
                Ok(())
            } else {
                Err(ResponseCode::NXRRSet)
            }
        }
        _ => Err(ResponseCode::FormErr),
    }
}

/// Turn one update record into additions/deletions in `plan`.
///
/// Class IN with RDATA = add; class ANY with empty RDATA = delete RRset;
/// class ANY/type ANY = delete everything at the name; class NONE with RDATA
/// = delete the specific RR (RFC 2136 §2.5.4). An SOA update at the apex
/// rewrites the zone's SOA metadata instead of adding a stored record.
fn build_update(
    zone: &Zone,
    name: &str,
    record: &Record,
    plan: &mut DynamicUpdate,
) -> std::result::Result<(), ResponseCode> {
    let rtype = record.record_type();
    match record.dns_class {
        DNSClass::IN => {
            if rtype == RecordType::ANY || rtype == RecordType::ZERO {
                return Err(ResponseCode::FormErr);
            }
            if rtype == RecordType::SOA && name == zone.name {
                let soa = match &record.data {
                    RData::SOA(soa) => SoaUpdate {
                        primary_ns: soa.mname.to_string(),
                        admin_mailbox: soa.rname.to_string(),
                        serial: soa.serial,
                        refresh: soa.refresh as u32,
                        retry: soa.retry as u32,
                        expire: soa.expire as u32,
                        minimum: soa.minimum,
                    },
                    _ => return Err(ResponseCode::FormErr),
                };
                plan.soa = Some(soa);
            } else {
                plan.adds.push(RecordInput {
                    name: format!("{name}."),
                    rtype: rtype.to_string(),
                    content: rdata_to_content(rtype, &record.data),
                    ttl: record.ttl,
                    priority: 0,
                    disabled: false,
                });
            }
            Ok(())
        }
        DNSClass::ANY | DNSClass::NONE => {
            if rtype == RecordType::ANY {
                plan.deletes.push(DeleteSpec {
                    name: name.to_string(),
                    rtype: None,
                    content: None,
                });
            } else if matches!(&record.data, RData::Update0(_)) {
                plan.deletes.push(DeleteSpec {
                    name: name.to_string(),
                    rtype: Some(rtype.to_string()),
                    content: None,
                });
            } else {
                plan.deletes.push(DeleteSpec {
                    name: name.to_string(),
                    rtype: Some(rtype.to_string()),
                    content: Some(rdata_to_content(rtype, &record.data)),
                });
            }
            Ok(())
        }
        _ => Err(ResponseCode::Refused),
    }
}

/// True when applying `plan` would delete every NS record at the zone apex.
fn would_remove_last_apex_ns(
    zone: &Zone,
    records: &[DbRecord],
    plan: &DynamicUpdate,
) -> bool {
    let apex_ns: Vec<&DbRecord> = records
        .iter()
        .filter(|r| !r.disabled && r.name == zone.name && r.rtype == "NS")
        .collect();
    if apex_ns.is_empty() {
        return false;
    }
    let mut remaining = apex_ns.len();
    for del in &plan.deletes {
        if del.name != zone.name {
            continue;
        }
        match del.rtype.as_deref() {
            None => remaining = 0,
            Some("NS") => {
                if let Some(content) = &del.content {
                    if apex_ns.iter().any(|r| &r.content == content) {
                        // saturating: duplicate delete specs for the same NS
                        // must not underflow (which would wrap and bypass the
                        // last-NS guard in release builds).
                        remaining = remaining.saturating_sub(1);
                    }
                } else {
                    remaining = 0;
                }
            }
            _ => {}
        }
    }
    remaining == 0
}

fn name_has_records(zone: &Zone, records: &[DbRecord], name: &str) -> bool {
    if name == zone.name {
        // The apex always carries the synthesized SOA plus NS records.
        return true;
    }
    records.iter().any(|r| !r.disabled && r.name == name)
}

fn rrset_exists(zone: &Zone, records: &[DbRecord], name: &str, rtype: RecordType) -> bool {
    if name == zone.name && rtype == RecordType::SOA {
        return true; // synthesized from zone metadata
    }
    records
        .iter()
        .any(|r| !r.disabled && r.name == name && r.rtype == rtype.to_string())
}

fn rdata_matches(
    zone: &Zone,
    records: &[DbRecord],
    name: &str,
    rtype: RecordType,
    rdata: &RData,
) -> bool {
    let content = rdata_to_content(rtype, rdata);
    if name == zone.name && rtype == RecordType::SOA {
        return content == synthesized_soa_content(zone);
    }
    records.iter().any(|r| {
        !r.disabled && r.name == name && r.rtype == rtype.to_string() && r.content == content
    })
}

fn synthesized_soa_content(zone: &Zone) -> String {
    format!(
        "{} {} {} {} {} {} {}",
        zone.primary_ns,
        zone.admin_mailbox,
        zone.serial,
        zone.refresh,
        zone.retry,
        zone.expire,
        zone.minimum,
    )
}

/// Canonical content string for storage, matching the zone-file form that
/// `RData::try_from_str` accepts. TXT values must be quoted so whitespace is
/// preserved through the parse round-trip.
fn rdata_to_content(rtype: RecordType, rdata: &RData) -> String {
    if rtype == RecordType::TXT {
        let escaped = rdata.to_string().replace('\\', "\\\\").replace('"', "\\\"");
        return format!("\"{escaped}\"");
    }
    rdata.to_string()
}

fn name_in_zone(name: &str, zone_name: &str) -> bool {
    name == zone_name || name.ends_with(&format!(".{zone_name}"))
}

fn lower_name(s: &str) -> String {
    s.trim_end_matches('.').to_ascii_lowercase()
}

/// Enforce the `update_networks` allow-list (empty = allow everyone).
fn update_client_allowed(networks: &[String], client: IpAddr) -> bool {
    if networks.is_empty() {
        return true;
    }
    networks
        .iter()
        .any(|net| net.parse::<ipnet::IpNet>().map(|ip| ip.contains(&client)).unwrap_or(false))
}

/// Send an RFC 2136 update response with only a response code.
async fn respond<R: ResponseHandler>(
    update: &Request,
    response_edns: Option<&Edns>,
    mut response_handle: R,
    code: ResponseCode,
) -> ResponseInfo {
    let mut metadata = Metadata::new(update.metadata.id, MessageType::Response, OpCode::Update);
    metadata.response_code = code;
    let response =
        MessageResponseBuilder::new(&update.queries, response_edns).build_no_records(metadata);
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            warn!("failed to send dynamic update response: {e}");
            fallback_response()
        }
    }
}

/// A minimal `ResponseInfo` used when the transport failed entirely.
fn fallback_response() -> ResponseInfo {
    ResponseInfo::from(hickory_proto::op::Header {
        metadata: hickory_proto::op::Metadata::new(0, MessageType::Response, OpCode::Update),
        counts: hickory_proto::op::HeaderCounts::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_names_and_zone_membership() {
        assert_eq!(lower_name("Example.COM."), "example.com");
        assert!(name_in_zone("www.example.com", "example.com"));
        assert!(name_in_zone("example.com", "example.com"));
        assert!(!name_in_zone("notexample.com", "example.com"));
        assert!(!name_in_zone("a.b.otherexample.com", "example.com"));
    }

    #[test]
    fn txt_content_is_quoted() {
        // A single TXT character-string with a space, as parsed from the wire.
        let rdata = RData::try_from_str(RecordType::TXT, "\"hello world\"").unwrap();
        assert_eq!(rdata.to_string(), "hello world");
        let content = rdata_to_content(RecordType::TXT, &rdata);
        assert_eq!(content, "\"hello world\"");
        // The stored content round-trips through try_from_str unchanged.
        let round = RData::try_from_str(RecordType::TXT, &content).unwrap();
        assert_eq!(round.to_string(), "hello world");
    }

    #[test]
    fn apex_soa_is_always_present() {
        let zone = Zone {
            id: "z".to_string(),
            name: "example.com".to_string(),
            primary_ns: "ns1.example.com.".to_string(),
            admin_mailbox: "admin.example.com.".to_string(),
            serial: 7,
            refresh: 3600,
            retry: 600,
            expire: 86400,
            minimum: 300,
            created_at: String::new(),
        };
        assert!(rrset_exists(&zone, &[], "example.com", RecordType::SOA));
        assert!(!rrset_exists(&zone, &[], "www.example.com", RecordType::A));
        assert_eq!(
            synthesized_soa_content(&zone),
            "ns1.example.com. admin.example.com. 7 3600 600 86400 300"
        );
    }
}
