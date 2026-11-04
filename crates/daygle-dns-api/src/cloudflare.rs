//! The Cloudflare API, for ACME DNS-01 challenges on domains whose DNS is
//! hosted at Cloudflare: the `_acme-challenge` TXT record is added there
//! through the API, and removed once the CA has looked.
//!
//! An API token with the **Zone → DNS → Edit** permission for the zone is
//! enough (Cloudflare's "Edit zone DNS" template): it can look the zone up
//! by name and add and delete its records.

use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

/// The Cloudflare API v4.
pub const API: &str = "https://api.cloudflare.com/client/v4";

const TIMEOUT: Duration = Duration::from_secs(30);

/// A TXT record added at Cloudflare, for removal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtRecord {
    pub zone_id: String,
    pub id: String,
    pub name: String,
}

pub struct Cloudflare {
    client: reqwest::Client,
    base: String,
    token: String,
}

/// Every Cloudflare API answer: `{success, errors, result}`.
#[derive(Deserialize)]
struct Envelope<T> {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    result: Option<T>,
}

#[derive(Deserialize)]
struct ApiError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct Zone {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct Record {
    id: String,
}

impl Cloudflare {
    /// A client for the Cloudflare API using `token`.
    pub fn new(token: &str) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .user_agent(concat!("daygle-dns/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| e.to_string())?;
        Self::with_client(client, API, token)
    }

    /// A client for the API at `base` (tests point it at a stand-in).
    pub fn with_client(client: reqwest::Client, base: &str, token: &str) -> Result<Self, String> {
        let token = token.trim();
        if token.is_empty() {
            return Err("no Cloudflare API token is set (Let's Encrypt Settings)".into());
        }
        Ok(Self {
            client,
            base: base.trim_end_matches('/').to_string(),
            token: token.to_string(),
        })
    }

    /// Send a request and unwrap Cloudflare's envelope.
    async fn send<T: serde::de::DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        what: &str,
    ) -> Result<T, String> {
        let response = request
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| format!("cannot reach the Cloudflare API to {what}: {e}"))?;
        let status = response.status();
        let body: Envelope<T> = response.json().await.map_err(|e| {
            format!("the Cloudflare API answered {status} to {what}, unreadably: {e}")
        })?;
        if !body.success || !status.is_success() {
            let errors: Vec<String> = body
                .errors
                .iter()
                .map(|e| format!("{} (code {})", e.message, e.code))
                .collect();
            let why = if errors.is_empty() {
                status.to_string()
            } else {
                errors.join("; ")
            };
            return Err(format!("Cloudflare would not {what}: {why}"));
        }
        body.result
            .ok_or_else(|| format!("the Cloudflare API sent no result to {what}"))
    }

    /// The Cloudflare zone holding `name`: the longest of its suffixes the
    /// token can see a zone for. Returns `(zone id, zone name)`.
    pub async fn zone_for(&self, name: &str) -> Result<(String, String), String> {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        let labels: Vec<&str> = name.split('.').collect();
        // Every suffix of two labels or more, longest first.
        for start in 0..labels.len().saturating_sub(1) {
            let candidate = labels[start..].join(".");
            let zones: Vec<Zone> = self
                .send(
                    self.client
                        .get(format!("{}/zones", self.base))
                        .query(&[("name", candidate.as_str())]),
                    &format!("look up the zone {candidate}"),
                )
                .await?;
            if let Some(zone) = zones
                .into_iter()
                .find(|z| z.name.eq_ignore_ascii_case(&candidate))
            {
                return Ok((zone.id, zone.name.to_ascii_lowercase()));
            }
        }
        Err(format!(
            "no Cloudflare zone this API token can edit holds {name}: give the token Zone → DNS → Edit for the domain's zone"
        ))
    }

    /// Add the TXT record `name` = `value`.
    pub async fn add_txt(&self, name: &str, value: &str) -> Result<TxtRecord, String> {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        let (zone_id, _) = self.zone_for(&name).await?;
        let record: Record = self
            .send(
                self.client
                    .post(format!("{}/zones/{zone_id}/dns_records", self.base))
                    .json(&json!({
                        "type": "TXT",
                        "name": name,
                        "content": format!("\"{value}\""),
                        "ttl": 60,
                        "comment": "ACME challenge, added and removed by daygle-dns",
                    })),
                &format!("add the TXT record {name}"),
            )
            .await?;
        Ok(TxtRecord {
            zone_id,
            id: record.id,
            name,
        })
    }

    /// Delete a TXT record added by [`Self::add_txt`].
    pub async fn delete(&self, record: &TxtRecord) -> Result<(), String> {
        self.send::<serde_json::Value>(
            self.client.delete(format!(
                "{}/zones/{}/dns_records/{}",
                self.base, record.zone_id, record.id
            )),
            &format!("remove the TXT record {}", record.name),
        )
        .await
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::{delete, get, post};
    use axum::{Json, Router};
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// A stand-in for the Cloudflare API holding the zone `example.com`.
    #[derive(Default)]
    struct Fake {
        records: Mutex<HashMap<String, serde_json::Value>>,
        zone_queries: Mutex<Vec<String>>,
    }

    const TOKEN: &str = "test-token";

    fn authorized(headers: &HeaderMap) -> bool {
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == format!("Bearer {TOKEN}"))
    }

    fn denied() -> (StatusCode, Json<serde_json::Value>) {
        (
            StatusCode::FORBIDDEN,
            Json(
                json!({"success": false, "errors": [{"code": 10000, "message": "Authentication error"}], "result": null}),
            ),
        )
    }

    async fn serve() -> (String, Arc<Fake>) {
        let fake = Arc::new(Fake::default());
        let app = Router::new()
            .route(
                "/zones",
                get(
                    |State(f): State<Arc<Fake>>,
                     headers: HeaderMap,
                     Query(q): Query<HashMap<String, String>>| async move {
                        if !authorized(&headers) {
                            return denied();
                        }
                        let name = q.get("name").cloned().unwrap_or_default();
                        f.zone_queries.lock().push(name.clone());
                        let result = if name == "example.com" {
                            json!([{"id": "zone1", "name": "example.com"}])
                        } else {
                            json!([])
                        };
                        (StatusCode::OK, Json(json!({"success": true, "errors": [], "result": result})))
                    },
                ),
            )
            .route(
                "/zones/{zone}/dns_records",
                post(
                    |State(f): State<Arc<Fake>>,
                     headers: HeaderMap,
                     Path(zone): Path<String>,
                     Json(body): Json<serde_json::Value>| async move {
                        if !authorized(&headers) {
                            return denied();
                        }
                        assert_eq!(zone, "zone1");
                        let id = format!("rec{}", f.records.lock().len() + 1);
                        f.records.lock().insert(id.clone(), body);
                        (StatusCode::OK, Json(json!({"success": true, "errors": [], "result": {"id": id}})))
                    },
                ),
            )
            .route(
                "/zones/{zone}/dns_records/{id}",
                delete(
                    |State(f): State<Arc<Fake>>,
                     headers: HeaderMap,
                     Path((_zone, id)): Path<(String, String)>| async move {
                        if !authorized(&headers) {
                            return denied();
                        }
                        match f.records.lock().remove(&id) {
                            Some(_) => (StatusCode::OK, Json(json!({"success": true, "errors": [], "result": {"id": id}}))),
                            None => (
                                StatusCode::NOT_FOUND,
                                Json(json!({"success": false, "errors": [{"code": 81044, "message": "Record does not exist."}], "result": null})),
                            ),
                        }
                    },
                ),
            )
            .with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), fake)
    }

    fn client(base: &str, token: &str) -> Cloudflare {
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        Cloudflare::with_client(http, base, token).unwrap()
    }

    #[tokio::test]
    async fn adds_and_removes_a_challenge_record_in_the_closest_zone() {
        let (base, fake) = serve().await;
        let cf = client(&base, TOKEN);
        let record = cf
            .add_txt("_acme-challenge.dns.Example.com.", "abc123")
            .await
            .unwrap();
        assert_eq!(record.zone_id, "zone1");
        assert_eq!(record.name, "_acme-challenge.dns.example.com");
        // Longest suffix first, stopping at the first zone found.
        assert_eq!(
            *fake.zone_queries.lock(),
            [
                "_acme-challenge.dns.example.com",
                "dns.example.com",
                "example.com"
            ]
        );
        let stored = fake.records.lock().get(&record.id).cloned().unwrap();
        assert_eq!(stored["type"], "TXT");
        assert_eq!(stored["name"], "_acme-challenge.dns.example.com");
        assert_eq!(stored["content"], "\"abc123\"");

        cf.delete(&record).await.unwrap();
        assert!(fake.records.lock().is_empty());
        // Cloudflare's own error message comes through.
        let err = cf.delete(&record).await.unwrap_err();
        assert!(err.contains("Record does not exist"), "{err}");
    }

    #[tokio::test]
    async fn explains_a_missing_zone_or_a_bad_token() {
        let (base, _) = serve().await;
        let err = client(&base, TOKEN)
            .add_txt("_acme-challenge.other.org", "x")
            .await
            .unwrap_err();
        assert!(err.contains("no Cloudflare zone"), "{err}");

        let err = client(&base, "wrong")
            .add_txt("_acme-challenge.example.com", "x")
            .await
            .unwrap_err();
        assert!(err.contains("Authentication error"), "{err}");

        assert!(Cloudflare::with_client(reqwest::Client::new(), &base, " ").is_err());
    }
}
