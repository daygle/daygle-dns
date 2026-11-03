//! DNS accounts (Accounts page): devices recognised by the client ID in the
//! host name they reach DoT / DoQ at, or in the DoH URL path, wherever they
//! connect from. The account domain and whether accounts are required are
//! settings (`[accounts]`, `PUT /api/config`).
//!
//! | Method   | Path                          | Purpose |
//! |----------|-------------------------------|---------|
//! | `GET`    | `/api/accounts`               | settings, accounts and how to connect each |
//! | `POST`   | `/api/accounts`               | create (`client_id` empty: generated) |
//! | `PUT`    | `/api/accounts/{id}`          | rename, enable/disable, change the client ID |
//! | `POST`   | `/api/accounts/{id}/new-id`   | replace the client ID with a new random one |
//! | `DELETE` | `/api/accounts/{id}`          | delete (and drop it from filtering groups) |

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use daygle_dns_authoritative::accounts::{DnsAccount, DnsAccountInput};
use daygle_dns_authoritative::ZoneStore;
use daygle_dns_policy::identity::AccountDirectory;
use serde::Serialize;

use crate::handlers::{error_response, map_err};
use crate::AppState;

/// Load the enabled accounts into `directory` (at start-up and after every
/// change).
pub fn load(store: &ZoneStore, directory: &AccountDirectory) {
    match store.list_dns_accounts() {
        Ok(accounts) => directory.set_accounts(
            accounts
                .iter()
                .map(|a| (a.client_id.as_str(), a.name.as_str(), a.enabled)),
        ),
        Err(e) => tracing::warn!("cannot load DNS accounts: {e}"),
    }
}

/// After an account changes: recognise the new list, and rebuild the
/// filtering groups (a rename or delete rewrote their entries).
fn reload(state: &AppState) {
    load(state.catalog.store(), &state.accounts);
    crate::handlers::rebuild_advanced_blocking(state);
}

/// An account with how a device connects as it.
#[derive(Serialize)]
struct AccountView {
    #[serde(flatten)]
    account: DnsAccount,
    /// The DoT / DoQ host name (`<client id>.<domain>`); empty while no
    /// account domain is set.
    hostname: String,
    /// The DoH URL path (`<endpoint>/<client id>`).
    doh_path: String,
}

fn view(state: &AppState, account: DnsAccount) -> AccountView {
    let config = state.config.load();
    let domain = config.accounts.normalized_domain();
    let hostname = if domain.is_empty() {
        String::new()
    } else {
        format!("{}.{domain}", account.client_id)
    };
    let endpoint = config.doh.endpoint.trim_end_matches('/');
    let doh_path = format!("{endpoint}/{}", account.client_id);
    AccountView {
        account,
        hostname,
        doh_path,
    }
}

/// `GET /api/accounts`
pub async fn list(State(state): State<AppState>) -> Response {
    let accounts = match state.catalog.store().list_dns_accounts() {
        Ok(accounts) => accounts,
        Err(e) => return map_err(e),
    };
    let settings = state.config.load().accounts.clone();
    let views: Vec<AccountView> = accounts.into_iter().map(|a| view(&state, a)).collect();
    Json(serde_json::json!({
        "settings": settings,
        "accounts": views,
    }))
    .into_response()
}

/// `POST /api/accounts`
pub async fn create(State(state): State<AppState>, Json(input): Json<DnsAccountInput>) -> Response {
    match state.catalog.store().create_dns_account(&input) {
        Ok(account) => {
            reload(&state);
            state.logs.info(
                "accounts",
                format!("DNS account '{}' created", account.name),
            );
            (StatusCode::CREATED, Json(view(&state, account))).into_response()
        }
        Err(e) => map_err(e),
    }
}

/// `PUT /api/accounts/{id}`
pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<DnsAccountInput>,
) -> Response {
    match state.catalog.store().update_dns_account(&id, &input) {
        Ok(account) => {
            reload(&state);
            state.logs.info(
                "accounts",
                format!("DNS account '{}' changed", account.name),
            );
            Json(view(&state, account)).into_response()
        }
        Err(e) => map_err(e),
    }
}

/// `POST /api/accounts/{id}/new-id` - a new random client ID (the old one
/// stops working, e.g. after it leaked).
pub async fn new_client_id(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let store = state.catalog.store();
    let current = match store.get_dns_account(&id) {
        Ok(Some(account)) => account,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "no such account"),
        Err(e) => return map_err(e),
    };
    let input = DnsAccountInput {
        name: current.name,
        client_id: daygle_dns_authoritative::accounts::generate_client_id(),
        enabled: current.enabled,
    };
    match store.update_dns_account(&id, &input) {
        Ok(account) => {
            reload(&state);
            state.logs.info(
                "accounts",
                format!("DNS account '{}' given a new client ID", account.name),
            );
            Json(view(&state, account)).into_response()
        }
        Err(e) => map_err(e),
    }
}

/// `DELETE /api/accounts/{id}`
pub async fn delete(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match state.catalog.store().delete_dns_account(&id) {
        Ok(true) => {
            reload(&state);
            state
                .logs
                .info("accounts", "DNS account deleted".to_string());
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "no such account"),
        Err(e) => map_err(e),
    }
}
