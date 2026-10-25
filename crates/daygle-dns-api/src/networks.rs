//! Named networks (Settings -> Networks): `LAN` = `192.168.1.0/24` and the
//! like, which network settings name instead of repeating the addresses.
//!
//! The networks are part of the configuration (`[[networks]]`, saved with
//! the other console settings), so the config check can tell a network name
//! from a typo. Renaming a network renames every reference to it; deleting
//! one that is still in use is refused, with the list of what uses it.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use daygle_dns_core::config::{DaygleConfig, NamedNetwork, RuntimeSettings};
use serde::Deserialize;

use crate::handlers::{error_response, map_err, rebuild_advanced_blocking, validate_config_update};
use crate::AppState;

/// Where the network `name` is used: config settings and stored ones.
fn users(state: &AppState, config: &DaygleConfig, name: &str) -> Vec<String> {
    let mut users = config.network_users(name);
    match state.catalog.store().network_users(name) {
        Ok(stored) => users.extend(stored),
        Err(e) => state.logs.warn(
            "api",
            format!("cannot list where network '{name}' is used: {e}"),
        ),
    }
    users
}

/// `GET /api/networks`: the built-in and configured networks, each with
/// what uses it.
pub async fn list_networks(State(state): State<AppState>) -> Response {
    let config = state.config.load_full();
    let builtin = daygle_dns_core::config::builtin_networks();
    let networks: Vec<serde_json::Value> = config
        .all_networks()
        .into_iter()
        .map(|n| {
            let is_builtin = builtin.iter().any(|b| b.name == n.name);
            serde_json::json!({
                "used_by": users(&state, &config, &n.name),
                "builtin": is_builtin,
                "name": n.name,
                "cidrs": n.cidrs,
                "description": n.description,
            })
        })
        .collect();
    Json(serde_json::json!({ "networks": networks })).into_response()
}

/// Body for `POST /api/networks`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkInput {
    /// The network being edited (absent for a new one); a different `name`
    /// renames it and every reference to it.
    #[serde(default)]
    pub original_name: Option<String>,
    pub name: String,
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub description: String,
}

/// `POST /api/networks`: add a network, or change (and rename) one.
pub async fn save_network(
    State(state): State<AppState>,
    Json(input): Json<NetworkInput>,
) -> Response {
    let old = state.config.load_full();
    let network = NamedNetwork {
        name: input.name.trim().to_string(),
        cidrs: input
            .cidrs
            .iter()
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty())
            .collect(),
        description: input.description.trim().to_string(),
    };
    let mut config = (*old).clone();
    let original = input.original_name.as_deref().map(str::trim);
    match original {
        Some(original) => {
            let Some(slot) = config
                .networks
                .iter_mut()
                .find(|n| n.name.eq_ignore_ascii_case(original))
            else {
                return error_response(
                    StatusCode::NOT_FOUND,
                    format!("no network named '{original}'"),
                );
            };
            *slot = network.clone();
        }
        None => {
            if config.find_network(&network.name).is_some() {
                return error_response(
                    StatusCode::CONFLICT,
                    format!("a network named '{}' already exists", network.name),
                );
            }
            config.networks.push(network.clone());
        }
    }
    let renamed = original.filter(|o| *o != network.name);
    if let Some(original) = renamed {
        config.rename_network_refs(original, &network.name);
    }
    if let Err(response) = validate_config_update(&state, &old, &config, "networks") {
        return response;
    }
    if let Some(original) = renamed {
        if let Err(e) = state
            .catalog
            .store()
            .rename_network_refs(original, &network.name)
        {
            return map_err(e);
        }
    }
    if let Err(e) = apply(&state, &old, config).await {
        return map_err(e);
    }
    Json(network).into_response()
}

/// `DELETE /api/networks/{name}`: remove a network nothing uses (`409`
/// with `used_by` otherwise).
pub async fn delete_network(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let old = state.config.load_full();
    let Some(index) = old
        .networks
        .iter()
        .position(|n| n.name.eq_ignore_ascii_case(name.trim()))
    else {
        return error_response(StatusCode::NOT_FOUND, format!("no network named '{name}'"));
    };
    let used_by = users(&state, &old, &old.networks[index].name);
    if !used_by.is_empty() {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": format!(
                    "network '{}' is still used by: {}",
                    old.networks[index].name,
                    used_by.join(", ")
                ),
                "used_by": used_by,
            })),
        )
            .into_response();
    }
    let mut config = (*old).clone();
    config.networks.remove(index);
    if let Err(e) = apply(&state, &old, config).await {
        return map_err(e);
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Save a config whose networks changed (`old` is the config it replaces) and
/// apply it to everything that names networks: split horizon, the policy
/// engine, the recursive resolver, the zone-transfer and update gates, the
/// Advanced Blocking groups and the PROXY-protocol listeners.
pub(crate) async fn apply(
    state: &AppState,
    old: &DaygleConfig,
    config: DaygleConfig,
) -> daygle_dns_core::error::Result<()> {
    state
        .catalog
        .store()
        .put_runtime_settings(&RuntimeSettings::capture(&config))?;
    let networks = config.all_networks();
    state.config.store(Arc::new(config));
    state.catalog.set_networks(networks)?;
    apply_resolved_changes(state, old, &state.config.load_full()).await;
    Ok(())
}

/// Rebuild what a network change alters. Every component is built from the
/// config with its names resolved to addresses, so this compares those
/// copies: only a setting whose addresses really changed is rebuilt.
async fn apply_resolved_changes(state: &AppState, old: &DaygleConfig, new: &DaygleConfig) {
    let old_r = old.with_networks_resolved();
    let new_r = new.with_networks_resolved();
    if old_r.policy != new_r.policy {
        match daygle_dns_policy::build_engine(&new_r.policy) {
            Ok(mut engine) => {
                // Keep the remote blocklist; the source refresher owns it.
                if let Some(remote) = state.policy.load_full().remote_blocklist_snapshot() {
                    engine.set_remote_blocklist(remote.as_ref().clone());
                }
                // Same for the DoT-scoped listener set.
                if let Some(dot) = state.policy.load_full().dot_blocklist_snapshot() {
                    engine.set_dot_blocklist(dot.as_ref().clone());
                }
                state.policy.store(Arc::new(engine));
            }
            Err(e) => state.logs.warn(
                "api",
                format!(
                    "policy rebuild after a network change failed, keeping the previous one: {e}"
                ),
            ),
        }
    }
    if old_r.recursive != new_r.recursive
        || old_r.authoritative.stub_zones != new_r.authoritative.stub_zones
    {
        if new_r.recursive.enabled {
            match crate::handlers::build_resolver(state, &new_r).await {
                Ok(resolver) => state.resolver.store(Some(Arc::new(resolver))),
                Err(e) => state.logs.warn(
                    "api",
                    format!("recursive resolver rebuild after a network change failed, keeping the previous one: {e}"),
                ),
            }
        } else {
            state.resolver.store(None);
        }
    }
    let (old_gates, new_gates) = (&old_r.authoritative, &new_r.authoritative);
    if old_gates.axfr_enabled != new_gates.axfr_enabled
        || old_gates.axfr_networks != new_gates.axfr_networks
        || old_gates.allow_dynamic_updates != new_gates.allow_dynamic_updates
        || old_gates.update_networks != new_gates.update_networks
    {
        state.catalog.update_gate_settings(
            new_gates.axfr_enabled,
            new_gates.axfr_networks.clone(),
            new_gates.allow_dynamic_updates,
            new_gates.update_networks.clone(),
        );
    }
    // Advanced Blocking groups can name networks too.
    rebuild_advanced_blocking(state);
    if old_r.server != new_r.server {
        if let Some(rebuild) = &state.request_dns_rebuild {
            rebuild();
        }
    }
}
