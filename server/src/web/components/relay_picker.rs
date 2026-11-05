//! Relay URL picker: mac-mgmt credential → instance → service selects that
//! fill a relay URL field. Shared by the folder creation form and the
//! webspace detail settings.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::ui::FormField;
use crate::api_mcp::endpoints::mac_mgmt::{
    MacMgmtRelayUrlRow, MacMgmtRelayUrlsInput, list_mac_mgmt_relay_urls,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayCredOption {
    pub id: Uuid,
    pub name: String,
}

/// mac-mgmt credentials the current user may pick (all for admins; else
/// their orgs' plus a global one only if it is the `selected` current value).
/// Mirrors the folder-form loader.
#[server]
pub async fn load_mac_mgmt_creds(
    selected: Vec<Uuid>,
) -> Result<Vec<RelayCredOption>, ServerFnError> {
    let user = crate::web::user::current_user().await?;
    let pool = crate::server_pool()?;
    let rows = crate::api_mcp::endpoints::credentials::credential_options_for_user(
        &pool, &user, &["mac-mgmt"], &selected,
    )
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, _)| RelayCredOption { id, name })
        .collect())
}

/// Credential select + instance/service pickers + editable Relay URL input.
/// The pickers are best-effort: on lookup errors a warning is shown and the
/// URL stays manually editable.
#[component]
pub fn RelayUrlPicker(
    creds: Vec<RelayCredOption>,
    credential_id: Signal<String>,
    relay_url: Signal<String>,
) -> Element {
    let mut credential_id = credential_id;
    let mut relay_url = relay_url;
    let mut relay_instance = use_signal(String::new);
    let mut relay_service = use_signal(String::new);

    // Relay portal URLs visible to the selected credential's token — feeds the
    // instance/service pickers. Empty on error; manual entry always works.
    let relay_options = use_resource(move || {
        let cred = credential_id.read().clone();
        async move {
            if cred.is_empty() {
                return Ok(Vec::new());
            }
            let cred_id =
                Uuid::parse_str(&cred).map_err(|_| "invalid credential id".to_string())?;
            list_mac_mgmt_relay_urls(MacMgmtRelayUrlsInput {
                credential_id: cred_id,
            })
            .await
            .map_err(|e| e.to_string())
        }
    });

    rsx! {
        FormField { label: "mac-mgmt Credential",
            select {
                class: "input",
                value: "{credential_id}",
                oninput: move |evt| {
                    credential_id.set(evt.value());
                    relay_instance.set(String::new());
                    relay_service.set(String::new());
                },
                if creds.is_empty() {
                    option { value: "", "No mac-mgmt credentials — add one first" }
                }
                for c in &creds {
                    option { value: "{c.id}", "{c.name}" }
                }
            }
        }
        {
            let (rows, load_err) = match &*relay_options.read() {
                Some(Ok(rows)) => (rows.clone(), None),
                Some(Err(e)) => (Vec::new(), Some(e.clone())),
                None => (Vec::new(), None),
            };
            let mut instances: Vec<(String, String)> = Vec::new();
            for r in &rows {
                if !instances.iter().any(|(id, _)| id == &r.instance_id) {
                    let host = r.hostname.clone().unwrap_or_else(|| {
                        r.instance_id.chars().take(12).collect()
                    });
                    let proxy = r
                        .relay_proxy_url
                        .trim_start_matches("https://")
                        .trim_start_matches("http://")
                        .trim_end_matches('/');
                    instances.push((r.instance_id.clone(), format!("{host} — {proxy}")));
                }
            }
            let services: Vec<MacMgmtRelayUrlRow> = rows
                .iter()
                .filter(|r| r.instance_id == *relay_instance.read())
                .cloned()
                .collect();
            let rows_on_instance = rows.clone();
            let rows_on_service = rows;
            rsx! {
                if let Some(err) = load_err {
                    div { class: "text-amber-400 text-sm",
                        "Relay URL lookup failed (enter the URL manually): {err}"
                    }
                }
                if !instances.is_empty() {
                    FormField { label: "Instance",
                        help: "Machines reporting relay tunnels, listed via the credential's token.",
                        select {
                            class: "input",
                            value: "{relay_instance}",
                            oninput: move |evt| {
                                let iid = evt.value();
                                relay_instance.set(iid.clone());
                                match rows_on_instance.iter().find(|r| r.instance_id == iid) {
                                    Some(first) => {
                                        relay_service.set(first.tunnel.clone());
                                        relay_url.set(first.url.clone());
                                    }
                                    None => relay_service.set(String::new()),
                                }
                            },
                            option { value: "", "Manual entry" }
                            for (iid, label) in &instances {
                                option { value: "{iid}", "{label}" }
                            }
                        }
                    }
                }
                if !services.is_empty() {
                    FormField { label: "Service",
                        select {
                            class: "input",
                            value: "{relay_service}",
                            oninput: move |evt| {
                                let tunnel = evt.value();
                                relay_service.set(tunnel.clone());
                                let iid = relay_instance.read().clone();
                                if let Some(r) = rows_on_service
                                    .iter()
                                    .find(|r| r.instance_id == iid && r.tunnel == tunnel)
                                {
                                    relay_url.set(r.url.clone());
                                }
                            },
                            for s in &services {
                                option { value: "{s.tunnel}", "{s.tunnel}" }
                            }
                        }
                    }
                }
            }
        }
        FormField { label: "Relay URL",
            help: "Full URL from the relay (e.g. https://abc123-ollama.relay.plan.ai). Filled in by the pickers above; editable.",
            input {
                class: "input font-mono",
                r#type: "url",
                required: true,
                placeholder: "https://instance-tunnel.relay.example.com",
                value: "{relay_url}",
                oninput: move |evt| relay_url.set(evt.value()),
            }
        }
    }
}
