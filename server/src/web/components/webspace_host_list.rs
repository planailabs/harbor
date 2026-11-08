//! Webspace-host list page.
//!
//! Hosts own the hostname, domain bindings, the CNAME flow, and
//! ChangeDetection (their `webspace` children are path-mounted folders). The
//! mass operations that used to live on the flat webspace list — bulk
//! ChangeDetection assign/remove, and the "Missing CNAME" filter — therefore
//! live here, at the host level.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::ui::{
    Badge, BadgeVariant, Button, ButtonVariant, Card, FormField, OrgTreeCard, PageHeader, TreeItem,
    group_by_org,
};

// HostRow + the list/bulk-ChangeDetection endpoints now live in the shared
// api_mcp layer.
use crate::api_mcp::endpoints::webspace_hosts::{
    BulkOpResult, HostBulkClearChangedetectionInput, HostBulkSetChangedetectionInput,
    HostListInput, HostRow, bulk_assign_changedetection, bulk_remove_changedetection, list_hosts,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CdCredOption {
    id: Uuid,
    name: String,
}

#[server]
async fn list_cd_creds_for_bulk() -> Result<Vec<CdCredOption>, ServerFnError> {
    let user = crate::web::user::current_user().await?;
    let pool = crate::server_pool()?;
    let rows = crate::api_mcp::endpoints::credentials::credential_options_for_user(
        &pool,
        &user,
        &["changedetection"],
        &[],
    )
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, _)| CdCredOption { id, name })
        .collect())
}

#[component]
pub fn WebspaceHostList() -> Element {
    let hosts = use_server_future(move || list_hosts(HostListInput::default()))?;
    let cd_creds = use_server_future(list_cd_creds_for_bulk)?;

    let all_rows: Vec<HostRow> = match &*hosts.read() {
        Some(Ok(r)) => r.clone(),
        _ => vec![],
    };
    let cred_list: Vec<CdCredOption> = match &*cd_creds.read() {
        Some(Ok(c)) => c.clone(),
        _ => vec![],
    };

    let mut selected: Signal<Vec<Uuid>> = use_signal(Vec::new);
    let mut bulk_result = use_signal(|| None::<BulkOpResult>);
    let mut running = use_signal(|| false);
    let mut cd_cred_id = use_signal(|| {
        cred_list
            .first()
            .map(|c| c.id.to_string())
            .unwrap_or_default()
    });
    let mut filter = use_signal(|| "all".to_string());

    let filtered_rows: Vec<&HostRow> = match filter.read().as_str() {
        "cloudflare" => all_rows.iter().filter(|r| r.kind == "cloudflare").collect(),
        "proxy" => all_rows.iter().filter(|r| r.kind != "cloudflare").collect(),
        "missing_cname" => all_rows.iter().filter(|r| r.has_missing_cname).collect(),
        "no_cd" => all_rows.iter().filter(|r| !r.has_changedetection).collect(),
        "has_cd" => all_rows.iter().filter(|r| r.has_changedetection).collect(),
        _ => all_rows.iter().collect(),
    };

    let sel = selected.read();
    let sel_count = sel.len();
    let filtered_count = filtered_rows.len();

    let no_cd_selected: Vec<Uuid> = filtered_rows
        .iter()
        .filter(|r| sel.contains(&r.id) && !r.has_changedetection)
        .map(|r| r.id)
        .collect();
    let no_cd_count = no_cd_selected.len();

    let has_cd_selected: Vec<Uuid> = filtered_rows
        .iter()
        .filter(|r| sel.contains(&r.id) && r.has_changedetection)
        .map(|r| r.id)
        .collect();
    let has_cd_count = has_cd_selected.len();

    let filtered_ids: Vec<Uuid> = filtered_rows.iter().map(|r| r.id).collect();
    drop(sel);

    rsx! {
        PageHeader { "Webspace Hosts" }

        div { class: "mt-4 flex justify-end mb-4",
            Link {
                to: crate::web::app::Route::WebspaceHostForm {},
                class: "btn btn-primary",
                "Create Host"
            }
        }

        // Filter bar
        div { class: "mb-4 flex items-center gap-2 flex-wrap",
            span { class: "text-sm text-fg-muted", "Filter:" }
            {
                let filters: Vec<(&str, &str, usize)> = vec![
                    ("all", "All", all_rows.len()),
                    ("cloudflare", "Cloudflare", all_rows.iter().filter(|r| r.kind == "cloudflare").count()),
                    ("proxy", "Proxy", all_rows.iter().filter(|r| r.kind != "cloudflare").count()),
                    ("missing_cname", "Missing CNAME", all_rows.iter().filter(|r| r.has_missing_cname).count()),
                    ("no_cd", "No Change Detection", all_rows.iter().filter(|r| !r.has_changedetection).count()),
                    ("has_cd", "Has Change Detection", all_rows.iter().filter(|r| r.has_changedetection).count()),
                ];
                rsx! {
                    for (key, label, count) in filters {
                        Button {
                            variant: if *filter.read() == key { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                            onclick: {
                                let k = key.to_string();
                                move |_| { filter.set(k.clone()); selected.set(vec![]); }
                            },
                            "{label} ({count})"
                        }
                    }
                }
            }
        }

        // Bulk actions bar
        if sel_count > 0 {
            Card { class: "mb-4",
                div { class: "p-4 flex items-end gap-3 flex-wrap",
                    span { class: "text-sm font-medium", "{sel_count} selected" }

                    if no_cd_count > 0 && !cred_list.is_empty() {
                        FormField { label: "CD Credential",
                            select { class: "input w-48", value: "{cd_cred_id}", oninput: move |evt| cd_cred_id.set(evt.value()),
                                for c in &cred_list { option { value: "{c.id}", "{c.name}" } }
                            }
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            disabled: *running.read(),
                            onclick: {
                                let ids = no_cd_selected.clone();
                                move |_| {
                                    let ids = ids.clone();
                                    let cid_str = cd_cred_id.read().clone();
                                    running.set(true); bulk_result.set(None);
                                    spawn(async move {
                                        if let Ok(cid) = Uuid::parse_str(&cid_str) {
                                            match bulk_assign_changedetection(HostBulkSetChangedetectionInput {
                                                host_ids: ids,
                                                credential_id: cid,
                                            })
                                            .await
                                            {
                                                Ok(r) => bulk_result.set(Some(r)),
                                                Err(_) => bulk_result.set(Some(BulkOpResult { succeeded: 0, failed: 1 })),
                                            }
                                        }
                                        running.set(false);
                                    });
                                }
                            },
                            if *running.read() { "Assigning..." } else { "Assign CD ({no_cd_count})" }
                        }
                    }

                    if has_cd_count > 0 {
                        Button {
                            variant: ButtonVariant::Secondary,
                            disabled: *running.read(),
                            onclick: {
                                let ids = has_cd_selected.clone();
                                move |_| {
                                    let ids = ids.clone();
                                    running.set(true); bulk_result.set(None);
                                    spawn(async move {
                                        match bulk_remove_changedetection(HostBulkClearChangedetectionInput { host_ids: ids }).await {
                                            Ok(r) => bulk_result.set(Some(r)),
                                            Err(_) => bulk_result.set(Some(BulkOpResult { succeeded: 0, failed: 1 })),
                                        }
                                        running.set(false);
                                    });
                                }
                            },
                            if *running.read() { "Removing..." } else { "Remove CD ({has_cd_count})" }
                        }
                    }
                }
            }
        }

        // Bulk operation results
        if let Some(ref result) = *bulk_result.read() {
            Card { class: "mb-4",
                div { class: "p-4",
                    if result.succeeded > 0 {
                        div { class: "text-sm mb-2",
                            Badge { variant: BadgeVariant::Success, "{result.succeeded} updated" }
                        }
                    }
                    if result.failed > 0 {
                        div { class: "text-sm",
                            Badge { variant: BadgeVariant::Warn, "{result.failed} failed" }
                        }
                    }
                    div { class: "mt-2",
                        Button {
                            variant: ButtonVariant::Secondary,
                            onclick: move |_| {
                                bulk_result.set(None);
                                selected.set(vec![]);
                                navigator().replace(crate::web::app::Route::WebspaceHostList {});
                            },
                            "Dismiss & Reload"
                        }
                    }
                }
            }
        }

        if filtered_rows.is_empty() {
            Card { div { class: "card-pad text-fg-muted text-center", "No hosts yet" } }
        } else {
            label { class: "mb-2 flex items-center gap-2 text-sm text-fg-muted",
                input {
                    r#type: "checkbox",
                    checked: sel_count > 0 && sel_count == filtered_count,
                    oninput: {
                        let all = filtered_ids.clone();
                        move |evt| selected.set(if evt.checked() { all.clone() } else { vec![] })
                    }
                }
                "Select all"
            }
        }
        for (org, rows) in group_by_org(filtered_rows.iter().copied(), |r| &r.organization_name) {
            OrgTreeCard { key: "{org}", name: org.clone(), meta: format!("{} hosts", rows.len()),
                for row in rows {
                    {
                        let rid = row.id;
                        let is_selected = selected.read().contains(&rid);
                        rsx! {
                            TreeItem { key: "{rid}",
                                div { class: "flex items-center gap-2 flex-wrap min-h-6 cursor-pointer rounded hover:bg-surface-2",
                                    onclick: {
                                        let id = rid.to_string();
                                        move |_| { navigator().push(crate::web::app::Route::WebspaceHostDetail { id: id.clone() }); }
                                    },
                                    input {
                                        r#type: "checkbox",
                                        checked: is_selected,
                                        onclick: move |evt| { evt.stop_propagation(); },
                                        oninput: move |evt| {
                                            let mut sel = selected.write();
                                            if evt.checked() {
                                                if !sel.contains(&rid) { sel.push(rid); }
                                            } else {
                                                sel.retain(|&id| id != rid);
                                            }
                                        }
                                    }
                                    span { class: "font-medium", "{row.name}" }
                                    if row.kind == "cloudflare" {
                                        Badge { variant: BadgeVariant::Info, "Cloudflare" }
                                    } else {
                                        Badge { variant: BadgeVariant::Accent, "Proxy" }
                                    }
                                    if let Some(ref h) = row.hostname {
                                        span { class: "font-mono text-sm text-fg-muted", "{h}" }
                                    }
                                    span { class: "text-sm text-fg-muted", "· {row.folder_count} folders" }
                                    if row.has_changedetection {
                                        Badge { variant: BadgeVariant::Success, "CD" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
