//! Cross-host folder list as a tree: organization card → host → folders.
//! Domains, CNAME, and ChangeDetection are managed on the parent host.

use dioxus::prelude::*;

use super::ui::{
    Badge, BadgeVariant, Button, ButtonVariant, Card, OrgTreeCard, PageHeader, TreeItem, TreeList,
    group_by_org,
};

// WebspaceRow + the list endpoint now live in the shared api_mcp layer.
use crate::api_mcp::endpoints::webspaces::{WebspaceListInput, WebspaceRow, list_webspaces};

#[component]
pub fn WebspaceList() -> Element {
    let webspaces = use_server_future(move || list_webspaces(WebspaceListInput::default()))?;
    let all_rows: Vec<WebspaceRow> = match &*webspaces.read() {
        Some(Ok(r)) => r.clone(),
        _ => vec![],
    };

    let mut filter = use_signal(|| "all".to_string());
    let filtered_rows: Vec<&WebspaceRow> = match filter.read().as_str() {
        "pages" => all_rows
            .iter()
            .filter(|r| r.hosting_type == "cloudflare_pages")
            .collect(),
        "local" => all_rows
            .iter()
            .filter(|r| r.hosting_type == "local")
            .collect(),
        "relay" => all_rows
            .iter()
            .filter(|r| r.hosting_type == "relay")
            .collect(),
        "tunnel" => all_rows
            .iter()
            .filter(|r| r.hosting_type == "tunnel")
            .collect(),
        _ => all_rows.iter().collect(),
    };

    rsx! {
        PageHeader { "Webspaces (folders)" }

        div { class: "mt-4 flex justify-end gap-3 mb-4",
            Link { to: crate::web::app::Route::WebspaceImport {}, class: "btn btn-secondary", "Import from Credential" }
            Link { to: crate::web::app::Route::WebspaceHostList {}, class: "btn btn-primary", "Manage Hosts" }
        }

        div { class: "mb-4 flex items-center gap-2 flex-wrap",
            span { class: "text-sm text-fg-muted", "Filter:" }
            {
                let filters: Vec<(&str, &str, usize)> = vec![
                    ("all", "All", all_rows.len()),
                    ("pages", "Pages", all_rows.iter().filter(|r| r.hosting_type == "cloudflare_pages").count()),
                    ("local", "Local", all_rows.iter().filter(|r| r.hosting_type == "local").count()),
                    ("relay", "Relay", all_rows.iter().filter(|r| r.hosting_type == "relay").count()),
                    ("tunnel", "Tunnel", all_rows.iter().filter(|r| r.hosting_type == "tunnel").count()),
                ];
                rsx! {
                    for (key, label, count) in filters {
                        Button {
                            variant: if *filter.read() == key { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                            onclick: { let k = key.to_string(); move |_| filter.set(k.clone()) },
                            "{label} ({count})"
                        }
                    }
                }
            }
        }

        if filtered_rows.is_empty() {
            Card { div { class: "card-pad text-fg-muted text-center", "No folders yet" } }
        }
        for (org, rows) in group_by_org(filtered_rows.iter().copied(), |r| &r.organization_name) {
            {
                let hosts = rows.chunk_by(|a, b| a.host_id == b.host_id).map(<[_]>::to_vec).collect::<Vec<_>>();
                let meta = format!("{} folders", rows.len());
                rsx! {
                    OrgTreeCard { key: "{org}", name: org.clone(), meta,
                        for folders in hosts {
                            TreeItem { key: "{folders[0].host_id}",
                                div { class: "flex items-center gap-2 min-h-6",
                                    Link {
                                        to: crate::web::app::Route::WebspaceHostDetail { id: folders[0].host_id.to_string() },
                                        class: "text-brand underline font-medium",
                                        "{folders[0].host_name}"
                                    }
                                }
                                TreeList {
                                    for row in folders {
                                        TreeItem { key: "{row.id}",
                                            FolderNode { row: (*row).clone() }
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
}

#[component]
fn FolderNode(row: WebspaceRow) -> Element {
    let fid = row.id.to_string();
    rsx! {
        div { class: "flex items-center gap-2 flex-wrap min-h-6",
            span { class: "font-mono text-sm", "{row.path_prefix}" }
            Link { to: crate::web::app::Route::WebspaceDetail { id: fid }, class: "hover:underline", "{row.name}" }
            match row.hosting_type.as_str() {
                "cloudflare_pages" => rsx! { Badge { variant: BadgeVariant::Info, "CF Pages" } },
                "local" => rsx! { Badge { "Local" } },
                "relay" => rsx! { Badge { variant: BadgeVariant::Accent, "Relay" } },
                "tunnel" => rsx! { Badge { variant: BadgeVariant::Accent, "Tunnel" } },
                _ => rsx! {},
            }
            match (row.hosting_type.as_str(), row.local_status.as_deref()) {
                ("local", Some("running")) => rsx! { Badge { variant: BadgeVariant::Success, "Running" } },
                ("local", Some("error")) => rsx! { Badge { variant: BadgeVariant::Danger, "Error" } },
                ("local", Some("starting")) => rsx! { Badge { variant: BadgeVariant::Warn, "Starting" } },
                ("local", Some(_)) => rsx! { span { class: "text-sm text-fg-muted", "Stopped" } },
                _ => match row.runtime {
                    Some(ref rt) => rsx! { Badge { "{rt}" } },
                    None => rsx! {},
                },
            }
            match row.auth_mode.as_str() {
                "oidc" => rsx! { Badge { variant: BadgeVariant::Info, "OIDC" } },
                "basic" => rsx! { Badge { variant: BadgeVariant::Accent, "Basic" } },
                _ => rsx! {},
            }
        }
    }
}
