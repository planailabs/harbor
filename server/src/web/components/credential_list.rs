use dioxus::prelude::*;

use super::ui::{Card, OrgGroup, OrgTreeCard, PageHeader, Td, TdMuted, Th, TreeTd, group_by_org};

// CredentialRow + the list endpoint now live in the shared api_mcp layer.
use crate::api_mcp::endpoints::credentials::{CredentialListInput, list_credentials};

#[server]
async fn viewer_is_admin() -> Result<bool, ServerFnError> {
    Ok(crate::web::user::current_user().await?.is_admin)
}

/// Shown to non-admins, who never get plan.ai's global credentials listed.
/// The app's shared .ftl bundles live in the design submodule, so this one
/// line picks its language directly.
fn global_credentials_note() -> &'static str {
    if dioxus_i18n::prelude::i18n().language().language.as_str() == "de" {
        "Die gemeinsamen Zugangsdaten von plan.ai werden hier nicht aufgelistet; ein Admin kann sie bei Bedarf auswählen."
    } else {
        "plan.ai's shared credentials aren't listed here; an admin can select them for you."
    }
}

#[component]
pub fn CredentialList() -> Element {
    let credentials = use_server_future(move || list_credentials(CredentialListInput::default()))?;
    let is_admin = use_server_future(viewer_is_admin)?;
    let show_global_note = matches!(&*is_admin.read(), Some(Ok(false)));
    let rows = credentials.read();
    let rows = match &*rows {
        Some(Ok(r)) => r.as_slice(),
        _ => &[],
    };

    rsx! {
        PageHeader { "Credentials" }

        if show_global_note {
            p { class: "mt-2 text-sm text-fg-muted", {global_credentials_note()} }
        }

        div { class: "mt-4 flex justify-end mb-4",
            Link {
                to: crate::web::app::Route::CredentialForm {},
                class: "btn btn-primary",
                "Add Credential"
            }
        }

        if rows.is_empty() {
            Card { div { class: "card-pad text-fg-muted text-center", "No credentials yet" } }
        }
        for OrgGroup { id, name, rows } in group_by_org(rows, |r| (r.organization_id, r.organization_name.as_deref().unwrap_or("Global"))) {
            {
                let n = rows.len();
                rsx! {
                    OrgTreeCard { key: "{name}", id, name: name.clone(), meta: format!("{n} credentials"), cols: 3,
                        head: rsx! {
                            Th { "Name" }
                            Th { "Type" }
                            Th { "Created" }
                        },
                        for (i, row) in rows.into_iter().enumerate() {
                            tr { key: "{row.id}", class: "cursor-pointer hover:bg-surface-2",
                                onclick: {
                                    let id = row.id.to_string();
                                    move |_| { navigator().push(crate::web::app::Route::CredentialEdit { id: id.clone() }); }
                                },
                                TreeTd { last: i + 1 == n, "{row.name}" }
                                Td {
                                    span { class: "badge badge-info", "{row.credential_type}" }
                                }
                                TdMuted { "{row.created_at}" }
                            }
                        }
                    }
                }
            }
        }
    }
}
