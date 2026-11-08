use dioxus::prelude::*;

use super::ui::{Card, OrgGroup, OrgTreeCard, PageHeader, Td, Th, TreeTd, group_by_org};

// BasicAuthListRow + the list endpoint now live in the shared api_mcp layer.
use crate::api_mcp::endpoints::basic_auth::{BasicAuthListInput, list_basic_auth_lists};

#[component]
pub fn BasicAuthList() -> Element {
    let lists = use_server_future(move || list_basic_auth_lists(BasicAuthListInput::default()))?;
    let rows = match &*lists.read() {
        Some(Ok(r)) => r.clone(),
        _ => vec![],
    };

    rsx! {
        PageHeader { "Basic Auth Lists" }

        div { class: "mt-4 flex justify-end mb-4",
            Link { to: crate::web::app::Route::BasicAuthForm {}, class: "btn btn-primary", "Create List" }
        }

        if rows.is_empty() {
            Card { div { class: "card-pad text-fg-muted text-center", "No basic auth lists" } }
        }
        for OrgGroup { id, name, rows } in group_by_org(&rows, |r| (Some(r.organization_id), r.organization_name.as_str())) {
            {
                let n = rows.len();
                rsx! {
                    OrgTreeCard { key: "{name}", id, name: name.clone(), meta: format!("{n} lists"), cols: 2,
                        head: rsx! {
                            Th { "Name" }
                            Th { "Credentials" }
                        },
                        for (i, row) in rows.into_iter().enumerate() {
                            tr { key: "{row.id}", class: "cursor-pointer hover:bg-surface-2",
                                onclick: {
                                    let id = row.id.to_string();
                                    move |_| {
                                        navigator().push(crate::web::app::Route::BasicAuthDetail { id: id.clone() });
                                    }
                                },
                                TreeTd { last: i + 1 == n, "{row.name}" }
                                Td { "{row.credential_count}" }
                            }
                        }
                    }
                }
            }
        }
    }
}
