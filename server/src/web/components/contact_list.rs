use dioxus::prelude::*;

use super::ui::{
    Badge, BadgeVariant, Card, OrgGroup, OrgTreeCard, PageHeader, Td, Th, TreeTd, TreeTh,
    group_by_org,
};

// ContactRow + the list endpoint now live in the shared api_mcp layer.
use crate::api_mcp::endpoints::contacts::{ContactListInput, list_contacts};

#[component]
pub fn ContactList() -> Element {
    let contacts = use_server_future(move || list_contacts(ContactListInput::default()))?;
    let rows = contacts.read();
    let rows = match &*rows {
        Some(Ok(r)) => r.as_slice(),
        _ => &[],
    };

    rsx! {
        PageHeader { "Contacts" }

        div { class: "mt-4 flex justify-end mb-4",
            Link {
                to: crate::web::app::Route::ContactForm {},
                class: "btn btn-primary",
                "Add Contact"
            }
        }

        if rows.is_empty() {
            Card { div { class: "card-pad text-fg-muted text-center", "No contacts yet" } }
        }
        for OrgGroup { id, name, rows } in group_by_org(rows, |r| (Some(r.organization_id), r.organization_name.as_str())) {
            {
                let n = rows.len();
                rsx! {
                    OrgTreeCard { key: "{name}", id, name: name.clone(), meta: format!("{n} contacts"), cols: 5,
                        head: rsx! {
                            TreeTh { "Label" }
                            Th { "Name" }
                            Th { "Email" }
                            Th { "Country" }
                            Th { "Spaceship" }
                        },
                        for (i, row) in rows.into_iter().enumerate() {
                            tr { key: "{row.id}",
                                TreeTd { last: i + 1 == n, "{row.label}" }
                                Td { "{row.first_name} {row.last_name}" }
                                Td { "{row.email}" }
                                Td { "{row.country}" }
                                Td {
                                    if row.spaceship_synced {
                                        Badge { variant: BadgeVariant::Success, "Synced" }
                                    } else {
                                        span { class: "text-fg-muted", "Not synced" }
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
