#![allow(dead_code, unused_imports)]

use dioxus::prelude::*;

pub use plan_ai_design::{
    Alert, AlertVariant, Badge, BadgeVariant, Button, ButtonKind, ButtonSize, ButtonVariant, Card,
    DataTable, ErrorText, FormField, HelpText, Kicker, Mono, PageHeader, Pill, PillVariant,
    SectionHeading, SortState, SortableTh, StatBlock, SuccessText, TableToolbar, Td, TdMono,
    TdMuted, Th, TokenCreateForm, TokenCreateInput, TokenReveal, TokenRow, TokenTable,
};

/// Groups rows by organization name (unique in the DB), orgs sorted by name,
/// row order within an org preserved.
pub fn group_by_org<'a, T>(
    rows: impl IntoIterator<Item = &'a T>,
    org: impl Fn(&T) -> &str,
) -> Vec<(String, Vec<&'a T>)> {
    let mut groups: std::collections::BTreeMap<String, Vec<&'a T>> = Default::default();
    for r in rows {
        groups.entry(org(r).to_string()).or_default().push(r);
    }
    groups.into_iter().collect()
}

/// Outer card for one organization: round letter icon + name on top, its
/// children hang below as a tree (`TreeItem`s).
#[component]
pub fn OrgTreeCard(
    name: String,
    #[props(default, into)] meta: String,
    children: Element,
) -> Element {
    let letter = name
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_default();
    rsx! {
        Card { class: "mb-4",
            div { class: "card-pad",
                div { class: "flex items-center gap-3",
                    span { class: "w-8 h-8 shrink-0 rounded-full bg-brand text-fg-invert flex items-center justify-center font-semibold", "{letter}" }
                    span { class: "font-semibold text-fg-strong", "{name}" }
                    if !meta.is_empty() {
                        span { class: "text-sm text-fg-muted", "{meta}" }
                    }
                }
                TreeList { {children} }
            }
        }
    }
}

/// Vertical tree guide; nest inside a `TreeItem` for deeper levels. The 1rem
/// indent lines up with the centre of the 2rem letter icon.
#[component]
pub fn TreeList(children: Element) -> Element {
    rsx! { ul { class: "ml-4 border-l border-line", {children} } }
}

/// One tree node with a horizontal connector to its parent's guide line.
#[component]
pub fn TreeItem(#[props(default, into)] class: String, children: Element) -> Element {
    rsx! {
        li { class: "relative pl-6 pt-3 before:content-[''] before:absolute before:left-0 before:top-6 before:w-4 before:border-t before:border-line {class}",
            {children}
        }
    }
}
