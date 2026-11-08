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

/// Outer card for one organization: its own column header (`head`), then the
/// org row (round letter icon + name) with the tree hanging below it. Each
/// child row's first cell is a `TreeTd`.
#[component]
pub fn OrgTreeCard(
    name: String,
    #[props(default, into)] meta: String,
    cols: usize,
    head: Element,
    children: Element,
) -> Element {
    let letter = name
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_default();
    rsx! {
        Card { class: "mb-4",
            div { class: "overflow-x-auto",
                table { class: "table w-full",
                    thead { tr { {head} } }
                    tbody {
                        tr {
                            td { class: "td relative", colspan: "{cols}",
                                // Trunk from the icon down to the first child; `TreeTd` x = 2.5rem.
                                span { class: "absolute left-10 top-[calc(50%+1rem)] bottom-0 border-l border-line" }
                                div { class: "flex items-center gap-3",
                                    span { class: "w-8 h-8 shrink-0 rounded-full bg-brand text-fg-invert flex items-center justify-center font-semibold", "{letter}" }
                                    span { class: "font-semibold text-fg-strong", "{name}" }
                                    if !meta.is_empty() {
                                        span { class: "text-sm text-fg-muted", "{meta}" }
                                    }
                                }
                            }
                        }
                        {children}
                    }
                }
            }
        }
    }
}

/// First cell of a tree row. `guides[i]` = ancestor at level i has later
/// siblings (keep its line running); `last` = this node is its parent's last
/// child. Level 0 lines up with the org icon's centre (td px-6 + 1rem).
#[component]
pub fn TreeTd(#[props(default)] guides: Vec<bool>, last: bool, children: Element) -> Element {
    let x = |level: usize| 2.5 + level as f32 * 1.5;
    let depth = guides.len();
    let pad = x(depth) + 1.5;
    rsx! {
        td { class: "td relative whitespace-nowrap", style: "padding-left: {pad}rem",
            for (i, _) in guides.iter().enumerate().filter(|(_, g)| **g) {
                span { class: "absolute top-0 bottom-0 border-l border-line", style: "left: {x(i)}rem" }
            }
            span {
                class: if last { "absolute top-0 h-1/2 border-l border-line" } else { "absolute top-0 bottom-0 border-l border-line" },
                style: "left: {x(depth)}rem",
            }
            span { class: "absolute top-1/2 w-4 border-t border-line", style: "left: {x(depth)}rem" }
            {children}
        }
    }
}
