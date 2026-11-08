#![allow(dead_code, unused_imports)]

use dioxus::prelude::*;

pub use plan_ai_design::{
    Alert, AlertVariant, Badge, BadgeVariant, Button, ButtonKind, ButtonSize, ButtonVariant, Card,
    DataTable, ErrorText, FormField, HelpText, Kicker, Mono, PageHeader, Pill, PillVariant,
    SectionHeading, SortState, SortableTh, StatBlock, SuccessText, TableToolbar, Td, TdMono,
    TdMuted, Th, TokenCreateForm, TokenCreateInput, TokenReveal, TokenRow, TokenTable,
};

/// One organization's rows. `id` is `None` for org-less (global) rows.
pub struct OrgGroup<'a, T> {
    pub id: Option<uuid::Uuid>,
    pub name: String,
    pub rows: Vec<&'a T>,
}

/// Groups rows by organization, orgs sorted by name (global rows, `None`,
/// last), row order within an org preserved.
pub fn group_by_org<'a, T>(
    rows: impl IntoIterator<Item = &'a T>,
    org: impl Fn(&T) -> (Option<uuid::Uuid>, &str),
) -> Vec<OrgGroup<'a, T>> {
    let mut groups: std::collections::BTreeMap<(bool, String, Option<uuid::Uuid>), Vec<&'a T>> =
        Default::default();
    for r in rows {
        let (id, name) = org(r);
        groups
            .entry((id.is_none(), name.to_string(), id))
            .or_default()
            .push(r);
    }
    groups
        .into_iter()
        .map(|((_, name, id), rows)| OrgGroup { id, name, rows })
        .collect()
}

/// Round letter icon for an organization. The colour is derived from the org
/// id, so it is stable across pages and reloads; `None` (global) is neutral.
#[component]
pub fn OrgIcon(id: Option<uuid::Uuid>, name: String) -> Element {
    let letter = name
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_default();
    let base = "w-8 h-8 shrink-0 rounded-full flex items-center justify-center font-semibold";
    match id {
        Some(id) => {
            let b = id.as_bytes();
            let hue = u16::from_be_bytes([b[0], b[1]]) % 360;
            rsx! {
                span { class: "{base} text-white", style: "background-color: hsl({hue} 60% 42%)", "{letter}" }
            }
        }
        None => rsx! { span { class: "{base} bg-surface-3 text-fg-muted", "{letter}" } },
    }
}

/// Open/collapsed state of one `OrgTreeCard`, read by its `TreeTh` toggle.
#[derive(Clone, Copy)]
struct OrgTreeOpen(Signal<bool>);

/// Outer card for one organization: its own column header (`head`), then the
/// org row (round letter icon + name) with the tree hanging below it. Each
/// child row's first cell is a `TreeTd`.
#[component]
pub fn OrgTreeCard(
    id: Option<uuid::Uuid>,
    name: String,
    #[props(default, into)] meta: String,
    cols: usize,
    head: Element,
    children: Element,
) -> Element {
    let open = use_context_provider(|| OrgTreeOpen(Signal::new(true))).0;
    rsx! {
        Card { class: "mb-4",
            div { class: "overflow-x-auto",
                table { class: "table w-full",
                    thead { tr { {head} } }
                    tbody {
                        tr {
                            td { class: "td relative", colspan: "{cols}",
                                // Trunk from the icon down to the first child; `TreeTd` x = 2.5rem.
                                if open() {
                                    span { class: "absolute left-10 top-[calc(50%+1rem)] bottom-0 border-l border-line" }
                                }
                                div { class: "flex items-center gap-3",
                                    OrgIcon { id, name: name.clone() }
                                    span { class: "font-semibold text-fg-strong", "{name}" }
                                    if !meta.is_empty() {
                                        span { class: "text-sm text-fg-muted", "{meta}" }
                                    }
                                }
                            }
                        }
                        if open() {
                            {children}
                        }
                    }
                }
            }
        }
    }
}

/// rem offset of the level-0 tree line (td px-6 + half the 2rem org icon),
/// and how far a node's content sits right of its line.
const TREE_X0: f32 = 2.5;
const TREE_INDENT: f32 = 1.5;

/// Header for the tree column, aligned with level-0 node labels. `checkbox`
/// reserves the width of the row checkboxes that precede those labels.
#[component]
pub fn TreeTh(#[props(default)] checkbox: bool, children: Element) -> Element {
    let pad = TREE_X0 + TREE_INDENT;
    let toggle = try_use_context::<OrgTreeOpen>().map(|o| o.0);
    rsx! {
        th { class: "th relative", style: "padding-left: {pad}rem",
            // Collapse/expand the org tree, centred in the padding left of the label.
            if let Some(mut open) = toggle {
                button {
                    r#type: "button",
                    class: "absolute top-1/2 -translate-x-1/2 -translate-y-1/2 w-9 h-9 text-2xl leading-none flex items-center justify-center rounded text-fg-muted hover:text-fg-strong hover:bg-surface-3",
                    style: "left: {pad / 2.0}rem",
                    aria_expanded: "{open()}",
                    aria_label: if open() { "Collapse" } else { "Expand" },
                    title: if open() { "Collapse" } else { "Expand" },
                    onclick: move |_| open.toggle(),
                    if open() { "▾" } else { "▸" }
                }
            }
            if checkbox {
                input { r#type: "checkbox", class: "mr-2 invisible", tabindex: "-1", aria_hidden: "true" }
            }
            {children}
        }
    }
}

/// First cell of a tree row. `guides[i]` = ancestor at level i has later
/// siblings (keep its line running); `last` = this node is its parent's last
/// child. Level 0 lines up with the org icon's centre (td px-6 + 1rem).
#[component]
pub fn TreeTd(#[props(default)] guides: Vec<bool>, last: bool, children: Element) -> Element {
    let x = |level: usize| TREE_X0 + level as f32 * 1.5;
    let depth = guides.len();
    let pad = x(depth) + TREE_INDENT;
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
