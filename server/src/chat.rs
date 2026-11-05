//! Interactive Harbor chatbot — Harbor's instantiation of the reusable
//! [`plan_ai_chat::service`] chat agent over the api-mcp registry (domains,
//! webspaces, credentials, action templates, ...), surfaced through the
//! plan-ai-chat-ui sidebar.

use std::sync::{Arc, OnceLock};

use anyhow::Result;
use async_trait::async_trait;
use plan_ai_chat::ConnectorConfig;
use plan_ai_chat::service::{
    ChatServiceConfig, ChatState, ChatUserCtx, SystemPromptBuilder, tool_index,
};
use plan_ai_chat_ui::backend::{BackendResult, ChatBackend};
use plan_ai_chat_ui::render::ModelEntry;
use plan_ai_chat_ui::sidebar::{ChatContext, ChatSessionMeta, ChatSessionSummary};

use crate::config::ChatConfig;
use crate::web::user::{current_user, principal_from};

static CHAT: OnceLock<ChatState> = OnceLock::new();

pub fn chat_state() -> Option<ChatState> {
    CHAT.get().cloned()
}

/// Initialize the chat service (idempotent) and register the sidebar
/// backend. No-op when `[chat]` is disabled.
pub async fn init(pool: sqlx::PgPool, cfg: &crate::config::ServerConfig) -> Result<()> {
    let Some(chat_cfg) = cfg.chat.as_ref().filter(|c| c.enabled) else {
        return Ok(());
    };
    if CHAT.get().is_some() {
        return Ok(());
    }

    let registry = crate::api_mcp::shared_registry(pool.clone());
    let connector = ConnectorConfig {
        ollama_url: chat_cfg.ollama_url.clone(),
        anthropic_api_key: chat_cfg.anthropic_api_key.clone(),
        openrouter_api_key: chat_cfg.openrouter_api_key.clone(),
        openai_sources: chat_cfg.openai.clone(),
        token_budget: chat_cfg.token_budget,
        ..ConnectorConfig::default()
    };
    let service_cfg = ChatServiceConfig {
        token_budget: chat_cfg.token_budget,
        risk_threshold: chat_cfg.risk_threshold.clone(),
        allow_approve_all: chat_cfg.allow_approve_all,
        max_active_sessions_per_user: chat_cfg.max_active_sessions_per_user,
        idle_park_minutes: chat_cfg.idle_park_minutes,
        tools_include: chat_cfg.tools_include.clone(),
        tools_exclude: chat_cfg.tools_exclude.clone(),
        validator_provider: chat_cfg.validator_provider.clone(),
        validator_model: chat_cfg.validator_model.clone(),
    };
    let state = ChatState::new(
        pool,
        registry,
        connector,
        service_cfg,
        Arc::new(HarborPromptBuilder),
    )
    .await?;
    let _ = CHAT.set(state);
    plan_ai_chat_ui::backend::set_chat_backend(Arc::new(HarborChatBackend));
    Ok(())
}

struct HarborPromptBuilder;

#[async_trait]
impl SystemPromptBuilder for HarborPromptBuilder {
    async fn build(&self, user: &ChatUserCtx, resumed: bool, state: &ChatState) -> String {
        let tool_index = tool_index(state.registry(), &user.principal);

        let access_line = if user.is_admin {
            "They are a GLOBAL ADMIN with full access.".to_string()
        } else {
            format!(
                "They are NOT a global admin; access is scoped to their organizations. \
                 Authorization is enforced server-side on every tool call — a call failing \
                 with 'access denied'/'forbidden' means {} lacks access; report it, do not retry.",
                user.email
            )
        };

        let resume_line = if resumed {
            "\nThis session was resumed. The conversation history above contains your previous work — continue from where you left off.\n"
        } else {
            ""
        };

        let threshold = &state.config().risk_threshold;

        format!(
            r#"You are the Harbor assistant: an operations agent for Harbor, a web agency platform (domains, DNS via Cloudflare, domain registration, webspaces and static hosting, credentials, contacts, billing, change detection, and action templates).

You are talking to {email}. {access_line}

## How to work
- Act through your tools; NEVER invent tool names or arguments. Tool names follow <resource>_<action>.
- Every tool call requires a `_reason` argument — one sentence on why you are calling it.
- Read before you write: fetch current state before changing anything.
- Tool calls at or above the "{threshold}" risk level pause and wait for the user to approve them in the chat UI. Explain WHAT you are about to change and WHY before making such calls, so the approval prompt makes sense.
- Track your progress with `set_phase`: planning (deciding what to do), executing (doing it), executed (current request done).
- Pin durable findings with the `pin` tool (slots: notes, plan, summary) so they stay visible in long conversations.
- Name the session early with `name_session` once you understand the topic.
- Answer in the user's language; be concise and concrete. Render lists/tables in markdown.
{resume_line}
## Available tool groups
{tool_index}
"#,
            email = user.email,
        )
    }
}

// ── Sidebar backend ─────────────────────────────────────────────────────

struct HarborChatBackend;

fn state() -> BackendResult<ChatState> {
    chat_state().ok_or_else(|| "chat is not enabled".to_string())
}

async fn chat_user() -> BackendResult<ChatUserCtx> {
    let user = current_user().await.map_err(|e| e.to_string())?;
    Ok(ChatUserCtx {
        email: user.email.clone(),
        is_admin: user.is_admin,
        principal: principal_from(&user),
    })
}

fn parse_id(id: &str) -> BackendResult<uuid::Uuid> {
    id.parse().map_err(|_| "invalid id".to_string())
}

#[async_trait]
impl ChatBackend for HarborChatBackend {
    async fn context(&self) -> BackendResult<ChatContext> {
        if current_user().await.is_err() {
            return Ok(ChatContext {
                enabled: false,
                models: Vec::new(),
            });
        }
        let cfg = crate::config::load();
        Ok(ChatContext {
            enabled: chat_state().is_some(),
            models: cfg
                .model_catalog()
                .models_for("chat")
                .into_iter()
                .map(|m| ModelEntry {
                    name: m.name.clone(),
                    model: m.model.clone(),
                    provider: m.provider.clone(),
                })
                .collect(),
        })
    }

    async fn list_sessions(&self) -> BackendResult<Vec<ChatSessionSummary>> {
        let user = chat_user().await?;
        let chat = state()?;
        let sessions = chat
            .list_sessions(&user.email)
            .await
            .map_err(|e| e.to_string())?;
        let mut out = Vec::with_capacity(sessions.len());
        for s in sessions {
            let tokens = chat.store().get_token_usage(s.id).await.unwrap_or(0);
            out.push(ChatSessionSummary {
                id: s.id.to_string(),
                label: s.label,
                state: s.state,
                model: s.model,
                updated_at: s.updated_at,
                tokens_used: tokens,
            });
        }
        Ok(out)
    }

    async fn start_session(
        &self,
        provider: Option<String>,
        model: Option<String>,
        message: String,
        page_context: Option<String>,
    ) -> BackendResult<String> {
        let user = chat_user().await?;
        let id = state()?
            .start_session(&user, provider, model, message, page_context)
            .await
            .map_err(|e| e.to_string())?;
        Ok(id.to_string())
    }

    async fn send_message(
        &self,
        session_id: String,
        message: String,
        page_context: Option<String>,
    ) -> BackendResult<()> {
        let user = chat_user().await?;
        state()?
            .send_message(&user, parse_id(&session_id)?, message, page_context)
            .await
            .map_err(|e| e.to_string())
    }

    async fn approve(
        &self,
        session_id: String,
        approval_id: String,
        decision: String,
        reason: Option<String>,
    ) -> BackendResult<()> {
        let user = chat_user().await?;
        let decision = match decision.as_str() {
            "approve" => plan_ai_chat::ApprovalDecision::Approve,
            "approve_all" => plan_ai_chat::ApprovalDecision::ApproveAllForSession,
            _ => plan_ai_chat::ApprovalDecision::Deny { reason },
        };
        state()?
            .resolve_approval(
                &user,
                parse_id(&session_id)?,
                parse_id(&approval_id)?,
                decision,
            )
            .await
            .map_err(|e| e.to_string())
    }

    async fn pause(&self, session_id: String) -> BackendResult<()> {
        let user = chat_user().await?;
        state()?
            .pause(&user, parse_id(&session_id)?)
            .await
            .map_err(|e| e.to_string())
    }

    async fn cancel(&self, session_id: String) -> BackendResult<()> {
        let user = chat_user().await?;
        state()?
            .cancel(&user, parse_id(&session_id)?)
            .await
            .map_err(|e| e.to_string())
    }

    async fn extend_budget(&self, session_id: String) -> BackendResult<()> {
        let user = chat_user().await?;
        state()?
            .extend_budget(&user, parse_id(&session_id)?)
            .await
            .map_err(|e| e.to_string())
    }

    async fn set_auto_approve(&self, session_id: String, value: bool) -> BackendResult<()> {
        let user = chat_user().await?;
        state()?
            .set_auto_approve(&user, parse_id(&session_id)?, value)
            .await
            .map_err(|e| e.to_string())
    }

    async fn session_meta(&self, session_id: String) -> BackendResult<ChatSessionMeta> {
        let user = chat_user().await?;
        let chat = state()?;
        let id = parse_id(&session_id)?;
        let sess = chat
            .get_session_checked(&user, id)
            .await
            .map_err(|e| e.to_string())?;
        let tokens_used = chat.store().get_token_usage(id).await.unwrap_or(0);
        let token_budget = chat.store().get_token_budget(id).await.unwrap_or(0);
        Ok(ChatSessionMeta {
            label: sess.label,
            state: sess.state,
            provider: sess.provider,
            model: sess.model,
            tokens_used,
            token_budget,
            auto_approve: chat.auto_approve(id),
        })
    }
}
