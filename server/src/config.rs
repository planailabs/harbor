use serde::Deserialize;
use std::sync::OnceLock;

pub use plan_ai_auth::AuthConfig;

static CONFIG: OnceLock<ServerConfig> = OnceLock::new();

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub database: DatabaseConfig,
    #[serde(default)]
    pub web: WebConfig,
    pub local_hosting: LocalHostingConfig,
    pub auth: Option<AuthConfig>,
    pub secrets: Option<SecretsConfig>,
    pub proxy: Option<ProxyConfig>,
    /// Interactive Harbor chatbot (agent over the api-mcp tool surface).
    #[serde(default)]
    pub chat: Option<ChatConfig>,
    /// Unified model list (`[[models]]`). Entries may set `validator = true`,
    /// `validator_only = true` and `restrict = "chat" | [types]`.
    #[serde(default)]
    pub models: Vec<LlmModelEntry>,
    /// Accept signed-in users' Zitadel access tokens on the API / MCP.
    pub zitadel_bearer: Option<ZitadelBearerConfig>,
}

/// `[zitadel_bearer]` — a plan.ai user's own Zitadel access token (e.g. the
/// chat acting as them by token exchange) as an API bearer. Each is checked at
/// `{issuer}/oauth/v2/introspect` (cached a minute), must carry `project_id`
/// in its audience, and acts as the user with its email — exactly as their web
/// session would.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZitadelBearerConfig {
    /// e.g. `https://id.plan.ai`.
    pub issuer: String,
    /// The Zitadel project the token must be meant for.
    pub project_id: String,
    /// Client id + secret of that project's API application (introspection).
    pub client_id: String,
    pub client_secret: String,
    /// Create the user of a token with a verified email that has none yet, as
    /// a first web sign-in would (the `[[auth.providers]]` entry with this
    /// issuer decides who may). `false` → unknown users get 403.
    #[serde(default = "yes")]
    pub auto_create: bool,
}

fn yes() -> bool {
    true
}

impl std::fmt::Debug for ZitadelBearerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZitadelBearerConfig")
            .field("issuer", &self.issuer)
            .field("project_id", &self.project_id)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("auto_create", &self.auto_create)
            .finish()
    }
}

pub use plan_ai_chat::models::{LlmModelEntry, ModelCatalog};

impl ServerConfig {
    /// The unified model catalog; falls back to a small built-in list so an
    /// enabled chat works without explicit model config.
    pub fn model_catalog(&self) -> ModelCatalog {
        if !self.models.is_empty() {
            return ModelCatalog::new(self.models.clone());
        }
        ModelCatalog::new(vec![
            LlmModelEntry::with_budget(
                "Claude Sonnet 4.6",
                "claude-sonnet-4-6",
                "anthropic",
                200_000,
            ),
            LlmModelEntry::with_budget(
                "Claude Haiku 4.5",
                "claude-haiku-4-5-20251001",
                "anthropic",
                400_000,
            ),
        ])
    }
}

/// `[chat]` — interactive Harbor chatbot. The agent's tools are the api-mcp
/// registry endpoints, dispatched with the chat user's principal; calls at or
/// above `risk_threshold` pause for human approval in the chat UI.
#[derive(Debug, Clone, Deserialize)]
pub struct ChatConfig {
    /// Master switch. Default off.
    #[serde(default)]
    pub enabled: bool,
    /// LLM providers.
    #[serde(default)]
    pub ollama_url: Option<String>,
    #[serde(default)]
    pub anthropic_api_key: Option<String>,
    #[serde(default)]
    pub openrouter_api_key: Option<String>,
    /// Named OpenAI-compatible sources (`[[chat.openai]]`): api.openai.com,
    /// vLLM, LM Studio, ... Each name doubles as the provider string in
    /// [[models]] entries (must not be "ollama"/"anthropic"/"openrouter").
    #[serde(default)]
    pub openai: Vec<plan_ai_chat::connector::OpenAiSource>,
    /// Validator LLM for the guard layer (shown alongside approval prompts).
    #[serde(default)]
    pub validator_provider: Option<String>,
    #[serde(default)]
    pub validator_model: Option<String>,
    /// Per-session token budget. 0 = unlimited. Default 500k.
    #[serde(default = "default_chat_token_budget")]
    pub token_budget: u64,
    /// Minimum tool risk that requires human approval:
    /// "mutating" (default), "destructive", or "never" (disable the gate).
    #[serde(default = "default_chat_risk_threshold")]
    pub risk_threshold: String,
    /// Offer/accept "approve all for this session". Default true.
    #[serde(default = "default_true")]
    pub allow_approve_all: bool,
    /// Max concurrently running agent sessions per user. Default 3.
    #[serde(default = "default_chat_max_sessions")]
    pub max_active_sessions_per_user: u32,
    /// Minutes an interactive session idles before parking. Default 30.
    #[serde(default = "default_chat_idle_park_minutes")]
    pub idle_park_minutes: u64,
    /// Tool-name globs to include (empty = all registry tools).
    #[serde(default)]
    pub tools_include: Vec<String>,
    /// Tool-name globs to exclude.
    #[serde(default)]
    pub tools_exclude: Vec<String>,
}

fn default_chat_token_budget() -> u64 {
    500_000
}
fn default_chat_risk_threshold() -> String {
    "mutating".to_string()
}
fn default_true() -> bool {
    true
}
fn default_chat_max_sessions() -> u32 {
    3
}
fn default_chat_idle_park_minutes() -> u64 {
    30
}

#[derive(Debug, Deserialize)]
pub struct LocalHostingConfig {
    /// Root directory for locally-hosted static webspace content. Each webspace
    /// is served from `{dir}/{webspace_id}/`. Required.
    pub dir: String,
}

/// The `[proxy]` section is shared with the `harbor-proxy` binary, which
/// parses it with its own struct; fields only the proxy reads (bind
/// addresses, server_url) live in `proxy/src/config.rs`.
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub domain: String,
    #[serde(default = "default_upstream")]
    pub upstream: String,
    pub acme_email: Option<String>,
    /// ACME directory URL override. Defaults to Let's Encrypt production;
    /// tests point this at a pebble instance.
    pub acme_directory_url: Option<String>,
    #[serde(default = "default_internal_token_path")]
    pub internal_token_path: String,
}

fn default_upstream() -> String {
    "127.0.0.1:7380".to_string()
}
fn default_internal_token_path() -> String {
    "/var/lib/harbor-server/internal.token".to_string()
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct WebConfig {
    #[serde(default = "default_web_port")]
    pub port: u16,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            port: default_web_port(),
        }
    }
}

fn default_web_port() -> u16 {
    7380
}

#[derive(Debug, Deserialize)]
pub struct SecretsConfig {
    pub encryption_key: String,
}

pub fn load() -> &'static ServerConfig {
    CONFIG.get_or_init(|| {
        let path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "./config.toml".to_string());
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read config from {path}: {e}"));
        toml::from_str(&content)
            .unwrap_or_else(|e| panic!("failed to parse config from {path}: {e}"))
    })
}

pub fn config() -> &'static ServerConfig {
    CONFIG.get().expect("config not loaded")
}

/// The config, if loaded (tests build the registry without one).
pub fn try_config() -> Option<&'static ServerConfig> {
    CONFIG.get()
}
