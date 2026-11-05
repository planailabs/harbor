//! Stateful in-memory mock of the changedetection.io API.
//!
//! Covers the operations the Harbor server uses: system info, watch
//! create/list/update/delete and tag create/list/get/update/delete.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Default)]
struct Inner {
    watches: HashMap<Uuid, Value>,
    tags: HashMap<Uuid, Value>,
}

type AppState = Arc<Mutex<Inner>>;

pub fn router() -> Router {
    let state: AppState = AppState::default();
    Router::new()
        .route("/systeminfo", get(system_info))
        .route("/watch", get(list_watches).post(create_watch))
        .route("/watch/{uuid}", put(update_watch).delete(delete_watch))
        .route("/tags", get(list_tags))
        .route("/tag", post(create_tag))
        .route(
            "/tag/{uuid}",
            get(get_tag).put(update_tag).delete(delete_tag),
        )
        .layer(axum::middleware::from_fn(require_api_key))
        .with_state(state)
}

async fn require_api_key(req: Request, next: Next) -> Response {
    let ok = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    if !ok {
        return (StatusCode::FORBIDDEN, "Invalid access - API key invalid.").into_response();
    }
    next.run(req).await
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Merge object fields of `patch` into `target` (shallow).
fn merge_object(target: &mut Value, patch: &Value) {
    if let (Some(target), Some(patch)) = (target.as_object_mut(), patch.as_object()) {
        for (k, v) in patch {
            target.insert(k.clone(), v.clone());
        }
    }
}

async fn system_info(State(state): State<AppState>) -> Json<Value> {
    let inner = state.lock().unwrap();
    Json(json!({
        "version": "0.50.0-mock",
        "uptime": "1.0",
        "tag_count": inner.tags.len(),
        "watch_count": inner.watches.len(),
    }))
}

async fn list_watches(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<Value> {
    let inner = state.lock().unwrap();

    // The `tag` query param filters by tag *title* (case-insensitive).
    let tag_uuids: Option<Vec<String>> = params.get("tag").map(|title| {
        inner
            .tags
            .iter()
            .filter(|(_, t)| {
                t["title"]
                    .as_str()
                    .map(|s| s.eq_ignore_ascii_case(title))
                    .unwrap_or(false)
            })
            .map(|(id, _)| id.to_string())
            .collect()
    });

    let out: serde_json::Map<String, Value> = inner
        .watches
        .iter()
        .filter(|(_, w)| match &tag_uuids {
            None => true,
            Some(ids) => {
                let in_tags = w["tags"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|t| t.as_str())
                            .any(|t| ids.iter().any(|id| id == t))
                    })
                    .unwrap_or(false);
                let in_tag = w["tag"]
                    .as_str()
                    .map(|t| ids.iter().any(|id| id == t))
                    .unwrap_or(false);
                in_tags || in_tag
            }
        })
        .map(|(id, w)| (id.to_string(), w.clone()))
        .collect();
    Json(Value::Object(out))
}

async fn create_watch(State(state): State<AppState>, Json(body): Json<Value>) -> Response {
    let url = match body["url"].as_str() {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "No URL given").into_response();
        }
    };
    let uuid = Uuid::new_v4();
    let mut watch = json!({
        "uuid": uuid,
        "url": url,
        "tags": [],
        "paused": false,
        "notification_muted": false,
        "last_checked": 0,
        "last_changed": 0,
        "date_created": now_ts(),
    });
    merge_object(&mut watch, &body);
    state.lock().unwrap().watches.insert(uuid, watch);
    (StatusCode::CREATED, Json(json!({ "uuid": uuid }))).into_response()
}

async fn update_watch(
    State(state): State<AppState>,
    Path(uuid): Path<Uuid>,
    Json(body): Json<Value>,
) -> Response {
    let mut inner = state.lock().unwrap();
    match inner.watches.get_mut(&uuid) {
        Some(watch) => {
            merge_object(watch, &body);
            watch["uuid"] = json!(uuid);
            (StatusCode::OK, "OK").into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn delete_watch(State(state): State<AppState>, Path(uuid): Path<Uuid>) -> StatusCode {
    if state.lock().unwrap().watches.remove(&uuid).is_some() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn list_tags(State(state): State<AppState>) -> Json<Value> {
    let inner = state.lock().unwrap();
    let out: serde_json::Map<String, Value> = inner
        .tags
        .iter()
        .map(|(id, t)| (id.to_string(), t.clone()))
        .collect();
    Json(Value::Object(out))
}

async fn create_tag(State(state): State<AppState>, Json(body): Json<Value>) -> Response {
    if body["title"].as_str().map(str::is_empty).unwrap_or(true) {
        return (StatusCode::BAD_REQUEST, "Invalid or missing title").into_response();
    }
    let uuid = Uuid::new_v4();
    let mut tag = json!({
        "uuid": uuid,
        "notification_muted": false,
        "date_created": now_ts(),
    });
    merge_object(&mut tag, &body);
    state.lock().unwrap().tags.insert(uuid, tag);
    (StatusCode::CREATED, Json(json!({ "uuid": uuid }))).into_response()
}

async fn get_tag(State(state): State<AppState>, Path(uuid): Path<Uuid>) -> Response {
    match state.lock().unwrap().tags.get(&uuid) {
        Some(tag) => Json(tag.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn update_tag(
    State(state): State<AppState>,
    Path(uuid): Path<Uuid>,
    Json(body): Json<Value>,
) -> Response {
    let mut inner = state.lock().unwrap();
    match inner.tags.get_mut(&uuid) {
        Some(tag) => {
            merge_object(tag, &body);
            tag["uuid"] = json!(uuid);
            (StatusCode::OK, "OK").into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn delete_tag(State(state): State<AppState>, Path(uuid): Path<Uuid>) -> StatusCode {
    let mut inner = state.lock().unwrap();
    if inner.tags.remove(&uuid).is_none() {
        return StatusCode::NOT_FOUND;
    }
    // Real API removes the tag from all watches as well.
    let id = uuid.to_string();
    for watch in inner.watches.values_mut() {
        if let Some(tags) = watch["tags"].as_array_mut() {
            tags.retain(|t| t.as_str() != Some(id.as_str()));
        }
        if watch["tag"].as_str() == Some(id.as_str()) {
            watch["tag"] = Value::Null;
        }
    }
    StatusCode::NO_CONTENT
}
