//! Drives the real progenitor-generated changedetection_api::Client against
//! the mock, constructed the same way as server/src/credentials.rs.

use changedetection_api::types;

async fn spawn_mock() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, mock_changedetection::router())
            .await
            .unwrap();
    });
    format!("http://{addr}")
}

fn make_client(base: &str, api_key: Option<&str>) -> changedetection_api::Client {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install rustls provider");
    });
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(key) = api_key {
        headers.insert(
            reqwest::header::HeaderName::from_static("x-api-key"),
            reqwest::header::HeaderValue::from_str(key).unwrap(),
        );
    }
    let http = reqwest::ClientBuilder::new()
        .default_headers(headers)
        .build()
        .unwrap();
    changedetection_api::Client::new_with_client(base, http)
}

#[tokio::test]
async fn requires_api_key() {
    let base = spawn_mock().await;
    let client = make_client(&base, None);
    let err = client.list_tags().await.unwrap_err();
    match err {
        changedetection_api::Error::UnexpectedResponse(r) => {
            assert_eq!(r.status().as_u16(), 403);
        }
        other => panic!("expected 403 UnexpectedResponse, got: {other}"),
    }
}

#[tokio::test]
async fn system_info() {
    let base = spawn_mock().await;
    let client = make_client(&base, Some("test-key"));
    let info = client.get_system_info().await.unwrap().into_inner();
    assert!(info.version.is_some());
    assert_eq!(info.watch_count, Some(0));
    assert_eq!(info.tag_count, Some(0));
}

#[tokio::test]
async fn tag_lifecycle() {
    let base = spawn_mock().await;
    let client = make_client(&base, Some("test-key"));

    // Create (as find_or_create_tag does).
    let create: types::CreateTag =
        serde_json::from_value(serde_json::json!({ "title": "group-a" })).unwrap();
    let created = client.create_tag(&create).await.unwrap().into_inner();
    let tag_uuid = created.uuid.expect("create_tag returned no UUID");

    // Missing title is rejected.
    let bad: types::CreateTag = serde_json::from_value(serde_json::json!({})).unwrap();
    assert!(client.create_tag(&bad).await.is_err());

    // List contains it, keyed by UUID string.
    let tags = client.list_tags().await.unwrap().into_inner();
    let tag = tags.get(&tag_uuid.to_string()).expect("tag in list");
    assert_eq!(tag.title.as_deref().map(|t| t.as_str()), Some("group-a"));

    // Get single tag.
    let tag = client
        .get_tag(&tag_uuid, None, None)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(tag.title.as_deref().map(|t| t.as_str()), Some("group-a"));
    assert!(tag.notification_urls.is_empty());

    // Update notification_urls (as sync_tag_notifications does) and verify
    // the title survives the partial update.
    let webhook = "json://https://harbor.example/api/changedetection/s3cr3t";
    let update: types::Tag = serde_json::from_value(serde_json::json!({
        "notification_urls": [webhook],
        "notification_format": "markdown",
    }))
    .unwrap();
    client.update_tag(&tag_uuid, &update).await.unwrap();

    let tag = client
        .get_tag(&tag_uuid, None, None)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(tag.title.as_deref().map(|t| t.as_str()), Some("group-a"));
    assert!(tag.notification_urls.iter().any(|u| u.as_str() == webhook));

    // Update title (as resolve_or_create_suburl_tag does).
    let update: types::Tag =
        serde_json::from_value(serde_json::json!({ "title": "group-b" })).unwrap();
    client.update_tag(&tag_uuid, &update).await.unwrap();
    let tag = client
        .get_tag(&tag_uuid, None, None)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(tag.title.as_deref().map(|t| t.as_str()), Some("group-b"));

    // Delete, then get returns an error.
    client.delete_tag(&tag_uuid).await.unwrap();
    assert!(client.get_tag(&tag_uuid, None, None).await.is_err());
    assert!(client.list_tags().await.unwrap().into_inner().is_empty());
}

#[tokio::test]
async fn watch_lifecycle() {
    let base = spawn_mock().await;
    let client = make_client(&base, Some("test-key"));

    // Create two tags so we can verify title-based filtering.
    let mut tag_ids = Vec::new();
    for title in ["group", "group:ws:/pricing"] {
        let create: types::CreateTag =
            serde_json::from_value(serde_json::json!({ "title": title })).unwrap();
        let resp = client.create_tag(&create).await.unwrap().into_inner();
        tag_ids.push(resp.uuid.unwrap().to_string());
    }

    // Create a watch tagged with both (as sync_changedetection_for_suburl does).
    let create: types::CreateWatch = serde_json::from_value(serde_json::json!({
        "url": "https://example.com/pricing",
        "title": "example.com/pricing",
        "tags": tag_ids,
    }))
    .unwrap();
    client.create_watch(&create).await.unwrap();

    // List filtered by sub-URL tag title.
    let watches = client
        .list_watches(None, Some("group:ws:/pricing"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(watches.len(), 1);
    let (uuid_str, watch) = watches.iter().next().unwrap();
    assert_eq!(watch.url.as_deref(), Some("https://example.com/pricing"));
    assert_eq!(
        watch.title.as_deref().map(|t| t.as_str()),
        Some("example.com/pricing")
    );
    assert!(tag_ids.iter().all(|t| watch.tags.iter().any(|wt| wt == t)));
    let watch_uuid: uuid::Uuid = uuid_str.parse().unwrap();

    // Filter by a title that matches nothing.
    let watches = client
        .list_watches(None, Some("other-group"))
        .await
        .unwrap()
        .into_inner();
    assert!(watches.is_empty());

    // Update title + tags.
    let update: types::UpdateWatch = serde_json::from_value(serde_json::json!({
        "title": "renamed",
        "tags": [tag_ids[0]],
    }))
    .unwrap();
    client.update_watch(&watch_uuid, &update).await.unwrap();

    let watches = client
        .list_watches(None, Some("group"))
        .await
        .unwrap()
        .into_inner();
    let watch = watches.get(&watch_uuid.to_string()).expect("watch in list");
    assert_eq!(watch.title.as_deref().map(|t| t.as_str()), Some("renamed"));
    assert_eq!(watch.tags, vec![tag_ids[0].clone()]);

    // Dropping the sub-URL tag means the old filter no longer matches.
    let watches = client
        .list_watches(None, Some("group:ws:/pricing"))
        .await
        .unwrap()
        .into_inner();
    assert!(watches.is_empty());

    // Delete watch.
    client.delete_watch(&watch_uuid).await.unwrap();
    let watches = client.list_watches(None, None).await.unwrap().into_inner();
    assert!(watches.is_empty());
    assert!(client.delete_watch(&watch_uuid).await.is_err());
}

#[tokio::test]
async fn delete_tag_detaches_it_from_watches() {
    let base = spawn_mock().await;
    let client = make_client(&base, Some("test-key"));

    let create: types::CreateTag =
        serde_json::from_value(serde_json::json!({ "title": "doomed" })).unwrap();
    let tag_uuid = client
        .create_tag(&create)
        .await
        .unwrap()
        .into_inner()
        .uuid
        .unwrap();

    let create: types::CreateWatch = serde_json::from_value(serde_json::json!({
        "url": "https://example.com/",
        "tags": [tag_uuid.to_string()],
    }))
    .unwrap();
    client.create_watch(&create).await.unwrap();

    client.delete_tag(&tag_uuid).await.unwrap();

    let watches = client.list_watches(None, None).await.unwrap().into_inner();
    assert_eq!(watches.len(), 1);
    assert!(watches.values().next().unwrap().tags.is_empty());
}
