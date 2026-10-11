//! Milestone 6D: the API serves the NOC UI from the same origin, with a
//! strict Content-Security-Policy on the page and security headers on every
//! response (ADR 0044). No database is needed: the pool is never used.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use tower::ServiceExt;
use wetechinetmon_api::web::{WebRoot, API_CSP, PAGE_CSP};
use wetechinetmon_api::{router, AppState};
use wetechinetmon_incident_postgres::pool::PoolPolicy;

fn app(root: &std::path::Path) -> axum::Router {
    // A pool to nowhere: building it connects to nothing.
    let (pool, _) = wetechinetmon_incident_postgres::connect::connect(
        "host=127.0.0.1 port=9 user=nobody dbname=none",
        None,
        PoolPolicy::starting_default(),
    )
    .unwrap();
    router(AppState::new(pool).with_web(WebRoot::new(root).unwrap()))
}

async fn get(app: &axum::Router, method: Method, path: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn the_ui_is_served_with_its_policy_and_the_api_keeps_its_own() {
    let root = std::env::temp_dir().join(format!("wnm-web-test-{}", std::process::id()));
    std::fs::create_dir_all(root.join("assets")).unwrap();
    std::fs::write(root.join("index.html"), "<!doctype html><title>NOC</title>").unwrap();
    std::fs::write(root.join("assets/index-abc123.js"), "export{}").unwrap();
    std::fs::write(root.join("secret.txt"), "not for the web").unwrap();
    let app = app(&root);

    // Every page of the app is the index, uncached, under the page policy.
    for page in ["/", "/incidents", "/incidents/0192f3c4"] {
        let response = get(&app, Method::GET, page).await;
        assert_eq!(response.status(), StatusCode::OK, "{page}");
        let headers = response.headers();
        assert!(headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html"));
        assert_eq!(headers[header::CONTENT_SECURITY_POLICY], PAGE_CSP);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(
            headers[header::STRICT_TRANSPORT_SECURITY],
            "max-age=31536000"
        );
    }

    // An asset is immutable and typed; nothing else under the root is served.
    let response = get(&app, Method::GET, "/assets/index-abc123.js").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers()[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("text/javascript"));
    assert!(response.headers()[header::CACHE_CONTROL]
        .to_str()
        .unwrap()
        .contains("immutable"));
    for refused in [
        "/assets/../secret.txt",
        "/assets/%2e%2e/secret.txt",
        "/assets/secret.txt",
        "/assets/missing.js",
    ] {
        let response = get(&app, Method::GET, refused).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{refused}");
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("not for the web"));
    }

    // The API is never the page: unknown API paths and other methods are
    // the usual problem, under the deny-all policy.
    for (method, path) in [
        (Method::GET, "/api/v1/nothing-here"),
        (Method::POST, "/incidents"),
        (Method::DELETE, "/"),
    ] {
        let response = get(&app, method.clone(), path).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY], API_CSP);
        assert_eq!(response.headers()[header::X_FRAME_OPTIONS], "DENY");
    }
    let response = get(&app, Method::GET, "/healthz").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY], API_CSP);

    std::fs::remove_dir_all(root).unwrap();
}
