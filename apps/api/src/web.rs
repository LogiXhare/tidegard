//! The NOC UI's files, and the security headers on every response
//! (ADR 0044).
//!
//! - **Same origin.** The API serves the built UI from
//!   `TIDEGARD_API_WEB_ROOT`, so the page needs no CORS and the
//!   session cookie needs no relaxing.
//! - **Only two kinds of file are served:** `index.html`, for every page
//!   of the single-page app, and files directly under `assets/` with an
//!   allowlisted extension. A path that tries to leave the root, or names
//!   anything else, gets `index.html` or `404`, never a file outside.
//! - **A strict Content-Security-Policy** on the page allows scripts and
//!   styles from this origin only, never inline, and no framing. Every
//!   API response carries a deny-all policy and the other headers below.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::problem::{ErrorCode, Problem};
use crate::AppState;

/// The page may load scripts, styles and data from this origin only.
pub const PAGE_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; \
base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
/// An API response is data, never a document.
pub const API_CSP: &str = "default-src 'none'; frame-ancestors 'none'";
/// A built asset is at most this large.
const MAX_ASSET_BYTES: u64 = 8 * 1024 * 1024;

const ASSET_TYPES: &[(&str, &str)] = &[
    ("js", "text/javascript; charset=utf-8"),
    ("css", "text/css; charset=utf-8"),
    ("woff2", "font/woff2"),
    ("png", "image/png"),
    ("ico", "image/x-icon"),
];

/// Where the built UI is.
#[derive(Debug, Clone)]
pub struct WebRoot {
    root: PathBuf,
}

impl WebRoot {
    /// Refuses a root without `index.html`, so a wrong path fails at
    /// startup rather than at the first page load.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, String> {
        let root = root.into();
        if !root.join("index.html").is_file() {
            return Err(format!("{} holds no index.html", root.display()));
        }
        Ok(WebRoot { root })
    }

    /// The file a request path names, if it may be served: the page for
    /// any path outside `assets/`, or one asset file.
    fn resolve(&self, path: &str) -> Option<(PathBuf, &'static str, bool)> {
        match path.strip_prefix("/assets/") {
            None => Some((
                self.root.join("index.html"),
                "text/html; charset=utf-8",
                false,
            )),
            Some(name) => {
                let safe = !name.is_empty()
                    && name.len() <= 128
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                    && !name.starts_with('.')
                    && !name.contains("..");
                if !safe {
                    return None;
                }
                let extension = Path::new(name).extension()?.to_str()?;
                let content_type = ASSET_TYPES
                    .iter()
                    .find(|(known, _)| *known == extension)
                    .map(|(_, content_type)| *content_type)?;
                Some((self.root.join("assets").join(name), content_type, true))
            }
        }
    }
}

/// Serves the UI for a `GET` or `HEAD` outside `/api/`; anything else is
/// the usual `404` problem.
pub async fn fallback(State(state): State<AppState>, method: Method, request: Request) -> Response {
    let path = request.uri().path();
    let Some(web) = state.web.as_deref() else {
        return Problem::new(ErrorCode::NotFound).into_response();
    };
    if !(method == Method::GET || method == Method::HEAD) || path.starts_with("/api/") {
        return Problem::new(ErrorCode::NotFound).into_response();
    }
    let Some((file, content_type, immutable)) = web.resolve(path) else {
        return Problem::new(ErrorCode::NotFound).into_response();
    };
    // Small files, read off the async workers.
    let read = tokio::task::spawn_blocking(move || {
        let meta = std::fs::metadata(&file).ok()?;
        (meta.is_file() && meta.len() <= MAX_ASSET_BYTES)
            .then(|| std::fs::read(&file).ok())
            .flatten()
    })
    .await;
    let Ok(Some(bytes)) = read else {
        return Problem::new(ErrorCode::NotFound).into_response();
    };
    let mut response = if method == Method::HEAD {
        StatusCode::OK.into_response()
    } else {
        (StatusCode::OK, bytes).into_response()
    };
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if immutable {
            // Vite names every asset by its content hash.
            "public, max-age=31536000, immutable"
        } else {
            "no-store"
        }),
    );
    if !immutable {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(PAGE_CSP),
        );
    }
    response
}

/// Headers on every response, page and API alike. A handler's own CSP,
/// such as the page's, is kept.
pub async fn security_headers(
    State(hsts): State<Arc<bool>>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    apply(response.headers_mut(), *hsts);
    response
}

pub fn apply(headers: &mut HeaderMap, hsts: bool) {
    let set = |headers: &mut HeaderMap, name: HeaderName, value: &'static str| {
        headers
            .entry(name)
            .or_insert_with(|| HeaderValue::from_static(value));
    };
    set(headers, header::CONTENT_SECURITY_POLICY, API_CSP);
    set(headers, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(headers, header::X_FRAME_OPTIONS, "DENY");
    set(headers, header::REFERRER_POLICY, "no-referrer");
    set(
        headers,
        HeaderName::from_static("cross-origin-opener-policy"),
        "same-origin",
    );
    set(
        headers,
        HeaderName::from_static("permissions-policy"),
        "camera=(), microphone=(), geolocation=(), payment=()",
    );
    if hsts {
        set(
            headers,
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> (WebRoot, PathBuf) {
        let dir = std::env::temp_dir().join(format!("wnm-web-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("assets")).unwrap();
        std::fs::write(dir.join("index.html"), "<!doctype html>").unwrap();
        std::fs::write(dir.join("assets/index-abc.js"), "export{}").unwrap();
        (WebRoot::new(&dir).unwrap(), dir)
    }

    #[test]
    fn pages_get_the_index_and_assets_only_their_own_files() {
        let (web, dir) = root();
        for page in [
            "/",
            "/incidents",
            "/incidents/0192f3c4",
            "/..%2f..%2fetc/passwd",
        ] {
            let (file, content_type, immutable) = web.resolve(page).unwrap();
            assert_eq!(file, dir.join("index.html"), "{page}");
            assert!(content_type.starts_with("text/html"));
            assert!(!immutable);
        }
        let (file, content_type, immutable) = web.resolve("/assets/index-abc.js").unwrap();
        assert_eq!(file, dir.join("assets/index-abc.js"));
        assert!(content_type.starts_with("text/javascript"));
        assert!(immutable);
        for refused in [
            "/assets/",
            "/assets/../index.html",
            "/assets/..%2findex.html",
            "/assets/a/b.js",
            "/assets/.env",
            "/assets/x.html",
            "/assets/x.svg",
            "/assets/x.js\0",
            "/assets/x\\..\\y.js",
        ] {
            assert!(web.resolve(refused).is_none(), "{refused}");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_root_without_an_index_is_refused() {
        assert!(WebRoot::new(std::env::temp_dir().join("wnm-web-missing")).is_err());
    }

    #[test]
    fn every_response_gets_the_headers_and_keeps_its_own_policy() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(PAGE_CSP),
        );
        apply(&mut headers, true);
        assert_eq!(headers[header::CONTENT_SECURITY_POLICY], PAGE_CSP);
        assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert!(headers.contains_key(header::STRICT_TRANSPORT_SECURITY));
        let mut api = HeaderMap::new();
        apply(&mut api, false);
        assert_eq!(api[header::CONTENT_SECURITY_POLICY], API_CSP);
        assert!(!api.contains_key(header::STRICT_TRANSPORT_SECURITY));
    }

    #[test]
    fn the_page_policy_allows_no_inline_code_and_no_framing() {
        assert!(!PAGE_CSP.contains("unsafe-inline"));
        assert!(!PAGE_CSP.contains("unsafe-eval"));
        assert!(PAGE_CSP.contains("frame-ancestors 'none'"));
        assert!(PAGE_CSP.contains("script-src 'self'"));
    }
}
