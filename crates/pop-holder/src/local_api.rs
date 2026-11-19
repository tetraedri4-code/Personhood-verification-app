//! HTTP API on 127.0.0.1 for the browser extension. The extension has no secret and makes no proofs;
//! when the person likes a post it asks the holder app to report it.
//!
//! Any web page can send requests to 127.0.0.1, so every call needs the pairing token the app shows at
//! start (the person pastes it into the extension's options once). Without it a hostile page could make
//! the holder report likes. The token travels in a header, which a cross-site page cannot set without a
//! CORS preflight that this server answers only for browser-extension origins.
use crate::holder::{Holder, HolderError};
use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};

#[derive(Clone)]
struct St {
    holder: Arc<Holder>,
    token: Arc<String>,
}

pub fn new_token() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

pub fn router(holder: Arc<Holder>, token: String) -> Router {
    let st = St { holder, token: Arc::new(token) };
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|o: &HeaderValue, _| {
            let o = o.as_bytes();
            o.starts_with(b"chrome-extension://") || o.starts_with(b"moz-extension://")
        }))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE, header::HeaderName::from_static("x-pop-token")]);
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/like", post(like))
        .route("/v1/liked", post(liked))
        .layer(middleware::from_fn_with_state(st.clone(), auth))
        .layer(cors)
        .with_state(st)
        // public and fixed: the instructions for securing an eID, linked from the app's messages
        .route(crate::holder::RESET_EID_PATH, get(crate::help::index))
        .route("/help/reset-eid/:cc", get(crate::help::country_page))
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn auth(State(s): State<St>, req: Request, next: Next) -> Response {
    if req.method() == Method::OPTIONS {
        return next.run(req).await;
    }
    let ok = req.headers().get("x-pop-token").map(|t| ct_eq(t.as_bytes(), s.token.as_bytes())).unwrap_or(false);
    if !ok {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "missing or wrong pairing token"}))).into_response();
    }
    next.run(req).await
}

fn fail(e: HolderError) -> Response {
    let code = match e {
        HolderError::NotEnrolled => StatusCode::CONFLICT,
        HolderError::UnknownPlatform(_) | HolderError::Platform(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::BAD_GATEWAY,
    };
    (code, Json(json!({"error": e.to_string()}))).into_response()
}

async fn status(State(s): State<St>) -> Response {
    // refresh the revocation list (changes only) so that a suspension shows; offline is fine
    let _ = s.holder.suspended().await;
    match s.holder.status() {
        Ok(st) => Json(st).into_response(),
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
struct LikeReq {
    platform: String,
    post: String,
}

async fn like(State(s): State<St>, Json(r): Json<LikeReq>) -> Response {
    match s.holder.like(&r.platform, &r.post).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
struct LikedReq {
    platform: String,
    /// canonical post ids
    posts: Vec<String>,
}

async fn liked(State(s): State<St>, Json(r): Json<LikedReq>) -> Response {
    let v: Vec<&String> = r.posts.iter().filter(|p| s.holder.has_liked(&r.platform, p)).collect();
    Json(json!({"liked": v})).into_response()
}
