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
    // likes that were waiting when the app stopped
    let h = holder.clone();
    tokio::spawn(async move {
        if let Err(e) = h.resume_queued_likes().await {
            tracing::warn!("queued likes not resumed: {e}");
        }
    });
    holder.spawn_pairing_collector();
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
        .route("/v1/pairings", get(pairings).post(pair))
        .route("/v1/pairings/collect", post(collect))
        .route("/v1/pairings/auto", post(set_auto))
        .route("/v1/pairings/unpair", post(unpair))
        .route("/v1/inbox/approve", post(approve))
        .route("/v1/inbox/reject", post(reject))
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
        HolderError::UnknownPlatform(_) | HolderError::Platform(_) | HolderError::Pairing(_) => StatusCode::BAD_REQUEST,
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

/// Queues the like: it is proved and sent at a random moment of the next window (the issuer's
/// `like_window_secs`), so the answer only says it is queued. What can fail early (no credential, probation, a bad post id)
/// fails here.
async fn like(State(s): State<St>, Json(r): Json<LikeReq>) -> Response {
    match s.holder.like_later(&r.platform, &r.post).await {
        Ok((post, within)) => Json(json!({"queued": true, "post": post, "within_secs": within})).into_response(),
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

// ---- paired computers (crate::paired)

async fn pairings(State(s): State<St>) -> Response {
    match (s.holder.pairings(), s.holder.inbox()) {
        (Ok(p), Ok(i)) => Json(json!({"pairings": p, "inbox": i})).into_response(),
        (Err(e), _) | (_, Err(e)) => fail(e),
    }
}

/// Collect now instead of at the next round (every few minutes).
async fn collect(State(s): State<St>) -> Response {
    match s.holder.collect_pairings().await {
        Ok(n) => Json(json!({"collected": n})).into_response(),
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
struct PairReq {
    words: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    auto: bool,
}

async fn pair(State(s): State<St>, Json(r): Json<PairReq>) -> Response {
    match s.holder.pair(&r.words, r.name.as_deref(), r.auto).await {
        Ok(p) => Json(p).into_response(),
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
struct AutoReq {
    name: String,
    auto: bool,
}

async fn set_auto(State(s): State<St>, Json(r): Json<AutoReq>) -> Response {
    match s.holder.set_auto(&r.name, r.auto).await {
        Ok(()) => Json(json!({})).into_response(),
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
struct NameReq {
    name: String,
}

async fn unpair(State(s): State<St>, Json(r): Json<NameReq>) -> Response {
    match s.holder.unpair(&r.name).await {
        Ok(()) => Json(json!({})).into_response(),
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
struct IdsReq {
    ids: Vec<u64>,
}

async fn approve(State(s): State<St>, Json(r): Json<IdsReq>) -> Response {
    match s.holder.approve(&r.ids).await {
        Ok(v) => Json(json!({"results": v})).into_response(),
        Err(e) => fail(e),
    }
}

async fn reject(State(s): State<St>, Json(r): Json<IdsReq>) -> Response {
    match s.holder.reject(&r.ids).await {
        Ok(n) => Json(json!({"rejected": n})).into_response(),
        Err(e) => fail(e),
    }
}
