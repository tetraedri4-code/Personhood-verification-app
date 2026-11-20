//! A relay: forwards encrypted requests to the gateways it is set up for and their answers back. It
//! passes on the body and nothing else: no address, no header of the sender's. It keeps no log of
//! requests. It also serves each gateway's key, fetched once for everyone and kept at least
//! [`KEYS_MIN_AGE`], so that a gateway cannot hand one client a key of its own and so recognise its
//! requests: everyone who asks in that time gets the same key.
//!
//! Routes, for each gateway named `name`: `POST /name` (an encrypted request) and `GET /name/keys`.
use crate::{KEYS_TYPE, REQ_TYPE, RES_TYPE};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

/// Largest request passed on (a backup of 1,000,000 characters plus encryption fits).
const MAX_REQUEST: usize = 2 << 20;
const MAX_RESPONSE: usize = crate::gateway::MAX_INNER_RESPONSE + (64 << 10);
const KEYS_TTL: Duration = Duration::from_secs(3600);
/// A gateway that says its key changed gets its key fetched again, but not sooner than this after the
/// last fetch. Otherwise anyone could send undecryptable requests to empty the cache, and a gateway
/// doing so could give every client that fetches next a key of its own.
pub const KEYS_MIN_AGE: Duration = Duration::from_secs(600);

#[derive(Clone, Debug)]
pub struct Options {
    /// see [`KEYS_MIN_AGE`]
    pub keys_min_age: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options { keys_min_age: KEYS_MIN_AGE }
    }
}

struct Relay {
    /// name to gateway base address
    gateways: BTreeMap<String, String>,
    http: reqwest::Client,
    keys: Mutex<BTreeMap<String, (Instant, Bytes)>>,
    opts: Options,
}

/// `gateways`: name to the base address of a service with a gateway (its `/ohttp` is used).
pub fn router(gateways: BTreeMap<String, String>) -> anyhow::Result<Router> {
    router_with(gateways, Options::default())
}

pub fn router_with(gateways: BTreeMap<String, String>, opts: Options) -> anyhow::Result<Router> {
    for (name, url) in &gateways {
        anyhow::ensure!(!name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'), "relay: bad gateway name {name:?}");
        url::Url::parse(url).map_err(|e| anyhow::anyhow!("relay: bad address for {name}: {e}"))?;
    }
    let http = reqwest::Client::builder().timeout(Duration::from_secs(120)).redirect(reqwest::redirect::Policy::none()).build()?;
    let st = Arc::new(Relay { gateways: gateways.into_iter().map(|(k, v)| (k, v.trim_end_matches('/').to_string())).collect(), http, keys: Mutex::new(BTreeMap::new()), opts });
    Ok(Router::new().route("/:name", post(forward)).route("/:name/keys", get(keys)).layer(DefaultBodyLimit::max(MAX_REQUEST)).with_state(st))
}

fn plain(status: StatusCode, msg: &str) -> Response {
    (status, msg.to_string()).into_response()
}

async fn read_limited(r: reqwest::Response) -> Result<Bytes, Response> {
    if r.content_length().is_some_and(|n| n as usize > MAX_RESPONSE) {
        return Err(plain(StatusCode::BAD_GATEWAY, "answer too large"));
    }
    let mut r = r;
    let mut out = Vec::new();
    while let Some(chunk) = r.chunk().await.map_err(|_| plain(StatusCode::BAD_GATEWAY, "gateway failed"))? {
        if out.len() + chunk.len() > MAX_RESPONSE {
            return Err(plain(StatusCode::BAD_GATEWAY, "answer too large"));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(out))
}

async fn forward(State(s): State<Arc<Relay>>, Path(name): Path<String>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(gw) = s.gateways.get(&name) else { return plain(StatusCode::NOT_FOUND, "no such gateway") };
    if headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) != Some(REQ_TYPE) {
        return plain(StatusCode::UNSUPPORTED_MEDIA_TYPE, "expected message/ohttp-req");
    }
    // a new request with only the body: nothing of the sender's goes on
    let r = match s.http.post(format!("{gw}/ohttp")).header(header::CONTENT_TYPE, REQ_TYPE).body(body).send().await {
        Ok(r) => r,
        Err(_) => return plain(StatusCode::BAD_GATEWAY, "gateway not reachable"),
    };
    let status = r.status();
    let ct = if status.is_success() { RES_TYPE } else { "text/plain" };
    match read_limited(r).await {
        Ok(b) => {
            if status == StatusCode::BAD_REQUEST && b.as_ref() == crate::BAD_KEY.as_bytes() {
                // the gateway may have a new key: the next key request fetches it, if the copy is old enough
                let mut k = s.keys.lock().await;
                if k.get(&name).is_some_and(|(at, _)| at.elapsed() >= s.opts.keys_min_age) {
                    k.remove(&name);
                }
            }
            (status, [(header::CONTENT_TYPE, ct), (header::CACHE_CONTROL, "no-store")], b).into_response()
        }
        Err(e) => e,
    }
}

async fn keys(State(s): State<Arc<Relay>>, Path(name): Path<String>) -> Response {
    let Some(gw) = s.gateways.get(&name) else { return plain(StatusCode::NOT_FOUND, "no such gateway") };
    // one lock for all: one fetch at a time, and everyone gets the copy the last fetch brought
    let mut cache = s.keys.lock().await;
    let fresh = cache.get(&name).filter(|(at, _)| at.elapsed() < KEYS_TTL).map(|(_, b)| b.clone());
    let b = match fresh {
        Some(b) => b,
        None => {
            let r = match s.http.get(format!("{gw}/ohttp/keys")).timeout(Duration::from_secs(10)).send().await {
                Ok(r) if r.status().is_success() => r,
                _ => return plain(StatusCode::BAD_GATEWAY, "gateway key not available"),
            };
            match read_limited(r).await {
                Ok(b) if b.len() <= 4096 => {
                    cache.insert(name, (Instant::now(), b.clone()));
                    b
                }
                _ => return plain(StatusCode::BAD_GATEWAY, "gateway key not available"),
            }
        }
    };
    ([(header::CONTENT_TYPE, KEYS_TYPE), (header::CACHE_CONTROL, "public, max-age=600")], b).into_response()
}
