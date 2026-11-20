//! The gateway: decrypts a request, hands it to the service's own routes, encrypts the answer.
use crate::{BAD_KEY, KEYS_TYPE, REQ_TYPE, RES_TYPE};
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header, HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use ohttp::{
    hpke::{Aead, Kdf, Kem},
    KeyConfig, Server, SymmetricSuite,
};
use std::{io::Cursor, sync::Arc};
use tower::ServiceExt;

/// Largest answer of the service the gateway will encrypt. Each request in flight holds about three
/// copies; the largest answers today are the proving keys (under 2 MB).
pub const MAX_INNER_RESPONSE: usize = 32 << 20;
/// Request headers passed on to the service. Anything else the client put in is dropped.
const PASSED: &[&str] = &["content-type", "accept"];

struct Key {
    server: Server,
    keys: Vec<u8>,
}

/// The gateway's key. Every client gets the same key, so the key cannot tell clients apart; clients
/// fetch it again when it changes.
pub struct Gateway(std::sync::RwLock<Arc<Key>>, Vec<u32>);

fn new_key() -> anyhow::Result<Key> {
    let cfg = KeyConfig::new(rand::random(), Kem::X25519Sha256, vec![SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm)])
        .map_err(|e| anyhow::anyhow!("ohttp key: {e}"))?;
    let keys = KeyConfig::encode_list(&[&cfg]).map_err(|e| anyhow::anyhow!("ohttp key: {e}"))?;
    Ok(Key { server: Server::new(cfg).map_err(|e| anyhow::anyhow!("ohttp: {e}"))?, keys })
}

impl Gateway {
    /// A gateway with a new key, kept for the life of the process unless [`Gateway::rotate`]d, padding
    /// with the default size classes.
    pub fn generate() -> anyhow::Result<Arc<Self>> {
        Self::with_pad_sizes(crate::DEFAULT_PAD_SIZES.to_vec())
    }

    /// The same, padding answers to these size classes (the issuer's `policy.pad_sizes`).
    pub fn with_pad_sizes(pad_sizes: Vec<u32>) -> anyhow::Result<Arc<Self>> {
        crate::check_pad_sizes(&pad_sizes).map_err(|e| anyhow::anyhow!(e))?;
        Ok(Arc::new(Gateway(std::sync::RwLock::new(Arc::new(new_key()?)), pad_sizes)))
    }

    /// Replace the key. Requests encrypted to the old one are refused (without reaching the service),
    /// and their clients fetch the new key and send them again.
    pub fn rotate(&self) -> anyhow::Result<()> {
        *self.0.write().unwrap() = Arc::new(new_key()?);
        Ok(())
    }

    fn current(&self) -> Arc<Key> {
        self.0.read().unwrap().clone()
    }

    /// The key list (`application/ohttp-keys`).
    pub fn keys(&self) -> Vec<u8> {
        self.current().keys.clone()
    }
}

struct Gw {
    gw: Arc<Gateway>,
    inner: Router,
}

/// `app` with a gateway in front: the same routes, plus `POST /ohttp` and `GET /ohttp/keys`.
pub fn wrap(app: Router, gw: Arc<Gateway>) -> Router {
    let st = Arc::new(Gw { gw, inner: app.clone() });
    let outer = Router::new().route("/ohttp", post(handle)).route("/ohttp/keys", get(keys)).with_state(st);
    app.merge(outer)
}

async fn keys(State(s): State<Arc<Gw>>) -> Response {
    ([(header::CONTENT_TYPE, KEYS_TYPE), (header::CACHE_CONTROL, "public, max-age=600")], s.gw.keys()).into_response()
}

fn plain(status: StatusCode, msg: &str) -> Response {
    (status, msg.to_string()).into_response()
}

async fn handle(State(s): State<Arc<Gw>>, headers: HeaderMap, body: Bytes) -> Response {
    if headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) != Some(REQ_TYPE) {
        return plain(StatusCode::UNSUPPORTED_MEDIA_TYPE, "expected message/ohttp-req");
    }
    let Ok((plain_req, ctx)) = s.gw.current().server.decapsulate(&body) else {
        return plain(StatusCode::BAD_REQUEST, BAD_KEY);
    };
    let (status, ct, content) = match inner_request(&plain_req) {
        Ok(req) => answer(&s.inner, req).await,
        Err(e) => (StatusCode::BAD_REQUEST, "text/plain".to_string(), Bytes::from(format!("bad inner request: {e}"))),
    };
    let mut m = bhttp::Message::response(bhttp::StatusCode::try_from(status.as_u16()).unwrap_or(bhttp::StatusCode::OK));
    m.put_header("content-type", ct);
    // the server's time, for the holder's clock (pop_protocol::clock): inside the encryption, so that
    // the relay can neither read nor change it
    m.put_header("date", httpdate::fmt_http_date(std::time::SystemTime::now()));
    let sizes = &s.gw.1;
    m.put_header(crate::PAD_HEADER, sizes.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(","));
    m.write_content(&content);
    let mut out = vec![];
    if m.write_bhttp(bhttp::Mode::KnownLength, &mut out).is_err() {
        return plain(StatusCode::INTERNAL_SERVER_ERROR, "ohttp: cannot encode the answer");
    }
    crate::pad(&mut out, sizes);
    match ctx.encapsulate(&out) {
        Ok(enc) => ([(header::CONTENT_TYPE, RES_TYPE), (header::CACHE_CONTROL, "no-store")], enc).into_response(),
        Err(_) => plain(StatusCode::INTERNAL_SERVER_ERROR, "ohttp: cannot encrypt the answer"),
    }
}

fn inner_request(bytes: &[u8]) -> anyhow::Result<Request<Body>> {
    let mut c = Cursor::new(bytes);
    let m = bhttp::Message::read_bhttp::<Cursor<&[u8]>, Cursor<&[u8]>>(&mut c).map_err(|e| anyhow::anyhow!("{e}"))?;
    let method = m.control().method().ok_or_else(|| anyhow::anyhow!("not a request"))?;
    let path = m.control().path().ok_or_else(|| anyhow::anyhow!("no path"))?;
    let path = std::str::from_utf8(path)?;
    // only a path on this service: never a full address, never the gateway itself
    if !path.starts_with('/') || path.starts_with("//") || path == "/ohttp" || path.starts_with("/ohttp/") || path.starts_with("/ohttp?") {
        anyhow::bail!("path not allowed");
    }
    let mut b = Request::builder().method(axum::http::Method::from_bytes(method)?).uri(path);
    for f in m.header().fields() {
        let name = std::str::from_utf8(f.name())?.to_ascii_lowercase();
        if PASSED.contains(&name.as_str()) {
            b = b.header(name, f.value());
        }
    }
    Ok(b.body(Body::from(m.content().to_vec()))?)
}

async fn answer(inner: &Router, req: Request<Body>) -> (StatusCode, String, Bytes) {
    let r = match inner.clone().oneshot(req).await {
        Ok(r) => r,
        Err(e) => match e {},
    };
    let status = r.status();
    let ct = r.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("application/octet-stream").to_string();
    match axum::body::to_bytes(r.into_body(), MAX_INNER_RESPONSE).await {
        Ok(b) => (status, ct, b),
        Err(_) => (StatusCode::BAD_GATEWAY, "text/plain".into(), Bytes::from_static(b"answer too large")),
    }
}
