//! # pop-mock-idp
//!
//! A local stand-in for a bank-ID broker. It speaks OpenID Connect (discovery, authorize, token, JWKS)
//! and signs ID tokens with a fresh Ed25519 key, so the issuer talks to it through the same
//! `pop_idp::oidc::OidcProvider` it would use for a real broker.
//!
//! The login page offers fake persons with Finnish-style identity codes (individual numbers 900–999 are
//! the range used for test identities). `login_hint=<code>&auto=1` on the authorize URL skips the page,
//! which the CLI and the tests use.
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct MockClient {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

#[derive(Clone, Debug)]
pub struct MockIdpConfig {
    /// public base URL of this server, used as the token issuer
    pub issuer: String,
    pub clients: Vec<MockClient>,
}

/// Fake persons on the login page: (identity code, name).
pub const TEST_PERSONS: &[(&str, &str)] = &[
    ("010190-900A", "Aino Testinen"),
    ("020285-901B", "Bertta Kokeilu"),
    ("030375-902C", "Celsius Demo"),
    ("040466-903D", "Daniel Malli"),
];

struct Pending {
    client_id: String,
    subject: String,
    nonce: String,
}

struct Inner {
    cfg: MockIdpConfig,
    key: EncodingKey,
    public: Vec<u8>,
    codes: Mutex<HashMap<String, Pending>>,
}

type St = Arc<Inner>;

pub fn router(cfg: MockIdpConfig) -> Router {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let inner = Inner {
        cfg,
        key: EncodingKey::from_ed_der(pkcs8.as_ref()),
        public: kp.public_key().as_ref().to_vec(),
        codes: Mutex::new(HashMap::new()),
    };
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/authorize", get(authorize))
        .route("/login", post(login))
        .route("/token", post(token))
        .route("/jwks", get(jwks))
        .with_state(Arc::new(inner))
}

async fn discovery(State(s): State<St>) -> Json<serde_json::Value> {
    let i = s.cfg.issuer.trim_end_matches('/');
    Json(serde_json::json!({
        "issuer": i,
        "authorization_endpoint": format!("{i}/authorize"),
        "token_endpoint": format!("{i}/token"),
        "jwks_uri": format!("{i}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["pairwise"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "claims_supported": ["sub", "hetu", "name", "acr", "nonce"],
    }))
}

async fn jwks(State(s): State<St>) -> Json<serde_json::Value> {
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&s.public);
    Json(serde_json::json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": x, "kid": "mock-1", "alg": "EdDSA", "use": "sig"}]}))
}

#[derive(Deserialize, Clone)]
struct AuthQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    nonce: String,
    #[serde(default)]
    login_hint: Option<String>,
    #[serde(default)]
    auto: Option<String>,
}

fn bad(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, msg.to_string()).into_response()
}

fn check_client(s: &Inner, client_id: &str, redirect_uri: &str) -> bool {
    s.cfg.clients.iter().any(|c| c.client_id == client_id && c.redirect_uri == redirect_uri)
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn finish(s: &Inner, q: &AuthQuery, subject: &str) -> Response {
    let code = hex::encode(rand::random::<[u8; 16]>());
    s.codes.lock().unwrap().insert(code.clone(), Pending { client_id: q.client_id.clone(), subject: subject.into(), nonce: q.nonce.clone() });
    let mut u = match url::Url::parse(&q.redirect_uri) {
        Ok(u) => u,
        Err(_) => return bad("bad redirect_uri"),
    };
    u.query_pairs_mut().append_pair("code", &code).append_pair("state", &q.state);
    Redirect::to(u.as_str()).into_response()
}

async fn authorize(State(s): State<St>, Query(q): Query<AuthQuery>) -> Response {
    if q.response_type != "code" || !check_client(&s, &q.client_id, &q.redirect_uri) {
        return bad("unknown client or redirect_uri");
    }
    if let (Some(h), Some(_)) = (&q.login_hint, &q.auto) {
        return finish(&s, &q, h);
    }
    let hidden = format!(
        r#"<input type="hidden" name="response_type" value="code"><input type="hidden" name="client_id" value="{}"><input type="hidden" name="redirect_uri" value="{}"><input type="hidden" name="state" value="{}"><input type="hidden" name="nonce" value="{}">"#,
        esc(&q.client_id),
        esc(&q.redirect_uri),
        esc(&q.state),
        esc(&q.nonce)
    );
    let persons: String = TEST_PERSONS
        .iter()
        .map(|(id, name)| {
            format!(
                r#"<form method="post" action="login">{hidden}<input type="hidden" name="subject" value="{id}"><button>{name} <small>{id}</small></button></form>"#
            )
        })
        .collect();
    Html(format!(
        r#"<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Mock bank ID</title>
<style>body{{font-family:system-ui;max-width:28rem;margin:2rem auto;padding:0 1rem}}button{{display:block;width:100%;margin:.4rem 0;padding:.7rem;font-size:1rem;text-align:left}}small{{color:#666}}</style>
<h1>Mock bank ID</h1><p>Local test identity provider. Nothing here is a real identity. Choose a test person:</p>{persons}
<form method="post" action="login">{hidden}<p>Or type any test identity code:</p><input name="subject" placeholder="050505-999X" required><button>Log in</button></form>"#
    ))
    .into_response()
}

#[derive(Deserialize)]
struct LoginForm {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    nonce: String,
    subject: String,
}

async fn login(State(s): State<St>, Form(f): Form<LoginForm>) -> Response {
    let q = AuthQuery {
        response_type: f.response_type,
        client_id: f.client_id,
        redirect_uri: f.redirect_uri,
        state: f.state,
        nonce: f.nonce,
        login_hint: None,
        auto: None,
    };
    if !check_client(&s, &q.client_id, &q.redirect_uri) {
        return bad("unknown client");
    }
    finish(&s, &q, f.subject.trim())
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    code: String,
    client_id: String,
    client_secret: String,
}

async fn token(State(s): State<St>, Form(f): Form<TokenForm>) -> Response {
    if f.grant_type != "authorization_code" {
        return bad("unsupported grant_type");
    }
    if !s.cfg.clients.iter().any(|c| c.client_id == f.client_id && c.client_secret == f.client_secret) {
        return (StatusCode::UNAUTHORIZED, "bad client credentials").into_response();
    }
    let p = match s.codes.lock().unwrap().remove(&f.code) {
        Some(p) if p.client_id == f.client_id => p,
        _ => return bad("unknown or used code"),
    };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let name = TEST_PERSONS.iter().find(|(id, _)| *id == p.subject).map(|(_, n)| *n).unwrap_or("Test Person");
    // pairwise subject, as real brokers do; the lifelong identifier travels in the "hetu" claim
    let sub = hex::encode(&<sha2::Sha256 as sha2::Digest>::digest(format!("{}|{}", f.client_id, p.subject).as_bytes())[..16]);
    let claims = serde_json::json!({
        "iss": s.cfg.issuer.trim_end_matches('/'),
        "aud": f.client_id,
        "sub": sub,
        "hetu": p.subject,
        "name": name,
        "acr": "mock:loa:high",
        "nonce": p.nonce,
        "iat": now,
        "exp": now + 300,
    });
    let mut h = Header::new(Algorithm::EdDSA);
    h.kid = Some("mock-1".into());
    match encode(&h, &claims, &s.key) {
        Ok(t) => Json(serde_json::json!({"access_token": "unused", "token_type": "Bearer", "id_token": t, "expires_in": 300})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
