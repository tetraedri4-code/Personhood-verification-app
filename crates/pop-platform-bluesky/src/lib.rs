//! Platform adapter for Bluesky, over the AT Protocol's XRPC interface.
//!
//! * The stable account id is the DID (`did:plc:...`); handles can change, DIDs do not.
//! * Reading (resolve a handle, read a bio and recent posts) uses the public AppView and needs no login.
//! * Writing the code into the bio or a post needs an *app password* the person creates in Bluesky's
//!   settings. It stays on the person's device: only the holder app uses it, never a server.
//! * The canonical post id is the AT URI `at://<did>/app.bsky.feed.post/<rkey>`, so a like tag is the
//!   same whether the post was opened by handle or by DID.
//!
//! This adapter does not publish labels or run a feed generator. Those are the next step for Bluesky
//! (voluntary-app report §6) and would live in their own service, reading the directory's public list.
use async_trait::async_trait;
use pop_protocol::platform::{CodePlacement, Platform, PlatformError};
use pop_protocol::AccountRef;
use serde_json::{json, Value};

pub const PUBLIC_APPVIEW: &str = "https://public.api.bsky.app";
pub const DEFAULT_PDS: &str = "https://bsky.social";

#[derive(Clone, Debug)]
pub struct BlueskyConfig {
    /// read-only public API
    pub appview: String,
    /// the account's personal data server, for login and writes
    pub pds: String,
    /// handle or DID to log in as, with an app password; None = read-only
    pub identifier: Option<String>,
    pub app_password: Option<String>,
}

impl Default for BlueskyConfig {
    fn default() -> Self {
        BlueskyConfig { appview: PUBLIC_APPVIEW.into(), pds: DEFAULT_PDS.into(), identifier: None, app_password: None }
    }
}

pub struct Bluesky {
    cfg: BlueskyConfig,
    http: reqwest::Client,
}

struct Session {
    did: String,
    jwt: String,
}

impl Bluesky {
    pub fn new(cfg: BlueskyConfig) -> Self {
        let http = reqwest::Client::builder().user_agent("pop-voluntary-prototype").build().expect("http client");
        Bluesky { cfg, http }
    }

    async fn check(r: reqwest::Response, what: &str) -> Result<Value, PlatformError> {
        let status = r.status();
        let body: Value = r.json().await.unwrap_or(Value::Null);
        if status.is_success() {
            return Ok(body);
        }
        let msg = format!("{what}: {status} {}", body["message"].as_str().unwrap_or_default());
        if status.as_u16() == 400 && matches!(body["error"].as_str(), Some("InvalidRequest" | "AccountNotFound" | "RecordNotFound")) {
            Err(PlatformError::NotFound(msg))
        } else {
            Err(PlatformError::Http(msg))
        }
    }

    async fn query(&self, base: &str, nsid: &str, params: &[(&str, &str)], jwt: Option<&str>) -> Result<Value, PlatformError> {
        let mut rq = self.http.get(format!("{}/xrpc/{nsid}", base.trim_end_matches('/'))).query(params);
        if let Some(j) = jwt {
            rq = rq.bearer_auth(j);
        }
        Self::check(rq.send().await.map_err(|e| PlatformError::Http(e.to_string()))?, nsid).await
    }

    async fn procedure(&self, nsid: &str, body: Value, jwt: Option<&str>) -> Result<Value, PlatformError> {
        let mut rq = self.http.post(format!("{}/xrpc/{nsid}", self.cfg.pds.trim_end_matches('/'))).json(&body);
        if let Some(j) = jwt {
            rq = rq.bearer_auth(j);
        }
        Self::check(rq.send().await.map_err(|e| PlatformError::Http(e.to_string()))?, nsid).await
    }

    async fn session(&self, account: &AccountRef) -> Result<Session, PlatformError> {
        let (Some(id), Some(pw)) = (&self.cfg.identifier, &self.cfg.app_password) else {
            return Err(PlatformError::NoCredentials);
        };
        let r = self.procedure("com.atproto.server.createSession", json!({"identifier": id, "password": pw}), None).await?;
        let did = r["did"].as_str().unwrap_or_default().to_string();
        if did != account.account_id {
            // the credentials are for another account: never write there
            return Err(PlatformError::NoCredentials);
        }
        Ok(Session { did, jwt: r["accessJwt"].as_str().unwrap_or_default().to_string() })
    }

    async fn did_of(&self, actor: &str) -> Result<String, PlatformError> {
        if actor.starts_with("did:") {
            return Ok(actor.to_string());
        }
        let r = self.query(&self.cfg.appview, "com.atproto.identity.resolveHandle", &[("handle", actor)], None).await?;
        r["did"].as_str().map(String::from).ok_or_else(|| PlatformError::NotFound(actor.into()))
    }

    /// Read the profile record, change its description, write it back. Other fields are kept, and the
    /// write is conditional on the record not having changed in between.
    async fn edit_bio(&self, account: &AccountRef, edit: impl Fn(&str) -> Option<String>) -> Result<(), PlatformError> {
        let s = self.session(account).await?;
        let got = self
            .query(&self.cfg.pds, "com.atproto.repo.getRecord", &[("repo", &s.did), ("collection", "app.bsky.actor.profile"), ("rkey", "self")], Some(&s.jwt))
            .await;
        let (mut record, cid) = match got {
            Ok(v) => (v["value"].clone(), v["cid"].as_str().map(String::from)),
            Err(PlatformError::NotFound(_)) => (json!({"$type": "app.bsky.actor.profile"}), None),
            Err(e) => return Err(e),
        };
        let old = record["description"].as_str().unwrap_or_default().to_string();
        let Some(new) = edit(&old) else { return Ok(()) };
        if new.chars().count() > 256 {
            return Err(PlatformError::Http("bio would exceed Bluesky's 256 characters; shorten it or use a post".into()));
        }
        record["description"] = json!(new);
        let mut body = json!({"repo": s.did, "collection": "app.bsky.actor.profile", "rkey": "self", "record": record});
        if let Some(c) = cid {
            body["swapRecord"] = json!(c);
        }
        self.procedure("com.atproto.repo.putRecord", body, Some(&s.jwt)).await?;
        Ok(())
    }
}

/// Handle or DID from what a person types: "@name.bsky.social", "name.bsky.social", a DID, or a
/// bsky.app profile URL.
fn actor_of(input: &str) -> String {
    let s = input.trim();
    let s = match s.find("/profile/") {
        Some(i) => s[i + 9..].split('/').next().unwrap_or_default(),
        None => s,
    };
    let s = s.trim_start_matches('@');
    if s.starts_with("did:") {
        s.to_string()
    } else {
        s.to_lowercase()
    }
}

fn now_rfc3339() -> String {
    // seconds since epoch → UTC timestamp, without pulling in a date library
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[async_trait]
impl Platform for Bluesky {
    fn id(&self) -> &'static str {
        "bluesky"
    }
    fn display_name(&self) -> &'static str {
        "Bluesky"
    }

    async fn resolve_account(&self, handle_or_url: &str) -> Result<AccountRef, PlatformError> {
        let actor = actor_of(handle_or_url);
        let p = self.query(&self.cfg.appview, "app.bsky.actor.getProfile", &[("actor", &actor)], None).await?;
        let did = p["did"].as_str().ok_or_else(|| PlatformError::NotFound(actor.clone()))?;
        Ok(AccountRef { platform: "bluesky".into(), account_id: did.into(), handle: p["handle"].as_str().unwrap_or(&actor).into() })
    }

    async fn publish_code(&self, account: &AccountRef, code: &str, placement: CodePlacement) -> Result<(), PlatformError> {
        match placement {
            CodePlacement::Bio => {
                self.edit_bio(account, |old| {
                    if old.contains(code) {
                        None
                    } else if old.is_empty() {
                        Some(code.to_string())
                    } else {
                        Some(format!("{old}\n{code}"))
                    }
                })
                .await
            }
            CodePlacement::Post => {
                let s = self.session(account).await?;
                let record = json!({
                    "$type": "app.bsky.feed.post",
                    "text": format!("Verifying that one enrolled person runs this account: {code}"),
                    "createdAt": now_rfc3339(),
                    "langs": ["en"],
                });
                self.procedure("com.atproto.repo.createRecord", json!({"repo": s.did, "collection": "app.bsky.feed.post", "record": record}), Some(&s.jwt)).await?;
                Ok(())
            }
        }
    }

    async fn remove_code(&self, account: &AccountRef, code: &str) -> Result<(), PlatformError> {
        self.edit_bio(account, |old| old.contains(code).then(|| old.replace(code, "").trim().to_string())).await
    }

    async fn public_texts(&self, account: &AccountRef) -> Result<Vec<String>, PlatformError> {
        let p = self.query(&self.cfg.appview, "app.bsky.actor.getProfile", &[("actor", &account.account_id)], None).await?;
        let mut v = vec![p["description"].as_str().unwrap_or_default().to_string()];
        let f = self
            .query(&self.cfg.appview, "app.bsky.feed.getAuthorFeed", &[("actor", &account.account_id), ("limit", "30"), ("filter", "posts_no_replies")], None)
            .await?;
        if let Some(items) = f["feed"].as_array() {
            for it in items {
                // reposts appear in an author feed; only the account's own posts count
                if it["post"]["author"]["did"].as_str() == Some(&account.account_id) {
                    if let Some(t) = it["post"]["record"]["text"].as_str() {
                        v.push(t.to_string());
                    }
                }
            }
        }
        Ok(v)
    }

    async fn canonical_post_id(&self, raw: &str) -> Result<String, PlatformError> {
        let raw = raw.trim();
        let (actor, rkey) = if let Some(rest) = raw.strip_prefix("at://") {
            let mut p = rest.split('/');
            match (p.next(), p.next(), p.next()) {
                (Some(a), Some("app.bsky.feed.post"), Some(k)) => (a.to_string(), k.to_string()),
                _ => return Err(PlatformError::NotFound(raw.into())),
            }
        } else if let (Some(i), Some(j)) = (raw.find("/profile/"), raw.find("/post/")) {
            if j < i + 9 {
                return Err(PlatformError::NotFound(raw.into()));
            }
            let key = raw[j + 6..].split(['/', '?', '#']).next().unwrap_or_default();
            (actor_of(&raw[i + 9..j]), key.to_string())
        } else {
            return Err(PlatformError::NotFound(raw.into()));
        };
        if rkey.is_empty() || !rkey.chars().all(|c| c.is_ascii_alphanumeric() || "-._~:".contains(c)) {
            return Err(PlatformError::NotFound(raw.into()));
        }
        Ok(format!("at://{}/app.bsky.feed.post/{rkey}", self.did_of(&actor).await?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::{Query, State},
        http::{HeaderMap, StatusCode},
        routing::{get, post},
        Json, Router,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// A fake PDS + AppView with one account, enough to exercise the adapter's requests.
    #[derive(Default)]
    struct Fake {
        profile: Value,
        cid: u32,
        posts: Vec<String>,
    }
    type St = Arc<Mutex<Fake>>;
    const DID: &str = "did:plc:alice123";
    type R = Result<Json<Value>, (StatusCode, Json<Value>)>;

    fn xerr(e: &str) -> (StatusCode, Json<Value>) {
        (StatusCode::BAD_REQUEST, Json(json!({"error": e, "message": e})))
    }
    fn authed(h: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
        if h.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer jwt-alice") {
            Ok(())
        } else {
            Err((StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthMissing"}))))
        }
    }

    async fn fake() -> String {
        let st: St = Arc::new(Mutex::new(Fake { profile: json!({"$type": "app.bsky.actor.profile", "displayName": "Alice", "description": "Hi"}), cid: 1, posts: vec![] }));
        let app = Router::new()
            .route(
                "/xrpc/com.atproto.identity.resolveHandle",
                get(|Query(q): Query<HashMap<String, String>>| async move {
                    if q["handle"] == "alice.test" { Ok(Json(json!({"did": DID}))) } else { Err(xerr("InvalidRequest")) }
                }),
            )
            .route(
                "/xrpc/app.bsky.actor.getProfile",
                get(|State(s): State<St>, Query(q): Query<HashMap<String, String>>| async move {
                    if q["actor"] != "alice.test" && q["actor"] != DID {
                        return Err(xerr("InvalidRequest"));
                    }
                    let d = s.lock().unwrap().profile["description"].clone();
                    let r: R = Ok(Json(json!({"did": DID, "handle": "alice.test", "description": d})));
                    r
                }),
            )
            .route(
                "/xrpc/app.bsky.feed.getAuthorFeed",
                get(|State(s): State<St>| async move {
                    let mut feed: Vec<Value> = s.lock().unwrap().posts.iter().map(|t| json!({"post": {"author": {"did": DID}, "record": {"text": t}}})).collect();
                    feed.push(json!({"post": {"author": {"did": "did:plc:other"}, "record": {"text": "reposted pop1-aaaa-aaaa-aaaa"}}}));
                    Json(json!({"feed": feed}))
                }),
            )
            .route(
                "/xrpc/com.atproto.server.createSession",
                post(|Json(b): Json<Value>| async move {
                    if b["identifier"] == "alice.test" && b["password"] == "app-pw" {
                        Ok(Json(json!({"did": DID, "accessJwt": "jwt-alice"})))
                    } else {
                        Err((StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationRequired"}))))
                    }
                }),
            )
            .route(
                "/xrpc/com.atproto.repo.getRecord",
                get(|State(s): State<St>, h: HeaderMap| async move {
                    authed(&h)?;
                    let f = s.lock().unwrap();
                    let r: R = Ok(Json(json!({"value": f.profile, "cid": format!("cid{}", f.cid)})));
                    r
                }),
            )
            .route(
                "/xrpc/com.atproto.repo.putRecord",
                post(|State(s): State<St>, h: HeaderMap, Json(b): Json<Value>| async move {
                    authed(&h)?;
                    let mut f = s.lock().unwrap();
                    if b["swapRecord"] != json!(format!("cid{}", f.cid)) || b["repo"] != DID {
                        return Err(xerr("InvalidSwap"));
                    }
                    f.profile = b["record"].clone();
                    f.cid += 1;
                    let r: R = Ok(Json(json!({})));
                    r
                }),
            )
            .route(
                "/xrpc/com.atproto.repo.createRecord",
                post(|State(s): State<St>, h: HeaderMap, Json(b): Json<Value>| async move {
                    authed(&h)?;
                    assert_eq!(b["record"]["$type"], "app.bsky.feed.post");
                    assert!(b["record"]["createdAt"].as_str().unwrap().ends_with('Z'));
                    s.lock().unwrap().posts.push(b["record"]["text"].as_str().unwrap().to_string());
                    let r: R = Ok(Json(json!({})));
                    r
                }),
            )
            .with_state(st);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        format!("http://{addr}")
    }

    fn adapter(base: &str, pw: Option<&str>) -> Bluesky {
        Bluesky::new(BlueskyConfig { appview: base.into(), pds: base.into(), identifier: pw.map(|_| "alice.test".into()), app_password: pw.map(String::from) })
    }

    #[tokio::test]
    async fn read_write_against_fake_xrpc() {
        let base = fake().await;
        let b = adapter(&base, Some("app-pw"));
        let a = b.resolve_account("https://bsky.app/profile/Alice.Test").await.unwrap();
        assert_eq!((a.account_id.as_str(), a.handle.as_str()), (DID, "alice.test"));
        let code = "pop1-abcd-efgh-ijkm";
        b.publish_code(&a, code, CodePlacement::Bio).await.unwrap();
        b.publish_code(&a, code, CodePlacement::Bio).await.unwrap(); // idempotent
        let t = b.public_texts(&a).await.unwrap();
        assert_eq!(t[0], format!("Hi\n{code}"));
        b.publish_code(&a, code, CodePlacement::Post).await.unwrap();
        let t = b.public_texts(&a).await.unwrap();
        assert_eq!(t.len(), 2, "other people's reposted text is ignored");
        assert!(t[1].contains(code));
        b.remove_code(&a, code).await.unwrap();
        assert_eq!(b.public_texts(&a).await.unwrap()[0], "Hi");
        assert!(matches!(b.resolve_account("nobody.test").await, Err(PlatformError::NotFound(_))));
    }

    #[tokio::test]
    async fn no_credentials_and_wrong_account() {
        let base = fake().await;
        let a = AccountRef { platform: "bluesky".into(), account_id: DID.into(), handle: "alice.test".into() };
        assert!(matches!(adapter(&base, None).publish_code(&a, "c", CodePlacement::Bio).await, Err(PlatformError::NoCredentials)));
        let other = AccountRef { account_id: "did:plc:bob".into(), ..a };
        assert!(matches!(adapter(&base, Some("app-pw")).publish_code(&other, "c", CodePlacement::Bio).await, Err(PlatformError::NoCredentials)));
    }

    #[tokio::test]
    async fn post_ids_are_canonical() {
        let base = fake().await;
        let b = adapter(&base, None);
        let want = format!("at://{DID}/app.bsky.feed.post/3kabc");
        assert_eq!(b.canonical_post_id("https://bsky.app/profile/alice.test/post/3kabc?x=1").await.unwrap(), want);
        assert_eq!(b.canonical_post_id(&format!("https://bsky.app/profile/{DID}/post/3kabc")).await.unwrap(), want);
        assert_eq!(b.canonical_post_id(&want).await.unwrap(), want);
        assert!(b.canonical_post_id("https://bsky.app/profile/alice.test").await.is_err());
    }

    #[test]
    fn timestamp_shape() {
        let t = now_rfc3339();
        assert_eq!(t.len(), 24);
        assert!(t.starts_with("20"));
    }
}
