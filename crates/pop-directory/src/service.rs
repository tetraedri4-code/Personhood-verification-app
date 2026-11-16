use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use pop_crypto::{dates, fingerprint, root_from_hex, Day, IssuerPublicKey, Scheme, VerifyCtx, WitnessPublicKey};
use pop_protocol::api::*;
use pop_protocol::platform::{PlatformError, PlatformRegistry};
use pop_protocol::{binding_code, binding_context, context_id, withdraw_context, AccountRef};
use pop_storage::SharedStore;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use tower_http::cors::CorsLayer;

pub type Clock = Arc<dyn Fn() -> Day + Send + Sync>;

#[derive(Default)]
pub struct DirectoryConfig {
    pub clock: Option<Clock>,
}

pub struct Directory {
    scheme: Arc<Scheme>,
    issuer_api: Arc<dyn IssuerApi>,
    issuer_pk: IssuerPublicKey,
    witness_pk: WitnessPublicKey,
    roots: RwLock<(String, Option<String>)>,
    platforms: PlatformRegistry,
    store: SharedStore,
    cfg: DirectoryConfig,
    write: tokio::sync::Mutex<()>,
}

const T_BIND: &str = "bindings";
const T_NYM: &str = "nyms";
const T_LIKES: &str = "likes";
const T_COUNTS: &str = "like_counts";
const T_NONCES: &str = "nonces";
const MAX_FIELD: usize = 256;

fn key(a: &str, b: &str) -> String {
    format!("{a}|{b}")
}

impl Directory {
    /// Fetch the issuer's public parameters (and LegoGroth16 verifying keys) and start.
    pub async fn connect(issuer_api: Arc<dyn IssuerApi>, platforms: PlatformRegistry, store: SharedStore, cfg: DirectoryConfig) -> anyhow::Result<Arc<Self>> {
        let p = issuer_api.params().await?;
        let scheme = Arc::new(Scheme::new(p.config.clone()));
        for k in &p.statements {
            scheme.install_lego_keys(*k, &issuer_api.lego_keys(*k).await?)?;
        }
        let rv = issuer_api.revocations().await?;
        Ok(Arc::new(Directory {
            scheme,
            issuer_pk: IssuerPublicKey::from_hex(&p.issuer_public_key)?,
            witness_pk: WitnessPublicKey::from_hex(&p.witness_public_key)?,
            issuer_api,
            roots: RwLock::new((rv.root, rv.previous_root)),
            platforms,
            store,
            cfg,
            write: tokio::sync::Mutex::new(()),
        }))
    }

    pub fn today(&self) -> Day {
        self.cfg.clock.as_ref().map(|c| c()).unwrap_or_else(dates::today)
    }

    /// Accept a proof's revocation root if it is the issuer's current or previous one.
    async fn check_root(&self, root: &str) -> Result<(), ApiErr> {
        let known = |r: &(String, Option<String>)| r.0 == root || r.1.as_deref() == Some(root);
        if known(&self.roots.read().unwrap()) {
            return Ok(());
        }
        let rv = self.issuer_api.revocations().await.map_err(|e| err(StatusCode::BAD_GATEWAY, e.to_string()))?;
        let mut w = self.roots.write().unwrap();
        *w = (rv.root, rv.previous_root);
        if known(&w) {
            Ok(())
        } else {
            Err(err(StatusCode::CONFLICT, "stale revocation root; fetch the issuer's /v1/revocations and prove again"))
        }
    }

    /// Contexts are named by the operator: only platforms this directory was started with are accepted.
    /// Without this, an enrolled person could fill the store with bindings on made-up platforms.
    fn platform(&self, id: &str) -> Result<Arc<dyn pop_protocol::platform::Platform>, ApiErr> {
        self.platforms.get(id).ok_or_else(|| err(StatusCode::BAD_REQUEST, "unknown platform"))
    }

    /// A proof is accepted once. Binding records are public, so without this anyone could replay a
    /// published proof the same day, for example to bring back a badge its owner just withdrew.
    async fn use_nonce(&self, kind: &str, platform: &str, nonce: &str) -> Result<(), ApiErr> {
        if nonce.len() < 16 || nonce.len() > 64 {
            return Err(err(StatusCode::BAD_REQUEST, "bad nonce"));
        }
        let today = self.today();
        // proofs are valid for the day they name, plus or minus one: older nonces can go
        for (k, v) in self.store.list(T_NONCES).await? {
            if v.as_u64().map(|d| (d as Day) + 3 < today).unwrap_or(true) {
                self.store.delete(T_NONCES, &k).await?;
            }
        }
        if !self.store.insert_new(T_NONCES, &format!("{kind}|{platform}|{nonce}"), json!(today)).await? {
            return Err(err(StatusCode::CONFLICT, "this proof was already used"));
        }
        Ok(())
    }

    fn check_day(&self, d: Day) -> Result<(), ApiErr> {
        if d.abs_diff(self.today()) > 1 {
            return Err(err(StatusCode::BAD_REQUEST, "date out of window"));
        }
        Ok(())
    }

    fn vc(&self, today: Day, root: &str) -> Result<VerifyCtx<'_>, ApiErr> {
        Ok(VerifyCtx { issuer: &self.issuer_pk, witness: &self.witness_pk, today, revocation_root: root_from_hex(root)? })
    }

    /// Look for the code in the account's public texts, if the platform adapter can read them.
    async fn code_check(&self, entry: &mut BindingEntry) {
        let Some(p) = self.platforms.get(&entry.platform) else { return };
        let acct = AccountRef { platform: entry.platform.clone(), account_id: entry.account_id.clone(), handle: entry.handle.clone() };
        match p.public_texts(&acct).await {
            Ok(texts) => {
                if texts.iter().any(|t| t.to_lowercase().contains(&entry.code)) {
                    entry.code_seen_on = Some(self.today());
                } else {
                    entry.code_seen_on = None;
                }
            }
            Err(PlatformError::Unsupported(_)) => {}
            Err(e) => tracing::warn!("code check for {} failed: {e}", entry.account_id),
        }
    }

    async fn bind(&self, mut req: BindRequest) -> Result<BindingEntry, ApiErr> {
        self.check_day(req.today)?;
        if req.account_id.is_empty() || req.account_id.len() > MAX_FIELD || req.handle.is_empty() || req.handle.len() > MAX_FIELD {
            return Err(err(StatusCode::BAD_REQUEST, "bad account"));
        }
        let p = self.platform(&req.platform)?;
        self.check_root(&req.revocation_root).await?;
        let ctx = context_id(&req.platform);
        let bind = binding_context(&req.platform, &req.account_id, &req.nonce);
        self.scheme.verify_binding(&self.vc(req.today, &req.revocation_root)?, &ctx, &bind, &req.proof).map_err(|e| err(StatusCode::UNAUTHORIZED, e.to_string()))?;
        // where the platform can resolve handles, the handle must belong to the account id, and the
        // list shows the platform's spelling of it, not the submitter's
        match p.resolve_account(&req.handle).await {
            Ok(a) if a.account_id != req.account_id => return Err(err(StatusCode::BAD_REQUEST, "handle does not belong to this account")),
            Ok(a) => req.handle = a.handle,
            Err(PlatformError::Unsupported(_)) => {}
            Err(PlatformError::NotFound(_)) => return Err(err(StatusCode::BAD_REQUEST, "account not found on the platform")),
            Err(e) => return Err(err(StatusCode::BAD_GATEWAY, e.to_string())),
        }
        let _g = self.write.lock().await;
        self.use_nonce("bind", &req.platform, &req.nonce).await?;
        let today = self.today();
        let mut entry = BindingEntry {
            platform: req.platform.clone(),
            account_id: req.account_id.clone(),
            handle: req.handle.clone(),
            code: binding_code(&req.platform, &req.account_id, &req.proof.nym),
            slot: req.proof.slot,
            nym: fingerprint(&req.proof.nym),
            bound_on: today,
            lease_until: today + dates::LEASE_DAYS,
            counted: req.proof.probation_cleared,
            code_seen_on: None,
        };
        // A pseudonym is bound to one account at a time: re-binding moves it.
        // An account may have several claims, each from a different pseudonym: anyone enrolled can
        // submit a proof naming any account, so a new claim must never push out an existing one. Which
        // claim is real is decided by the code on the account, seen by this server or by a viewer.
        let fp = fingerprint(&req.proof.nym);
        let nk = key(&req.platform, &req.proof.nym);
        let bk = format!("{}|{}|{}", req.platform, req.account_id, fp);
        if let Some(prev) = self.store.get(T_NYM, &nk).await? {
            let prev = prev.as_str().unwrap_or_default().to_string();
            if prev != req.account_id {
                self.store.delete(T_BIND, &format!("{}|{}|{}", req.platform, prev, fp)).await?;
            }
        }
        self.code_check(&mut entry).await;
        let rec = BindingRecord { entry: entry.clone(), request: req.clone() };
        self.store.put(T_NYM, &nk, json!(req.account_id)).await?;
        self.store.put(T_BIND, &bk, serde_json::to_value(rec)?).await?;
        Ok(entry)
    }

    /// All claims on an account.
    async fn records(&self, platform: &str, account_id: &str) -> Result<Vec<BindingRecord>, ApiErr> {
        let prefix = format!("{platform}|{account_id}|");
        Ok(self
            .store
            .list(T_BIND)
            .await?
            .into_iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .filter_map(|(_, v)| serde_json::from_value::<BindingRecord>(v).ok())
            .filter(|r| r.entry.platform == platform && r.entry.account_id == account_id)
            .collect())
    }

    async fn withdraw(&self, req: WithdrawRequest) -> Result<(), ApiErr> {
        self.check_day(req.today)?;
        self.platform(&req.platform)?;
        self.check_root(&req.revocation_root).await?;
        if !self.records(&req.platform, &req.account_id).await?.iter().any(|r| r.request.proof.nym == req.proof.nym) {
            return Err(err(StatusCode::NOT_FOUND, "this pseudonym has no binding on this account"));
        }
        let bind = withdraw_context(&req.platform, &req.account_id, &req.nonce);
        self.scheme
            .verify_binding(&self.vc(req.today, &req.revocation_root)?, &context_id(&req.platform), &bind, &req.proof)
            .map_err(|e| err(StatusCode::UNAUTHORIZED, e.to_string()))?;
        let _g = self.write.lock().await;
        self.use_nonce("withdraw", &req.platform, &req.nonce).await?;
        self.store.delete(T_BIND, &format!("{}|{}|{}", req.platform, req.account_id, fingerprint(&req.proof.nym))).await?;
        self.store.delete(T_NYM, &key(&req.platform, &req.proof.nym)).await?;
        Ok(())
    }

    async fn like(&self, req: LikeRequest) -> Result<LikeResponse, ApiErr> {
        self.check_day(req.today)?;
        self.check_root(&req.revocation_root).await?;
        // only ids in the platform's canonical form: one post, one id, and no free-text keys in the store
        let p = self.platform(&req.platform)?;
        if req.post_id.is_empty() || req.post_id.len() > MAX_FIELD || p.canonical_post_id(&req.post_id).await.ok().as_deref() != Some(req.post_id.as_str()) {
            return Err(err(StatusCode::BAD_REQUEST, "post id is not in the platform's canonical form"));
        }
        self.scheme
            .verify_like(&self.vc(req.today, &req.revocation_root)?, &context_id(&req.platform), &req.post_id, &req.proof)
            .map_err(|e| err(StatusCode::UNAUTHORIZED, e.to_string()))?;
        let _g = self.write.lock().await;
        let pk = key(&req.platform, &req.post_id);
        let new = self.store.insert_new(T_LIKES, &key(&pk, &req.proof.tag), json!({"on": req.today})).await?;
        let mut count = self.store.get(T_COUNTS, &pk).await?.and_then(|v| v.as_u64()).unwrap_or(0);
        if new {
            count += 1;
            self.store.put(T_COUNTS, &pk, json!(count)).await?;
        }
        Ok(LikeResponse { new, count })
    }
}

// ------------------------------------------------------------------ HTTP

pub struct ApiErr(StatusCode, String);

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}

impl<E: std::fmt::Display> From<E> for ApiErr {
    fn from(e: E) -> Self {
        ApiErr(StatusCode::BAD_REQUEST, e.to_string())
    }
}

fn err(code: StatusCode, msg: impl Into<String>) -> ApiErr {
    ApiErr(code, msg.into())
}

type St = Arc<Directory>;

/// The directory is read from browser extensions on any page, so its read endpoints allow any origin.
/// It sets no cookies and needs no credentials.
pub fn router(d: Arc<Directory>) -> Router {
    Router::new()
        .route("/v1/bindings", get(list).post(bind))
        .route("/v1/bindings/withdraw", post(withdraw))
        .route("/v1/bindings/recheck", post(recheck))
        .route("/v1/bindings/:platform/:account", get(record))
        .route("/v1/likes", post(like))
        .route("/v1/likes/counts", post(counts))
        .route("/v1/likes/table", get(table))
        .layer(CorsLayer::permissive())
        .with_state(d)
}

#[derive(Deserialize)]
struct ListQ {
    platform: String,
}

async fn list(State(d): State<St>, Query(q): Query<ListQ>) -> Result<Json<BindingList>, ApiErr> {
    let today = d.today();
    let prefix = format!("{}|", q.platform);
    let mut entries: Vec<BindingEntry> = d
        .store
        .list(T_BIND)
        .await?
        .into_iter()
        .filter(|(k, _)| k.starts_with(&prefix))
        .filter_map(|(_, v)| serde_json::from_value::<BindingRecord>(v).ok())
        .map(|r| r.entry)
        .filter(|e| e.lease_until >= today)
        .collect();
    entries.sort_by(|a, b| a.account_id.cmp(&b.account_id));
    Ok(Json(BindingList { platform: q.platform, today, entries }))
}

async fn bind(State(d): State<St>, Json(req): Json<BindRequest>) -> Result<Json<BindingEntry>, ApiErr> {
    Ok(Json(d.bind(req).await?))
}

async fn withdraw(State(d): State<St>, Json(req): Json<WithdrawRequest>) -> Result<Json<serde_json::Value>, ApiErr> {
    d.withdraw(req).await?;
    Ok(Json(json!({"withdrawn": true})))
}

#[derive(Deserialize)]
struct RecheckReq {
    platform: String,
    account_id: String,
}

async fn recheck(State(d): State<St>, Json(r): Json<RecheckReq>) -> Result<Json<Vec<BindingEntry>>, ApiErr> {
    let mut out = vec![];
    for mut rec in d.records(&r.platform, &r.account_id).await? {
        d.code_check(&mut rec.entry).await;
        let _g = d.write.lock().await;
        let k = format!("{}|{}|{}", r.platform, r.account_id, fingerprint(&rec.request.proof.nym));
        // only update a claim that still exists (it may have been withdrawn meanwhile)
        if d.store.get(T_BIND, &k).await?.is_some() {
            d.store.put(T_BIND, &k, serde_json::to_value(&rec)?).await?;
            out.push(rec.entry);
        }
    }
    Ok(Json(out))
}

async fn record(State(d): State<St>, Path((platform, account)): Path<(String, String)>) -> Result<Json<Vec<BindingRecord>>, ApiErr> {
    Ok(Json(d.records(&platform, &account).await?))
}

async fn like(State(d): State<St>, Json(req): Json<LikeRequest>) -> Result<Json<LikeResponse>, ApiErr> {
    Ok(Json(d.like(req).await?))
}

async fn counts(State(d): State<St>, Json(req): Json<CountsRequest>) -> Result<Json<CountsResponse>, ApiErr> {
    if req.posts.len() > 500 {
        return Err(err(StatusCode::BAD_REQUEST, "at most 500 posts per request"));
    }
    let mut counts = BTreeMap::new();
    for p in req.posts {
        let c = d.store.get(T_COUNTS, &key(&req.platform, &p)).await?.and_then(|v| v.as_u64()).unwrap_or(0);
        counts.insert(p, c);
    }
    Ok(Json(CountsResponse { counts }))
}

/// Every non-zero count of a platform. Extensions download this whole table instead of asking about the
/// posts on a page, so the directory does not learn what anyone reads. At scale this becomes a bucketed
/// download (docs/real-servers.md).
async fn table(State(d): State<St>, Query(q): Query<ListQ>) -> Result<Json<CountsResponse>, ApiErr> {
    let prefix = format!("{}|", q.platform);
    let counts = d
        .store
        .list(T_COUNTS)
        .await?
        .into_iter()
        .filter_map(|(k, v)| Some((k.strip_prefix(&prefix)?.to_string(), v.as_u64()?)))
        .collect();
    Ok(Json(CountsResponse { counts }))
}
