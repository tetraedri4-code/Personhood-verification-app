use crate::uniqueness::{DedupKey, UniquenessService};
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use pop_crypto::{dates, root_to_hex, BlindSignature, Day, IssuedAttrs, IssuerKey, Scheme, StatementKind, VerifyCtx, WitnessKey};
use pop_idp::{IdentityProvider, Loa};
use pop_protocol::api::*;
use pop_storage::SharedStore;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

pub type Clock = Arc<dyn Fn() -> Day + Send + Sync>;

pub struct IssuerConfig {
    /// directory for keys (issuer, witness, LegoGroth16); None = fresh keys in memory
    pub keys_dir: Option<PathBuf>,
    /// published provider code of `idp` (attribute e)
    pub provider_code: u32,
    /// minimum level of assurance at enrolment. The design asks "high"; Finnish bank IDs are "substantial".
    pub min_loa: Loa,
    /// Rollout window (design §4.5): while set, secrets count as certified on this quarter start, so a
    /// launch gives counted badges at once. None = probation runs nine months from enrolment.
    pub rollout_certified: Option<Day>,
    /// override "today" (tests)
    pub clock: Option<Clock>,
}

impl Default for IssuerConfig {
    fn default() -> Self {
        IssuerConfig { keys_dir: None, provider_code: 1, min_loa: Loa::Substantial, rollout_certified: None, clock: None }
    }
}

struct RevState {
    epoch: u64,
    revoked: Vec<u64>,
    root: String,
    previous_root: Option<String>,
    tree: pop_crypto::revtree::RevocationTree,
}

pub struct Issuer {
    scheme: Arc<Scheme>,
    key: IssuerKey,
    witness: WitnessKey,
    lego: HashMap<StatementKind, Vec<u8>>,
    idp: Arc<dyn IdentityProvider>,
    uniq: Arc<dyn UniquenessService>,
    store: SharedStore,
    cfg: IssuerConfig,
    rev: RwLock<RevState>,
    rng: Mutex<ChaCha20Rng>,
}

const T_SESSIONS: &str = "enrol_sessions";
const T_STATES: &str = "enrol_states";
const T_ENROL: &str = "enrolments";
const T_REVOKED: &str = "revoked";

/// An enrolment session lives this long; the identity check and the blind issuance must fit in it.
const SESSION_TTL_SECS: u64 = 15 * 60;
const MAX_CONFIRM_ATTEMPTS: u32 = 5;
const MAX_OPEN_SESSIONS: usize = 10_000;

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Serialize, Deserialize, Clone)]
struct Session {
    /// `state` sent through the browser and the identity provider. It is NOT the session id: the
    /// session id is known only to the holder app, so neither the provider nor anyone who sees the
    /// redirect can finish the enrolment.
    state: String,
    created: u64,
    /// shown in the browser after login, typed into the app
    confirm_code: Option<String>,
    attempts: u32,
    nonce: String,
    status: EnrolStatus,
    dedup: Option<String>,
    /// uniqueness key version `dedup` was computed under
    #[serde(default)]
    dedup_version: Option<String>,
    country: Option<u32>,
    error: Option<String>,
}

/// Enrolment record d ↦ (r, guardian key, status). The identity code itself is never stored.
#[derive(Serialize, Deserialize, Clone)]
struct Enrolment {
    handle: u64,
    guardian: String,
    status: String,
    enrolled_on: Day,
    /// Version of the uniqueness key the record's key d was computed under. d is only comparable with
    /// values made under the same key, so a record without its key is a record nobody can match.
    #[serde(default)]
    key_version: String,
}

fn load_or<T>(dir: &Option<PathBuf>, name: &str, make: impl FnOnce() -> (T, Vec<u8>), parse: impl FnOnce(&[u8]) -> Option<T>) -> T {
    if let Some(d) = dir {
        let p = d.join(name);
        if let Ok(b) = std::fs::read(&p) {
            if let Some(v) = parse(&b) {
                return v;
            }
        }
        let (v, b) = make();
        std::fs::create_dir_all(d).ok();
        std::fs::write(&p, b).expect("write key file");
        v
    } else {
        make().0
    }
}

impl Issuer {
    pub async fn new(
        scheme: Arc<Scheme>,
        idp: Arc<dyn IdentityProvider>,
        uniq: Arc<dyn UniquenessService>,
        store: SharedStore,
        cfg: IssuerConfig,
    ) -> anyhow::Result<Arc<Self>> {
        let mut rng = ChaCha20Rng::from_entropy();
        let key = load_or(&cfg.keys_dir, "issuer.key", || { let k = IssuerKey::generate(&mut rng); let b = k.to_bytes(); (k, b) }, |b| IssuerKey::from_bytes(b).ok());
        let witness = load_or(&cfg.keys_dir, "witness.key", || { let k = WitnessKey::generate(&mut rng); let b = k.to_bytes(); (k, b) }, |b| WitnessKey::from_bytes(b).ok());
        let mut lego = HashMap::new();
        if scheme.config.proof_system == pop_crypto::ProofSystem::LegoGroth16 {
            for kind in StatementKind::ALL {
                let name = format!("lego-{}-d{}.bin", kind.name(), scheme.config.tree_depth);
                let sch = scheme.clone();
                let bytes = load_or(
                    &cfg.keys_dir,
                    &name,
                    || {
                        tracing::info!("LegoGroth16 setup for statement {} (one-time)", kind.name());
                        let b = sch.lego_setup(&mut rng, kind);
                        (b.clone(), b)
                    },
                    |b| Some(b.to_vec()),
                );
                scheme.install_lego_keys(kind, &bytes)?;
                lego.insert(kind, bytes);
            }
        }
        let revoked: Vec<u64> = store.list(T_REVOKED).await?.iter().filter_map(|(k, _)| k.parse().ok()).collect();
        let tree = scheme.revocation_tree(&revoked)?;
        check_key_versions(&*uniq, &store).await?;
        let rev = RevState { epoch: 0, root: root_to_hex(&tree.root()), previous_root: None, revoked, tree };
        Ok(Arc::new(Issuer { scheme, key, witness, lego, idp, uniq, store, cfg, rev: RwLock::new(rev), rng: Mutex::new(rng) }))
    }

    pub fn today(&self) -> Day {
        self.cfg.clock.as_ref().map(|c| c()).unwrap_or_else(dates::today)
    }

    fn rand_hex(&self, n: usize) -> String {
        let mut b = vec![0u8; n];
        self.rng.lock().unwrap().fill_bytes(&mut b);
        hex::encode(b)
    }

    pub fn params(&self) -> Params {
        let mut providers = BTreeMap::new();
        providers.insert(self.cfg.provider_code, self.idp.name().to_string());
        Params {
            config: self.scheme.config.clone(),
            issuer_public_key: self.key.public.to_hex(),
            witness_public_key: self.witness.public.to_hex(),
            statements: self.lego.keys().copied().collect(),
            today: self.today(),
            providers,
        }
    }

    fn attrs_for(&self, handle: u64) -> IssuedAttrs {
        let today = self.today();
        let q = dates::quarter_of(today);
        // valid to the end of this quarter, or of the next one if fewer than 30 days remain
        let expiry = if dates::quarter_end(q) - today < 30 { dates::quarter_end(q + 1) } else { dates::quarter_end(q) };
        let certified = self.cfg.rollout_certified.unwrap_or_else(|| dates::quarter_start(q));
        IssuedAttrs {
            handle,
            expiry,
            certified,
            last_check: dates::month_start(today),
            country: 246,
            first_quarter: q,
            provider: self.cfg.provider_code,
        }
    }

    async fn revoke_handle(&self, handle: u64) -> anyhow::Result<()> {
        self.store.put(T_REVOKED, &handle.to_string(), json!({"on": self.today()})).await?;
        let mut rv = self.rev.write().unwrap();
        if rv.revoked.contains(&handle) {
            return Ok(());
        }
        let mut revoked = rv.revoked.clone();
        revoked.push(handle);
        let tree = self.scheme.revocation_tree(&revoked)?;
        rv.previous_root = Some(rv.root.clone());
        rv.root = root_to_hex(&tree.root());
        rv.epoch += 1;
        rv.revoked = revoked;
        rv.tree = tree;
        Ok(())
    }

    pub fn revocations(&self) -> Revocations {
        let rv = self.rev.read().unwrap();
        Revocations { epoch: rv.epoch, revoked: rv.revoked.clone(), root: rv.root.clone(), previous_root: rv.previous_root.clone() }
    }
}

/// Fail closed: every enrolment record must be under a key version the uniqueness service still holds.
/// If a key was lost, replaced or regenerated, the records under it can no longer recognise anyone and
/// every enrolled person could enrol again. Starting anyway would silently drop the one-per-person
/// guarantee, so the issuer refuses.
async fn check_key_versions(uniq: &dyn UniquenessService, store: &SharedStore) -> anyhow::Result<()> {
    let live = uniq.versions().await?;
    anyhow::ensure!(!live.is_empty(), "the uniqueness service lists no key version");
    let mut orphans: BTreeMap<String, usize> = BTreeMap::new();
    for (_, v) in store.list(T_ENROL).await? {
        let version = v["key_version"].as_str().unwrap_or_default().to_string();
        if !live.contains(&version) {
            *orphans.entry(version).or_default() += 1;
        }
    }
    if orphans.is_empty() {
        return Ok(());
    }
    let list: Vec<String> = orphans
        .iter()
        .map(|(v, n)| if v.is_empty() { format!("{n} record(s) without a key version (made before key versions existed)") } else { format!("{n} record(s) under {v}") })
        .collect();
    anyhow::bail!(
        "refusing to start: enrolment records exist under uniqueness key version(s) this service does not hold: {}. \
         Live versions: {}. Restore the missing key (docs/real-servers.md, \"Uniqueness keys\"); starting without it \
         would let every person under it enrol a second time.",
        list.join("; "),
        live.join(", ")
    )
}

/// Outcome of looking a person up under every live key version.
enum Lookup {
    New(DedupKey),
    Enrolled,
}

impl Issuer {
    /// Look the person up under every live key version (newest first). A match under an older version
    /// is moved to the newest one, so old keys empty out as people log in.
    async fn lookup_and_migrate(&self, country: u32, subject: &str) -> Result<Lookup, ApiErr> {
        let keys = self.uniq.dedup_keys(country, subject).await.map_err(|e| {
            tracing::error!("uniqueness service failed: {e:#}");
            err(StatusCode::SERVICE_UNAVAILABLE, "the uniqueness service is not available; try again later")
        })?;
        let live = self.uniq.versions().await.map_err(|e| err(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
        // an answer that leaves a version out would let an enrolled person through as new
        if keys.is_empty() || keys.len() != live.len() || keys.iter().zip(&live).any(|(k, v)| k.version != *v) {
            tracing::error!("uniqueness service answered for {} of {} key versions", keys.len(), live.len());
            return Err(err(StatusCode::SERVICE_UNAVAILABLE, "the uniqueness service is not available; try again later"));
        }
        let current = keys[0].clone();
        for (i, k) in keys.iter().enumerate() {
            let Some(v) = self.store.get(T_ENROL, &k.d).await? else { continue };
            if i > 0 {
                let mut rec: Enrolment = serde_json::from_value(v)?;
                let from = std::mem::replace(&mut rec.key_version, current.version.clone());
                // write the new record first: a crash in between leaves two records of one person,
                // both of which still block a second enrolment
                self.store.insert_new(T_ENROL, &current.d, serde_json::to_value(&rec)?).await?;
                self.store.delete(T_ENROL, &k.d).await?;
                tracing::info!("migrated an enrolment record from key version {from} to {}", current.version);
            }
            return Ok(Lookup::Enrolled);
        }
        Ok(Lookup::New(current))
    }

    /// How many enrolment records sit under each key version (for the operator: when an old key has no
    /// records left, it can be retired).
    pub async fn records_per_key_version(&self) -> anyhow::Result<BTreeMap<String, u64>> {
        let mut m = BTreeMap::new();
        for v in self.uniq.versions().await? {
            m.insert(v, 0);
        }
        for (_, v) in self.store.list(T_ENROL).await? {
            *m.entry(v["key_version"].as_str().unwrap_or_default().to_string()).or_default() += 1;
        }
        Ok(m)
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

type St = Arc<Issuer>;

pub fn router(issuer: Arc<Issuer>) -> Router {
    Router::new()
        .route("/v1/params", get(params))
        .route("/v1/params/lego/:name", get(lego))
        .route("/v1/enrol/start", post(enrol_start))
        .route("/v1/enrol/callback", get(enrol_callback))
        .route("/v1/enrol/status", get(enrol_status))
        .route("/v1/enrol/finish", post(enrol_finish))
        .route("/v1/renew", post(renew))
        .route("/v1/revocations", get(revocations))
        .route("/v1/revoke", post(revoke))
        .with_state(issuer)
}

async fn params(State(s): State<St>) -> Json<Params> {
    Json(s.params())
}

async fn lego(State(s): State<St>, Path(name): Path<String>) -> Result<Response, ApiErr> {
    let kind = StatementKind::ALL.into_iter().find(|k| k.name() == name).ok_or_else(|| err(StatusCode::NOT_FOUND, "no such statement"))?;
    let b = s.lego.get(&kind).ok_or_else(|| err(StatusCode::NOT_FOUND, "no keys for this proof system"))?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], b.clone()).into_response())
}

async fn drop_session(s: &Issuer, id: &str, sess: &Session) -> Result<(), ApiErr> {
    s.store.delete(T_STATES, &sess.state).await?;
    s.store.delete(T_SESSIONS, id).await?;
    Ok(())
}

/// Remove expired sessions. They hold a deduplication key, which must not pile up into a log of logins.
async fn sweep_sessions(s: &Issuer) -> Result<usize, ApiErr> {
    let now = now_secs();
    let mut live = 0;
    for (id, v) in s.store.list(T_SESSIONS).await? {
        match serde_json::from_value::<Session>(v) {
            Ok(sess) if now.saturating_sub(sess.created) <= SESSION_TTL_SECS => live += 1,
            Ok(sess) => drop_session(s, &id, &sess).await?,
            Err(_) => s.store.delete(T_SESSIONS, &id).await?,
        }
    }
    Ok(live)
}

async fn enrol_start(State(s): State<St>) -> Result<Json<EnrolStartResponse>, ApiErr> {
    if sweep_sessions(&s).await? >= MAX_OPEN_SESSIONS {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many enrolments in progress; try again in a few minutes"));
    }
    let session = s.rand_hex(16);
    let state = s.rand_hex(16);
    let nonce = s.rand_hex(16);
    let url = s.idp.authorization_url(&state, &nonce).await?;
    let sess = Session { state: state.clone(), created: now_secs(), confirm_code: None, attempts: 0, nonce, status: EnrolStatus::WaitingForLogin, dedup: None, dedup_version: None, country: None, error: None };
    s.store.put(T_SESSIONS, &session, serde_json::to_value(sess)?).await?;
    s.store.put(T_STATES, &state, json!(session)).await?;
    Ok(Json(EnrolStartResponse { session, authorize_url: url }))
}

#[derive(Deserialize)]
struct CallbackQ {
    code: Option<String>,
    state: String,
    error: Option<String>,
}

async fn load_session(s: &Issuer, id: &str) -> Result<Session, ApiErr> {
    let v = s.store.get(T_SESSIONS, id).await?.ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown session"))?;
    let sess: Session = serde_json::from_value(v)?;
    if now_secs().saturating_sub(sess.created) > SESSION_TTL_SECS {
        drop_session(s, id, &sess).await?;
        return Err(err(StatusCode::GONE, "session expired; start again"));
    }
    Ok(sess)
}

fn page(msg: &str, code: Option<&str>) -> Html<String> {
    // `msg` and `code` are produced by this server only (fixed strings and digits), never by the request
    let code = code.map(|c| format!("<p>Type this code into the app:</p><p id=\"confirm-code\" style=\"font:700 2rem monospace;letter-spacing:.2em\">{c}</p><p>Only type it into the app on your own device. If someone else sent you the link that brought you here, close this page.</p>")).unwrap_or_default();
    Html(format!("<!doctype html><meta charset=utf-8><meta name=referrer content=no-referrer><title>Enrolment</title><body style=\"font-family:system-ui;max-width:30rem;margin:3rem auto;padding:0 1rem\"><h1>Enrolment</h1><p>{msg}</p>{code}"))
}

async fn enrol_callback(State(s): State<St>, Query(q): Query<CallbackQ>) -> Result<Html<String>, ApiErr> {
    let session_id = s.store.get(T_STATES, &q.state).await?.and_then(|v| v.as_str().map(String::from)).ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown session"))?;
    let mut sess = load_session(&s, &session_id).await?;
    if sess.status != EnrolStatus::WaitingForLogin {
        return Err(err(StatusCode::CONFLICT, "session already used"));
    }
    let outcome = match (q.code, q.error) {
        (Some(code), None) => match s.idp.complete(&code, &sess.nonce).await {
            Ok(id) if id.loa < s.cfg.min_loa => Err(format!("level of assurance too low: {:?}", id.loa)),
            Ok(id) => Ok(id),
            Err(e) => Err(e.to_string()),
        },
        (_, e) => Err(e.unwrap_or_else(|| "no code".into())),
    };
    let mut shown = None;
    let msg = match outcome {
        Ok(id) => {
            // d is all we keep; `id.subject` goes out of scope here
            let found = s.lookup_and_migrate(id.country, &id.subject).await?;
            let exists = matches!(found, Lookup::Enrolled);
            sess.status = if exists { EnrolStatus::AlreadyEnrolled } else { EnrolStatus::Authenticated };
            if let Lookup::New(k) = found {
                sess.dedup = Some(k.d);
                sess.dedup_version = Some(k.version);
            }
            sess.country = Some(id.country);
            if exists {
                "This person is already enrolled. Use your existing device."
            } else {
                let code = format!("{:06}", s.rng.lock().unwrap().next_u32() % 1_000_000);
                sess.confirm_code = Some(code.clone());
                shown = Some(code);
                "Identity checked."
            }
        }
        Err(e) => {
            tracing::warn!("identity check failed: {e}");
            sess.status = EnrolStatus::Failed;
            sess.error = Some(e);
            "Identity check failed. Return to the app and try again."
        }
    };
    s.store.put(T_SESSIONS, &session_id, serde_json::to_value(&sess)?).await?;
    Ok(page(msg, shown.as_deref()))
}

#[derive(Deserialize)]
struct StatusQ {
    session: String,
}

async fn enrol_status(State(s): State<St>, Query(q): Query<StatusQ>) -> Result<Json<EnrolStatus>, ApiErr> {
    Ok(Json(load_session(&s, &q.session).await?.status))
}

async fn enrol_finish(State(s): State<St>, Json(req): Json<EnrolFinishRequest>) -> Result<Json<IssuanceResponse>, ApiErr> {
    let mut sess = load_session(&s, &req.session).await?;
    match sess.status {
        EnrolStatus::Authenticated => {}
        EnrolStatus::AlreadyEnrolled => return Err(err(StatusCode::CONFLICT, "already enrolled")),
        _ => return Err(err(StatusCode::CONFLICT, format!("session not ready: {:?}", sess.status))),
    }
    sess.attempts += 1;
    if sess.attempts > MAX_CONFIRM_ATTEMPTS {
        drop_session(&s, &req.session, &sess).await?;
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many wrong codes; start again"));
    }
    s.store.put(T_SESSIONS, &req.session, serde_json::to_value(&sess)?).await?;
    if !ct_eq(sess.confirm_code.as_deref().unwrap_or_default().as_bytes(), req.confirm_code.trim().as_bytes()) || sess.confirm_code.is_none() {
        return Err(err(StatusCode::FORBIDDEN, "wrong confirmation code"));
    }
    let g = hex::decode(&req.guardian_public_key)?;
    if g.len() != 32 {
        return Err(err(StatusCode::BAD_REQUEST, "guardian key must be an Ed25519 public key"));
    }
    let (Some(d), Some(key_version)) = (sess.dedup.clone(), sess.dedup_version.clone()) else {
        return Err(err(StatusCode::CONFLICT, "session has no deduplication key; start again"));
    };
    // the key may have been rotated between login and finish; a record under a retired key would be
    // an orphan, so the person starts again under the current key
    if s.uniq.versions().await.ok().and_then(|v| v.first().cloned()).as_deref() != Some(key_version.as_str()) {
        drop_session(&s, &req.session, &sess).await?;
        return Err(err(StatusCode::CONFLICT, "the uniqueness key changed during enrolment; start again"));
    }
    let handle = loop {
        let h = (s.rng.lock().unwrap().next_u64() >> 1).max(1);
        if !s.rev.read().unwrap().revoked.contains(&h) {
            break h;
        }
    };
    let rec = Enrolment { handle, guardian: req.guardian_public_key.clone(), status: "active".into(), enrolled_on: s.today(), key_version };
    // atomic: two sessions of one person cannot both get through
    if !s.store.insert_new(T_ENROL, &d, serde_json::to_value(&rec)?).await? {
        return Err(err(StatusCode::CONFLICT, "already enrolled"));
    }
    let attrs = s.attrs_for(handle);
    let sig = {
        let mut rng = s.rng.lock().unwrap();
        s.scheme.issue_blind(&mut *rng, &s.key, &req.blind_request, &attrs, req.session.as_bytes())
    };
    let sig = match sig {
        Ok(sig) => sig,
        Err(e) => {
            s.store.delete(T_ENROL, &d).await?;
            return Err(e.into());
        }
    };
    let hs = s.witness.sign_handle(&mut *s.rng.lock().unwrap(), handle);
    // the session held the deduplication key; nothing links this enrolment to a login after this
    drop_session(&s, &req.session, &sess).await?;
    tracing::info!("enrolled a new person (handle logged, identity not stored)");
    Ok(Json(IssuanceResponse { signature: sig, attrs, handle_signature: hs.to_hex() }))
}

async fn renew(State(s): State<St>, Json(req): Json<RenewRequest>) -> Result<Json<RenewResponse>, ApiErr> {
    let today = s.today();
    if req.today.abs_diff(today) > 1 {
        return Err(err(StatusCode::BAD_REQUEST, "date out of window"));
    }
    {
        let rv = s.rev.read().unwrap();
        if req.revocation_root != rv.root && Some(&req.revocation_root) != rv.previous_root.as_ref() {
            return Err(err(StatusCode::CONFLICT, "stale revocation root; fetch /v1/revocations"));
        }
    }
    let root = pop_crypto::root_from_hex(&req.revocation_root)?;
    let new_expiry = dates::quarter_end(dates::quarter_of(today) + 1);
    let vc = VerifyCtx { issuer: &s.key.public, witness: &s.witness.public, today: req.today, revocation_root: root };
    let sig: BlindSignature = {
        let mut rng = s.rng.lock().unwrap();
        s.scheme.reissue(&mut *rng, &s.key, &vc, req.nonce.as_bytes(), &req.proof, new_expiry)?
    };
    Ok(Json(RenewResponse { signature: sig, new_expiry }))
}

async fn revocations(State(s): State<St>) -> Json<Revocations> {
    Json(s.revocations())
}

async fn revoke(State(s): State<St>, Json(req): Json<RevokeRequest>) -> Result<Json<serde_json::Value>, ApiErr> {
    let found = s
        .store
        .list(T_ENROL)
        .await?
        .into_iter()
        .find(|(_, v)| v["handle"].as_u64() == Some(req.handle) && v["guardian"].as_str() == Some(&req.guardian_public_key));
    let (d, v) = found.ok_or_else(|| err(StatusCode::NOT_FOUND, "no enrolment with this handle and guardian key"))?;
    let pk = hex::decode(&req.guardian_public_key)?;
    let sig = hex::decode(&req.signature)?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pk)
        .verify(&revoke_message(req.handle), &sig)
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "bad guardian signature"))?;
    let mut rec: Enrolment = serde_json::from_value(v)?;
    rec.status = "revoked".into();
    s.store.put(T_ENROL, &d, serde_json::to_value(rec)?).await?;
    s.revoke_handle(req.handle).await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"revoked": true})))
}
