use crate::wallet::{LocalBinding, PendingEnrolment, WalletState, WalletStore};
use pop_crypto::codec::{from_hex, to_hex};
use pop_crypto::revtree::RevocationTree;
use pop_crypto::{
    dates, BindingProof, BlindRequest, Credential, CryptoError, Day, HandleSignature, HolderSecrets, IssuerPublicKey, Scheme, WitnessPublicKey,
};
use pop_protocol::api::*;
use pop_protocol::platform::{CodePlacement, PlatformError, PlatformRegistry};
use pop_protocol::{binding_code, binding_context, context_id, withdraw_context, AccountRef};
use rand::rngs::OsRng;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum HolderError {
    #[error("not enrolled yet")]
    NotEnrolled,
    #[error("already enrolled on this device")]
    AlreadyEnrolled,
    #[error("no enrolment in progress; start one first")]
    NoPending,
    #[error("enrolment not ready: {0:?}")]
    EnrolNotReady(EnrolStatus),
    #[error("unknown platform: {0}")]
    UnknownPlatform(String),
    #[error("the issuer's date differs from this device's clock by more than a day")]
    ClockMismatch,
    #[error("the issuer changed its public key; refusing to continue")]
    KeyChanged,
    #[error("no binding for this account on this device")]
    NoBinding,
    #[error("likes count from {0}: a new or replaced secret waits nine months first")]
    Probation(String),
    #[error("no backup found for this code")]
    NoBackup,
    #[error("the backup could not be decrypted: wrong code or damaged backup")]
    BadBackup,
    #[error("the issuer gave no backup ticket; a ticket comes with enrolment, re-check and replacement")]
    NoBackupTicket,
    #[error("no replacement is waiting")]
    NoClaim,
    #[error("the replacement waits until {0}")]
    ClaimTooEarly(String),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Platform(#[from] PlatformError),
    #[error("wallet storage: {0}")]
    Wallet(#[from] std::io::Error),
    #[error("pairing: {0}")]
    Pairing(String),
    #[error("internal: {0}")]
    Internal(String),
}

type Result<T> = std::result::Result<T, HolderError>;

/// What `bind` did, so the UI can tell the person what is left to do.
#[derive(Clone, Debug, Serialize)]
pub struct BindOutcome {
    pub entry: BindingEntry,
    /// true if the adapter put the code in the bio/post; false = the person must paste it
    pub code_published: bool,
    pub publish_note: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Status {
    pub enrolled: bool,
    pub expiry: Option<String>,
    pub counted_from: Option<String>,
    /// the identity re-check must be done by this day, or the credential stops renewing
    pub recheck_by: Option<String>,
    /// a theft report suspended this secret; a re-check (`pop holder veto`) lifts it
    pub suspended: bool,
    /// the alarm about stolen eID logins is on: secrets counting from after this day do not count
    pub alarm_cutoff: Option<String>,
    /// an encrypted backup exists
    pub backup: bool,
    /// a replacement of the secret asked from this device waits until this day
    pub replacement_waits_until: Option<String>,
    pub bindings: Vec<LocalBinding>,
    pub liked: usize,
    pub platforms: Vec<&'static str>,
}

/// Public state fetched from the issuer for one operation.
pub(crate) struct Ctx {
    pub(crate) scheme: Arc<Scheme>,
    pub(crate) issuer_pk: IssuerPublicKey,
    pub(crate) witness_pk: WitnessPublicKey,
    pub(crate) today: Day,
    /// the issuer's alarm cutoff, if the alarm is on
    pub(crate) alarm: Option<Day>,
}

impl Ctx {
    /// Secrets counting from after this day are in probation today.
    pub(crate) fn cutoff(&self) -> Day {
        dates::count_cutoff(self.today, self.alarm)
    }
}

/// Where the app's instructions for securing an eID are: docs/reset-eid/ (one page per EU state and
/// language), also served by the
/// holder app at `/help/reset-eid` on its local address.
pub const RESET_EID_HELP: &str = "https://github.com/tetraedri4-code/Personhood-verification-app/blob/main/docs/reset-eid/README.md";
pub const RESET_EID_PATH: &str = "/help/reset-eid";

pub struct Holder {
    pub(crate) issuer: Arc<dyn IssuerApi>,
    directory: Arc<dyn DirectoryApi>,
    platforms: PlatformRegistry,
    pub(crate) wallet: Arc<dyn WalletStore>,
    scheme: tokio::sync::OnceCell<(Arc<Scheme>, String, String)>,
    /// one proof at a time, and no interleaved wallet writes
    pub(crate) busy: tokio::sync::Mutex<()>,
    /// the issuer's parameters, reused for a few minutes instead of fetched before every proof
    params: std::sync::Mutex<Option<(std::time::Instant, Params)>>,
    /// the revocation list and its tree, so that only new revocations are downloaded
    pub(crate) revs: tokio::sync::Mutex<Option<RevCache>>,
    /// the time the like windows follow: the middle of the servers' times (pop_protocol::clock)
    pub(crate) clock: Arc<pop_protocol::clock::Clock>,
    /// where paired computers leave likes (crate::paired); none: pairing is off
    pub(crate) mailbox: Option<Arc<dyn pop_protocol::mailbox::MailboxApi>>,
    /// one collection from the mailboxes at a time
    pub(crate) collecting: tokio::sync::Mutex<()>,
}

pub(crate) struct RevCache {
    pub(crate) revoked: Vec<u64>,
    tree: Arc<RevocationTree>,
    root: String,
}

/// How long the issuer's parameters are reused. Its date may then be up to this much old, which the
/// one-day window of every verifier absorbs.
const PARAMS_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// The holder asks for revocations from a multiple of this, not from the exact length of its list,
/// so that the position it asks from says little about when it last asked.
const REV_STEP: u64 = 64;

fn nonce() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

impl Holder {
    pub fn new(issuer: Arc<dyn IssuerApi>, directory: Arc<dyn DirectoryApi>, platforms: PlatformRegistry, wallet: Arc<dyn WalletStore>) -> Self {
        Holder { issuer, directory, platforms, wallet, scheme: tokio::sync::OnceCell::new(), busy: tokio::sync::Mutex::new(()), params: std::sync::Mutex::new(None), revs: tokio::sync::Mutex::new(None), clock: Arc::new(pop_protocol::clock::Clock::new()), mailbox: None, collecting: tokio::sync::Mutex::new(()) }
    }

    /// Let computers without the app be paired, leaving likes in `mailbox` ([`crate::paired`]).
    pub fn with_mailbox(mut self, mailbox: Arc<dyn pop_protocol::mailbox::MailboxApi>) -> Self {
        self.mailbox = Some(mailbox);
        self
    }

    /// Go by `clock` for the like windows; give the same clock to the issuer and directory clients
    /// (`HttpClient::with_clock`), so that it learns their times. Without it: the device's clock.
    pub fn with_clock(mut self, clock: Arc<pop_protocol::clock::Clock>) -> Self {
        self.clock = clock;
        self
    }

    async fn params(&self) -> Result<Params> {
        if let Some((at, p)) = self.params.lock().unwrap().as_ref() {
            if at.elapsed() < PARAMS_TTL && p.today == dates::today() {
                return Ok(p.clone());
            }
        }
        let p = self.issuer.params().await?;
        *self.params.lock().unwrap() = Some((std::time::Instant::now(), p.clone()));
        Ok(p)
    }

    pub(crate) async fn ctx(&self) -> Result<Ctx> {
        let p = self.params().await?;
        let (scheme, ipk, wpk) = self
            .scheme
            .get_or_try_init(|| async {
                let scheme = Arc::new(Scheme::new(p.config.clone()));
                for k in &p.statements {
                    // proving keys are public and large: cache them, keyed by the issuer key they belong to
                    let name = format!("lego2-{}-{}.bin", k.name(), pop_crypto::fingerprint(&p.issuer_public_key));
                    let bytes = match self.wallet.cache_get(&name) {
                        Some(b) => b,
                        None => {
                            let b = self.issuer.lego_keys(*k).await?;
                            self.wallet.cache_put(&name, &b);
                            b
                        }
                    };
                    scheme.install_lego_keys(*k, &bytes)?;
                }
                Ok::<_, HolderError>((scheme, p.issuer_public_key.clone(), p.witness_public_key.clone()))
            })
            .await?;
        // the keys a credential was issued under must not change under the holder's feet
        if *ipk != p.issuer_public_key || *wpk != p.witness_public_key {
            return Err(HolderError::KeyChanged);
        }
        // the date comes from the issuer, accepted only within one day of the device's clock (§4.4)
        if p.today.abs_diff(dates::today()) > 1 {
            return Err(HolderError::ClockMismatch);
        }
        Ok(Ctx { scheme: scheme.clone(), issuer_pk: IssuerPublicKey::from_hex(ipk)?, witness_pk: WitnessPublicKey::from_hex(wpk)?, today: p.today, alarm: p.alarm_cutoff })
    }

    /// A renewed credential runs to the end of this quarter or the next. Any other date would be a
    /// value the issuer picked for this one person, and a mark it could recognise them by later.
    pub(crate) fn check_new_expiry(today: Day, new_expiry: Day) -> Result<()> {
        let q = dates::quarter_of(today);
        if (q.saturating_sub(1)..=q + 2).any(|x| dates::quarter_end(x) == new_expiry) && new_expiry + 1 >= today {
            Ok(())
        } else {
            Err(HolderError::Internal("the issuer set an unexpected expiry date".into()))
        }
    }

    pub(crate) fn credential(state: &WalletState) -> Result<Credential> {
        Ok(Credential::from_json(state.credential.as_ref().ok_or(HolderError::NotEnrolled)?)?)
    }

    /// The revocation tree at the issuer's current root. Only the handles revoked since the last call
    /// are downloaded; the list is kept on disk too. Whatever the cache holds, the rebuilt tree must
    /// match the issuer's root, and if it does not the whole list is fetched again.
    pub(crate) async fn tree(&self, cx: &Ctx) -> Result<(Arc<RevocationTree>, String)> {
        let mut cache = self.revs.lock().await;
        let file = self.scheme.get().map(|(_, ipk, _)| format!("revoked-{}.json", pop_crypto::fingerprint(ipk)));
        let mut known: Vec<u64> = match (cache.as_ref(), &file) {
            (Some(c), _) => c.revoked.clone(),
            (None, Some(f)) => self.wallet.cache_get(f).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default(),
            (None, None) => vec![],
        };
        for attempt in 0..2 {
            let since = if attempt == 0 { (known.len() as u64 / REV_STEP) * REV_STEP } else { 0 };
            let rv = self.issuer.revocations_since(since).await?;
            if rv.from > known.len() as u64 || (rv.from != since && rv.total >= since) {
                known.clear();
                continue;
            }
            known.truncate(rv.from as usize);
            known.extend_from_slice(&rv.revoked);
            if let Some(c) = cache.as_ref() {
                if c.root == rv.root && c.revoked == known {
                    return Ok((c.tree.clone(), c.root.clone()));
                }
            }
            let scheme = cx.scheme.clone();
            let list = known.clone();
            let tree = tokio::task::spawn_blocking(move || scheme.revocation_tree(&list)).await.map_err(|e| HolderError::Internal(e.to_string()))??;
            let root = pop_crypto::root_to_hex(&tree.root());
            if root != rv.root {
                // a stale or damaged cache, or a list the issuer reordered: start again from nothing
                known.clear();
                *cache = None;
                continue;
            }
            let tree = Arc::new(tree);
            if let Some(f) = &file {
                if let Ok(b) = serde_json::to_vec(&known) {
                    self.wallet.cache_put(f, &b);
                }
            }
            *cache = Some(RevCache { revoked: known, tree: tree.clone(), root: root.clone() });
            return Ok((tree, root));
        }
        Err(HolderError::Internal("issuer's revocation root does not match its list".into()))
    }

    // ------------------------------------------------------------ enrolment

    /// Step 1: returns the URL to open in a browser for the identity check.
    pub async fn enrol_start(&self) -> Result<String> {
        let _g = self.busy.lock().await;
        let mut st = self.wallet.load()?;
        if st.credential.is_some() {
            return Err(HolderError::AlreadyEnrolled);
        }
        let cx = self.ctx().await?;
        let r = self.issuer.enrol_start(Purpose::Enrol).await?;
        // the secret is drawn here, on the device, before the issuer has seen anything
        let (secrets, _) = BlindRequest::new(&mut OsRng, &cx.scheme, r.session.as_bytes());
        st.pending = Some(PendingEnrolment { session: r.session, rho: to_hex(&secrets.rho), s: to_hex(&secrets.s), delta: secrets.delta, purpose: Purpose::Enrol, new_guardian_pkcs8: None });
        self.wallet.save(&st)?;
        Ok(r.authorize_url)
    }

    /// Step 2, after the identity check in the browser: blind issuance.
    /// `confirm_code` is the code the issuer showed in the browser after login.
    pub async fn enrol_finish(&self, confirm_code: &str) -> Result<()> {
        let _g = self.busy.lock().await;
        let mut st = self.wallet.load()?;
        let p = st.pending.clone().filter(|p| p.purpose == Purpose::Enrol).ok_or(HolderError::NoPending)?;
        let cx = self.ctx().await?;
        match self.issuer.enrol_status(&p.session).await? {
            EnrolStatus::Authenticated => {}
            other => return Err(HolderError::EnrolNotReady(other)),
        }
        let secrets = HolderSecrets { rho: from_hex(&p.rho)?, s: from_hex(&p.s)?, delta: p.delta };
        let req = BlindRequest::for_secrets(&mut OsRng, &cx.scheme, &secrets, p.session.as_bytes());
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).map_err(|_| HolderError::Internal("keygen".into()))?;
        let guardian = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| HolderError::Internal("keygen".into()))?;
        // save the guardian key before the issuer records it
        st.guardian_pkcs8 = Some(hex::encode(pkcs8.as_ref()));
        self.wallet.save(&st)?;
        let resp = self
            .issuer
            .enrol_finish(&EnrolFinishRequest { session: p.session.clone(), blind_request: req, guardian_public_key: hex::encode(guardian.public_key().as_ref()), confirm_code: confirm_code.trim().to_string() })
            .await?;
        // finish_issuance checks the signature, the witness signature and that every value is on the grid
        let cred = cx.scheme.finish_issuance(
            &cx.issuer_pk,
            &cx.witness_pk,
            &secrets,
            &resp.signature,
            &resp.attrs,
            &HandleSignature::from_hex(&resp.handle_signature)?,
        )?;
        st.credential = Some(cred.to_json());
        st.pending = None;
        st.backup_ticket = resp.backup_ticket.or(st.backup_ticket.take());
        self.wallet.save(&st)?;
        Ok(())
    }

    // ------------------------------------------------------------ binding

    async fn binding_proof(&self, cx: &Ctx, cred: &Credential, platform: &str, slot: u32, bind: Vec<u8>) -> Result<(BindingProof, String)> {
        let (tree, root) = self.tree(cx).await?;
        let cutoff = cx.cutoff();
        let probation = cred.attrs.certified <= cutoff;
        let (scheme, cred, ipk, wpk, today, ctx) = (cx.scheme.clone(), cred.clone(), cx.issuer_pk.clone(), cx.witness_pk.clone(), cx.today, context_id(platform));
        let proof = tokio::task::spawn_blocking(move || scheme.prove_binding(&mut OsRng, &cred, &tree, &ipk, &wpk, &ctx, slot, today, cutoff, probation, &bind))
            .await
            .map_err(|e| HolderError::Internal(e.to_string()))??;
        Ok((proof, root))
    }

    /// Bind (or renew the lease of) an account: prove, register with the directory, show the code.
    pub async fn bind(&self, platform: &str, handle_or_url: &str, slot: u32, placement: CodePlacement) -> Result<BindOutcome> {
        let _g = self.busy.lock().await;
        let mut st = self.wallet.load()?;
        let cred = Self::credential(&st)?;
        let p = self.platforms.get(platform).ok_or_else(|| HolderError::UnknownPlatform(platform.into()))?;
        let account: AccountRef = p.resolve_account(handle_or_url).await?;
        let cx = self.ctx().await?;
        let n = nonce();
        let (proof, root) = self.binding_proof(&cx, &cred, platform, slot, binding_context(platform, &account.account_id, &n)).await?;
        // publish the code first, so the directory's own check can already see it
        let code = binding_code(platform, &account.account_id, &proof.nym);
        let (code_published, publish_note) = match p.publish_code(&account, &code, placement).await {
            Ok(()) => (true, None),
            Err(PlatformError::NoCredentials) => (false, Some(format!("Add this code to the account's bio or a post yourself: {code}"))),
            Err(e) => (false, Some(format!("Could not publish the code ({e}). Add it yourself: {code}"))),
        };
        let entry = self
            .directory
            .bind(&BindRequest {
                platform: platform.into(),
                account_id: account.account_id.clone(),
                handle: account.handle.clone(),
                nonce: n,
                today: cx.today,
                alarm_cutoff: cx.alarm,
                revocation_root: root,
                proof,
            })
            .await
            .map_err(|e| self.after_directory_error(e))?;
        if entry.code != code {
            return Err(HolderError::Internal("directory returned a different code".into()));
        }
        st.bindings.retain(|b| !(b.platform == platform && (b.account_id == account.account_id || b.slot == slot)));
        st.bindings.push(LocalBinding { platform: platform.into(), account_id: account.account_id, handle: account.handle, slot, code, lease_until: entry.lease_until });
        self.wallet.save(&st)?;
        // No backup update here. The backup host can know whose backup it is; an update at the
        // moment of a binding would tell it which account that person just bound. The list of bound
        // accounts reaches the backup with the next renewal.
        Ok(BindOutcome { entry, code_published, publish_note })
    }

    /// Switch the badge off for an account and take the code out of the bio where possible.
    pub async fn unbind(&self, platform: &str, account_id_or_handle: &str) -> Result<()> {
        let _g = self.busy.lock().await;
        let mut st = self.wallet.load()?;
        let cred = Self::credential(&st)?;
        let b = st
            .bindings
            .iter()
            .find(|b| b.platform == platform && (b.account_id == account_id_or_handle || b.handle == account_id_or_handle.trim_start_matches('@')))
            .cloned()
            .ok_or(HolderError::NoBinding)?;
        let cx = self.ctx().await?;
        let n = nonce();
        let (proof, root) = self.binding_proof(&cx, &cred, platform, b.slot, withdraw_context(platform, &b.account_id, &n)).await?;
        self.directory
            .withdraw(&WithdrawRequest { platform: platform.into(), account_id: b.account_id.clone(), nonce: n, today: cx.today, alarm_cutoff: cx.alarm, revocation_root: root, proof })
            .await?;
        if let Some(p) = self.platforms.get(platform) {
            let acct = AccountRef { platform: platform.into(), account_id: b.account_id.clone(), handle: b.handle.clone() };
            let _ = p.remove_code(&acct, &b.code).await;
        }
        st.bindings.retain(|x| x != &b);
        self.wallet.save(&st)?;
        Ok(())
    }

    // ------------------------------------------------------------ likes

    /// Report a like with a one-per-person tag. Returns the verified count of the post.
    /// The request carries no account and no pseudonym, and tags of different posts are unlinkable.
    /// The wait before a like is proved and sent, and the longest it can be, in seconds. Likes go out
    /// on a schedule shared by everyone: windows of the issuer's `like_window_secs`, counted from the
    /// Unix epoch by the middle of the servers' times ([`Holder::with_clock`]). A like clicked in one window is sent at a random moment of the next, so a public
    /// count going up, or a send seen by the relay, tells only the window of the click. Without the
    /// wait, the moment a count goes up shows when the person clicked, which a relay that sees their
    /// address could match.
    pub async fn like_delay(&self) -> Result<(std::time::Duration, u64)> {
        let w = self.params().await?.like_window_secs as u64;
        Ok(like_send_delay(self.clock.now_ms(), w, &mut OsRng))
    }

    /// Check at once what can be checked before the wait (credential, probation, post id), then queue
    /// the like: it is proved and sent after [`Holder::like_delay`]. Survives a restart of the app
    /// ([`Holder::resume_queued_likes`]). Returns the canonical post id and the longest wait in seconds.
    pub async fn like_later(self: &Arc<Self>, platform: &str, raw_post: &str) -> Result<(String, u64)> {
        let (post, new) = {
            let _g = self.busy.lock().await;
            let mut st = self.wallet.load()?;
            let cred = Self::credential(&st)?;
            let post = self.platforms.get(platform).ok_or_else(|| HolderError::UnknownPlatform(platform.into()))?.canonical_post_id(raw_post).await?;
            self.check_probation(&cred, &self.ctx().await?)?;
            let k = format!("{platform}|{post}");
            // already sent or waiting: nothing more goes out
            let new = !st.queued_likes.contains(&k) && !st.liked.contains(&k);
            if new {
                st.queued_likes.push(k);
                self.wallet.save(&st)?;
            }
            (post, new)
        };
        let (delay, within) = self.like_delay().await?;
        if new {
            self.spawn_queued(platform.to_string(), post.clone(), delay);
        }
        Ok((post, within))
    }

    fn spawn_queued(self: &Arc<Self>, platform: String, post: String, delay: std::time::Duration) {
        let h = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            if let Err(e) = h.like(&platform, &post).await {
                tracing::warn!("a queued like could not be reported: {e}");
            }
            // sent or refused, it leaves the queue; a refused like can be clicked again
            let _g = h.busy.lock().await;
            if let Ok(mut st) = h.wallet.load() {
                st.queued_likes.retain(|k| k != &format!("{platform}|{post}"));
                let _ = h.wallet.save(&st);
            }
        });
    }

    /// How many likes wait to be sent.
    pub fn queued_likes(&self) -> usize {
        self.wallet.load().map(|s| s.queued_likes.len()).unwrap_or(0)
    }

    /// Queue again the likes that were waiting when the app stopped: each is sent at its own random
    /// moment of the window after this one.
    pub async fn resume_queued_likes(self: &Arc<Self>) -> Result<usize> {
        let q = self.wallet.load()?.queued_likes;
        for k in &q {
            if let Some((platform, post)) = k.split_once('|') {
                let (delay, _) = self.like_delay().await?;
                self.spawn_queued(platform.to_string(), post.to_string(), delay);
            }
        }
        Ok(q.len())
    }

    fn check_probation(&self, cred: &Credential, cx: &Ctx) -> Result<()> {
        let cutoff = cx.cutoff();
        if cred.attrs.certified > cutoff {
            return Err(match cx.alarm {
                Some(a) if cred.attrs.certified <= cx.today => HolderError::Probation(format!(
                    "the end of the alarm about stolen eID logins (secrets counting from after {} are paused)",
                    dates::fmt_day(a)
                )),
                _ => HolderError::Probation(dates::fmt_day(cred.attrs.certified)),
            });
        }
        Ok(())
    }

    pub async fn like(&self, platform: &str, raw_post: &str) -> Result<LikeResponse> {
        let _g = self.busy.lock().await;
        let mut st = self.wallet.load()?;
        let cred = Self::credential(&st)?;
        let p = self.platforms.get(platform).ok_or_else(|| HolderError::UnknownPlatform(platform.into()))?;
        let post = p.canonical_post_id(raw_post).await?;
        let cx = self.ctx().await?;
        let cutoff = cx.cutoff();
        if cred.attrs.certified > cutoff {
            return Err(match cx.alarm {
                Some(a) if cred.attrs.certified <= cx.today => HolderError::Probation(format!(
                    "the end of the alarm about stolen eID logins (secrets counting from after {} are paused)",
                    dates::fmt_day(a)
                )),
                _ => HolderError::Probation(dates::fmt_day(cred.attrs.certified)),
            });
        }
        let (tree, root) = self.tree(&cx).await?;
        let (scheme, ipk, wpk, today, ctx, post2) = (cx.scheme.clone(), cx.issuer_pk.clone(), cx.witness_pk.clone(), cx.today, context_id(platform), post.clone());
        let proof = tokio::task::spawn_blocking(move || scheme.prove_like(&mut OsRng, &cred, &tree, &ipk, &wpk, &ctx, &post2, today, cutoff))
            .await
            .map_err(|e| HolderError::Internal(e.to_string()))??;
        let r = self
            .directory
            .like(&LikeRequest { platform: platform.into(), post_id: post.clone(), today: cx.today, alarm_cutoff: cx.alarm, revocation_root: root, proof })
            .await
            .map_err(|e| self.after_directory_error(e))?;
        let k = format!("{platform}|{post}");
        if !st.liked.contains(&k) {
            st.liked.push(k);
            self.wallet.save(&st)?;
        }
        Ok(r)
    }

    /// A conflict from the directory may mean the alarm changed: fetch the issuer's parameters again
    /// next time.
    fn after_directory_error(&self, e: ApiError) -> HolderError {
        if matches!(e, ApiError::Server { status: 409, .. }) {
            *self.params.lock().unwrap() = None;
        }
        e.into()
    }

    /// Has a theft report suspended this wallet's secret? Its handle is then on the revocation list,
    /// though this app never asked to revoke it. A re-check (`recheck_start`, `recheck_finish`) lifts it.
    pub async fn suspended(&self) -> Result<bool> {
        let st = self.wallet.load()?;
        let Ok(cred) = Self::credential(&st) else { return Ok(false) };
        let cx = self.ctx().await?;
        self.tree(&cx).await?;
        Ok(self.revs.lock().await.as_ref().is_some_and(|c| c.revoked.contains(&cred.handle())))
    }

    pub fn has_liked(&self, platform: &str, canonical_post: &str) -> bool {
        let k = format!("{platform}|{canonical_post}");
        self.wallet.load().map(|s| s.liked.contains(&k) || s.queued_likes.contains(&k)).unwrap_or(false)
    }

    // ------------------------------------------------------------ renewal, revocation

    /// Blind renewal of the credential (about once a quarter). Pseudonyms do not change.
    pub async fn renew(&self) -> Result<Day> {
        let _g = self.busy.lock().await;
        let mut st = self.wallet.load()?;
        let cred = Self::credential(&st)?;
        let cx = self.ctx().await?;
        let (tree, root) = self.tree(&cx).await?;
        let n = nonce();
        let (scheme, c2, ipk, wpk, today, n2) = (cx.scheme.clone(), cred.clone(), cx.issuer_pk.clone(), cx.witness_pk.clone(), cx.today, n.clone());
        let (proof, rho) = tokio::task::spawn_blocking(move || scheme.prove_renewal(&mut OsRng, &c2, &tree, &ipk, &wpk, today, n2.as_bytes()))
            .await
            .map_err(|e| HolderError::Internal(e.to_string()))??;
        let r = self.issuer.renew(&RenewRequest { nonce: n, today: cx.today, revocation_root: root, proof }).await?;
        Self::check_new_expiry(cx.today, r.new_expiry)?;
        let new = cx.scheme.finish_renewal(&cx.issuer_pk, &cred, rho, &r.signature, r.new_expiry)?;
        st.credential = Some(new.to_json());
        self.wallet.save(&st)?;
        self.sync_backup(&st).await;
        Ok(r.new_expiry)
    }

    /// The holder's own revocation request, signed with the guardian key. The credential stops working
    /// everywhere; existing badges run out with their leases.
    pub async fn revoke(&self) -> Result<()> {
        let _g = self.busy.lock().await;
        let mut st = self.wallet.load()?;
        let cred = Self::credential(&st)?;
        let pkcs8 = hex::decode(st.guardian_pkcs8.as_ref().ok_or(HolderError::NotEnrolled)?).map_err(|e| HolderError::Internal(e.to_string()))?;
        let g = Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| HolderError::Internal("guardian key".into()))?;
        let sig = g.sign(&revoke_message(cred.handle()));
        self.issuer
            .revoke(&RevokeRequest { handle: cred.handle(), guardian_public_key: hex::encode(g.public_key().as_ref()), signature: hex::encode(sig.as_ref()) })
            .await?;
        st.credential = None;
        st.bindings.clear();
        self.wallet.save(&st)?;
        // the backup holds a credential that no longer works
        self.delete_backup(&mut st).await;
        Ok(())
    }

    pub fn status(&self) -> Result<Status> {
        let st = self.wallet.load()?;
        let cred = st.credential.as_ref().map(Credential::from_json).transpose()?;
        Ok(Status {
            enrolled: cred.is_some(),
            expiry: cred.as_ref().map(|c| dates::fmt_day(c.expiry())),
            counted_from: cred.as_ref().map(|c| dates::fmt_day(c.attrs.certified)),
            recheck_by: cred.as_ref().map(|c| dates::fmt_day(c.attrs.last_check + dates::RECHECK_DAYS)),
            // the handle is on the revocation list this app last downloaded, though the app never asked to revoke it
            suspended: cred.as_ref().is_some_and(|c| self.revs.try_lock().ok().and_then(|g| g.as_ref().map(|r| r.revoked.contains(&c.handle()))).unwrap_or(false)),
            alarm_cutoff: self.params.lock().unwrap().as_ref().and_then(|(_, p)| p.alarm_cutoff).map(dates::fmt_day),
            backup: st.backup.is_some(),
            replacement_waits_until: st.claim.as_ref().map(|c| dates::fmt_day(c.claim_after)),
            bindings: st.bindings,
            liked: st.liked.len(),
            platforms: self.platforms.ids(),
        })
    }

    pub fn platforms(&self) -> &PlatformRegistry {
        &self.platforms
    }
}

/// The wait before sending a like clicked at `now_ms` (Unix time, milliseconds) with windows of
/// `window_secs`: until a random moment of the next window. Also returns the longest possible wait in
/// seconds (until the end of the next window). A window of 0 sends at once.
pub fn like_send_delay(now_ms: u64, window_secs: u64, rng: &mut impl rand::RngCore) -> (std::time::Duration, u64) {
    use rand::Rng;
    if window_secs == 0 {
        return (std::time::Duration::ZERO, 0);
    }
    let w = window_secs * 1000;
    let next = (now_ms / w + 1) * w;
    let at = next + rng.gen_range(0..w);
    (std::time::Duration::from_millis(at - now_ms), (next + w - now_ms).div_ceil(1000))
}

#[cfg(test)]
mod like_schedule_tests {
    use super::like_send_delay;

    #[test]
    fn a_like_goes_out_in_the_next_window_whenever_it_was_clicked() {
        let mut rng = rand::rngs::OsRng;
        let w = 1800u64;
        for now in [0u64, 1, 899_999, 1_799_999, 1_800_000, 1_800_001, 1_763_600_123_456] {
            for _ in 0..200 {
                let (d, within) = like_send_delay(now, w, &mut rng);
                let at = now + d.as_millis() as u64;
                assert_eq!(at / (w * 1000), now / (w * 1000) + 1, "sent in the window after the click");
                assert!(d.as_secs() <= within && within <= 2 * w);
            }
        }
        assert_eq!(like_send_delay(5, 0, &mut rng), (std::time::Duration::ZERO, 0));
    }
}
