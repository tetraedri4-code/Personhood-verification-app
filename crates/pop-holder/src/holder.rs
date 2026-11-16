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
}

pub struct Holder {
    pub(crate) issuer: Arc<dyn IssuerApi>,
    directory: Arc<dyn DirectoryApi>,
    platforms: PlatformRegistry,
    pub(crate) wallet: Arc<dyn WalletStore>,
    scheme: tokio::sync::OnceCell<(Arc<Scheme>, String, String)>,
    /// one proof at a time, and no interleaved wallet writes
    pub(crate) busy: tokio::sync::Mutex<()>,
}

fn nonce() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

impl Holder {
    pub fn new(issuer: Arc<dyn IssuerApi>, directory: Arc<dyn DirectoryApi>, platforms: PlatformRegistry, wallet: Arc<dyn WalletStore>) -> Self {
        Holder { issuer, directory, platforms, wallet, scheme: tokio::sync::OnceCell::new(), busy: tokio::sync::Mutex::new(()) }
    }

    pub(crate) async fn ctx(&self) -> Result<Ctx> {
        let p = self.issuer.params().await?;
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
        Ok(Ctx { scheme: scheme.clone(), issuer_pk: IssuerPublicKey::from_hex(ipk)?, witness_pk: WitnessPublicKey::from_hex(wpk)?, today: p.today })
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

    pub(crate) async fn tree(&self, cx: &Ctx) -> Result<(Arc<RevocationTree>, String)> {
        let rv = self.issuer.revocations().await?;
        let scheme = cx.scheme.clone();
        let tree = tokio::task::spawn_blocking(move || scheme.revocation_tree(&rv.revoked)).await.map_err(|e| HolderError::Internal(e.to_string()))??;
        let root = pop_crypto::root_to_hex(&tree.root());
        if root != rv.root {
            return Err(HolderError::Internal("issuer's revocation root does not match its list".into()));
        }
        Ok((Arc::new(tree), root))
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
        let probation = cred.attrs.certified + dates::PROBATION_DAYS <= cx.today;
        let (scheme, cred, ipk, wpk, today, ctx) = (cx.scheme.clone(), cred.clone(), cx.issuer_pk.clone(), cx.witness_pk.clone(), cx.today, context_id(platform));
        let proof = tokio::task::spawn_blocking(move || scheme.prove_binding(&mut OsRng, &cred, &tree, &ipk, &wpk, &ctx, slot, today, probation, &bind))
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
                revocation_root: root,
                proof,
            })
            .await?;
        if entry.code != code {
            return Err(HolderError::Internal("directory returned a different code".into()));
        }
        st.bindings.retain(|b| !(b.platform == platform && (b.account_id == account.account_id || b.slot == slot)));
        st.bindings.push(LocalBinding { platform: platform.into(), account_id: account.account_id, handle: account.handle, slot, code, lease_until: entry.lease_until });
        self.wallet.save(&st)?;
        self.sync_backup(&st).await;
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
            .withdraw(&WithdrawRequest { platform: platform.into(), account_id: b.account_id.clone(), nonce: n, today: cx.today, revocation_root: root, proof })
            .await?;
        if let Some(p) = self.platforms.get(platform) {
            let acct = AccountRef { platform: platform.into(), account_id: b.account_id.clone(), handle: b.handle.clone() };
            let _ = p.remove_code(&acct, &b.code).await;
        }
        st.bindings.retain(|x| x != &b);
        self.wallet.save(&st)?;
        self.sync_backup(&st).await;
        Ok(())
    }

    // ------------------------------------------------------------ likes

    /// Report a like with a one-per-person tag. Returns the verified count of the post.
    /// The request carries no account and no pseudonym, and tags of different posts are unlinkable.
    pub async fn like(&self, platform: &str, raw_post: &str) -> Result<LikeResponse> {
        let _g = self.busy.lock().await;
        let mut st = self.wallet.load()?;
        let cred = Self::credential(&st)?;
        let p = self.platforms.get(platform).ok_or_else(|| HolderError::UnknownPlatform(platform.into()))?;
        let post = p.canonical_post_id(raw_post).await?;
        let cx = self.ctx().await?;
        let counted_from = cred.attrs.certified + dates::PROBATION_DAYS;
        if counted_from > cx.today {
            return Err(HolderError::Probation(dates::fmt_day(counted_from)));
        }
        let (tree, root) = self.tree(&cx).await?;
        let (scheme, ipk, wpk, today, ctx, post2) = (cx.scheme.clone(), cx.issuer_pk.clone(), cx.witness_pk.clone(), cx.today, context_id(platform), post.clone());
        let proof = tokio::task::spawn_blocking(move || scheme.prove_like(&mut OsRng, &cred, &tree, &ipk, &wpk, &ctx, &post2, today))
            .await
            .map_err(|e| HolderError::Internal(e.to_string()))??;
        let r = self.directory.like(&LikeRequest { platform: platform.into(), post_id: post.clone(), today: cx.today, revocation_root: root, proof }).await?;
        let k = format!("{platform}|{post}");
        if !st.liked.contains(&k) {
            st.liked.push(k);
            self.wallet.save(&st)?;
        }
        Ok(r)
    }

    pub fn has_liked(&self, platform: &str, canonical_post: &str) -> bool {
        self.wallet.load().map(|s| s.liked.contains(&format!("{platform}|{canonical_post}"))).unwrap_or(false)
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
            counted_from: cred.as_ref().map(|c| dates::fmt_day(c.attrs.certified + dates::PROBATION_DAYS)),
            recheck_by: cred.as_ref().map(|c| dates::fmt_day(c.attrs.last_check + dates::RECHECK_DAYS)),
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
