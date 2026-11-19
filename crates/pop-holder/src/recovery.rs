//! Re-check, backup and replacement (docs/recovery.md).
//!
//! * **Re-check**: every two years the person logs in with the eID again; the secret and the
//!   pseudonyms stay.
//! * **Backup (level 1)**: the wallet, encrypted under a key derived from a 130-bit code that the
//!   person writes on paper. The server stores ciphertext it cannot read. Restoring gives back the
//!   same secret, so nothing changes for the person's accounts.
//! * **Replacement (level 2)**: no backup, or the secret was stolen. After an eID login a new secret
//!   is certified and the old one revoked. If this device still has the old guardian key that happens
//!   at once; otherwise it waits, and the person can refuse it by doing a re-check with the old
//!   app. The new secret starts a fresh nine-month probation and has new pseudonyms.
use crate::holder::{Holder, HolderError};
use crate::wallet::{BackupKeys, LocalBinding, PendingClaim, PendingEnrolment, WalletState};
use base64::Engine;
use pop_crypto::codec::{from_hex, to_hex};
use pop_crypto::{dates, BlindRequest, Day, HandleSignature, HolderSecrets};
use pop_protocol::api::*;
use rand::rngs::OsRng;
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, HolderError>;

/// What a replacement request led to.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum ReplaceOutcome {
    /// the new secret is certified; likes and badges count from `counted_from`
    Issued { counted_from: String },
    /// the old guardian key was not available: claim between these days, unless a re-check with
    /// the old app cancels it
    /// the old app cancels it. `suspended`: a theft report stopped the other secret meanwhile.
    Waiting { claim_after: String, claim_before: String, suspended: bool },
}

// ---------------------------------------------------------------- paper code

/// Crockford base32: no I, L, O or U, so a handwritten code is hard to misread.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// 26 characters of 5 bits = 130 bits
const CODE_CHARS: usize = 26;

fn new_code() -> String {
    let mut b = [0u8; CODE_CHARS];
    OsRng.fill_bytes(&mut b);
    b.iter().map(|x| ALPHABET[(x & 31) as usize] as char).collect()
}

/// `ABCDE-FGHJK-...` for reading and typing.
pub fn format_code(code: &str) -> String {
    code.as_bytes().chunks(5).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("-")
}

/// Accept what a person types: any case, spaces and dashes, and the usual look-alikes.
fn normalise_code(typed: &str) -> Option<String> {
    let s: String = typed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect();
    (s.len() == CODE_CHARS && s.bytes().all(|b| ALPHABET.contains(&b))).then_some(s)
}

/// Three independent values from the code: where the backup is, the right to overwrite it, and the
/// key that decrypts it. The server learns the first and a hash of the second.
fn derive(code: &str) -> BackupKeys {
    let h = |label: &str| Sha256::digest(format!("pop-backup-v1|{label}|{code}").as_bytes());
    BackupKeys { id: hex::encode(&h("id")[..16]), write_key: hex::encode(h("write")), enc_key: hex::encode(h("enc")) }
}

#[derive(Serialize, Deserialize)]
struct BackupFile {
    v: u32,
    credential: serde_json::Value,
    guardian_pkcs8: Option<String>,
    bindings: Vec<LocalBinding>,
    saved_on: Day,
}

const AAD: &[u8] = b"pop-backup-v1";
/// the plaintext is padded to a multiple of this, so its size says little about the wallet
const PAD: usize = 4096;

fn key(enc_key_hex: &str) -> Result<LessSafeKey> {
    let k = hex::decode(enc_key_hex).map_err(|_| HolderError::BadBackup)?;
    Ok(LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &k).map_err(|_| HolderError::BadBackup)?))
}

fn seal(keys: &BackupKeys, file: &BackupFile) -> Result<String> {
    let mut data = serde_json::to_vec(file).map_err(|e| HolderError::Internal(e.to_string()))?;
    // JSON ignores trailing spaces
    data.resize(data.len().div_ceil(PAD) * PAD, b' ');
    let mut n = [0u8; 12];
    OsRng.fill_bytes(&mut n);
    key(&keys.enc_key)?.seal_in_place_append_tag(Nonce::assume_unique_for_key(n), Aad::from(AAD), &mut data).map_err(|_| HolderError::Internal("encrypt".into()))?;
    let mut out = n.to_vec();
    out.extend_from_slice(&data);
    Ok(base64::engine::general_purpose::STANDARD.encode(out))
}

fn open(keys: &BackupKeys, blob: &str) -> Result<BackupFile> {
    let mut raw = base64::engine::general_purpose::STANDARD.decode(blob).map_err(|_| HolderError::BadBackup)?;
    if raw.len() < 12 + 16 {
        return Err(HolderError::BadBackup);
    }
    let mut data = raw.split_off(12);
    let n: [u8; 12] = raw.try_into().map_err(|_| HolderError::BadBackup)?;
    let plain = key(&keys.enc_key)?.open_in_place(Nonce::assume_unique_for_key(n), Aad::from(AAD), &mut data).map_err(|_| HolderError::BadBackup)?;
    serde_json::from_slice(plain).map_err(|_| HolderError::BadBackup)
}

fn new_guardian() -> Result<(String, Ed25519KeyPair)> {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).map_err(|_| HolderError::Internal("keygen".into()))?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| HolderError::Internal("keygen".into()))?;
    Ok((hex::encode(pkcs8.as_ref()), pair))
}

fn guardian_of(st: &WalletState) -> Option<Ed25519KeyPair> {
    let pkcs8 = hex::decode(st.guardian_pkcs8.as_ref()?).ok()?;
    Ed25519KeyPair::from_pkcs8(&pkcs8).ok()
}

impl Holder {
    // ------------------------------------------------------------ re-check

    /// Step 1 of the two-year re-check: returns the URL for the identity check.
    pub async fn recheck_start(&self) -> Result<String> {
        let _g = self.busy.lock().await;
        let mut st = self.wallet.load()?;
        Self::credential(&st)?;
        self.ctx().await?;
        let r = self.issuer.enrol_start(Purpose::Recheck).await?;
        st.pending = Some(PendingEnrolment { session: r.session, rho: String::new(), s: String::new(), delta: 0, purpose: Purpose::Recheck, new_guardian_pkcs8: None });
        self.wallet.save(&st)?;
        Ok(r.authorize_url)
    }

    /// Step 2: show the credential to the issuer, bound to the login, and get it signed for two more
    /// years. Returns the day by which the next re-check is due.
    pub async fn recheck_finish(&self, confirm_code: &str) -> Result<Day> {
        let _g = self.busy.lock().await;
        let mut st = self.wallet.load()?;
        let p = st.pending.clone().filter(|p| p.purpose == Purpose::Recheck).ok_or(HolderError::NoPending)?;
        let cred = Self::credential(&st)?;
        let cx = self.ctx().await?;
        match self.issuer.enrol_status(&p.session).await? {
            EnrolStatus::Authenticated => {}
            other => return Err(HolderError::EnrolNotReady(other)),
        }
        let (mut tree, mut root) = self.tree(&cx).await?;
        let suspended = self.revs.lock().await.as_ref().and_then(|c| c.revoked.iter().position(|h| *h == cred.handle()));
        if let Some(pos) = suspended {
            // A theft report suspended this secret. Prove against the list as it was before: the
            // issuer checks the shown handle itself and lifts the suspension with a new handle.
            let prefix = self.revs.lock().await.as_ref().map(|c| c.revoked[..pos].to_vec()).unwrap_or_default();
            let scheme = cx.scheme.clone();
            let t = tokio::task::spawn_blocking(move || scheme.revocation_tree(&prefix)).await.map_err(|e| HolderError::Internal(e.to_string()))??;
            root = pop_crypto::root_to_hex(&t.root());
            tree = std::sync::Arc::new(t);
        }
        let (scheme, c2, ipk, wpk, today, session) = (cx.scheme.clone(), cred.clone(), cx.issuer_pk.clone(), cx.witness_pk.clone(), cx.today, p.session.clone());
        let (proof, rho) = tokio::task::spawn_blocking(move || scheme.prove_recheck(&mut OsRng, &c2, &tree, &ipk, &wpk, today, session.as_bytes()))
            .await
            .map_err(|e| HolderError::Internal(e.to_string()))??;
        let r = self
            .issuer
            .identity_recheck(&RecheckRequest {
                session: p.session.clone(),
                confirm_code: confirm_code.trim().to_string(),
                today: cx.today,
                revocation_root: root,
                handle: cred.handle(),
                last_check: cred.attrs.last_check,
                proof,
            })
            .await?;
        // the issuer may only move the month forward to now, never tag the credential with another date
        if r.new_check != dates::month_start(cx.today) && r.new_check != dates::month_start(dates::today()) {
            return Err(HolderError::Internal("the issuer set an unexpected re-check month".into()));
        }
        Self::check_new_expiry(cx.today, r.new_expiry)?;
        let new_handle = match (&r.new_handle, suspended) {
            (Some((h, hs)), Some(_)) => Some((*h, HandleSignature::from_hex(hs)?)),
            (None, None) => None,
            _ => return Err(HolderError::Internal("the issuer changed the handle unasked, or did not lift the suspension".into())),
        };
        let new = cx.scheme.finish_recheck(&cx.issuer_pk, &cx.witness_pk, &cred, rho, &r.signature, r.new_expiry, r.new_check, new_handle.as_ref().map(|(h, hs)| (*h, hs)))?;
        st.credential = Some(new.to_json());
        st.pending = None;
        if r.backup_ticket.is_some() {
            st.backup_ticket = r.backup_ticket;
        }
        self.wallet.save(&st)?;
        self.sync_backup(&st).await;
        Ok(r.new_check + dates::RECHECK_DAYS)
    }

    // ------------------------------------------------------------ backup (level 1)

    fn backup_file(st: &WalletState) -> Result<BackupFile> {
        Ok(BackupFile {
            v: 1,
            credential: st.credential.clone().ok_or(HolderError::NotEnrolled)?,
            guardian_pkcs8: st.guardian_pkcs8.clone(),
            bindings: st.bindings.clone(),
            saved_on: dates::today(),
        })
    }

    /// Make an encrypted backup and return its code, formatted for writing down. The code is shown
    /// this once and not kept on the device. Calling this again makes a new code and deletes the
    /// backup under the old one.
    pub async fn backup_create(&self) -> Result<String> {
        let _g = self.busy.lock().await;
        let mut st = self.wallet.load()?;
        let file = Self::backup_file(&st)?;
        if st.backup.is_some() {
            self.delete_backup(&mut st).await;
        }
        let ticket = st.backup_ticket.clone().ok_or(HolderError::NoBackupTicket)?;
        let code = new_code();
        let keys = derive(&code);
        self.issuer.backup_put(&BackupPut { id: keys.id.clone(), write_key: keys.write_key.clone(), ticket: Some(ticket), blob: seal(&keys, &file)? }).await?;
        st.backup = Some(keys);
        st.backup_ticket = None;
        self.wallet.save(&st)?;
        Ok(format_code(&code))
    }

    /// Bring the stored backup up to date. Best effort: a failure leaves the older backup in place,
    /// and an older backup still restores (it renews itself) for about a year. Called only after
    /// renewal, re-check and replacement, never after a binding or a like (see `Holder::bind`).
    pub(crate) async fn sync_backup(&self, st: &WalletState) -> bool {
        let (Some(keys), Ok(file)) = (&st.backup, Self::backup_file(st)) else { return false };
        let Ok(blob) = seal(keys, &file) else { return false };
        match self.issuer.backup_put(&BackupPut { id: keys.id.clone(), write_key: keys.write_key.clone(), ticket: None, blob }).await {
            Ok(_) => true,
            Err(e) => {
                tracing::warn!("could not update the backup: {e}");
                false
            }
        }
    }

    /// Delete the stored backup; the freed place comes back as a ticket.
    pub(crate) async fn delete_backup(&self, st: &mut WalletState) {
        let Some(keys) = st.backup.clone() else { return };
        match self.issuer.backup_put(&BackupPut { id: keys.id, write_key: keys.write_key, ticket: None, blob: String::new() }).await {
            Ok(ticket) => {
                st.backup = None;
                if ticket.is_some() {
                    st.backup_ticket = ticket;
                }
                let _ = self.wallet.save(st);
            }
            // gone already (deleted from another device): nothing to keep track of
            Err(ApiError::Server { status: 404, .. }) => {
                st.backup = None;
                let _ = self.wallet.save(st);
            }
            Err(e) => tracing::warn!("could not delete the backup: {e}"),
        }
    }

    /// Restore a backup onto a device that has no credential. `typed_code` is the paper code.
    pub async fn restore(&self, typed_code: &str) -> Result<()> {
        let _g = self.busy.lock().await;
        let mut st = self.wallet.load()?;
        if st.credential.is_some() {
            return Err(HolderError::AlreadyEnrolled);
        }
        let keys = derive(&normalise_code(typed_code).ok_or(HolderError::NoBackup)?);
        let blob = match self.issuer.backup_get(&keys.id).await {
            Ok(b) => b.blob,
            Err(ApiError::Server { status: 404, .. }) => return Err(HolderError::NoBackup),
            Err(e) => return Err(e.into()),
        };
        let file = open(&keys, &blob)?;
        if file.v != 1 {
            return Err(HolderError::BadBackup);
        }
        // refuse a backup that does not parse as a credential before anything is written
        pop_crypto::Credential::from_json(&file.credential).map_err(|_| HolderError::BadBackup)?;
        st.credential = Some(file.credential);
        st.guardian_pkcs8 = file.guardian_pkcs8;
        st.bindings = file.bindings;
        st.backup = Some(keys);
        st.pending = None;
        self.wallet.save(&st)?;
        Ok(())
    }

    // ------------------------------------------------------------ replacement (level 2)

    /// Step 1: returns the URL for the identity check. The new secret is drawn here.
    pub async fn replace_start(&self) -> Result<String> {
        let _g = self.busy.lock().await;
        let mut st = self.wallet.load()?;
        let cx = self.ctx().await?;
        let r = self.issuer.enrol_start(Purpose::Replace).await?;
        let (secrets, _) = BlindRequest::new(&mut OsRng, &cx.scheme, r.session.as_bytes());
        let (pkcs8, _) = new_guardian()?;
        st.pending = Some(PendingEnrolment {
            session: r.session,
            rho: to_hex(&secrets.rho),
            s: to_hex(&secrets.s),
            delta: secrets.delta,
            purpose: Purpose::Replace,
            new_guardian_pkcs8: Some(pkcs8),
        });
        self.wallet.save(&st)?;
        Ok(r.authorize_url)
    }

    fn install_replacement(st: &mut WalletState, cred: &pop_crypto::Credential, guardian_pkcs8: String, ticket: Option<String>) {
        st.credential = Some(cred.to_json());
        st.guardian_pkcs8 = Some(guardian_pkcs8);
        // the new secret has new pseudonyms and new like tags
        st.bindings.clear();
        st.liked.clear();
        st.pending = None;
        st.claim = None;
        if ticket.is_some() {
            st.backup_ticket = ticket;
        }
    }

    /// Step 2. If this device still holds the guardian key of the old secret, it signs the request
    /// and the new credential comes at once. Otherwise the request waits.
    /// `report_theft`: "it wasn't me". The person did not enrol the secret that blocks their
    /// enrolment. It is suspended at once and the report counted; secure the eID first (see
    /// [`crate::holder::RESET_EID_HELP`]), or whoever holds it can lift the suspension again.
    pub async fn replace_finish(&self, confirm_code: &str, report_theft: bool) -> Result<ReplaceOutcome> {
        let _g = self.busy.lock().await;
        let mut st = self.wallet.load()?;
        let p = st.pending.clone().filter(|p| p.purpose == Purpose::Replace).ok_or(HolderError::NoPending)?;
        let new_pkcs8 = p.new_guardian_pkcs8.clone().ok_or(HolderError::NoPending)?;
        let cx = self.ctx().await?;
        match self.issuer.enrol_status(&p.session).await? {
            EnrolStatus::Authenticated => {}
            other => return Err(HolderError::EnrolNotReady(other)),
        }
        let secrets = HolderSecrets { rho: from_hex(&p.rho)?, s: from_hex(&p.s)?, delta: p.delta };
        let req = BlindRequest::for_secrets(&mut OsRng, &cx.scheme, &secrets, p.session.as_bytes());
        let new_guardian = Ed25519KeyPair::from_pkcs8(&hex::decode(&new_pkcs8).map_err(|e| HolderError::Internal(e.to_string()))?).map_err(|_| HolderError::Internal("guardian key".into()))?;
        let new_pub = hex::encode(new_guardian.public_key().as_ref());
        // a report says this device does not hold the secret, so it signs nothing with an old key
        let old_sig = if report_theft { None } else { guardian_of(&st).map(|g| hex::encode(g.sign(&replace_message(&p.session, &req.commitment, &new_pub)).as_ref())) };
        let mut request = ReplaceRequest {
            session: p.session.clone(),
            confirm_code: confirm_code.trim().to_string(),
            blind_request: req,
            guardian_public_key: new_pub,
            old_guardian_signature: old_sig,
            report_theft,
        };
        let resp = match self.issuer.replace(&request).await {
            // this device's guardian key is not the enrolment's current one (an old backup, say):
            // ask again without it and wait like anyone who has only the eID
            Err(ApiError::Server { status: 401, .. }) if request.old_guardian_signature.is_some() => {
                request.old_guardian_signature = None;
                self.issuer.replace(&request).await?
            }
            r => r?,
        };
        match resp {
            ReplaceResponse::Issued { issuance } => {
                let cred = cx.scheme.finish_issuance(&cx.issuer_pk, &cx.witness_pk, &secrets, &issuance.signature, &issuance.attrs, &HandleSignature::from_hex(&issuance.handle_signature)?)?;
                Self::install_replacement(&mut st, &cred, new_pkcs8, issuance.backup_ticket);
                self.wallet.save(&st)?;
                self.sync_backup(&st).await;
                Ok(ReplaceOutcome::Issued { counted_from: dates::fmt_day(cred.attrs.certified) })
            }
            ReplaceResponse::Pending { claim_token, claim_after, claim_before, suspended } => {
                st.claim = Some(PendingClaim { claim_token, rho: p.rho, s: p.s, delta: p.delta, guardian_pkcs8: new_pkcs8, claim_after, claim_before });
                st.pending = None;
                self.wallet.save(&st)?;
                Ok(ReplaceOutcome::Waiting { claim_after: dates::fmt_day(claim_after), claim_before: dates::fmt_day(claim_before), suspended })
            }
        }
    }

    /// Collect the credential of a replacement whose wait is over. Returns the day from which the new
    /// secret counts.
    pub async fn replace_claim(&self) -> Result<String> {
        let _g = self.busy.lock().await;
        let mut st = self.wallet.load()?;
        let c = st.claim.clone().ok_or(HolderError::NoClaim)?;
        let cx = self.ctx().await?;
        if cx.today < c.claim_after {
            return Err(HolderError::ClaimTooEarly(dates::fmt_day(c.claim_after)));
        }
        let secrets = HolderSecrets { rho: from_hex(&c.rho)?, s: from_hex(&c.s)?, delta: c.delta };
        let req = BlindRequest::for_secrets(&mut OsRng, &cx.scheme, &secrets, &claim_session(&c.claim_token));
        let issuance = match self.issuer.replace_claim(&ClaimRequest { claim_token: c.claim_token.clone(), blind_request: req }).await {
            // refused by the old app, superseded or run out: nothing left to wait for
            Err(e @ ApiError::Server { status: 404 | 410, .. }) => {
                st.claim = None;
                self.wallet.save(&st)?;
                return Err(e.into());
            }
            r => r?,
        };
        let cred = cx.scheme.finish_issuance(&cx.issuer_pk, &cx.witness_pk, &secrets, &issuance.signature, &issuance.attrs, &HandleSignature::from_hex(&issuance.handle_signature)?)?;
        Self::install_replacement(&mut st, &cred, c.guardian_pkcs8, issuance.backup_ticket);
        self.wallet.save(&st)?;
        self.sync_backup(&st).await;
        Ok(dates::fmt_day(cred.attrs.certified))
    }

    /// Is someone waiting to replace THIS device's secret? The app asks at every start and warns the
    /// person. Unless they asked for it themselves on a new device, they refuse it by doing the
    /// identity re-check (`recheck_start`, `recheck_finish`): the eID and this device's secret
    /// together outrank the eID alone. The guardian key alone refuses nothing, so a thief of the
    /// phone cannot keep its owner from replacing the secret.
    pub async fn pending_replacement(&self) -> Result<Option<PendingReplacement>> {
        let st = self.wallet.load()?;
        let Ok(cred) = Self::credential(&st) else { return Ok(None) };
        let list = self.issuer.replace_pending().await?;
        Ok(list.entries.into_iter().find(|e| e.id == pending_id(cred.handle(), &e.nonce)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_round_trip_and_typing() {
        let code = new_code();
        assert_eq!(code.len(), CODE_CHARS);
        let shown = format_code(&code);
        assert_eq!(normalise_code(&shown).as_deref(), Some(code.as_str()));
        assert_eq!(normalise_code(&shown.to_lowercase().replace('-', " ")).as_deref(), Some(code.as_str()));
        assert_eq!(normalise_code("O0Il1-").map(|s| s.len()), None);
        assert!(normalise_code(&code[1..]).is_none());
    }

    #[test]
    fn seal_open_and_tamper() {
        let keys = derive(&new_code());
        let file = BackupFile { v: 1, credential: serde_json::json!({"x": 1}), guardian_pkcs8: Some("aa".into()), bindings: vec![], saved_on: 7 };
        let blob = seal(&keys, &file).unwrap();
        // padded: the size does not depend on small differences in content
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(&blob).unwrap().len(), 12 + PAD + 16);
        assert_eq!(open(&keys, &blob).unwrap().credential["x"], 1);
        assert!(matches!(open(&derive(&new_code()), &blob), Err(HolderError::BadBackup)));
        let mut raw = base64::engine::general_purpose::STANDARD.decode(&blob).unwrap();
        raw[40] ^= 1;
        assert!(matches!(open(&keys, &base64::engine::general_purpose::STANDARD.encode(raw)), Err(HolderError::BadBackup)));
        // id, write key and encryption key are unrelated values
        assert!(keys.id != keys.write_key[..32] && keys.write_key != keys.enc_key);
    }
}
