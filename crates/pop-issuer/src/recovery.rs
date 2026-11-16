//! The two-year identity re-check and the replacement of a lost secret (docs/recovery.md).
//!
//! Both start like an enrolment: `POST /v1/enrol/start` with a purpose, a login at the identity
//! provider, and the confirmation code typed into the app. What differs is what the session is good
//! for afterwards:
//!
//! * `POST /v1/recheck`: the holder still has its credential. It shows the handle and the month of
//!   the last check inside a renewal proof; the issuer signs the same secret with a new month. The
//!   pseudonyms stay.
//! * `POST /v1/replace`: the secret is gone or stolen. A new secret is certified, the old handle is
//!   revoked, and the new secret starts a fresh probation. With a signature of the old guardian key
//!   this happens at once; without it the request waits, and a re-check with the old secret
//!   cancels it.
use crate::service::{authenticated_session, check_date_and_root, check_guardian_key, drop_session, err, ApiErr, Enrolment, Issuer, St, T_ENROL};
use axum::{extract::State, http::StatusCode, Json};
use pop_crypto::{dates, BlindRequest, Day, VerifyCtx};
use pop_protocol::api::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A person can replace the secret at most this often. Each replacement puts one more handle on the
/// revocation list for good, so this bounds how fast one person can grow it.
pub const REPLACE_MIN_INTERVAL_DAYS: u32 = 30;
/// A replacement that has waited out its veto period must be claimed within this many days.
pub const CLAIM_WINDOW_DAYS: u32 = 90;

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct PendingReplace {
    /// day of the identity check
    pub(crate) requested_on: Day,
    /// SHA-256 of the claim token
    pub(crate) claim_hash: String,
    /// published with the pending entry, so that only the holder of the handle recognises it
    pub(crate) nonce: String,
    /// the new guardian key
    pub(crate) guardian: String,
}

fn sha_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn verify_guardian(guardian_hex: &str, msg: &[u8], sig_hex: &str) -> Result<(), ApiErr> {
    let pk = hex::decode(guardian_hex)?;
    let sig = hex::decode(sig_hex)?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pk)
        .verify(msg, &sig)
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "bad guardian signature"))
}

async fn load_record(s: &Issuer, d: &str) -> Result<Enrolment, ApiErr> {
    let v = s.store.get(T_ENROL, d).await?.ok_or_else(|| err(StatusCode::CONFLICT, "the enrolment record is gone; start again"))?;
    Ok(serde_json::from_value(v)?)
}

/// Every record with its key. The prototype's store has no secondary index; a real one looks records
/// up by handle and by claim hash.
async fn records(s: &Issuer) -> Result<Vec<(String, Enrolment)>, ApiErr> {
    let mut out = vec![];
    for (d, v) in s.store.list(T_ENROL).await? {
        if let Ok(rec) = serde_json::from_value::<Enrolment>(v) {
            out.push((d, rec));
        }
    }
    Ok(out)
}

fn pending_expired(s: &Issuer, p: &PendingReplace, today: Day) -> bool {
    today > p.requested_on + s.cfg.replace_wait_days + CLAIM_WINDOW_DAYS
}

pub(crate) async fn recheck(State(s): State<St>, Json(req): Json<RecheckRequest>) -> Result<Json<RecheckResponse>, ApiErr> {
    let (sess, d, _) = authenticated_session(&s, &req.session, Purpose::Recheck, &req.confirm_code).await?;
    let _g = s.records.lock().await;
    let mut rec = load_record(&s, &d).await?;
    if rec.status != "active" {
        return Err(err(StatusCode::CONFLICT, "this enrolment was revoked; replace the secret instead"));
    }
    // the login says who this is; the credential must be that person's own
    if rec.handle != req.handle {
        return Err(err(StatusCode::FORBIDDEN, "this credential does not belong to the person who logged in"));
    }
    let root = check_date_and_root(&s, req.today, &req.revocation_root, false)?;
    let today = s.today();
    let new_check = dates::month_start(today);
    let new_expiry = dates::quarter_end(dates::quarter_of(today) + 1);
    let vc = VerifyCtx { issuer: &s.key.public, witness: &s.witness.public, today: req.today, revocation_root: root };
    let signature = {
        let mut rng = s.rng.lock().unwrap();
        s.scheme.reissue_recheck(&mut *rng, &s.key, &vc, req.session.as_bytes(), &req.proof, req.handle, req.last_check, new_expiry, new_check)?
    };
    // the person holds both the eID and the old secret: whoever asked to replace it was someone else
    if rec.pending.take().is_some() {
        s.store.put(T_ENROL, &d, serde_json::to_value(&rec)?).await?;
        tracing::warn!("a waiting replacement was cancelled by a re-check with the old secret");
    }
    drop_session(&s, &req.session, &sess).await?;
    let backup_ticket = Some(crate::backup::new_ticket(&s).await?);
    Ok(Json(RecheckResponse { signature, new_expiry, new_check, backup_ticket }))
}

/// Certify a new secret for the person behind `rec`, revoke the old handle and update the record.
/// `checked_on` is the day of the identity check this replacement rests on.
async fn issue_replacement(s: &Issuer, d: &str, rec: &mut Enrolment, blind: &BlindRequest, session: &[u8], guardian: &str, checked_on: Day) -> Result<IssuanceResponse, ApiErr> {
    let today = s.today();
    let handle = s.new_handle();
    let mut attrs = s.attrs_for(handle);
    // A replaced secret never counts at once, rollout window or not: its probation runs from the
    // start of the NEXT quarter, so it is at least nine months long. This is what makes a stolen
    // eID login worth little.
    attrs.certified = dates::quarter_start(dates::quarter_of(today) + 1);
    attrs.last_check = dates::month_start(checked_on);
    attrs.first_quarter = dates::quarter_of(rec.enrolled_on);
    let signature = {
        let mut rng = s.rng.lock().unwrap();
        s.scheme.issue_blind(&mut *rng, &s.key, blind, &attrs, session)?
    };
    let hs = s.witness.sign_handle(&mut *s.rng.lock().unwrap(), handle);
    // revoke before the record changes: if anything fails in between, the person is left without a
    // working credential and asks again, never with two
    let old = rec.handle;
    s.revoke_handle(old).await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    rec.handle = handle;
    rec.guardian = guardian.to_string();
    rec.status = "active".into();
    rec.replaced_on = Some(today);
    rec.pending = None;
    s.store.put(T_ENROL, d, serde_json::to_value(&*rec)?).await?;
    tracing::info!("replaced a secret (old handle revoked, identity not stored)");
    let backup_ticket = Some(crate::backup::new_ticket(s).await?);
    Ok(IssuanceResponse { signature, attrs, handle_signature: hs.to_hex(), backup_ticket })
}

fn too_soon(rec: &Enrolment, today: Day) -> Result<(), ApiErr> {
    match rec.replaced_on {
        Some(last) if today < last + REPLACE_MIN_INTERVAL_DAYS => Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            format!("the secret was replaced on {}; the next replacement is possible from {}", dates::fmt_day(last), dates::fmt_day(last + REPLACE_MIN_INTERVAL_DAYS)),
        )),
        _ => Ok(()),
    }
}

pub(crate) async fn replace(State(s): State<St>, Json(req): Json<ReplaceRequest>) -> Result<Json<ReplaceResponse>, ApiErr> {
    let (sess, d, _) = authenticated_session(&s, &req.session, Purpose::Replace, &req.confirm_code).await?;
    check_guardian_key(&req.guardian_public_key)?;
    let _g = s.records.lock().await;
    let mut rec = load_record(&s, &d).await?;
    let today = s.today();
    too_soon(&rec, today)?;
    if let Some(sig) = &req.old_guardian_signature {
        verify_guardian(&rec.guardian, &replace_message(&req.session, &req.blind_request.commitment, &req.guardian_public_key), sig)?;
        let issuance = issue_replacement(&s, &d, &mut rec, &req.blind_request, req.session.as_bytes(), &req.guardian_public_key, today).await?;
        drop_session(&s, &req.session, &sess).await?;
        return Ok(Json(ReplaceResponse::Issued { issuance }));
    }
    // No proof of the old device: the eID alone asks. Wait, publish the request so the old app can
    // warn its owner (who refuses it with a re-check), and hand out the credential only afterwards. A newer request replaces an older one
    // and starts the wait again.
    let claim_token = s.rand_hex(24);
    rec.pending = Some(PendingReplace { requested_on: today, claim_hash: sha_hex(&claim_token), nonce: s.rand_hex(16), guardian: req.guardian_public_key.clone() });
    s.store.put(T_ENROL, &d, serde_json::to_value(&rec)?).await?;
    drop_session(&s, &req.session, &sess).await?;
    let claim_after = today + s.cfg.replace_wait_days;
    Ok(Json(ReplaceResponse::Pending { claim_token, claim_after, claim_before: claim_after + CLAIM_WINDOW_DAYS }))
}

pub(crate) async fn claim(State(s): State<St>, Json(req): Json<ClaimRequest>) -> Result<Json<IssuanceResponse>, ApiErr> {
    if req.claim_token.len() > 128 {
        return Err(err(StatusCode::BAD_REQUEST, "bad claim token"));
    }
    let _g = s.records.lock().await;
    let hash = sha_hex(&req.claim_token);
    let found = records(&s).await?.into_iter().find(|(_, r)| r.pending.as_ref().map(|p| p.claim_hash == hash).unwrap_or(false));
    let (d, mut rec) = found.ok_or_else(|| err(StatusCode::NOT_FOUND, "no waiting replacement for this token (it may have been refused with the old app, or replaced by a newer request)"))?;
    let p = rec.pending.clone().expect("found by its pending entry");
    let today = s.today();
    let claim_after = p.requested_on + s.cfg.replace_wait_days;
    if today < claim_after {
        return Err(err(StatusCode::CONFLICT, format!("this replacement waits until {}", dates::fmt_day(claim_after))));
    }
    if pending_expired(&s, &p, today) {
        rec.pending = None;
        s.store.put(T_ENROL, &d, serde_json::to_value(&rec)?).await?;
        return Err(err(StatusCode::GONE, "this replacement was not claimed in time; start again"));
    }
    too_soon(&rec, today)?;
    let issuance = issue_replacement(&s, &d, &mut rec, &req.blind_request, &claim_session(&req.claim_token), &p.guardian, p.requested_on).await?;
    Ok(Json(issuance))
}

pub(crate) async fn pending(State(s): State<St>) -> Result<Json<PendingReplacements>, ApiErr> {
    let today = s.today();
    let entries = records(&s)
        .await?
        .into_iter()
        .filter_map(|(_, r)| {
            let p = r.pending.as_ref()?;
            (!pending_expired(&s, p, today)).then(|| PendingReplacement {
                id: pending_id(r.handle, &p.nonce),
                nonce: p.nonce.clone(),
                requested_on: p.requested_on,
                claim_after: p.requested_on + s.cfg.replace_wait_days,
            })
        })
        .collect();
    Ok(Json(PendingReplacements { entries }))
}
