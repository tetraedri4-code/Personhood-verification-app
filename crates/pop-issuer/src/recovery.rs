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
use crate::service::{authenticated_session, check_date_and_root, check_date_and_root_before, check_guardian_key, drop_session, err, ApiErr, Enrolment, Issuer, St, T_ENROL};
use axum::{extract::State, http::StatusCode, Json};
use pop_crypto::{dates, BlindRequest, Day, VerifyCtx};
use pop_protocol::api::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// The numbers below (waits, probations, intervals) are settings: `s.cfg.policy`, see crate::policy.

/// A replacement issued at once after a theft report, which the replaced secret can still block.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct Contest {
    /// the replaced secret's handle (revoked; a re-check with it blocks the replacement)
    pub(crate) old_handle: u64,
    /// the replaced secret's guardian key, restored when it blocks
    pub(crate) old_guardian: String,
    /// last day a block is possible
    pub(crate) until: Day,
}

/// How long a new secret waits before it counts.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Probation {
    /// counts at once
    None,
    /// `policy.report_probation_days`, rounded up to a Monday
    Report,
    /// `policy.probation_days` (about nine months)
    Full,
}

/// Is the person's once-in-two-years allowance for a counted replacement after a report unused?
fn fresh_allowed(s: &Issuer, rec: &Enrolment, today: Day) -> bool {
    rec.fresh_replacement_on.is_none_or(|f| today >= f + s.cfg.policy.fresh_replacement_interval_days)
}

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
    /// the request came with a theft report ("it wasn't me")
    #[serde(default)]
    pub(crate) report: bool,
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

fn pending_expired(s: &Issuer, p: &PendingReplace, today: Day) -> bool {
    today > p.requested_on + s.cfg.policy.replace_wait_days + s.cfg.policy.claim_window_days
}

pub(crate) async fn recheck(State(s): State<St>, Json(req): Json<RecheckRequest>) -> Result<Json<RecheckResponse>, ApiErr> {
    let (sess, d, _) = authenticated_session(&s, &req.session, Purpose::Recheck, &req.confirm_code).await?;
    let _g = s.records.lock().await;
    let mut rec = load_record(&s, &d).await?;
    let today = s.today();
    if rec.contest.as_ref().is_some_and(|c| today > c.until) {
        rec.contest = None;
        crate::index::put_record(&s, &d, &rec).await?;
    }
    // the replaced secret of a replacement made after a theft report, within the time to block it
    let blocking = rec.contest.as_ref().is_some_and(|c| c.old_handle == req.handle);
    // (the reported side revoking its own new secret must not end the time to block)
    if rec.status != "active" && !blocking {
        return Err(err(StatusCode::CONFLICT, "this enrolment was revoked; replace the secret instead"));
    }
    // the login says who this is; the credential must be that person's own
    if rec.handle != req.handle && !blocking {
        return Err(err(StatusCode::FORBIDDEN, "this credential does not belong to the person who logged in"));
    }
    // A suspended secret's handle is on the revocation list, so its proof cannot be against the current
    // list. It is against the list as it was just before the handle went on it: the handle is shown and
    // checked against the record here, which is all non-revocation would have told.
    let (root, new_handle) = if blocking {
        (check_date_and_root_before(&s, req.today, &req.revocation_root, req.handle)?, Some(s.new_handle()))
    } else if rec.suspended_on.is_some() {
        (check_date_and_root_before(&s, req.today, &req.revocation_root, rec.handle)?, Some(s.new_handle()))
    } else {
        (check_date_and_root(&s, req.today, &req.revocation_root)?, None)
    };
    let new_check = dates::month_start(today);
    let new_expiry = dates::quarter_end(dates::quarter_of(today) + 1);
    let vc = VerifyCtx { issuer: &s.key.public, witness: &s.witness.public, today: req.today, revocation_root: root };
    let signature = {
        let mut rng = s.rng.lock().unwrap();
        s.scheme.reissue_recheck(&mut *rng, &s.key, &vc, req.session.as_bytes(), &req.proof, req.handle, req.last_check, new_expiry, new_check, new_handle)?
    };
    let new_handle = new_handle.map(|h| (h, s.witness.sign_handle(&mut *s.rng.lock().unwrap(), h).to_hex()));
    if let (true, Some((h, _))) = (blocking, &new_handle) {
        // The replaced secret and the eID together: the report was not the owner's. The secret it
        // gave is revoked, the old one works again under a new handle. The two-year allowance stays
        // used, so a thief who keeps the eID cannot repeat this every month.
        let c = rec.contest.take().expect("blocking");
        s.revoke_handle(rec.handle).await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        rec.handle = *h;
        rec.guardian = c.old_guardian;
        rec.status = "active".into();
        rec.suspended_on = None;
        rec.pending = None;
        crate::index::put_record(&s, &d, &rec).await?;
        tracing::warn!("a replacement after a theft report was blocked by a re-check with the replaced secret");
    } else if let Some((h, _)) = &new_handle {
        // the person has both the old secret and the eID: the report was not theirs to make, or the
        // thief has lost the eID since. Same secret, new handle; the old handle stays revoked.
        rec.handle = *h;
        rec.suspended_on = None;
        rec.pending = None;
        crate::index::put_record(&s, &d, &rec).await?;
        tracing::warn!("a suspension was lifted by a re-check with the old secret");
    }
    // the person holds both the eID and the old secret: whoever asked to replace it was someone else
    if rec.pending.take().is_some() {
        crate::index::put_record(&s, &d, &rec).await?;
        tracing::warn!("a waiting replacement was cancelled by a re-check with the old secret");
    }
    drop_session(&s, &req.session, &sess).await?;
    let backup_ticket = Some(crate::backup::new_ticket(&s).await?);
    Ok(Json(RecheckResponse { signature, new_expiry, new_check, backup_ticket, new_handle }))
}

/// Certify a new secret for the person behind `rec`, revoke the old handle and update the record.
/// `checked_on` is the day of the identity check this replacement rests on.
/// `probation`: when the new secret counts. Anything shorter than [`Probation::Full`] uses the
/// person's two-year allowance (`policy.fresh_replacement_interval_days`).
#[allow(clippy::too_many_arguments)]
async fn issue_replacement(s: &Issuer, d: &str, rec: &mut Enrolment, blind: &BlindRequest, session: &[u8], guardian: &str, checked_on: Day, probation: Probation) -> Result<IssuanceResponse, ApiErr> {
    let today = s.today();
    let handle = s.new_handle();
    let mut attrs = s.attrs_for(handle);
    // A replaced secret does not count for about nine months. Each new secret
    // can like every post again, and this is what makes a stolen eID login worth little.
    attrs.certified = match probation {
        Probation::None => dates::week_start(today),
        // at least the full probation, up to the next Monday
        Probation::Report => dates::week_start(today + s.cfg.policy.report_probation_days - 1) + 7,
        Probation::Full => dates::week_start(today) + s.cfg.policy.probation_days,
    };
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
    rec.suspended_on = None;
    // a block stays possible across later replacements: whoever holds the new secret's guardian key
    // must not be able to end it by replacing that secret again
    if probation != Probation::Full {
        rec.fresh_replacement_on = Some(today);
    }
    crate::index::put_record(s, d, rec).await?;
    tracing::info!("replaced a secret (old handle revoked, identity not stored)");
    let backup_ticket = Some(crate::backup::new_ticket(s).await?);
    Ok(IssuanceResponse { signature, attrs, handle_signature: hs.to_hex(), backup_ticket })
}

fn too_soon(s: &Issuer, rec: &Enrolment, today: Day) -> Result<(), ApiErr> {
    let min = s.cfg.policy.replace_min_interval_days;
    match rec.replaced_on {
        Some(last) if today < last + min => Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            format!("the secret was replaced on {}; the next replacement is possible from {}", dates::fmt_day(last), dates::fmt_day(last + min)),
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
    too_soon(&s, &rec, today)?;
    if let Some(sig) = &req.old_guardian_signature {
        if req.report_theft {
            return Err(err(StatusCode::BAD_REQUEST, "whoever holds the guardian key enrolled this secret: a theft report needs no key"));
        }
        verify_guardian(&rec.guardian, &replace_message(&req.session, &req.blind_request.commitment, &req.guardian_public_key), sig)?;
        let issuance = issue_replacement(&s, &d, &mut rec, &req.blind_request, req.session.as_bytes(), &req.guardian_public_key, today, Probation::Full).await?;
        drop_session(&s, &req.session, &sess).await?;
        return Ok(Json(ReplaceResponse::Issued { issuance }));
    }
    // "It wasn't me", with the two-year allowance unused: the new secret comes now, counts after a
    // week, and the replaced one can block it for 90 days with a re-check
    if req.report_theft && fresh_allowed(&s, &rec, today) {
        if rec.reported_on.is_none_or(|r| today >= r + s.cfg.policy.report_count_interval_days) {
            s.count_report().await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            rec.reported_on = Some(today);
        }
        let contest = Contest { old_handle: rec.handle, old_guardian: rec.guardian.clone(), until: today + s.cfg.policy.contest_days };
        let issuance = issue_replacement(&s, &d, &mut rec, &req.blind_request, req.session.as_bytes(), &req.guardian_public_key, today, Probation::Report).await?;
        rec.contest = Some(contest);
        crate::index::put_record(&s, &d, &rec).await?;
        drop_session(&s, &req.session, &sess).await?;
        tracing::warn!("a theft report replaced a secret at once; the replaced secret can block it");
        return Ok(Json(ReplaceResponse::Issued { issuance }));
    }
    // No proof of the old device: the eID alone asks. Wait, publish the request so the old app can
    // warn its owner (who refuses it with a re-check), and hand out the credential only afterwards. A newer request replaces an older one
    // and starts the wait again.
    let mut suspended = false;
    if req.report_theft {
        // "It wasn't me": stop the other secret now. Whoever holds it and the eID lifts this with a
        // re-check; a thief who no longer has the eID cannot.
        if rec.suspended_on.is_none() {
            s.revoke_handle(rec.handle).await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            rec.suspended_on = Some(today);
        }
        suspended = true;
        if rec.reported_on.is_none_or(|r| today >= r + s.cfg.policy.report_count_interval_days) {
            s.count_report().await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            rec.reported_on = Some(today);
        }
    }
    let claim_token = s.rand_hex(24);
    rec.pending = Some(PendingReplace {
        requested_on: today,
        claim_hash: sha_hex(&claim_token),
        nonce: s.rand_hex(16),
        guardian: req.guardian_public_key.clone(),
        report: req.report_theft,
    });
    crate::index::put_record(&s, &d, &rec).await?;
    drop_session(&s, &req.session, &sess).await?;
    let claim_after = today + s.cfg.policy.replace_wait_days;
    Ok(Json(ReplaceResponse::Pending { claim_token, claim_after, claim_before: claim_after + s.cfg.policy.claim_window_days, suspended }))
}

pub(crate) async fn claim(State(s): State<St>, Json(req): Json<ClaimRequest>) -> Result<Json<IssuanceResponse>, ApiErr> {
    if req.claim_token.len() > 128 {
        return Err(err(StatusCode::BAD_REQUEST, "bad claim token"));
    }
    let _g = s.records.lock().await;
    let hash = sha_hex(&req.claim_token);
    let found = crate::index::by_claim(&s, &hash).await?;
    let (d, mut rec) = found.ok_or_else(|| err(StatusCode::NOT_FOUND, "no waiting replacement for this token (it may have been refused with the old app, or replaced by a newer request)"))?;
    let p = rec.pending.clone().expect("found by its pending entry");
    let today = s.today();
    let claim_after = p.requested_on + s.cfg.policy.replace_wait_days;
    if today < claim_after {
        return Err(err(StatusCode::CONFLICT, format!("this replacement waits until {}", dates::fmt_day(claim_after))));
    }
    if pending_expired(&s, &p, today) {
        rec.pending = None;
        crate::index::put_record(&s, &d, &rec).await?;
        return Err(err(StatusCode::GONE, "this replacement was not claimed in time; start again"));
    }
    too_soon(&s, &rec, today)?;
    // Nobody lifted the suspension in all that time with the old secret and the eID: the report
    // stands, and the person should not wait again for a theft they suffered.
    let fresh = p.report && rec.suspended_on.is_some() && fresh_allowed(&s, &rec, today);
    let probation = if fresh { Probation::None } else { Probation::Full };
    let issuance = issue_replacement(&s, &d, &mut rec, &req.blind_request, &claim_session(&req.claim_token), &p.guardian, p.requested_on, probation).await?;
    Ok(Json(issuance))
}

pub(crate) async fn pending(State(s): State<St>) -> Result<Json<PendingReplacements>, ApiErr> {
    let today = s.today();
    let entries = crate::index::pending(&s)
        .await?
        .into_iter()
        .filter_map(|(_, r)| {
            let p = r.pending.as_ref()?;
            (!pending_expired(&s, p, today)).then(|| PendingReplacement {
                id: pending_id(r.handle, &p.nonce),
                nonce: p.nonce.clone(),
                requested_on: p.requested_on,
                claim_after: p.requested_on + s.cfg.policy.replace_wait_days,
            })
        })
        .collect();
    Ok(Json(PendingReplacements { entries }))
}
