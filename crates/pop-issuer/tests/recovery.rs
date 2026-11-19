//! Re-check, replacement and backup against a real issuer over HTTP, with the calendar under the
//! test's control. The "holder" here is the bare protocol (pop-crypto + the HTTP client), so the
//! tests can also send what an honest app never would.
use pop_crypto::{dates, root_to_hex, BlindRequest, Credential, Day, HandleSignature, HolderSecrets, IssuerPublicKey, ProofSystem, Scheme, SchemeConfig, WitnessPublicKey};
use pop_idp::StaticProvider;
use pop_issuer::{HmacUniqueness, Issuer, IssuerConfig, Policy};
use pop_protocol::api::*;
use pop_protocol::http::HttpClient;
use rand::rngs::OsRng;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

struct World {
    api: HttpClient,
    scheme: Arc<Scheme>,
    ipk: IssuerPublicKey,
    wpk: WitnessPublicKey,
    day: Arc<AtomicU32>,
    url: String,
}

struct Person {
    secrets: HolderSecrets,
    cred: Credential,
    guardian: Ed25519KeyPair,
    ticket: Option<String>,
}

fn status(e: &ApiError) -> u16 {
    match e {
        ApiError::Server { status, .. } => *status,
        _ => 0,
    }
}

async fn world(wait: u32) -> World {
    world_with(Policy { replace_wait_days: wait, ..Default::default() }).await
}

async fn world_with(policy: Policy) -> World {
    let config = SchemeConfig { proof_system: ProofSystem::Bulletproofs, tree_depth: 4, slots: 3, bp_gens_log2: 13 };
    let day = Arc::new(AtomicU32::new(dates::from_civil(2026, 11, 16)));
    let d2 = day.clone();
    let issuer = Issuer::new(
        Arc::new(Scheme::new(config.clone())),
        Arc::new(StaticProvider { country: 246 }),
        Arc::new(HmacUniqueness::new(vec![vec![7u8; 32]]).unwrap()),
        pop_storage::MemoryStore::shared(),
        IssuerConfig { clock: Some(Arc::new(move || d2.load(Ordering::SeqCst))), policy, ..Default::default() },
    )
    .await
    .unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let api = HttpClient::new(&url);
    tokio::spawn(async move { axum::serve(l, pop_issuer::router(issuer)).await.unwrap() });
    let p = api.params().await.unwrap();
    World { scheme: Arc::new(Scheme::new(p.config)), ipk: IssuerPublicKey::from_hex(&p.issuer_public_key).unwrap(), wpk: WitnessPublicKey::from_hex(&p.witness_public_key).unwrap(), api, day, url }
}

impl World {
    fn today(&self) -> Day {
        self.day.load(Ordering::SeqCst)
    }
    fn advance(&self, days: u32) {
        self.day.fetch_add(days, Ordering::SeqCst);
    }

    /// Log `subject` in for `purpose`. Returns the session and the confirmation code on the page
    /// (empty if the issuer showed none).
    async fn login(&self, purpose: Purpose, subject: &str) -> (String, String) {
        let r = self.api.enrol_start(purpose).await.unwrap();
        let state = r.authorize_url.strip_prefix("static:").unwrap();
        let html = reqwest::get(format!("{}/v1/enrol/callback?code={subject}&state={state}", self.api.base())).await.unwrap().text().await.unwrap();
        let code = html.split("id=\"confirm-code\"").nth(1).and_then(|r| r.split('>').nth(1)).and_then(|r| r.split('<').next()).unwrap_or_default().to_string();
        (r.session, code)
    }

    fn guardian() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn finish(&self, secrets: &HolderSecrets, r: &IssuanceResponse) -> Credential {
        self.scheme.finish_issuance(&self.ipk, &self.wpk, secrets, &r.signature, &r.attrs, &HandleSignature::from_hex(&r.handle_signature).unwrap()).unwrap()
    }

    async fn enrol(&self, subject: &str) -> Person {
        let (session, code) = self.login(Purpose::Enrol, subject).await;
        let (secrets, req) = BlindRequest::new(&mut OsRng, &self.scheme, session.as_bytes());
        let guardian = Self::guardian();
        let r = self
            .api
            .enrol_finish(&EnrolFinishRequest { session, blind_request: req, guardian_public_key: hex::encode(guardian.public_key().as_ref()), confirm_code: code })
            .await
            .unwrap();
        Person { cred: self.finish(&secrets, &r), secrets, guardian, ticket: r.backup_ticket }
    }

    async fn tree(&self) -> (pop_crypto::revtree::RevocationTree, String) {
        let rv = self.api.revocations().await.unwrap();
        let tree = self.scheme.revocation_tree(&rv.revoked).unwrap();
        let root = root_to_hex(&tree.root());
        (tree, root)
    }

    async fn renew(&self, p: &mut Person) -> Result<(), String> {
        let (tree, root) = self.tree().await;
        let (proof, rho) = self.scheme.prove_renewal(&mut OsRng, &p.cred, &tree, &self.ipk, &self.wpk, self.today(), b"n").map_err(|e| format!("prove: {e}"))?;
        let r = self.api.renew(&RenewRequest { nonce: "n".into(), today: self.today(), revocation_root: root, proof }).await.map_err(|e| e.to_string())?;
        p.cred = self.scheme.finish_renewal(&self.ipk, &p.cred, rho, &r.signature, r.new_expiry).map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn recheck_request(&self, cred: &Credential, session: &str, code: &str) -> (RecheckRequest, pop_crypto::params::Fr) {
        // a suspended secret proves against the list as it was just before its suspension
        let rv = self.api.revocations().await.unwrap().revoked;
        let (tree, root) = match rv.iter().position(|h| *h == cred.handle()) {
            Some(pos) => {
                let t = self.scheme.revocation_tree(&rv[..pos]).unwrap();
                let r = root_to_hex(&t.root());
                (t, r)
            }
            None => self.tree().await,
        };
        let (proof, rho) = self.scheme.prove_recheck(&mut OsRng, cred, &tree, &self.ipk, &self.wpk, self.today(), session.as_bytes()).unwrap();
        (RecheckRequest { session: session.into(), confirm_code: code.into(), today: self.today(), revocation_root: root, handle: cred.handle(), last_check: cred.attrs.last_check, proof }, rho)
    }

    async fn recheck(&self, p: &mut Person, subject: &str) -> Result<(), ApiError> {
        let (session, code) = self.login(Purpose::Recheck, subject).await;
        let (req, rho) = self.recheck_request(&p.cred, &session, &code).await;
        let r = self.api.identity_recheck(&req).await?;
        let nh = r.new_handle.as_ref().map(|(h, sig)| (*h, HandleSignature::from_hex(sig).unwrap()));
        p.cred = self.scheme.finish_recheck(&self.ipk, &self.wpk, &p.cred, rho, &r.signature, r.new_expiry, r.new_check, nh.as_ref().map(|(h, s)| (*h, s))).unwrap();
        Ok(())
    }

    /// Ask to replace `subject`'s secret; `signer` is the guardian key that signs, if any.
    async fn replace(&self, subject: &str, signer: Option<&Ed25519KeyPair>) -> Result<(HolderSecrets, Ed25519KeyPair, ReplaceResponse), ApiError> {
        self.replace_with(subject, signer, false).await
    }

    /// As `replace`, optionally as a theft report ("it wasn't me").
    async fn replace_with(&self, subject: &str, signer: Option<&Ed25519KeyPair>, report_theft: bool) -> Result<(HolderSecrets, Ed25519KeyPair, ReplaceResponse), ApiError> {
        let (session, code) = self.login(Purpose::Replace, subject).await;
        let (secrets, req) = BlindRequest::new(&mut OsRng, &self.scheme, session.as_bytes());
        let guardian = Self::guardian();
        let new_pub = hex::encode(guardian.public_key().as_ref());
        let sig = signer.map(|g| hex::encode(g.sign(&replace_message(&session, &req.commitment, &new_pub)).as_ref()));
        let r = self.api.replace(&ReplaceRequest { session, confirm_code: code, blind_request: req, guardian_public_key: new_pub, old_guardian_signature: sig, report_theft }).await?;
        Ok((secrets, guardian, r))
    }

    async fn claim(&self, token: &str, secrets: &HolderSecrets) -> Result<Credential, ApiError> {
        let req = BlindRequest::for_secrets(&mut OsRng, &self.scheme, secrets, &claim_session(token));
        let r = self.api.replace_claim(&ClaimRequest { claim_token: token.into(), blind_request: req }).await?;
        Ok(self.finish(secrets, &r))
    }
}

#[tokio::test]
async fn recheck_keeps_a_credential_alive_past_two_years() {
    let w = world(90).await;
    let mut alice = w.enrol("alice").await;
    let mut carol = w.enrol("carol").await;
    let secret = alice.cred.secret();

    // a login for one purpose is good for that purpose only
    let (session, code) = w.login(Purpose::Recheck, "alice").await;
    let (_, req) = BlindRequest::new(&mut OsRng, &w.scheme, session.as_bytes());
    let g = hex::encode(World::guardian().public_key().as_ref());
    let e = w.api.enrol_finish(&EnrolFinishRequest { session: session.clone(), blind_request: req.clone(), guardian_public_key: g.clone(), confirm_code: code.clone() }).await.unwrap_err();
    assert_eq!(status(&e), 409, "{e}");
    let e = w.api.replace(&ReplaceRequest { session, confirm_code: code, blind_request: req, guardian_public_key: g, old_guardian_signature: None, report_theft: false }).await.unwrap_err();
    assert_eq!(status(&e), 409, "{e}");
    // a person who is not enrolled cannot re-check or replace; an enrolled one cannot enrol
    let (s1, c1) = w.login(Purpose::Recheck, "nobody").await;
    assert_eq!((w.api.enrol_status(&s1).await.unwrap(), c1.as_str()), (EnrolStatus::NotEnrolled, ""));
    let (s2, _) = w.login(Purpose::Replace, "nobody").await;
    assert_eq!(w.api.enrol_status(&s2).await.unwrap(), EnrolStatus::NotEnrolled);
    let (s3, _) = w.login(Purpose::Enrol, "alice").await;
    assert_eq!(w.api.enrol_status(&s3).await.unwrap(), EnrolStatus::AlreadyEnrolled);

    w.advance(300);
    w.renew(&mut alice).await.unwrap();
    w.renew(&mut carol).await.unwrap();
    w.advance(300);
    w.renew(&mut carol).await.unwrap();

    // Carol logs in but shows Alice's credential: the handle is not the one of Carol's record
    let (session, code) = w.login(Purpose::Recheck, "carol").await;
    let (req, _) = w.recheck_request(&alice.cred, &session, &code).await;
    assert_eq!(status(&w.api.identity_recheck(&req).await.unwrap_err()), 403);
    // Alice's proof for her own session, replayed in another session of hers, with a wrong month, or
    // as a plain renewal proof
    let (session, code) = w.login(Purpose::Recheck, "alice").await;
    let (good, _) = w.recheck_request(&alice.cred, &session, &code).await;
    let (other, code2) = w.login(Purpose::Recheck, "alice").await;
    let e = w.api.identity_recheck(&RecheckRequest { session: other, confirm_code: code2, ..good.clone() }).await.unwrap_err();
    assert_eq!(status(&e), 400, "{e}");
    let e = w.api.identity_recheck(&RecheckRequest { last_check: good.last_check + 31, ..good.clone() }).await.unwrap_err();
    assert_eq!(status(&e), 400, "{e}");
    let e = w.api.identity_recheck(&RecheckRequest { confirm_code: "000000x".into(), ..good.clone() }).await.unwrap_err();
    assert_eq!(status(&e), 403, "{e}");

    let before = alice.cred.attrs.last_check;
    w.recheck(&mut alice, "alice").await.unwrap();
    assert_eq!(alice.cred.attrs.last_check, dates::month_start(w.today()));
    assert!(alice.cred.attrs.last_check > before);
    assert!(alice.cred.secret() == secret, "the secret, and with it every pseudonym, stays");

    // 30 months after enrolment: Alice renews, Carol (no re-check) cannot
    w.advance(200);
    w.renew(&mut alice).await.unwrap();
    w.advance(100);
    w.renew(&mut alice).await.unwrap();
    assert!(w.renew(&mut carol).await.is_err(), "a credential without re-check must stop renewing");
}

#[tokio::test]
async fn replacement_with_the_guardian_key() {
    let w = world(90).await;
    let alice = w.enrol("alice").await;
    let old_handle = alice.cred.handle();

    // a signature of some other key is refused
    let e = w.replace("alice", Some(&World::guardian())).await.err().unwrap();
    assert_eq!(status(&e), 401, "{e}");

    let (secrets, guardian2, r) = w.replace("alice", Some(&alice.guardian)).await.unwrap();
    let ReplaceResponse::Issued { issuance } = r else { panic!("expected the credential at once") };
    let mut new = Person { cred: w.finish(&secrets, &issuance), secrets, guardian: guardian2, ticket: issuance.backup_ticket.clone() };
    assert!(new.ticket.is_some());
    assert!(new.cred.handle() != old_handle);
    assert!(w.api.revocations().await.unwrap().revoked.contains(&old_handle), "the old secret is revoked");
    // probation starts over: forty weeks from this week's Monday
    let q = dates::quarter_of(w.today());
    assert_eq!(new.cred.attrs.certified, dates::week_start(w.today()) + Policy::default().probation_days);
    assert_eq!(new.cred.attrs.first_quarter, q, "the quarter of first enrolment stays");
    // ... so the new secret cannot like yet, nor show a counted badge
    let (tree, _) = w.tree().await;
    assert!(w.scheme.prove_like(&mut OsRng, &new.cred, &tree, &w.ipk, &w.wpk, "ctx", "post", w.today(), w.today()).is_err());
    assert!(w.scheme.prove_binding(&mut OsRng, &new.cred, &tree, &w.ipk, &w.wpk, "ctx", 1, w.today(), w.today(), true, b"x").is_err());
    assert!(w.scheme.prove_binding(&mut OsRng, &new.cred, &tree, &w.ipk, &w.wpk, "ctx", 1, w.today(), w.today(), false, b"x").is_ok());

    // the old credential is dead, the new one lives
    let mut old = alice;
    assert!(w.renew(&mut old).await.is_err());
    w.renew(&mut new).await.unwrap();

    // the old guardian key no longer speaks for the record, and replacing again has to wait
    let e = w.replace("alice", Some(&new.guardian)).await.err().unwrap();
    assert_eq!(status(&e), 429, "{e}");
    w.advance(31);
    let e = w.replace("alice", Some(&old.guardian)).await.err().unwrap();
    assert_eq!(status(&e), 401, "{e}");
    assert!(matches!(w.replace("alice", Some(&new.guardian)).await.unwrap().2, ReplaceResponse::Issued { .. }));

    // after probation the replaced secret likes again
    let (secrets, _, r) = { w.advance(31); if let Err(e) = w.replace("alice", Some(&World::guardian())).await { assert_eq!(status(&e), 401) } w.replace("alice", None).await.unwrap() };
    let ReplaceResponse::Pending { claim_token, .. } = r else { panic!() };
    w.advance(90);
    let c = w.claim(&claim_token, &secrets).await.unwrap();
    let mut p = Person { cred: c, secrets, guardian: World::guardian(), ticket: None };
    for _ in 0..3 {
        w.advance(100);
        w.renew(&mut p).await.unwrap();
    }
    let (tree, _) = w.tree().await;
    assert!(w.scheme.prove_like(&mut OsRng, &p.cred, &tree, &w.ipk, &w.wpk, "ctx", "post", w.today(), w.today()).is_ok());
}

#[tokio::test]
async fn replacement_without_the_guardian_key_waits_and_can_be_refused() {
    let w = world(90).await;
    let mut alice = w.enrol("alice").await;
    let _ = &alice.guardian;
    let handle = alice.cred.handle();

    let (secrets, _, r) = w.replace("alice", None).await.unwrap();
    let ReplaceResponse::Pending { claim_token, claim_after, claim_before, suspended } = r else { panic!("expected to wait") };
    assert_eq!((claim_after, claim_before), (w.today() + 90, w.today() + 180));
    assert!(!suspended, "a plain request suspends nothing");
    // nothing happened to the old secret yet
    assert!(!w.api.revocations().await.unwrap().revoked.contains(&handle));
    w.renew(&mut alice).await.unwrap();

    // the old app finds its own entry in the public list; nobody else can tell whose it is
    let list = w.api.replace_pending().await.unwrap().entries;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, pending_id(handle, &list[0].nonce));
    assert!(list[0].id != pending_id(handle + 1, &list[0].nonce));

    // too early
    let e = w.claim(&claim_token, &secrets).await.err().unwrap();
    assert_eq!(status(&e), 409, "{e}");
    w.advance(89);
    assert_eq!(status(&w.claim(&claim_token, &secrets).await.err().unwrap()), 409);

    // Refusing takes the eID and the old secret together: a re-check. Someone else's re-check, or
    // a plain renewal with the old secret, changes nothing.
    let mut bob = w.enrol("bob").await;
    w.recheck(&mut bob, "bob").await.unwrap();
    w.renew(&mut alice).await.unwrap();
    assert_eq!(w.api.replace_pending().await.unwrap().entries.len(), 1);
    w.recheck(&mut alice, "alice").await.unwrap();
    assert!(w.api.replace_pending().await.unwrap().entries.is_empty());
    w.advance(1);
    assert_eq!(status(&w.claim(&claim_token, &secrets).await.err().unwrap()), 404, "a refused replacement is gone");
    let (s1, _, r1) = w.replace("alice", None).await.unwrap();
    let ReplaceResponse::Pending { claim_token: t1, .. } = r1 else { panic!() };

    // a newer request takes the place of the older one and starts the wait again
    w.advance(50);
    let (s2, g2, r2) = w.replace("alice", None).await.unwrap();
    let ReplaceResponse::Pending { claim_token: t2, .. } = r2 else { panic!() };
    w.advance(60);
    assert_eq!(status(&w.claim(&t1, &s1).await.err().unwrap()), 404);
    assert_eq!(status(&w.claim(&t2, &s2).await.err().unwrap()), 409);
    w.advance(30);
    // a blind request bound to another token is refused
    let wrong = BlindRequest::for_secrets(&mut OsRng, &w.scheme, &s2, &claim_session("other"));
    assert_eq!(status(&w.api.replace_claim(&ClaimRequest { claim_token: t2.clone(), blind_request: wrong }).await.unwrap_err()), 400);
    let cred = w.claim(&t2, &s2).await.unwrap();
    assert!(w.api.revocations().await.unwrap().revoked.contains(&handle));
    assert_eq!(cred.attrs.certified, dates::week_start(w.today()) + Policy::default().probation_days);
    assert!(w.renew(&mut alice).await.is_err(), "the old secret is revoked once the new one is issued");
    assert_eq!(status(&w.claim(&t2, &s2).await.err().unwrap()), 404, "a claim works once");

    // an unclaimed replacement runs out
    w.advance(31);
    let (s3, _, r3) = w.replace("alice", None).await.unwrap();
    let ReplaceResponse::Pending { claim_token: t3, .. } = r3 else { panic!() };
    w.advance(181);
    assert!(w.api.replace_pending().await.unwrap().entries.is_empty());
    assert_eq!(status(&w.claim(&t3, &s3).await.err().unwrap()), 410);

    // a re-check with the current secret cancels a waiting replacement: eID and secret together
    // outrank the eID alone
    let mut now = Person { cred, secrets: s2, guardian: g2, ticket: None };
    w.renew(&mut now).await.unwrap();
    let (s4, _, r4) = w.replace("alice", None).await.unwrap();
    let ReplaceResponse::Pending { claim_token: t4, .. } = r4 else { panic!() };
    w.recheck(&mut now, "alice").await.unwrap();
    w.advance(90);
    assert_eq!(status(&w.claim(&t4, &s4).await.err().unwrap()), 404);
    let _ = now.secrets;
}

#[tokio::test]
async fn backup_storage_rules() {
    let w = world(90).await;
    let alice = w.enrol("alice").await;
    let ticket = alice.ticket.clone().expect("enrolment hands out a backup ticket");
    let put = |id: &str, key: &str, ticket: Option<&str>, blob: &str| BackupPut { id: id.repeat(32), write_key: key.repeat(64), ticket: ticket.map(String::from), blob: blob.into() };

    // no ticket, or an invented one: no new backup
    assert_eq!(status(&w.api.backup_put(&put("a", "1", None, "QUJD")).await.unwrap_err()), 403);
    assert_eq!(status(&w.api.backup_put(&put("a", "1", Some("00ff"), "QUJD")).await.unwrap_err()), 403);
    assert_eq!(status(&w.api.backup_get(&"a".repeat(32)).await.unwrap_err()), 404);
    // malformed ids and oversized or non-base64 blobs are refused before anything is stored
    assert_eq!(status(&w.api.backup_put(&BackupPut { id: "../x".into(), ..put("a", "1", Some(&ticket), "QUJD") }).await.unwrap_err()), 400);
    assert_eq!(status(&w.api.backup_put(&put("a", "1", Some(&ticket), &"A".repeat(50_000))).await.unwrap_err()), 413);
    assert_eq!(status(&w.api.backup_put(&put("a", "1", Some(&ticket), "<script>")).await.unwrap_err()), 413);

    w.api.backup_put(&put("a", "1", Some(&ticket), "QUJD")).await.unwrap();
    assert_eq!(w.api.backup_get(&"a".repeat(32)).await.unwrap().blob, "QUJD");
    // a ticket pays for one backup
    assert_eq!(status(&w.api.backup_put(&put("b", "1", Some(&ticket), "QUJD")).await.unwrap_err()), 403);
    // overwriting needs the write key, not a ticket
    assert_eq!(status(&w.api.backup_put(&put("a", "2", None, "WFla")).await.unwrap_err()), 403);
    w.api.backup_put(&put("a", "1", None, "WFla")).await.unwrap();
    assert_eq!(w.api.backup_get(&"a".repeat(32)).await.unwrap().blob, "WFla");
    // deleting needs the write key too, and frees one place
    assert_eq!(status(&w.api.backup_put(&put("a", "2", None, "")).await.unwrap_err()), 403);
    let t2 = w.api.backup_put(&put("a", "1", None, "")).await.unwrap().expect("a ticket for the freed place");
    assert_eq!(status(&w.api.backup_get(&"a".repeat(32)).await.unwrap_err()), 404);
    w.api.backup_put(&put("b", "3", Some(&t2), "QUJD")).await.unwrap();
    let _ = (&alice.secrets, &alice.guardian);
}

/// The enrolment status a fresh login for `purpose` shows.
async fn login_status(w: &World, purpose: Purpose, subject: &str) -> EnrolStatus {
    let (session, _) = w.login(purpose, subject).await;
    w.api.enrol_status(&session).await.unwrap()
}

fn can_like(w: &World, cred: &Credential, tree: &pop_crypto::revtree::RevocationTree, cutoff: Day) -> bool {
    w.scheme.prove_like(&mut OsRng, cred, tree, &w.ipk, &w.wpk, "ctx", "post", w.today(), cutoff).is_ok()
}

#[tokio::test]
async fn a_theft_report_replaces_at_once_and_the_replaced_secret_can_block_it() {
    let w = world(90).await;
    // a first enrolment counts at once
    let mut first = w.enrol("alice").await;
    let (tree, _) = w.tree().await;
    assert!(can_like(&w, &first.cred, &tree, w.today()));
    let old_handle = first.cred.handle();
    let secret = first.cred.secret();

    // Someone else logs in with Alice's eID, finds the identity enrolled and reports "it wasn't me".
    // A report never comes with the old guardian key: whoever holds it enrolled the secret.
    assert_eq!(login_status(&w, Purpose::Enrol, "alice").await, EnrolStatus::AlreadyEnrolled);
    let e = w.replace_with("alice", Some(&first.guardian), true).await.err().unwrap();
    assert_eq!(status(&e), 400, "{e}");
    let (secrets, g2, r) = w.replace_with("alice", None, true).await.unwrap();
    let ReplaceResponse::Issued { issuance } = r else { panic!("the first report in two years is served at once") };
    let mut reporter = Person { cred: w.finish(&secrets, &issuance), secrets, guardian: g2, ticket: None };
    // the new secret counts after a week, rounded up to a Monday
    let certified = reporter.cred.attrs.certified;
    assert!(certified >= w.today() + 7 && certified < w.today() + 14 && certified == dates::week_start(certified), "{certified}");
    let (tree, _) = w.tree().await;
    assert!(!can_like(&w, &reporter.cred, &tree, w.today()), "no likes count in the first week");
    // the replaced secret stops at once
    assert!(w.api.revocations().await.unwrap().revoked.contains(&old_handle));
    assert!(!can_like(&w, &first.cred, &tree, w.today()));
    assert!(w.renew(&mut first).await.is_err());
    // the report is counted, once per person a month
    let week = dates::week_start(w.today());
    let count = |r: &Reports| r.weeks.iter().find(|(d, _)| *d == week).map(|(_, n)| *n);
    assert_eq!(count(&w.api.reports().await.unwrap()), Some(1));
    assert_eq!(w.api.reports().await.unwrap().alarm_cutoff, None, "one report is no alarm");

    // after the week the reporter's likes count
    w.advance(14);
    w.renew(&mut reporter).await.unwrap();
    let (tree, _) = w.tree().await;
    assert!(can_like(&w, &reporter.cred, &tree, w.today()));
    // Replacing the reported secret again with its guardian key does not end the time to block.
    w.advance(17);
    let (s3, g3, r) = w.replace_with("alice", Some(&reporter.guardian), false).await.unwrap();
    let ReplaceResponse::Issued { issuance } = r else { panic!() };
    let reporter = Person { cred: w.finish(&s3, &issuance), secrets: s3, guardian: g3, ticket: None };

    // Whoever holds the replaced secret and can log in with the eID blocks the replacement: the
    // reported side's secret is revoked, the old one works again under a new handle.
    w.recheck(&mut first, "alice").await.unwrap();
    assert!(first.cred.secret() == secret);
    assert!(first.cred.handle() != old_handle);
    w.renew(&mut first).await.unwrap();
    let (tree, _) = w.tree().await;
    assert!(can_like(&w, &first.cred, &tree, w.today()));
    assert!(w.api.revocations().await.unwrap().revoked.contains(&reporter.cred.handle()));
    assert!(!can_like(&w, &reporter.cred, &tree, w.today()));
    // ... once only
    let mut again = Person { cred: first.cred.clone(), secrets: first.secrets.clone(), guardian: World::guardian(), ticket: None };
    w.recheck(&mut again, "alice").await.unwrap();
    assert_eq!(again.cred.handle(), first.cred.handle(), "a re-check of a working secret keeps its handle");

    // The two-year allowance stays used: the next report suspends and waits, and the replaced
    // secret lifts the suspension with a re-check.
    w.advance(31);
    w.renew(&mut first).await.unwrap();
    let h = first.cred.handle();
    let (secrets, _, r) = w.replace_with("alice", None, true).await.unwrap();
    let ReplaceResponse::Pending { claim_token, suspended: true, .. } = r else { panic!("expected to wait") };
    let _ = w.replace_with("alice", None, true).await.unwrap();
    assert!(w.renew(&mut first).await.is_err());
    w.advance(10);
    w.recheck(&mut first, "alice").await.unwrap();
    assert!(first.cred.handle() != h);
    w.renew(&mut first).await.unwrap();
    assert!(w.api.replace_pending().await.unwrap().entries.is_empty());
    w.advance(90);
    assert_eq!(status(&w.claim(&claim_token, &secrets).await.err().unwrap()), 404);
}

#[tokio::test]
async fn a_replacement_after_a_report_can_be_blocked_for_90_days_only() {
    let w = world(90).await;
    // the reported side revoking its own new secret does not end the time to block
    let mut first = w.enrol("bob").await;
    let (secrets, g, r) = w.replace_with("bob", None, true).await.unwrap();
    let ReplaceResponse::Issued { issuance } = r else { panic!() };
    let reporter = w.finish(&secrets, &issuance);
    let sig = hex::encode(g.sign(&revoke_message(reporter.handle())).as_ref());
    w.api.revoke(&RevokeRequest { handle: reporter.handle(), guardian_public_key: hex::encode(g.public_key().as_ref()), signature: sig }).await.unwrap();
    w.recheck(&mut first, "bob").await.unwrap();
    w.renew(&mut first).await.unwrap();

    let mut first = w.enrol("alice").await;
    let (secrets, _, r) = w.replace_with("alice", None, true).await.unwrap();
    let ReplaceResponse::Issued { issuance } = r else { panic!() };
    let mut reporter = Person { cred: w.finish(&secrets, &issuance), secrets, guardian: World::guardian(), ticket: None };
    w.advance(91);
    let e = w.recheck(&mut first, "alice").await.err().unwrap();
    assert_eq!(status(&e), 403, "{e}");
    w.renew(&mut reporter).await.unwrap();
    let (tree, _) = w.tree().await;
    assert!(can_like(&w, &reporter.cred, &tree, w.today()));
}

#[tokio::test]
async fn a_report_counts_quickly_only_once_in_two_years() {
    let w = world(90).await;
    let _first = w.enrol("alice").await;
    let (secrets, g, r) = w.replace_with("alice", None, true).await.unwrap();
    let ReplaceResponse::Issued { issuance } = r else { panic!() };
    let mut alice = Person { cred: w.finish(&secrets, &issuance), secrets, guardian: g, ticket: None };

    // another report within two years suspends, waits, and the new secret waits out probation
    w.advance(31);
    w.renew(&mut alice).await.unwrap();
    let (s2, _, r) = w.replace_with("alice", None, true).await.unwrap();
    let ReplaceResponse::Pending { claim_token: t2, suspended: true, .. } = r else { panic!() };
    w.advance(90);
    let c2 = w.claim(&t2, &s2).await.unwrap();
    assert_eq!(c2.attrs.certified, dates::week_start(w.today()) + Policy::default().probation_days);
    let (tree, _) = w.tree().await;
    assert!(!can_like(&w, &c2, &tree, w.today()));
    assert!(w.renew(&mut alice).await.is_err());

    // a plain replacement (no report) never counts quickly
    let mut p = Person { cred: c2, secrets: s2, guardian: World::guardian(), ticket: None };
    w.advance(31);
    w.renew(&mut p).await.unwrap();
    let (s3, _, r) = w.replace("alice", None).await.unwrap();
    let ReplaceResponse::Pending { claim_token: t3, suspended: false, .. } = r else { panic!() };
    w.advance(90);
    let c3 = w.claim(&t3, &s3).await.unwrap();
    assert_eq!(c3.attrs.certified, dates::week_start(w.today()) + Policy::default().probation_days);

    // two years after the first, a report is served at once again
    w.advance(730 - 31 - 90 - 31 - 90);
    let mut p = Person { cred: c3, secrets: s3, guardian: World::guardian(), ticket: None };
    w.renew(&mut p).await.ok();
    let (_, _, r) = w.replace_with("alice", None, true).await.unwrap();
    assert!(matches!(r, ReplaceResponse::Issued { .. }));
}

#[tokio::test]
async fn many_reports_raise_the_alarm_and_fresh_enrolments_stop_counting() {
    let w = world_with(Policy { alarm: pop_issuer::reports::AlarmRule { min_reports: 2, factor: 3, ..Default::default() }, ..Default::default() }).await;
    let mut bob = w.enrol("bob").await;
    w.advance(60);
    w.renew(&mut bob).await.unwrap();
    let carol = w.enrol("carol").await;
    assert_eq!(w.api.params().await.unwrap().alarm_cutoff, None);
    // two people report that their identity was taken
    for who in ["dave", "erin"] {
        let _thief = w.enrol(who).await;
        let (_, _, r) = w.replace_with(who, None, true).await.unwrap();
        assert!(matches!(r, ReplaceResponse::Issued { .. }));
    }
    let cut = dates::week_start(w.today()) - Policy::default().alarm.reach_days;
    let rep = w.api.reports().await.unwrap();
    assert_eq!(rep.alarm_cutoff, Some(cut));
    assert!(!rep.rule.is_empty());
    assert_eq!(w.api.params().await.unwrap().alarm_cutoff, Some(cut), "apps learn the cutoff with the parameters");
    // Carol enrolled within the reach of the alarm and stops counting; Bob, from before, still counts
    let (tree, _) = w.tree().await;
    assert!(!can_like(&w, &carol.cred, &tree, cut));
    assert!(can_like(&w, &bob.cred, &tree, cut));
    // the alarm ends four weeks after the high week
    w.advance(21);
    assert_eq!(w.api.params().await.unwrap().alarm_cutoff, Some(cut));
    w.advance(7);
    assert_eq!(w.api.params().await.unwrap().alarm_cutoff, None);
}

#[tokio::test]
async fn the_policy_is_a_setting_and_is_published() {
    let policy = Policy { report_probation_days: 14, contest_days: 30, ..Default::default() };
    let w = world_with(policy.clone()).await;
    let mut first = w.enrol("alice").await;
    let (secrets, _, r) = w.replace_with("alice", None, true).await.unwrap();
    let ReplaceResponse::Issued { issuance } = r else { panic!() };
    let c = w.finish(&secrets, &issuance);
    assert!(c.attrs.certified >= w.today() + 14 && c.attrs.certified < w.today() + 21);
    w.advance(31);
    assert_eq!(status(&w.recheck(&mut first, "alice").await.err().unwrap()), 403, "30 days to block, not 90");
    let published: Policy = reqwest::get(format!("{}/v1/policy", w.url)).await.unwrap().json().await.unwrap();
    assert_eq!(published, policy);
}
