//! End-to-end tests: every service on its own port, talking over HTTP as when deployed apart.
//! One devnet is shared by the tests in this file (the proof-system setup is the slow part).
use pop_cli::devnet::{self, Devnet, DevnetOpts};
use pop_cli::wiring::{self, PlatformOpts};
use pop_crypto::{ProofSystem, SchemeConfig};
use pop_holder::{Holder, HolderError, MemoryWallet};
use pop_protocol::api::*;
use pop_protocol::http::HttpClient;
use pop_protocol::platform::CodePlacement;
use std::sync::Arc;
use tokio::sync::OnceCell;

static NET: OnceCell<Devnet> = OnceCell::const_new();

async fn net() -> &'static Devnet {
    NET.get_or_init(|| async {
        // the servers must outlive the test that happened to start them
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let d = devnet::start(DevnetOpts {
                    scheme: SchemeConfig { proof_system: ProofSystem::LegoGroth16, tree_depth: 4, slots: 3, bp_gens_log2: 13 },
                    data_dir: None,
                    ports: [0; 4],
                    rollout: true,
                    uniqueness: devnet::UniquenessMode::Hmac,
                    replace_wait_days: None,
                })
                .await
                .unwrap();
                tx.send(d).unwrap();
                std::future::pending::<()>().await;
            });
        });
        tokio::task::spawn_blocking(move || rx.recv().unwrap()).await.unwrap()
    })
    .await
}

fn holder(d: &Devnet, as_handle: &str) -> Holder {
    let p = wiring::platforms(&PlatformOpts { mockfeed_url: Some(d.feed_url.clone()), mockfeed_as: Some(as_handle.into()), ..Default::default() });
    wiring::build_holder(&d.issuer_url, &d.directory_url, p, Arc::new(MemoryWallet::default()))
}

async fn enrolled(d: &Devnet, as_handle: &str, id: &str) -> Holder {
    let h = holder(d, as_handle);
    let url = h.enrol_start().await.unwrap();
    let code = devnet::mock_login(&url, id).await.unwrap();
    h.enrol_finish(&code).await.unwrap();
    h
}

fn dir(d: &Devnet) -> HttpClient {
    HttpClient::new(&d.directory_url)
}

fn status(e: &ApiError) -> u16 {
    match e {
        ApiError::Server { status, .. } => *status,
        _ => 0,
    }
}

#[tokio::test]
async fn full_flow() {
    let d = net().await;
    let alice = enrolled(d, "alice", "T-FLOW-ALICE").await;
    let bob = enrolled(d, "bob", "T-FLOW-BOB").await;

    // binding publishes the code and the directory sees it
    let out = alice.bind("mockfeed", "@alice", 1, CodePlacement::Bio).await.unwrap();
    assert!(out.code_published);
    assert!(out.entry.counted, "rollout window: counted at once");
    assert!(out.entry.code_seen_on.is_some());
    let list = dir(d).list("mockfeed").await.unwrap();
    assert!(list.entries.iter().any(|e| e.handle == "alice" && e.code == out.entry.code));

    // binding again (lease renewal) keeps the same code: same person, same slot, same account
    let again = alice.bind("mockfeed", "alice", 1, CodePlacement::Bio).await.unwrap();
    assert_eq!(again.entry.code, out.entry.code);

    // the holder cannot publish into someone else's account, and the directory then sees no code there
    let other = alice.bind("mockfeed", "carol", 2, CodePlacement::Bio).await.unwrap();
    assert!(!other.code_published);
    assert!(other.entry.code_seen_on.is_none(), "no badge without the code on the account");

    // likes: one per person per post
    let r1 = alice.like("mockfeed", "p1").await.unwrap();
    let r2 = alice.like("mockfeed", "p1").await.unwrap();
    let r3 = bob.like("mockfeed", "p1").await.unwrap();
    assert!(r1.new && !r2.new && r3.new);
    assert_eq!(r3.count, r1.count + 1);
    assert!(alice.has_liked("mockfeed", "p1"));

    // renewal keeps the pseudonym: binding after it gives the same code
    alice.renew().await.unwrap();
    let after = alice.bind("mockfeed", "alice", 1, CodePlacement::Bio).await.unwrap();
    assert_eq!(after.entry.code, out.entry.code);

    // withdrawing removes the entry and the code
    alice.unbind("mockfeed", "alice").await.unwrap();
    let list = dir(d).list("mockfeed").await.unwrap();
    assert!(!list.entries.iter().any(|e| e.handle == "alice"));

    // revocation: the credential stops working for a copy of the wallet too
    bob.revoke().await.unwrap();
    assert!(matches!(bob.like("mockfeed", "p2").await, Err(HolderError::NotEnrolled)));
}

#[tokio::test]
async fn one_enrolment_per_person() {
    let d = net().await;
    let _first = enrolled(d, "alice", "T-DUP-1").await;
    let second = holder(d, "bob");
    let url = second.enrol_start().await.unwrap();
    // same person, written differently
    let code = devnet::mock_login(&url, " t-dup-1 ").await.unwrap();
    assert!(code.is_empty(), "no confirmation code for a person already enrolled");
    assert!(matches!(second.enrol_finish(&code).await, Err(HolderError::EnrolNotReady(EnrolStatus::AlreadyEnrolled))));
}

#[tokio::test]
async fn enrolment_needs_the_code_from_the_browser() {
    let d = net().await;
    let h = holder(d, "alice");
    let url = h.enrol_start().await.unwrap();
    let code = devnet::mock_login(&url, "T-CODE-1").await.unwrap();
    assert_eq!(code.len(), 6);
    let wrong = if code == "000000" { "000001" } else { "000000" };
    match h.enrol_finish(wrong).await {
        Err(HolderError::Api(e)) => assert_eq!(status(&e), 403),
        other => panic!("wrong code accepted: {other:?}"),
    }
    h.enrol_finish(&code).await.unwrap();

    // five wrong codes end the session
    let h = holder(d, "alice");
    let url = h.enrol_start().await.unwrap();
    let code = devnet::mock_login(&url, "T-CODE-2").await.unwrap();
    for _ in 0..5 {
        assert!(h.enrol_finish("999999x").await.is_err());
    }
    assert!(h.enrol_finish(&code).await.is_err(), "session is gone after too many wrong codes");
}

#[tokio::test]
async fn the_redirect_state_is_not_the_session() {
    // whoever sees the redirect (the identity provider, browser history) must not be able to finish
    let d = net().await;
    let issuer = HttpClient::new(&d.issuer_url);
    let r = IssuerApi::enrol_start(&issuer, Purpose::Enrol).await.unwrap();
    let state = reqwest::Url::parse(&r.authorize_url).unwrap().query_pairs().find(|(k, _)| k == "state").unwrap().1.to_string();
    assert_ne!(state, r.session);
    let e = issuer.enrol_status(&state).await.unwrap_err();
    assert_eq!(status(&e), 404);
}

#[tokio::test]
async fn directory_rejects_replays_unknown_platforms_and_bad_posts() {
    let d = net().await;
    let alice = enrolled(d, "alice", "T-REPLAY-1").await;
    alice.bind("mockfeed", "dailytruth", 3, CodePlacement::Bio).await.unwrap();
    // the full record, proof included, is public
    let recs: Vec<BindingRecord> = dir(d).get("/v1/bindings/mockfeed/u4").await.unwrap();
    let rec = recs.into_iter().next().unwrap();
    // ... but submitting it again is refused
    let e = dir(d).bind(&rec.request).await.unwrap_err();
    assert_eq!(status(&e), 409, "{e}");
    // nor does it work for another account
    let mut moved = rec.request.clone();
    moved.account_id = "u2".into();
    moved.handle = "bob".into();
    assert_eq!(status(&dir(d).bind(&moved).await.unwrap_err()), 401);
    // a handle that belongs to a different account id
    let mut wrong_handle = rec.request.clone();
    wrong_handle.handle = "bob".into();
    wrong_handle.nonce = "ffffffffffffffffffffffffffffffff".into();
    assert!(dir(d).bind(&wrong_handle).await.is_err());
    // made-up platform
    let mut p = rec.request.clone();
    p.platform = "made-up".into();
    assert_eq!(status(&dir(d).bind(&p).await.unwrap_err()), 400);
    // likes only for canonical post ids of a known platform
    assert!(alice.like("mockfeed", "not a post").await.is_err());
    assert!(alice.like("made-up", "p1").await.is_err());
    // the directory serves the counts table without being asked about single posts
    alice.like("mockfeed", "p4").await.unwrap();
    let t: CountsResponse = dir(d).get("/v1/likes/table?platform=mockfeed").await.unwrap();
    assert!(t.counts["p4"] >= 1);
}

#[tokio::test]
async fn holder_local_api_needs_the_pairing_token() {
    let d = net().await;
    let h = Arc::new(enrolled(d, "alice", "T-LOCAL-1").await);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, pop_holder::local_api::router(h, "correct-token-0123".into())).await.unwrap() });
    let c = reqwest::Client::new();
    let body = serde_json::json!({"platform": "mockfeed", "post": "p3"});
    let r = c.post(format!("{base}/v1/like")).json(&body).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let r = c.post(format!("{base}/v1/like")).header("x-pop-token", "wrong").json(&body).send().await.unwrap();
    assert_eq!(r.status(), 401);
    // a web page's preflight is not answered with permission
    let r = c
        .request(reqwest::Method::OPTIONS, format!("{base}/v1/like"))
        .header("origin", "https://evil.example")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "x-pop-token")
        .send()
        .await
        .unwrap();
    assert!(r.headers().get("access-control-allow-origin").is_none());
    let r = c.post(format!("{base}/v1/like")).header("x-pop-token", "correct-token-0123").json(&body).send().await.unwrap();
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn a_false_claim_cannot_remove_someone_elses_badge() {
    let d = net().await;
    let carol = enrolled(d, "carol", "T-CLAIM-CAROL").await;
    let mallory = enrolled(d, "bob", "T-CLAIM-MALLORY").await;
    let real = carol.bind("mockfeed", "carol", 1, CodePlacement::Bio).await.unwrap();
    assert!(real.entry.code_seen_on.is_some());
    // Mallory proves personhood and names Carol's account. She cannot put her code in Carol's bio.
    let fake = mallory.bind("mockfeed", "carol", 1, CodePlacement::Bio).await.unwrap();
    assert!(fake.entry.code_seen_on.is_none());
    assert_ne!(fake.entry.code, real.entry.code);
    let list = dir(d).list("mockfeed").await.unwrap();
    let claims: Vec<_> = list.entries.iter().filter(|e| e.handle == "carol").collect();
    assert!(claims.iter().any(|e| e.code == real.entry.code && e.code_seen_on.is_some()), "Carol's confirmed claim is still there");
    assert!(claims.iter().any(|e| e.code == fake.entry.code && e.code_seen_on.is_none()));
}

#[tokio::test]
async fn recheck_backup_and_restore_keep_the_same_person() {
    let d = net().await;
    let phone = enrolled(d, "carol", "T-BACKUP-1").await;
    let out = phone.bind("mockfeed", "carol", 2, CodePlacement::Bio).await.unwrap();

    // the two-year re-check: a new login, the same secret, the same code on the account
    let url = phone.recheck_start().await.unwrap();
    let code = devnet::mock_login(&url, "T-BACKUP-1").await.unwrap();
    phone.recheck_finish(&code).await.unwrap();
    assert_eq!(phone.bind("mockfeed", "carol", 2, CodePlacement::Bio).await.unwrap().entry.code, out.entry.code);
    // someone else's login does not re-check this credential
    let _other = enrolled(d, "bob", "T-BACKUP-2").await;
    let url = phone.recheck_start().await.unwrap();
    let code = devnet::mock_login(&url, "T-BACKUP-2").await.unwrap();
    match phone.recheck_finish(&code).await {
        Err(HolderError::Api(e)) => assert_eq!(status(&e), 403, "{e}"),
        other => panic!("re-check with another person's login: {other:?}"),
    }

    let code = phone.backup_create().await.unwrap();
    assert_eq!(code.replace('-', "").len(), 26);
    assert!(phone.status().unwrap().backup);

    // a new device with the paper code: same secret, so the same pseudonym and code
    let tablet = holder(d, "carol");
    assert!(matches!(tablet.restore("AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-A").await, Err(HolderError::NoBackup)));
    assert!(matches!(tablet.restore("not a code").await, Err(HolderError::NoBackup)));
    tablet.restore(&code.to_lowercase().replace('-', " ")).await.unwrap();
    let st = tablet.status().unwrap();
    assert!(st.enrolled && st.bindings.len() == 1 && st.bindings[0].code == out.entry.code);
    tablet.renew().await.unwrap();
    assert_eq!(tablet.bind("mockfeed", "carol", 2, CodePlacement::Bio).await.unwrap().entry.code, out.entry.code);
    // restoring onto a device that has a credential is refused
    assert!(matches!(phone.restore(&code).await, Err(HolderError::AlreadyEnrolled)));

    // Binding an account does not touch the backup (its host must not see when a known person
    // binds); the new binding reaches the backup with the next renewal.
    phone.bind("mockfeed", "bob", 3, CodePlacement::Bio).await.unwrap();
    let probe = holder(d, "carol");
    probe.restore(&code).await.unwrap();
    assert_eq!(probe.status().unwrap().bindings.len(), 1);
    phone.renew().await.unwrap();
    let probe = holder(d, "carol");
    probe.restore(&code).await.unwrap();
    assert_eq!(probe.status().unwrap().bindings.len(), 2);

    // a new code replaces the old one
    let code2 = phone.backup_create().await.unwrap();
    assert_ne!(code, code2);
    assert!(matches!(holder(d, "carol").restore(&code).await, Err(HolderError::NoBackup)));
    holder(d, "carol").restore(&code2).await.unwrap();

    // revoking deletes the backup: there is nothing left to restore
    phone.revoke().await.unwrap();
    assert!(matches!(holder(d, "carol").restore(&code2).await, Err(HolderError::NoBackup)));
}

#[tokio::test]
async fn replacing_the_secret() {
    let d = net().await;
    let phone = enrolled(d, "alice", "T-REPLACE-1").await;
    phone.like("mockfeed", "p1").await.unwrap();

    // a new device has only the eID: the request waits, and the old app sees it and refuses
    let thief = holder(d, "bob");
    let url = thief.replace_start().await.unwrap();
    let code = devnet::mock_login(&url, "T-REPLACE-1").await.unwrap();
    assert!(matches!(thief.replace_finish(&code).await.unwrap(), pop_holder::ReplaceOutcome::Waiting { .. }));
    assert!(thief.status().unwrap().replacement_waits_until.is_some());
    assert!(matches!(thief.replace_claim().await, Err(HolderError::ClaimTooEarly(_))));
    assert!(phone.pending_replacement().await.unwrap().is_some(), "the old app is warned");
    let stranger = enrolled(d, "carol", "T-REPLACE-2").await;
    assert!(stranger.pending_replacement().await.unwrap().is_none(), "nobody else is");
    // she refuses with a re-check: her eID and the old secret together
    let url = phone.recheck_start().await.unwrap();
    let code = devnet::mock_login(&url, "T-REPLACE-1").await.unwrap();
    phone.recheck_finish(&code).await.unwrap();
    assert!(phone.pending_replacement().await.unwrap().is_none());
    assert!(thief.replace_claim().await.is_err());
    // the old secret was never touched
    phone.renew().await.unwrap();

    // the device that holds the guardian key replaces at once; the new secret starts probation
    let url = phone.replace_start().await.unwrap();
    let code = devnet::mock_login(&url, "T-REPLACE-1").await.unwrap();
    assert!(matches!(phone.replace_finish(&code).await.unwrap(), pop_holder::ReplaceOutcome::Issued { .. }));
    assert!(matches!(phone.like("mockfeed", "p1").await, Err(HolderError::Probation(_))));
    let out = phone.bind("mockfeed", "alice", 1, CodePlacement::Bio).await.unwrap();
    assert!(!out.entry.counted, "a replaced secret is not counted, rollout window or not");
    phone.renew().await.unwrap();
    // a person with no enrolment cannot replace anything
    let nobody = holder(d, "bob");
    let url = nobody.replace_start().await.unwrap();
    let code = devnet::mock_login(&url, "T-REPLACE-NOBODY").await.unwrap();
    assert!(matches!(nobody.replace_finish(&code).await, Err(HolderError::EnrolNotReady(EnrolStatus::NotEnrolled))));
}
