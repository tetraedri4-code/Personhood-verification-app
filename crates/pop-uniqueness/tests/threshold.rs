//! The threshold service end to end: real operators on loopback ports, talking over HTTP.
use ark_ec::{CurveGroup, Group};
use ark_std::UniformRand;
use pop_crypto::codec::to_hex;
use pop_crypto::params::{Fr, G2};
use pop_protocol::uniqueness::UniquenessService;
use pop_uniqueness::admin::{self, AdminEndpoint};
use pop_uniqueness::wire::*;
use pop_uniqueness::admin::Member;
use pop_uniqueness::operator::Fault;
use pop_uniqueness::{ident, round, Operator, OperatorConfig, OperatorEndpoint, ThresholdConfig, ThresholdUniqueness};
use std::time::Duration;
use std::path::PathBuf;

fn cfg(index: u32) -> OperatorConfig {
    OperatorConfig {
        index,
        eval_token: format!("eval-token-of-operator-number-{index}"),
        admin_token: format!("admin-token-of-operator-number-{index}"),
        state_file: None,
        max_evals_per_minute: 10_000,
        min_threshold: 2,
        test_fault: None,
    }
}

async fn spawn_with(c: OperatorConfig) -> (AdminEndpoint, OperatorEndpoint) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    let (a, e) = (
        AdminEndpoint { index: c.index, url: url.clone(), admin_token: c.admin_token.clone() },
        OperatorEndpoint { index: c.index, url, token: c.eval_token.clone() },
    );
    let app = pop_uniqueness::router(Operator::new(c).unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (a, e)
}

async fn spawn(index: u32) -> (AdminEndpoint, OperatorEndpoint) {
    spawn_with(cfg(index)).await
}

async fn cluster(indices: &[u32]) -> (Vec<AdminEndpoint>, Vec<OperatorEndpoint>) {
    let mut a = vec![];
    let mut e = vec![];
    for i in indices {
        let (x, y) = spawn(*i).await;
        a.push(x);
        e.push(y);
    }
    (a, e)
}

fn client(ops: &[OperatorEndpoint], keys: &[&str]) -> ThresholdUniqueness {
    ThresholdUniqueness::new(ThresholdConfig { operators: ops.to_vec(), keys: keys.iter().map(|k| k.to_string()).collect() }).unwrap()
}

async fn d(c: &ThresholdUniqueness, subject: &str) -> String {
    c.dedup_keys(246, subject).await.unwrap()[0].d.clone()
}

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("pop-uniq-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[tokio::test]
async fn d_survives_refresh_and_operator_changes() {
    let (admins, eps) = cluster(&[1, 2, 3, 4, 5, 6]).await;
    let key = admin::dkg(&admins[..3], 2).await.unwrap();
    let c = client(&eps, &[&key]);
    let (alice, bob) = (d(&c, "010190-900A").await, d(&c, "020285-901B").await);
    assert_ne!(alice, bob);
    assert_eq!(alice, d(&c, " 010190-900a ").await, "normalised input");
    assert_ne!(alice, c.dedup_keys(233, "010190-900A").await.unwrap()[0].d, "country is part of the input");

    // refresh: same set, new shares, old ones erased
    let before = admin::current_epoch(&key, &admins[..3]).await.unwrap();
    let epoch = admin::reshare(&key, &admins[..3], &admins[..3], 2).await.unwrap();
    assert_eq!(epoch, 2);
    let after = admin::current_epoch(&key, &admins[..3]).await.unwrap();
    assert!(before.vks.iter().all(|(i, v)| after.vks[i] != *v), "every share changed");
    assert_eq!(alice, d(&c, "010190-900A").await);
    assert_eq!(bob, d(&c, "020285-901B").await);
    let info = admin::public(&admins[0].url).await.unwrap();
    assert_eq!(info.keys[0].epochs.len(), 1, "old share erased");

    // replace operator 3 by operator 4
    let new_set = [admins[0].clone(), admins[1].clone(), admins[3].clone()];
    let epoch = admin::reshare(&key, &admins[..3], &new_set, 2).await.unwrap();
    assert_eq!(epoch, 3);
    assert!(admin::public(&admins[2].url).await.unwrap().keys.is_empty(), "the operator that left holds nothing");
    assert_eq!(alice, d(&c, "010190-900A").await);
    // the new member alone with one old member is enough
    assert_eq!(alice, d(&client(&[eps[1].clone(), eps[3].clone()], &[&key]), "010190-900A").await);

    // a round that leaves holders out is noticed: they would keep their old shares
    let cur = admin::current_epoch(&key, &new_set).await.unwrap();
    let m = |i: usize| Member::from(&admins[i]);
    assert_eq!(admin::holders_left_out(&cur, &[m(0)], &[m(4)]), vec![2, 4]);
    assert!(admin::holders_left_out(&cur, &[m(0), m(3)], &[m(1), m(3), m(4), m(5)]).is_empty());

    // other threshold and a mostly new set: 3-of-4 on operators 2, 4, 5, 6, dealt by two holders
    let newer = [admins[1].clone(), admins[3].clone(), admins[4].clone(), admins[5].clone()];
    admin::reshare(&key, &[admins[0].clone(), admins[3].clone()], &newer, 3).await.unwrap();
    assert!(admin::public(&admins[0].url).await.unwrap().keys.is_empty(), "the dealer that left erased its share");
    assert_eq!(alice, d(&c, "010190-900A").await);
    assert_eq!(bob, d(&c, "020285-901B").await);
    // two of the four are no longer enough
    let two = client(&[eps[4].clone(), eps[5].clone()], &[&key]);
    assert!(two.dedup_keys(246, "010190-900A").await.is_err());
    // one operator down: three of four still answer
    let three = client(&[eps[1].clone(), eps[3].clone(), eps[5].clone(), OperatorEndpoint { index: 5, url: "http://127.0.0.1:9".into(), token: "x".into() }], &[&key]);
    assert_eq!(alice, d(&three, "010190-900A").await);
}

#[tokio::test]
async fn keys_are_versioned_and_pinned() {
    let (admins, eps) = cluster(&[1, 2, 3]).await;
    let k1 = admin::dkg(&admins, 2).await.unwrap();
    let k2 = admin::dkg(&admins, 2).await.unwrap();
    assert_ne!(k1, k2);
    let c = client(&eps, &[&k1, &k2]);
    let v = c.versions().await.unwrap();
    assert_eq!(v, vec![pop_uniqueness::key_version(&k2), pop_uniqueness::key_version(&k1)], "newest first");
    let ds = c.dedup_keys(246, "X").await.unwrap();
    assert_eq!(ds.len(), 2);
    assert_eq!(ds[0].version, v[0]);
    assert_ne!(ds[0].d, ds[1].d);
    assert_eq!(ds[1].d, d(&client(&eps, &[&k1]), "X").await);

    // a key the operators do not hold: an error, never a made-up d
    let other = to_hex(&(G2::generator() * Fr::rand(&mut rand::thread_rng())).into_affine());
    assert!(client(&eps, &[&other]).dedup_keys(246, "X").await.is_err());
    assert!(client(&eps, &[&k1, &other]).dedup_keys(246, "X").await.is_err(), "one failing version fails the whole answer");
}

/// A stand-in for operator 3 that answers with a wrong value.
async fn lying_operator(key: String) -> OperatorEndpoint {
    use axum::{routing::post, Json, Router};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    let app = Router::new().route(
        "/v1/evaluate",
        post(move |Json(r): Json<EvalRequest>| {
            let _ = &key;
            async move { Json(EvalResponse { index: 3, partials: vec![Partial { epoch: 1, threshold: 2, value: r.point }] }) }
        }),
    );
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    OperatorEndpoint { index: 3, url, token: "t".into() }
}

#[tokio::test]
async fn a_lying_operator_cannot_change_d() {
    let (admins, eps) = cluster(&[1, 2, 3]).await;
    let key = admin::dkg(&admins, 2).await.unwrap();
    let honest = d(&client(&eps, &[&key]), "P").await;
    let liar = lying_operator(key.clone()).await;
    // the liar is listed first, so the first subsets tried contain its answer
    assert_eq!(honest, d(&client(&[liar.clone(), eps[0].clone(), eps[1].clone()], &[&key]), "P").await);
    // the liar and one honest operator: no valid pair, so an error
    assert!(client(&[liar, eps[0].clone()], &[&key]).dedup_keys(246, "P").await.is_err());
}

#[tokio::test]
async fn tokens_and_rate_limit() {
    let mut c1 = cfg(1);
    c1.max_evals_per_minute = 3;
    let (a1, e1) = spawn_with(c1).await;
    let (a2, e2) = spawn(2).await;
    let key = admin::dkg(&[a1.clone(), a2.clone()], 2).await.unwrap();
    let http = reqwest::Client::new();
    let point = to_hex(&pop_crypto::params::hash_to_g1(b"test", b"x"));
    let eval = |token: String| {
        let (http, url, key, point) = (http.clone(), e1.url.clone(), key.clone(), point.clone());
        async move { http.post(format!("{url}/v1/evaluate")).bearer_auth(token).json(&EvalRequest { key, point }).send().await.unwrap().status().as_u16() }
    };
    // every token opens only its own door
    assert_eq!(eval("wrong".into()).await, 401);
    assert_eq!(eval(a1.admin_token.clone()).await, 401);
    assert_eq!(eval(e2.token.clone()).await, 401, "another operator's evaluation token");
    for path in ["/v1/admin/round/start", "/v1/admin/round/advance", "/v1/admin/round/abort"] {
        for token in [e1.token.as_str(), "", a2.admin_token.as_str()] {
            let s = http.post(format!("{}{path}", e1.url)).bearer_auth(token).json(&serde_json::json!({"round_id": "00"})).send().await.unwrap().status().as_u16();
            assert_eq!(s, 401, "{path} with a wrong token");
        }
    }
    // the endpoints of the earlier protocol are gone
    for path in ["/v1/peer/deal", "/v1/admin/finalize", "/v1/admin/discard", "/v1/admin/round/commit"] {
        let s = http.post(format!("{}{path}", e1.url)).bearer_auth(&a1.admin_token).json(&serde_json::json!({})).send().await.unwrap().status().as_u16();
        assert_eq!(s, 404, "{path}");
    }
    // the point at infinity and garbage are refused
    let inf = to_hex(&pop_crypto::params::G1A::identity());
    let s = http.post(format!("{}/v1/evaluate", e1.url)).bearer_auth(&e1.token).json(&EvalRequest { key: key.clone(), point: inf }).send().await.unwrap().status().as_u16();
    assert_eq!(s, 400);
    // rate limit: 3 per minute (one was used just above, and a minute boundary may reset the count once)
    let mut codes = vec![];
    for _ in 0..8 {
        codes.push(eval(e1.token.clone()).await);
    }
    assert!(codes.contains(&200) && codes.iter().filter(|c| **c == 429).count() >= 2, "{codes:?}");
    // nothing secret in the public view
    let public = http.get(format!("{}/v1/public", e1.url)).send().await.unwrap().text().await.unwrap();
    assert!(!public.contains("share") && !public.contains("token"));
}

fn members(a: &[AdminEndpoint]) -> Vec<Member> {
    a.iter().map(Member::from).collect()
}

const T: Duration = Duration::from_secs(20);

/// Messages between operators count only when signed with the key the approved spec names.
#[tokio::test]
async fn peer_messages_need_the_senders_signature() {
    let (admins, eps) = cluster(&[1, 2, 3]).await;
    let key = admin::dkg(&admins, 2).await.unwrap();
    let before = d(&client(&eps, &[&key]), "S").await;
    let spec = admin::spec_reshare(&key, &members(&admins), &members(&admins), 2).await.unwrap();
    let id = spec.id();
    let http = reqwest::Client::new();
    let post = |url: String, env: Envelope| {
        let http = http.clone();
        async move { http.post(format!("{url}/v1/peer/msg")).json(&env).send().await.unwrap().status().as_u16() }
    };
    let outsider = ident::IdentityKey::generate();
    let forged = |from: u32, body: &Body| {
        let body = serde_json::to_string(body).unwrap();
        Envelope { round_id: id.clone(), from, sig: outsider.sign(&Envelope::signed_bytes(&id, from, &body)), body }
    };
    let commit = Body::Commit { hash: "00".repeat(32) };
    // a round nobody approved at this operator
    assert_eq!(post(admins[1].url.clone(), forged(1, &commit)).await, 404);
    admin::approve(&spec, &admins[1]).await.unwrap();
    // approved, but the signature is not operator 1's
    assert_eq!(post(admins[1].url.clone(), forged(1, &commit)).await, 401);
    // a sender outside the round, an operator's own name, an unsigned message
    assert_eq!(post(admins[1].url.clone(), forged(9, &commit)).await, 401);
    assert_eq!(post(admins[1].url.clone(), forged(2, &commit)).await, 400);
    assert_eq!(post(admins[1].url.clone(), Envelope { round_id: id.clone(), from: 1, body: "{}".into(), sig: String::new() }).await, 401);
    // nothing of this disturbed the round: it still completes
    admin::drive(&spec, &admins, T).await.unwrap();
    assert_eq!(before, d(&client(&eps, &[&key]), "S").await);

    // a spec that names another identity key for an existing member is refused by those who know it
    let mut m = members(&admins);
    let mut spec2 = admin::spec_reshare(&key, &m, &m, 2).await.unwrap();
    spec2.peers[0].identity = outsider.public_hex();
    let e = admin::approve(&spec2, &admins[1]).await.unwrap_err().to_string();
    assert!(e.contains("another identity key"), "{e}");
    // and a pinned identity that the operator does not publish stops the spec from being written
    m[0].identity = Some(outsider.public_hex());
    assert!(admin::spec_reshare(&key, &m, &m, 2).await.is_err());
}

/// Each administrator approves and drives only their own operator; nobody holds another's token.
#[tokio::test]
async fn no_coordinator_is_needed() {
    let (admins, eps) = cluster(&[1, 2, 3]).await;
    let m = members(&admins);
    let spec = admin::spec_dkg(&m, 2).await.unwrap();
    // two administrators alone get nowhere
    let early = admin::drive(&spec, &admins[..2], Duration::from_secs(2)).await.unwrap_err().to_string();
    assert!(early.contains("did not finish"), "{early}");
    // all three, each on their own
    let (s1, s2, s3) = (spec.clone(), spec.clone(), spec.clone());
    let (a1, a2, a3) = (admins[0].clone(), admins[1].clone(), admins[2].clone());
    let (r1, r2, r3) = tokio::join!(
        tokio::spawn(async move { admin::join(&s1, &a1, T).await }),
        tokio::spawn(async move { admin::join(&s2, &a2, T).await }),
        tokio::spawn(async move { admin::join(&s3, &a3, T).await }),
    );
    let (r1, r2, r3) = (r1.unwrap().unwrap(), r2.unwrap().unwrap(), r3.unwrap().unwrap());
    let key = r1.result.clone().unwrap().0;
    assert_eq!(r2.result.unwrap().0, key);
    assert_eq!(r3.result.unwrap().0, key);
    admin::verify_epoch(&key, 1, &admins).await.unwrap();
    let c = client(&eps, &[&key]);
    let before = d(&c, "N").await;
    // a refresh the same way
    let spec = admin::spec_reshare(&key, &m, &m, 2).await.unwrap();
    let mut tasks = vec![];
    for a in admins.clone() {
        let s = spec.clone();
        tasks.push(tokio::spawn(async move { admin::join(&s, &a, T).await }));
    }
    for t in tasks {
        assert!(t.await.unwrap().unwrap().done);
    }
    assert_eq!(before, d(&c, "N").await);
    assert_eq!(admin::public(&admins[0].url).await.unwrap().keys[0].epochs.len(), 1, "old share erased without anyone asking");
}

/// A dealer that sends a bad sub-share is named, with proof every operator checks for itself;
/// a receiver that complains about a good deal is named instead.
#[tokio::test]
async fn cheaters_are_named() {
    // key generation: operator 2 sends operator 3 a wrong value
    let (a1, _) = spawn(1).await;
    let mut c2 = cfg(2);
    c2.test_fault = Some(Fault::BadShareTo(3));
    let (a2, _) = spawn_with(c2).await;
    let (a3, _) = spawn(3).await;
    let admins = [a1.clone(), a2, a3.clone()];
    let e = format!("{:#}", admin::dkg(&admins, 2).await.unwrap_err());
    assert!(e.contains("operator 2 is at fault"), "{e}");
    for a in &admins {
        assert!(admin::public(&a.url).await.unwrap().keys.is_empty(), "nothing was stored");
    }
    // operator 1, which was not the victim, convinced itself from the evidence
    let spec = admin::spec_dkg(&members(&admins), 2).await.unwrap();
    for a in &admins {
        admin::approve(&spec, a).await.unwrap();
    }
    let mut blamed = None;
    for _ in 0..50 {
        let mut any = false;
        for a in &admins {
            let st: RoundStatus = reqwest::Client::new().post(format!("{}/v1/admin/round/advance", a.url)).bearer_auth(&a.admin_token).json(&RoundId { round_id: spec.id() }).send().await.unwrap().json().await.unwrap();
            if a.index == 1 {
                if let Some(f) = st.failed {
                    blamed = f.blamed;
                    any = true;
                }
            }
        }
        if any {
            break;
        }
    }
    assert_eq!(blamed, Some(2), "operator 1 blames the dealer on the strength of operator 3's complaint");

    // the honest two go on without it
    let key = admin::dkg(&[a1.clone(), a3.clone()], 2).await.unwrap();
    admin::verify_epoch(&key, 1, &[a1, a3]).await.unwrap();

    // a false complaint falls back on the complainer
    let (b1, _) = spawn(1).await;
    let (b2, _) = spawn(2).await;
    let mut c3 = cfg(3);
    c3.test_fault = Some(Fault::FalseComplaintAgainst(1));
    let (b3, _) = spawn_with(c3).await;
    let admins = [b1, b2, b3];
    let spec = admin::spec_dkg(&members(&admins), 2).await.unwrap();
    for a in &admins {
        admin::approve(&spec, a).await.unwrap();
    }
    let mut verdict = None;
    for _ in 0..50 {
        for a in &admins {
            let st: RoundStatus = reqwest::Client::new().post(format!("{}/v1/admin/round/advance", a.url)).bearer_auth(&a.admin_token).json(&RoundId { round_id: spec.id() }).send().await.unwrap().json().await.unwrap();
            if a.index == 2 && st.failed.is_some() {
                verdict = st.failed;
            }
        }
        if verdict.is_some() {
            break;
        }
    }
    let v = verdict.unwrap();
    assert_eq!(v.blamed, Some(3), "{}", v.reason);
}

/// Run a key generation among `admins` until operator `observer` reports a failure.
async fn failure_seen_by(admins: &[AdminEndpoint], observer: u32) -> Failure {
    let spec = admin::spec_dkg(&members(admins), 2).await.unwrap();
    for a in admins {
        admin::approve(&spec, a).await.unwrap();
    }
    for _ in 0..50 {
        let mut seen = None;
        for a in admins {
            let st: RoundStatus = reqwest::Client::new().post(format!("{}/v1/admin/round/advance", a.url)).bearer_auth(&a.admin_token).json(&RoundId { round_id: spec.id() }).send().await.unwrap().json().await.unwrap();
            assert!(!st.done, "the round must not succeed");
            if a.index == observer && st.failed.is_some() {
                seen = st.failed;
            }
        }
        if let Some(f) = seen {
            return f;
        }
    }
    let mut last = vec![];
    for a in admins {
        let st: RoundStatus = reqwest::Client::new().post(format!("{}/v1/admin/round/advance", a.url)).bearer_auth(&a.admin_token).json(&RoundId { round_id: spec.id() }).send().await.unwrap().json().await.unwrap();
        last.push(format!("{}: {} {:?} {:?}", a.index, st.phase, st.waiting_for, st.failed));
    }
    panic!("operator {observer} saw no failure: {last:#?}");
}

async fn with_fault(index: u32, fault: Fault) -> AdminEndpoint {
    let mut c = cfg(index);
    c.test_fault = Some(fault);
    spawn_with(c).await.0
}

/// Faults that used to end a round without naming anyone, or could have leaked a sub-share.
#[tokio::test]
async fn two_faced_dealers_and_lying_receivers_are_named() {
    // operator 2 commits and deals one polynomial to operator 3 and another to operator 1; each of
    // the two honest operators learns it from the other's ready message, which carries the signed commit
    let admins = [spawn(1).await.0, with_fault(2, Fault::EquivocateTo(3)).await, spawn(3).await.0];
    for observer in [1, 3] {
        let f = failure_seen_by(&admins, observer).await;
        assert_eq!(f.blamed, Some(2), "{}", f.reason);
        assert!(f.reason.contains("two different commits"), "{}", f.reason);
    }
    // operator 3 sends a ready hash that its own evidence does not explain
    let admins = [spawn(1).await.0, spawn(2).await.0, with_fault(3, Fault::LyingReady).await];
    let f = failure_seen_by(&admins, 1).await;
    assert_eq!(f.blamed, Some(3), "{}", f.reason);
    // operator 1 sends operator 2 a ciphertext with a copied E: operator 2 does not open it, and
    // operator 3 convicts operator 1 from the signed deal alone
    let admins = [with_fault(1, Fault::CopiedCiphertextTo(2)).await, spawn(2).await.0, spawn(3).await.0];
    for observer in [2, 3] {
        let f = failure_seen_by(&admins, observer).await;
        assert_eq!(f.blamed, Some(1), "{}", f.reason);
    }
    for a in &admins {
        assert!(admin::public(&a.url).await.unwrap().keys.is_empty(), "nothing was stored");
    }
}

/// The complaint check on its own: evidence is judged by anyone holding the spec.
#[tokio::test]
async fn complaints_are_checked_by_everyone() {
    use pop_uniqueness::shamir::{commit, eval_poly};
    let keys: Vec<ident::IdentityKey> = (0..3).map(|_| ident::IdentityKey::generate()).collect();
    let spec = RoundSpec {
        nonce: "ab".repeat(8),
        kind: RoundKind::Dkg,
        key: None,
        from_epoch: None,
        old_threshold: None,
        old_vks: Default::default(),
        new_epoch: 1,
        dealers: vec![1, 2, 3],
        receivers: vec![1, 2, 3],
        peers: (1..=3u32).map(|i| Peer { index: i, url: format!("https://op{i}.example"), identity: keys[i as usize - 1].public_hex() }).collect(),
        threshold: 2,
    };
    let checked = round::check_spec(&spec).unwrap();
    let id = spec.id();
    let sign = |k: &ident::IdentityKey, from: u32, body: &Body| {
        let body = serde_json::to_string(body).unwrap();
        Envelope { round_id: id.clone(), from, sig: k.sign(&Envelope::signed_bytes(&id, from, &body)), body }
    };
    // dealer 1 deals to receiver 2
    let poly = vec![Fr::rand(&mut rand::thread_rng()), Fr::rand(&mut rand::thread_rng())];
    let commitments: Vec<String> = commit(&poly).iter().map(to_hex).collect();
    let pok = Some(ident::pok_prove(&poly[0], &round::pok_context(&id, 1)));
    let hash = round::commit_hash(&commitments, &pok);
    let commit_env = sign(&keys[0], 1, &Body::Commit { hash });
    let ctx = round::seal_context(&id, 1, 2);
    let deal = |value: Fr| {
        let sealed = ident::seal(&keys[1].public, &ctx, &value);
        (sealed.clone(), sign(&keys[0], 1, &Body::Deal { to: 2, commitments: commitments.clone(), pok: pok.clone(), sealed }))
    };
    // a good deal: the complaint does not hold
    let (sealed, good) = deal(eval_poly(&poly, 2));
    let opening = keys[1].reveal(&ctx, &sealed).unwrap();
    assert!(round::verify_complaint(&spec, &checked, 2, &good, &commit_env, Some(&opening)).is_err());
    // a bad value: the dealer is at fault
    let (sealed, bad) = deal(eval_poly(&poly, 2) + Fr::from(1u64));
    let opening = keys[1].reveal(&ctx, &sealed).unwrap();
    assert_eq!(round::verify_complaint(&spec, &checked, 2, &bad, &commit_env, Some(&opening)), Ok(1));
    // the right evidence from the wrong complainer, an opening for another message, a deal the
    // complainer made up itself: none of them pins anything on the dealer
    assert!(round::verify_complaint(&spec, &checked, 3, &bad, &commit_env, Some(&opening)).is_err());
    let (other_sealed, _) = deal(eval_poly(&poly, 2));
    assert!(round::verify_complaint(&spec, &checked, 2, &bad, &commit_env, Some(&keys[1].reveal(&ctx, &other_sealed).unwrap())).is_err());
    let (_, self_made) = {
        let sealed = ident::seal(&keys[1].public, &ctx, &Fr::from(7u64));
        (sealed.clone(), sign(&keys[1], 1, &Body::Deal { to: 2, commitments: commitments.clone(), pok: pok.clone(), sealed }))
    };
    assert!(round::verify_complaint(&spec, &checked, 2, &self_made, &commit_env, Some(&opening)).is_err());
    // a deal that differs from the commitment is the dealer's fault without any decryption
    let other_commit = sign(&keys[0], 1, &Body::Commit { hash: "11".repeat(32) });
    let (sealed, good2) = deal(eval_poly(&poly, 2));
    let opening = keys[1].reveal(&ctx, &sealed).unwrap();
    assert_eq!(round::verify_complaint(&spec, &checked, 2, &good2, &other_commit, Some(&opening)), Ok(1));

    // A ciphertext whose E the dealer copied from somewhere (here: from its own earlier message, to
    // have the receiver reveal that message's pad) carries no valid proof of e. The receiver refuses
    // to open it, and the signed deal convicts the dealer without an opening.
    let (victim, _) = deal(eval_poly(&poly, 2));
    let mut copied = ident::seal(&keys[1].public, &ctx, &Fr::from(1u64));
    copied.e = victim.e.clone();
    copied.pok = victim.pok.clone();
    let replay_ctx = round::seal_context(&id, 3, 2);
    assert!(keys[1].reveal(&replay_ctx, &copied).is_err(), "the proof of e is bound to dealer and receiver");
    let from3 = sign(&keys[2], 3, &Body::Deal { to: 2, commitments: commitments.clone(), pok: pok.clone(), sealed: copied });
    let commit3 = sign(&keys[2], 3, &Body::Commit { hash: round::commit_hash(&commitments, &pok) });
    assert_eq!(round::verify_complaint(&spec, &checked, 2, &from3, &commit3, None), Ok(3));
    // ... while a complaint without an opening about a well-formed deal falls back on the complainer
    assert!(round::verify_complaint(&spec, &checked, 2, &good, &commit_env, None).is_err());

    // spec checks
    let mut s = spec.clone();
    s.peers[1].identity = s.peers[0].identity.clone();
    assert!(round::check_spec(&s).is_err(), "one key for two operators");
    let mut s = spec.clone();
    s.peers[0].url = "http://op1.example".into();
    assert!(round::check_spec(&s).is_err(), "plain http");
    let mut s = spec.clone();
    s.threshold = 4;
    assert!(round::check_spec(&s).is_err());
    let mut s = spec.clone();
    s.peers[0].identity = s.peers[0].identity.to_uppercase();
    assert!(round::check_spec(&s).is_err(), "one spelling per key");
    let mut s = spec.clone();
    s.nonce = "cd".repeat(8);
    assert_ne!(s.id(), spec.id(), "the id covers the whole spec");
}

#[tokio::test]
async fn rounds_are_all_or_nothing() {
    let (admins, eps) = cluster(&[1, 2, 3, 4]).await;
    let key = admin::dkg(&admins[..3], 2).await.unwrap();
    let c = client(&eps, &[&key]);
    let before = d(&c, "Q").await;
    let cur = admin::current_epoch(&key, &admins[..3]).await.unwrap();

    // thresholds below the operators' minimum are refused
    assert!(admin::reshare(&key, &admins[..3], &admins[..3], 1).await.is_err());
    // one dealer cannot reshare a 2-of-3 key
    assert!(admin::reshare(&key, &admins[..1], &admins[..3], 2).await.is_err());
    // a receiver that is unreachable: no spec can even be written
    let mut broken = admins[..3].to_vec();
    broken.push(AdminEndpoint { index: 9, url: "http://127.0.0.1:9".into(), admin_token: "x".into() });
    assert!(admin::reshare(&key, &admins[..3], &broken, 2).await.is_err());
    // a spec for another key that reuses these operators' verification keys does not pass
    let m = members(&admins[..3]);
    let mut spec = admin::spec_reshare(&key, &m, &m, 2).await.unwrap();
    spec.key = Some(to_hex(&(G2::generator() * Fr::rand(&mut rand::thread_rng())).into_affine()));
    assert!(admin::approve(&spec, &admins[0]).await.is_err());
    // nor one that swaps a dealer's verification key
    let mut spec = admin::spec_reshare(&key, &m, &m, 2).await.unwrap();
    spec.old_vks.insert(1, cur.vks[&2].clone());
    assert!(admin::approve(&spec, &admins[3]).await.is_err());

    // nothing changed
    assert_eq!(admin::current_epoch(&key, &admins[..3]).await.unwrap(), cur);
    assert!(admin::public(&admins[3].url).await.unwrap().keys.is_empty());
    assert_eq!(before, d(&c, "Q").await);
}

#[tokio::test]
async fn shares_survive_a_restart() {
    let dir = tmp("restart");
    let mut admins = vec![];
    let mut eps = vec![];
    for i in 1..=3u32 {
        let mut c = cfg(i);
        c.state_file = Some(dir.join(format!("op{i}.json")));
        let (a, e) = spawn_with(c).await;
        admins.push(a);
        eps.push(e);
    }
    let key = admin::dkg(&admins, 2).await.unwrap();
    let before = d(&client(&eps, &[&key]), "R").await;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.join("op1.json")).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // "restart": new servers on new ports from the same share files
    let mut eps2 = vec![];
    for i in 1..=3u32 {
        let mut c = cfg(i);
        c.state_file = Some(dir.join(format!("op{i}.json")));
        eps2.push(spawn_with(c).await.1);
    }
    assert_eq!(before, d(&client(&eps2, &[&key]), "R").await);
    // a damaged share file stops the operator instead of starting it empty
    std::fs::write(dir.join("op1.json"), b"{ not json").unwrap();
    let mut c = cfg(1);
    c.state_file = Some(dir.join("op1.json"));
    assert!(Operator::new(c).is_err());
    let _ = std::fs::remove_dir_all(dir);
}

/// One receiver cannot store its new share: the round stalls, nothing is erased, everything keeps
/// working, and the next round supersedes the leftover epoch.
#[tokio::test]
async fn a_stalled_round_loses_nothing() {
    let dir = tmp("undo");
    let (admins, eps) = cluster(&[1, 2, 3]).await;
    let key = admin::dkg(&admins, 2).await.unwrap();
    let c = client(&eps, &[&key]);
    let before = d(&c, "U").await;
    let mut c4 = cfg(4);
    c4.state_file = Some(dir.join("blocked").join("op4.json"));
    // the identity key is written at start; block the directory afterwards
    let (a4, _) = spawn_with(c4).await;
    std::fs::remove_dir_all(dir.join("blocked")).unwrap();
    std::fs::write(dir.join("blocked"), b"a file where the directory should be").unwrap(); // the share cannot be written
    let new_set = [admins[0].clone(), admins[1].clone(), a4];
    let m_all = members(&admins);
    let spec = admin::spec_reshare(&key, &m_all, &members(&new_set), 2).await.unwrap();
    let mut all = admins.to_vec();
    all.push(new_set[2].clone());
    let e = format!("{:#}", admin::drive(&spec, &all, Duration::from_secs(3)).await.unwrap_err());
    assert!(e.contains("cannot write share file") || e.contains("did not finish"), "{e}");
    // operators 1 and 2 may hold the new epoch; all three still hold the old one, and d is unchanged
    for a in &admins {
        let eps = admin::public(&a.url).await.unwrap().keys[0].epochs.clone();
        assert!(eps.iter().any(|e| e.epoch == 1), "operator {} kept its old share", a.index);
    }
    assert_eq!(before, d(&c, "U").await);
    // the next round starts from the old epoch, takes a later number, and erases the leftover
    let epoch = admin::reshare(&key, &admins, &admins, 2).await.unwrap();
    assert_eq!(epoch, 3);
    for a in &admins {
        let eps = admin::public(&a.url).await.unwrap().keys[0].epochs.clone();
        assert_eq!(eps.iter().map(|e| e.epoch).collect::<Vec<_>>(), vec![3]);
    }
    assert_eq!(before, d(&c, "U").await);
    let _ = std::fs::remove_dir_all(dir);
}

/// An operator that repeats its answer cannot break the combination.
#[tokio::test]
async fn repeated_answers_are_ignored() {
    use axum::{routing::post, Json, Router};
    let (admins, eps) = cluster(&[1, 2, 3]).await;
    let key = admin::dkg(&admins, 2).await.unwrap();
    let honest = d(&client(&eps, &[&key]), "V").await;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    let app = Router::new().route("/v1/evaluate", post(|Json(r): Json<EvalRequest>| async move {
        let p = Partial { epoch: 1, threshold: 2, value: r.point };
        Json(EvalResponse { index: 3, partials: vec![p.clone(), p.clone(), p] })
    }));
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    let c = client(&[OperatorEndpoint { index: 3, url, token: "t".into() }, eps[0].clone(), eps[1].clone()], &[&key]);
    assert_eq!(honest, d(&c, "V").await);
}

#[test]
fn configuration_is_checked() {
    let mut c = cfg(1);
    c.eval_token = "short".into();
    assert!(Operator::new(c).is_err());
    let mut c = cfg(1);
    c.admin_token = c.eval_token.clone();
    assert!(Operator::new(c).is_err());
    let mut c = cfg(0);
    c.index = 0;
    assert!(Operator::new(c).is_err());
    let ep = |url: &str| OperatorEndpoint { index: 1, url: url.into(), token: "t".into() };
    let key = to_hex(&G2::generator().into_affine());
    assert!(ThresholdUniqueness::new(ThresholdConfig { operators: vec![ep("http://example.org")], keys: vec![key.clone()] }).is_err(), "plain http off loopback");
    assert!(ThresholdUniqueness::new(ThresholdConfig { operators: vec![ep("https://example.org")], keys: vec![key.clone()] }).is_ok());
    assert!(ThresholdUniqueness::new(ThresholdConfig { operators: vec![ep("https://example.org")], keys: vec![] }).is_err());
    assert!(ThresholdUniqueness::new(ThresholdConfig { operators: vec![ep("https://a.example"), ep("https://b.example")], keys: vec![key] }).is_err(), "duplicate index");
}
