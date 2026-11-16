//! The threshold service end to end: real operators on loopback ports, talking over HTTP.
use ark_ec::{CurveGroup, Group};
use ark_ff::Field;
use ark_std::UniformRand;
use pop_crypto::codec::{from_hex, to_hex};
use pop_crypto::params::{Fr, G2, G2A};
use pop_protocol::uniqueness::UniquenessService;
use pop_uniqueness::admin::{self, AdminEndpoint};
use pop_uniqueness::wire::*;
use pop_uniqueness::{Operator, OperatorConfig, OperatorEndpoint, ThresholdConfig, ThresholdUniqueness};
use std::path::PathBuf;

const PEER: &str = "peer-token-peer-token-peer-token";

fn cfg(index: u32) -> OperatorConfig {
    OperatorConfig {
        index,
        eval_token: format!("eval-token-of-operator-number-{index}"),
        admin_token: format!("admin-token-of-operator-number-{index}"),
        peer_token: PEER.into(),
        state_file: None,
        max_evals_per_minute: 10_000,
        min_threshold: 2,
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
    assert_eq!(alice, d(&c, "010190-900A").await, "between commit and finalize both epochs answer");
    admin::finalize(&key, epoch, &admins[..3], &[]).await.unwrap();
    let after = admin::current_epoch(&key, &admins[..3]).await.unwrap();
    assert!(before.vks.iter().all(|(i, v)| after.vks[i] != *v), "every share changed");
    assert_eq!(alice, d(&c, "010190-900A").await);
    assert_eq!(bob, d(&c, "020285-901B").await);
    let info = admin::public(&admins[0].url).await.unwrap();
    assert_eq!(info.keys[0].epochs.len(), 1, "old share erased");

    // replace operator 3 by operator 4
    let new_set = [admins[0].clone(), admins[1].clone(), admins[3].clone()];
    let epoch = admin::reshare(&key, &admins[..3], &new_set, 2).await.unwrap();
    admin::finalize(&key, epoch, &new_set, &[admins[2].clone()]).await.unwrap();
    assert!(admin::public(&admins[2].url).await.unwrap().keys.is_empty(), "the operator that left holds nothing");
    assert_eq!(alice, d(&c, "010190-900A").await);
    // the new member alone with one old member is enough
    assert_eq!(alice, d(&client(&[eps[1].clone(), eps[3].clone()], &[&key]), "010190-900A").await);

    // other threshold and a mostly new set: 3-of-4 on operators 2, 4, 5, 6, dealt by two holders
    let newer = [admins[1].clone(), admins[3].clone(), admins[4].clone(), admins[5].clone()];
    let epoch = admin::reshare(&key, &[admins[0].clone(), admins[3].clone()], &newer, 3).await.unwrap();
    admin::finalize(&key, epoch, &newer, &[admins[0].clone()]).await.unwrap();
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
    assert_eq!(eval(PEER.into()).await, 401);
    assert_eq!(eval(e2.token.clone()).await, 401, "another operator's evaluation token");
    for path in ["/v1/admin/round/start", "/v1/admin/round/deal", "/v1/admin/round/status", "/v1/admin/round/commit", "/v1/admin/round/abort", "/v1/admin/finalize", "/v1/admin/discard", "/v1/peer/deal"] {
        for token in [e1.token.as_str(), "", if path.starts_with("/v1/peer") { a1.admin_token.as_str() } else { PEER }] {
            let s = http.post(format!("{}{path}", e1.url)).bearer_auth(token).json(&serde_json::json!({"round_id": "00"})).send().await.unwrap().status().as_u16();
            assert_eq!(s, 401, "{path} with a wrong token");
        }
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

#[tokio::test]
async fn rounds_are_all_or_nothing() {
    let (admins, eps) = cluster(&[1, 2, 3, 4]).await;
    let key = admin::dkg(&admins[..3], 2).await.unwrap();
    let c = client(&eps, &[&key]);
    let before = d(&c, "Q").await;
    let cur = admin::current_epoch(&key, &admins[..3]).await.unwrap();
    let http = reqwest::Client::new();

    // thresholds below the operators' minimum are refused
    assert!(admin::reshare(&key, &admins[..3], &admins[..3], 1).await.is_err());
    // one dealer cannot reshare a 2-of-3 key
    assert!(admin::reshare(&key, &admins[..1], &admins[..3], 2).await.is_err());
    // a receiver that is unreachable aborts the round
    let mut broken = admins[..3].to_vec();
    broken.push(AdminEndpoint { index: 9, url: "http://127.0.0.1:9".into(), admin_token: "x".into() });
    assert!(admin::reshare(&key, &admins[..3], &broken, 2).await.is_err());

    // Someone with the peer token deals in the name of operator 1 to operator 4 (a newcomer), with
    // commitments made up to fit: C0 is operator 1's verification key, C1 is solved for.
    let spec = RoundSpec {
        round_id: "ab".repeat(16),
        kind: RoundKind::Reshare,
        key: Some(key.clone()),
        from_epoch: Some(cur.epoch),
        old_threshold: Some(2),
        old_vks: cur.vks.clone(),
        dealers: vec![1, 2, 3],
        receivers: [&admins[0], &admins[1], &admins[3]].iter().map(|a| Peer { index: a.index, url: a.url.clone() }).collect(),
        threshold: 2,
    };
    for a in &admins {
        let r = http.post(format!("{}/v1/admin/round/start", a.url)).bearer_auth(&a.admin_token).json(&spec).send().await.unwrap();
        assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    }
    let v = Fr::rand(&mut rand::thread_rng());
    let vk1: G2A = from_hex(&cur.vks[&1]).unwrap();
    let c1 = ((G2::generator() * v - vk1) * Fr::from(4u64).inverse().unwrap()).into_affine();
    let forged = Deal { round_id: spec.round_id.clone(), from: 1, commitments: vec![cur.vks[&1].clone(), to_hex(&c1)], value: to_hex(&v) };
    let r = http.post(format!("{}/v1/peer/deal", admins[3].url)).bearer_auth(PEER).json(&forged).send().await.unwrap();
    assert!(r.status().is_success(), "the forgery passes the newcomer's local checks");
    // ... but operator 1 cannot be impersonated towards itself,
    let r = http.post(format!("{}/v1/peer/deal", admins[0].url)).bearer_auth(PEER).json(&forged).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 400);
    // the real deal of operator 1 now conflicts at operator 4,
    let id = RoundId { round_id: spec.round_id.clone() };
    let r = http.post(format!("{}/v1/admin/round/deal", admins[0].url)).bearer_auth(&admins[0].admin_token).json(&id).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 502);
    for a in &admins[1..3] {
        assert!(http.post(format!("{}/v1/admin/round/deal", a.url)).bearer_auth(&a.admin_token).json(&id).send().await.unwrap().status().is_success());
    }
    // and the transcripts differ, so no honest operator commits
    let st = |a: AdminEndpoint| {
        let (http, id) = (http.clone(), id.clone());
        async move { http.post(format!("{}/v1/admin/round/status", a.url)).bearer_auth(&a.admin_token).json(&id).send().await.unwrap().json::<RoundStatus>().await.unwrap() }
    };
    let (t2, t4) = (st(admins[1].clone()).await, st(admins[3].clone()).await);
    assert!(t2.missing.is_empty() && t4.missing.is_empty());
    assert_ne!(t2.transcript, t4.transcript);
    let r = http.post(format!("{}/v1/admin/round/commit", admins[1].url)).bearer_auth(&admins[1].admin_token).json(&CommitRequest { round_id: spec.round_id.clone(), transcript: t4.transcript.clone() }).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 409);
    for a in &admins {
        http.post(format!("{}/v1/admin/round/abort", a.url)).bearer_auth(&a.admin_token).json(&id).send().await.unwrap();
    }

    // a deal that does not match its commitments, or does not carry the dealer's share, is refused
    let mut spec2 = spec.clone();
    spec2.round_id = "cd".repeat(16);
    for a in &admins {
        assert!(http.post(format!("{}/v1/admin/round/start", a.url)).bearer_auth(&a.admin_token).json(&spec2).send().await.unwrap().status().is_success());
    }
    let mut bad = forged.clone();
    bad.round_id = spec2.round_id.clone();
    bad.value = to_hex(&Fr::rand(&mut rand::thread_rng()));
    assert_eq!(http.post(format!("{}/v1/peer/deal", admins[3].url)).bearer_auth(PEER).json(&bad).send().await.unwrap().status().as_u16(), 400);
    let g = to_hex(&G2::generator().into_affine());
    let other = Deal { round_id: spec2.round_id.clone(), from: 1, commitments: vec![g.clone(), g], value: to_hex(&Fr::from(5u64)) };
    assert_eq!(http.post(format!("{}/v1/peer/deal", admins[3].url)).bearer_auth(PEER).json(&other).send().await.unwrap().status().as_u16(), 400);

    // finalize with a wrong epoch erases nothing
    assert!(admin::finalize(&key, 7, &admins[..3], &[]).await.is_err());
    let r = http.post(format!("{}/v1/admin/finalize", admins[0].url)).bearer_auth(&admins[0].admin_token).json(&FinalizeRequest { key: key.clone(), epoch: 7, leaving: false }).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 409);

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

/// One receiver cannot store its new share: the others drop theirs again and the old sharing stands.
#[tokio::test]
async fn a_failed_commit_is_undone() {
    let dir = tmp("undo");
    let (admins, eps) = cluster(&[1, 2, 3]).await;
    let key = admin::dkg(&admins, 2).await.unwrap();
    let c = client(&eps, &[&key]);
    let before = d(&c, "U").await;
    let mut c4 = cfg(4);
    c4.state_file = Some(dir.join("blocked").join("op4.json"));
    let (a4, _) = spawn_with(c4).await;
    std::fs::write(dir.join("blocked"), b"a file where the directory should be").unwrap(); // the share cannot be written
    let new_set = [admins[0].clone(), admins[1].clone(), a4];
    let e = format!("{:#}", admin::reshare(&key, &admins, &new_set, 2).await.unwrap_err());
    assert!(e.contains("nothing changed"), "{e}");
    let cur = admin::current_epoch(&key, &admins).await.unwrap();
    assert_eq!(cur.epoch, 1);
    assert_eq!(admin::public(&admins[0].url).await.unwrap().keys[0].epochs.len(), 1);
    assert_eq!(before, d(&c, "U").await);
    // and the next round works
    assert_eq!(admin::reshare(&key, &admins, &admins, 2).await.unwrap(), 2);
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
    c.admin_token = c.peer_token.clone();
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
