//! A service behind a gateway, a relay in front, and a protocol client that goes through the relay.
use axum::{
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use pop_ohttp::{gateway, relay, Oblivious};
use pop_protocol::{api::ApiError, http::HttpClient};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

async fn serve(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    url
}

type Seen = Arc<Mutex<Vec<Vec<String>>>>;

fn service(seen: Seen) -> Router {
    let s1 = seen.clone();
    Router::new()
        .route(
            "/v1/echo",
            post(move |h: HeaderMap, Json(v): Json<Value>| {
                let seen = s1.clone();
                async move {
                    seen.lock().unwrap().push(h.keys().map(|k| k.to_string()).collect());
                    Json(json!({"echo": v}))
                }
            }),
        )
        .route("/v1/missing", get(|| async { (axum::http::StatusCode::NOT_FOUND, Json(json!({"error": "nothing here"}))) }))
}

#[tokio::test]
async fn requests_reach_the_service_through_the_relay_with_nothing_of_the_sender() {
    let seen: Seen = Default::default();
    let svc = serve(gateway::wrap(service(seen.clone()), gateway::Gateway::generate().unwrap())).await;
    let rel = serve(relay::router(BTreeMap::from([("svc".to_string(), svc.clone())])).unwrap()).await;
    let c = HttpClient::with_transport(&svc, Arc::new(Oblivious::new(&format!("{rel}/svc")).unwrap()));

    let v: Value = c.post("/v1/echo", &json!({"like": 1})).await.unwrap();
    assert_eq!(v, json!({"echo": {"like": 1}}));
    // errors come back as the service gave them
    match c.get::<Value>("/v1/missing").await {
        Err(ApiError::Server { status: 404, message }) => assert_eq!(message, "nothing here"),
        r => panic!("{r:?}"),
    }
    // the gateway itself cannot be reached from inside
    assert!(matches!(c.get::<Value>("/ohttp/keys").await, Err(ApiError::Server { status: 400, .. })));
    // the service saw only the content type: no address (not even the relay's), no other header
    assert_eq!(seen.lock().unwrap()[0], vec!["content-type".to_string()]);
}

async fn rotate(keys_min_age: Duration) -> (HttpClient, Seen) {
    let seen: Seen = Default::default();
    let gw = gateway::Gateway::generate().unwrap();
    let svc = serve(gateway::wrap(service(seen.clone()), gw.clone())).await;
    let rel = serve(relay::router_with(BTreeMap::from([("svc".to_string(), svc.clone())]), relay::Options { keys_min_age }).unwrap()).await;
    let c = HttpClient::with_transport(&svc, Arc::new(Oblivious::new(&format!("{rel}/svc")).unwrap()));
    let _: Value = c.post("/v1/echo", &json!(1)).await.unwrap();
    gw.rotate().unwrap();
    (c, seen)
}

#[tokio::test]
async fn a_new_gateway_key_is_fetched_again() {
    let (c, seen) = rotate(Duration::ZERO).await;
    let v: Value = c.post("/v1/echo", &json!(2)).await.unwrap();
    assert_eq!(v, json!({"echo": 2}));
    assert_eq!(seen.lock().unwrap().len(), 2, "the request that met the old key never reached the service");
}

#[tokio::test]
async fn the_relay_keeps_one_key_for_everyone_for_a_while() {
    // undecryptable requests (from a client, or from a gateway trying to hand out keys one by one) do
    // not make the relay fetch the key again before its copy is old enough
    let (c, seen) = rotate(relay::KEYS_MIN_AGE).await;
    let r = c.post::<_, Value>("/v1/echo", &json!(2)).await;
    assert!(matches!(r, Err(ApiError::Transport(_))), "{r:?}");
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn the_relay_refuses_what_is_not_an_encrypted_request() {
    let svc = serve(gateway::wrap(service(Default::default()), gateway::Gateway::generate().unwrap())).await;
    let rel = serve(relay::router(BTreeMap::from([("svc".to_string(), svc.clone())])).unwrap()).await;
    let h = reqwest::Client::new();
    assert_eq!(h.post(format!("{rel}/svc")).json(&json!({})).send().await.unwrap().status(), 415);
    assert_eq!(h.post(format!("{rel}/other")).header("content-type", "message/ohttp-req").body("x").send().await.unwrap().status(), 404);
    assert_eq!(h.post(format!("{rel}/svc")).header("content-type", "message/ohttp-req").body("garbage").send().await.unwrap().status(), 400);
    assert!(relay::router(BTreeMap::from([("../x".to_string(), svc)])).is_err());
}

#[tokio::test]
async fn messages_are_padded_so_their_size_says_little() {
    // a relay that records the sizes it passes on
    let sizes: Arc<Mutex<Vec<usize>>> = Default::default();
    let svc = serve(gateway::wrap(service(Default::default()), gateway::Gateway::generate().unwrap())).await;
    let rel = serve(relay::router(BTreeMap::from([("svc".to_string(), svc.clone())])).unwrap()).await;
    let (sz, rel2) = (sizes.clone(), rel.clone());
    let spy = serve(Router::new().route(
        "/svc",
        post(move |body: axum::body::Bytes| {
            let (sz, rel) = (sz.clone(), rel2.clone());
            async move {
                let r = reqwest::Client::new().post(format!("{rel}/svc")).header("content-type", "message/ohttp-req").body(body.clone()).send().await.unwrap();
                let b = r.bytes().await.unwrap();
                sz.lock().unwrap().extend([body.len(), b.len()]);
                ([("content-type", "message/ohttp-res")], b)
            }
        }),
    ).route("/svc/keys", get({ let rel = rel.clone(); move || async move { let r = reqwest::get(format!("{rel}/svc/keys")).await.unwrap(); ([("content-type", "application/ohttp-keys")], r.bytes().await.unwrap()) } })))
    .await;
    let c = HttpClient::with_transport(&svc, Arc::new(Oblivious::new(&format!("{spy}/svc")).unwrap()));
    let _: Value = c.post("/v1/echo", &json!("a")).await.unwrap();
    let _: Value = c.post("/v1/echo", &json!("a much longer request body than the first, still small")).await.unwrap();
    let s = sizes.lock().unwrap().clone();
    assert_eq!(s[0], s[2], "requests of different lengths look the same: {s:?}");
    assert_eq!(s[1], s[3], "answers of different lengths look the same: {s:?}");
}
