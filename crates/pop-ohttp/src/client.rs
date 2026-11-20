//! Sending protocol requests through a relay.
use crate::{BAD_KEY, KEYS_TYPE, REQ_TYPE, RES_TYPE};
use async_trait::async_trait;
use pop_protocol::{
    api::ApiError,
    http::{RawResponse, Transport},
};
use std::{io::Cursor, time::Duration};
use tokio::sync::Mutex;

/// A [`Transport`] through an Oblivious HTTP relay. `relay` is the relay's address for one server's
/// gateway (with the relay of this crate, `https://relay.example/directory`); the key is fetched from
/// `relay/keys`, through the relay, so the server cannot give this client a key of its own.
pub struct Oblivious {
    relay: String,
    http: reqwest::Client,
    keys: Mutex<Option<Vec<u8>>>,
    /// size classes from the last answer
    pad_sizes: std::sync::Mutex<Vec<u32>>,
}

fn t(e: impl std::fmt::Display) -> ApiError {
    ApiError::Transport(format!("relay: {e}"))
}

impl Oblivious {
    pub fn new(relay: &str) -> anyhow::Result<Self> {
        let u = url::Url::parse(relay)?;
        let loopback = matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        anyhow::ensure!(u.scheme() == "https" || (u.scheme() == "http" && loopback), "relay address must be https (or http on this computer)");
        let http = reqwest::Client::builder().timeout(Duration::from_secs(120)).redirect(reqwest::redirect::Policy::none()).build()?;
        Ok(Oblivious { relay: relay.trim_end_matches('/').to_string(), http, keys: Mutex::new(None), pad_sizes: std::sync::Mutex::new(crate::DEFAULT_PAD_SIZES.to_vec()) })
    }

    async fn keys(&self, refresh: bool) -> Result<Vec<u8>, ApiError> {
        let mut k = self.keys.lock().await;
        if refresh || k.is_none() {
            let r = self.http.get(format!("{}/keys", self.relay)).send().await.map_err(t)?;
            if !r.status().is_success() {
                return Err(t(format!("key: {}", r.status())));
            }
            if r.headers().get("content-type").and_then(|v| v.to_str().ok()) != Some(KEYS_TYPE) {
                return Err(t("key: wrong content type"));
            }
            *k = Some(r.bytes().await.map_err(t)?.to_vec());
        }
        Ok(k.clone().unwrap_or_default())
    }
}

#[async_trait]
impl Transport for Oblivious {
    async fn send(&self, method: &str, base: &str, path: &str, json_body: Option<Vec<u8>>) -> Result<RawResponse, ApiError> {
        let u = url::Url::parse(base).map_err(t)?;
        let authority = match u.port() {
            Some(p) => format!("{}:{p}", u.host_str().unwrap_or_default()),
            None => u.host_str().unwrap_or_default().to_string(),
        };
        let mut m = bhttp::Message::request(method.as_bytes().to_vec(), u.scheme().as_bytes().to_vec(), authority.into_bytes(), path.as_bytes().to_vec());
        if let Some(b) = &json_body {
            m.put_header("content-type", "application/json");
            m.write_content(b);
        }
        let mut plain = vec![];
        m.write_bhttp(bhttp::Mode::KnownLength, &mut plain).map_err(t)?;
        let sizes = self.pad_sizes.lock().unwrap().clone();
        crate::pad(&mut plain, &sizes);
        for attempt in 0..2 {
            let keys = self.keys(attempt > 0).await?;
            let (enc, ctx) = ohttp::ClientRequest::from_encoded_config_list(&keys).map_err(t)?.encapsulate(&plain).map_err(t)?;
            let r = self.http.post(&self.relay).header("content-type", REQ_TYPE).body(enc).send().await.map_err(t)?;
            let status = r.status();
            let ct = r.headers().get("content-type").and_then(|v| v.to_str().ok()).map(String::from);
            let relay_date = r.headers().get("date").and_then(|v| v.to_str().ok()).map(String::from);
            let body = r.bytes().await.map_err(t)?;
            if status == reqwest::StatusCode::BAD_REQUEST && body.as_ref() == BAD_KEY.as_bytes() && attempt == 0 {
                continue; // the gateway has a new key; the request did not reach the server
            }
            if !status.is_success() || ct.as_deref() != Some(RES_TYPE) {
                return Err(t(format!("{status}: {}", String::from_utf8_lossy(&body[..body.len().min(200)]))));
            }
            let inner = ctx.decapsulate(&body).map_err(t)?;
            let mut c = Cursor::new(&inner[..]);
            let resp = bhttp::Message::read_bhttp::<Cursor<&[u8]>, Cursor<&[u8]>>(&mut c).map_err(t)?;
            let status = resp.control().status().ok_or_else(|| t("not a response"))?.code();
            if let Some(s) = resp.header().get(crate::PAD_HEADER.as_bytes()).and_then(crate::parse_pad_sizes) {
                *self.pad_sizes.lock().unwrap() = s;
            }
            let server_date = resp.header().get(b"date").and_then(|v| std::str::from_utf8(v).ok()).map(String::from);
            return Ok(RawResponse { status, body: resp.content().to_vec(), server_date, relay_date });
        }
        Err(t("the gateway's key keeps changing"))
    }
}
