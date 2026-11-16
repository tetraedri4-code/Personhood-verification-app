//! Platform adapter for the mock feed (`pop-mockfeed`). The smallest complete example of
//! [`pop_protocol::platform::Platform`]; copy it when adding a platform (docs/adding-a-platform.md).
use async_trait::async_trait;
use pop_protocol::platform::{CodePlacement, Platform, PlatformError};
use pop_protocol::AccountRef;
use serde_json::{json, Value};

pub struct MockFeed {
    base: String,
    http: reqwest::Client,
    /// handle to act as (the mock has no passwords); None = read-only
    login_as: Option<String>,
}

impl MockFeed {
    pub fn new(base: &str, login_as: Option<String>) -> Self {
        MockFeed { base: base.trim_end_matches('/').into(), http: reqwest::Client::new(), login_as }
    }

    async fn get(&self, path: &str) -> Result<Value, PlatformError> {
        let r = self.http.get(format!("{}{}", self.base, path)).send().await.map_err(|e| PlatformError::Http(e.to_string()))?;
        if r.status() == 404 {
            return Err(PlatformError::NotFound(path.into()));
        }
        r.error_for_status().map_err(|e| PlatformError::Http(e.to_string()))?.json().await.map_err(|e| PlatformError::Http(e.to_string()))
    }

    async fn send(&self, method: reqwest::Method, path: &str, token: Option<&str>, body: Value) -> Result<Value, PlatformError> {
        let mut rq = self.http.request(method, format!("{}{}", self.base, path)).json(&body);
        if let Some(t) = token {
            rq = rq.bearer_auth(t);
        }
        let r = rq.send().await.map_err(|e| PlatformError::Http(e.to_string()))?;
        r.error_for_status().map_err(|e| PlatformError::Http(e.to_string()))?.json().await.map_err(|e| PlatformError::Http(e.to_string()))
    }

    /// Log in as the configured handle, which must be the account's handle.
    async fn session(&self, account: &AccountRef) -> Result<String, PlatformError> {
        let h = self.login_as.as_deref().ok_or(PlatformError::NoCredentials)?;
        let r = self.send(reqwest::Method::POST, "/api/login", None, json!({"handle": h})).await?;
        if r["user"]["id"].as_str() != Some(&account.account_id) {
            return Err(PlatformError::NoCredentials);
        }
        Ok(r["token"].as_str().unwrap_or_default().to_string())
    }
}

fn handle_of(input: &str) -> String {
    let s = input.trim();
    let s = s.rsplit("/u/").next().unwrap_or(s);
    s.trim_start_matches('@').trim_end_matches('/').to_lowercase()
}

#[async_trait]
impl Platform for MockFeed {
    fn id(&self) -> &'static str {
        "mockfeed"
    }
    fn display_name(&self) -> &'static str {
        "MockFeed (local)"
    }

    async fn resolve_account(&self, handle_or_url: &str) -> Result<AccountRef, PlatformError> {
        let h = handle_of(handle_or_url);
        let u = self.get(&format!("/api/users/{h}")).await?;
        Ok(AccountRef {
            platform: "mockfeed".into(),
            account_id: u["id"].as_str().unwrap_or_default().into(),
            handle: u["handle"].as_str().unwrap_or_default().into(),
        })
    }

    async fn publish_code(&self, account: &AccountRef, code: &str, placement: CodePlacement) -> Result<(), PlatformError> {
        let token = self.session(account).await?;
        match placement {
            CodePlacement::Bio => {
                let u = self.get(&format!("/api/users/{}", account.handle)).await?;
                let bio = u["bio"].as_str().unwrap_or_default();
                if bio.contains(code) {
                    return Ok(());
                }
                let new_bio = if bio.is_empty() { code.to_string() } else { format!("{bio} {code}") };
                self.send(reqwest::Method::PUT, "/api/me/bio", Some(&token), json!({"bio": new_bio})).await?;
            }
            CodePlacement::Post => {
                self.send(reqwest::Method::POST, "/api/posts", Some(&token), json!({"text": format!("Verifying that one enrolled person runs this account: {code}")}))
                    .await?;
            }
        }
        Ok(())
    }

    async fn remove_code(&self, account: &AccountRef, code: &str) -> Result<(), PlatformError> {
        let token = self.session(account).await?;
        let u = self.get(&format!("/api/users/{}", account.handle)).await?;
        let bio = u["bio"].as_str().unwrap_or_default().replace(code, "").trim().to_string();
        self.send(reqwest::Method::PUT, "/api/me/bio", Some(&token), json!({"bio": bio})).await?;
        Ok(())
    }

    async fn public_texts(&self, account: &AccountRef) -> Result<Vec<String>, PlatformError> {
        let u = self.get(&format!("/api/users/{}", account.handle)).await?;
        if u["id"].as_str() != Some(&account.account_id) {
            return Err(PlatformError::NotFound(account.handle.clone()));
        }
        let mut v = vec![u["bio"].as_str().unwrap_or_default().to_string()];
        if let Value::Array(posts) = self.get(&format!("/api/users/{}/posts", account.handle)).await? {
            v.extend(posts.iter().filter_map(|p| p["text"].as_str().map(String::from)));
        }
        Ok(v)
    }

    async fn canonical_post_id(&self, raw: &str) -> Result<String, PlatformError> {
        let id = raw.trim().rsplit('/').next().unwrap_or_default();
        if id.starts_with('p') && id.len() > 1 && id[1..].chars().all(|c| c.is_ascii_digit()) {
            Ok(id.to_string())
        } else {
            Err(PlatformError::NotFound(raw.into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_and_read_code() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, pop_mockfeed::router()).await.unwrap() });
        let base = format!("http://{addr}");
        let mf = MockFeed::new(&base, Some("alice".into()));
        let a = mf.resolve_account(&format!("{base}/u/alice")).await.unwrap();
        assert_eq!(a.handle, "alice");
        mf.publish_code(&a, "pop1-abcd-efgh-ijkm", CodePlacement::Bio).await.unwrap();
        assert!(mf.public_texts(&a).await.unwrap()[0].contains("pop1-abcd-efgh-ijkm"));
        mf.remove_code(&a, "pop1-abcd-efgh-ijkm").await.unwrap();
        assert!(!mf.public_texts(&a).await.unwrap()[0].contains("pop1"));
        // cannot act for another account
        let b = mf.resolve_account("@bob").await.unwrap();
        assert!(matches!(mf.publish_code(&b, "x", CodePlacement::Bio).await, Err(PlatformError::NoCredentials)));
        assert_eq!(mf.canonical_post_id(&format!("{base}/p/p3")).await.unwrap(), "p3");
    }
}
