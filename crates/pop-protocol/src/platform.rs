//! The interface a social platform adapter implements. The holder app and the directory use only this
//! trait; each adapter lives in its own crate (`pop-platform-mockfeed`, `pop-platform-bluesky`) and
//! depends on nothing but this crate. See docs/adding-a-platform.md.
use crate::AccountRef;
use async_trait::async_trait;

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("account not found: {0}")]
    NotFound(String),
    #[error("this adapter has no credentials to act for the account; publish the code by hand")]
    NoCredentials,
    #[error("not supported by this platform: {0}")]
    Unsupported(&'static str),
    #[error("platform request failed: {0}")]
    Http(String),
}

/// Where the holder shows the binding code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CodePlacement {
    Bio,
    Post,
}

#[async_trait]
pub trait Platform: Send + Sync {
    /// Short machine id, used in context ids and URLs: "mockfeed", "bluesky".
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;

    /// Turn what a person types (a handle, a profile URL) into a stable account reference.
    async fn resolve_account(&self, handle_or_url: &str) -> Result<AccountRef, PlatformError>;

    /// Show the code in the account's bio or in a new post. Needs credentials the person gave the adapter
    /// (e.g. a Bluesky app password). Adapters without credentials return `NoCredentials` and the holder
    /// app asks the person to paste the code by hand.
    async fn publish_code(&self, account: &AccountRef, code: &str, placement: CodePlacement) -> Result<(), PlatformError>;

    /// Remove a previously published code from the bio (posts are left alone).
    async fn remove_code(&self, account: &AccountRef, code: &str) -> Result<(), PlatformError>;

    /// Public text where a code may appear (bio, and recent posts if the platform exposes them), read
    /// through an official public interface. `Unsupported` on closed platforms, where only viewers'
    /// extensions check codes in the page they are shown.
    async fn public_texts(&self, account: &AccountRef) -> Result<Vec<String>, PlatformError>;

    /// Canonical id of a post from what the extension or the person supplies (URL or native id), so that
    /// every viewer computes the same like tag for the same post.
    async fn canonical_post_id(&self, raw: &str) -> Result<String, PlatformError>;
}

/// Platforms known to a process, by id.
#[derive(Default, Clone)]
pub struct PlatformRegistry {
    items: Vec<std::sync::Arc<dyn Platform>>,
}

impl PlatformRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with(mut self, p: std::sync::Arc<dyn Platform>) -> Self {
        self.items.retain(|q| q.id() != p.id());
        self.items.push(p);
        self
    }
    pub fn get(&self, id: &str) -> Option<std::sync::Arc<dyn Platform>> {
        self.items.iter().find(|p| p.id() == id).cloned()
    }
    pub fn ids(&self) -> Vec<&'static str> {
        self.items.iter().map(|p| p.id()).collect()
    }
}
