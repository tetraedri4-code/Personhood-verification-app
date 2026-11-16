//! Deduplication key d (design §4.2). The design computes d with a threshold OPRF whose key is shared
//! among independent operators. This prototype has one operator and a keyed hash; the trait is the seam
//! where a threshold service plugs in (docs/real-servers.md).
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use pop_idp::VerifiedIdentity;
use sha2::Sha256;

#[async_trait]
pub trait UniquenessService: Send + Sync {
    /// d = F_K(country, lifelong identifier). Must be deterministic per person and unpredictable
    /// without the key.
    async fn dedup_key(&self, id: &VerifiedIdentity) -> anyhow::Result<String>;
}

pub struct HmacUniqueness {
    key: Vec<u8>,
}

impl HmacUniqueness {
    pub fn new(key: Vec<u8>) -> Self {
        assert!(key.len() >= 32, "uniqueness key must be at least 32 bytes");
        HmacUniqueness { key }
    }
}

#[async_trait]
impl UniquenessService for HmacUniqueness {
    async fn dedup_key(&self, id: &VerifiedIdentity) -> anyhow::Result<String> {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&self.key)?;
        // normalise: identity codes are case-insensitive and may carry spaces
        let subject: String = id.subject.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase();
        m.update(format!("pop-dedup-v1|{}|{}", id.country, subject).as_bytes());
        Ok(hex::encode(m.finalize().into_bytes()))
    }
}
