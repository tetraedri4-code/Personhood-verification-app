//! Single-operator uniqueness: a keyed hash with versioned keys. The threshold service of the design
//! (`pop-uniqueness`) implements the same [`UniquenessService`] interface; pick one in the issuer
//! configuration (docs/real-servers.md).
use async_trait::async_trait;
use hmac::{Hmac, Mac};
pub use pop_protocol::uniqueness::{identity_input, DedupKey, UniquenessService};
use sha2::{Digest, Sha256};

/// HMAC-SHA256 under one or more keys. The last key is the current one; older keys stay only so that
/// people enrolled under them are still recognised (and migrated) when they log in.
pub struct HmacUniqueness {
    /// (version, key), newest first
    keys: Vec<(String, Vec<u8>)>,
}

/// Version of an HMAC key: a fingerprint, so that a wrong or regenerated key file is noticed.
pub fn hmac_key_version(key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"pop-uniqueness-key-fingerprint-v1");
    h.update(key);
    format!("hmac:{}", hex::encode(&h.finalize()[..8]))
}

impl HmacUniqueness {
    /// `keys` oldest first; the last one is used for new enrolments.
    pub fn new(keys: Vec<Vec<u8>>) -> anyhow::Result<Self> {
        anyhow::ensure!(!keys.is_empty(), "no uniqueness key");
        let mut out: Vec<(String, Vec<u8>)> = vec![];
        for k in keys.into_iter().rev() {
            anyhow::ensure!(k.len() >= 32, "uniqueness key must be at least 32 bytes");
            let v = hmac_key_version(&k);
            if !out.iter().any(|(x, _)| *x == v) {
                out.push((v, k));
            }
        }
        Ok(HmacUniqueness { keys: out })
    }
}

#[async_trait]
impl UniquenessService for HmacUniqueness {
    async fn versions(&self) -> anyhow::Result<Vec<String>> {
        Ok(self.keys.iter().map(|(v, _)| v.clone()).collect())
    }

    async fn dedup_keys(&self, country: u32, subject: &str) -> anyhow::Result<Vec<DedupKey>> {
        let input = format!("pop-dedup-v1|{}", identity_input(country, subject));
        self.keys
            .iter()
            .map(|(v, k)| {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(k)?;
                m.update(input.as_bytes());
                Ok(DedupKey { version: v.clone(), d: hex::encode(m.finalize().into_bytes()) })
            })
            .collect()
    }
}
