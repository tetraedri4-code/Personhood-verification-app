//! The uniqueness interface (design §4.2): the issuer learns a deduplication key d for a verified
//! identity and nothing else is kept. It lives in this crate so that the issuer and every
//! implementation (the single-operator keyed hash in `pop-issuer`, the threshold service in
//! `pop-uniqueness`) depend on the interface and not on each other.
//!
//! Keys are versioned. A deduplication key is only comparable with records made under the same key, so
//! every enrolment record carries the version it was made under, and a service that holds several keys
//! returns d under each of them. The issuer looks a person up under every live version and moves the
//! record to the newest one when it finds an older match.
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DedupKey {
    /// which key produced `d`; opaque to the issuer, stable for the life of the key
    pub version: String,
    pub d: String,
}

#[async_trait]
pub trait UniquenessService: Send + Sync {
    /// The key versions this service can evaluate, newest first. Must not be empty. The issuer refuses
    /// to start if it holds records under a version that is not listed.
    async fn versions(&self) -> anyhow::Result<Vec<String>>;

    /// d = F_K(country, lifelong identifier) under every version of [`Self::versions`], in the same
    /// order. Deterministic per person and key; unpredictable without the key. An implementation that
    /// cannot evaluate one of its versions must fail, not leave it out: a missing answer would let an
    /// enrolled person through as new.
    async fn dedup_keys(&self, country: u32, subject: &str) -> anyhow::Result<Vec<DedupKey>>;
}

/// The byte string every implementation feeds to its keyed function. Identity codes are
/// case-insensitive and may carry spaces; both are normalised away so one person gives one input.
pub fn identity_input(country: u32, subject: &str) -> String {
    let subject: String = subject.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase();
    format!("{country}|{subject}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalised() {
        assert_eq!(identity_input(246, " 010190-123a "), identity_input(246, "010190-123A"));
        assert_ne!(identity_input(246, "X"), identity_input(233, "X"));
    }
}
