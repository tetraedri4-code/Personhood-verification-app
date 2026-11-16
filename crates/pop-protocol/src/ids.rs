//! Identifiers shared by all parts.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Context id P of a platform (design §4.4). In the voluntary app the operator names contexts itself,
/// one per platform, in a public list; there is no platform registration.
pub fn context_id(platform: &str) -> String {
    format!("pop:ctx:v1:{platform}")
}

/// An account on a platform. `account_id` must be stable for the account's lifetime (a Bluesky DID,
/// a numeric user id), `handle` is what people see and may change.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AccountRef {
    pub platform: String,
    pub account_id: String,
    pub handle: String,
}

/// The bytes a binding proof is bound to: platform, stable account id and a nonce. They enter the proof's
/// Fiat–Shamir challenge, so a proof cannot be reused for another account (design §4.5).
pub fn binding_context(platform: &str, account_id: &str, nonce: &str) -> Vec<u8> {
    format!("pop-bind-v1|{platform}|{account_id}|{nonce}").into_bytes()
}

/// Bytes for withdrawing a badge from an account.
pub fn withdraw_context(platform: &str, account_id: &str, nonce: &str) -> Vec<u8> {
    format!("pop-withdraw-v1|{platform}|{account_id}|{nonce}").into_bytes()
}

const B32: &[u8; 32] = b"abcdefghijkmnpqrstuvwxyz23456789";

/// The short code a holder shows in the account's bio or in a post, Keybase-style. It commits to the
/// platform, the account and the pseudonym, so it points at exactly one directory entry:
/// `pop1-xxxx-xxxx-xxxx` (60 bits, lower-case base32 without look-alike characters).
pub fn binding_code(platform: &str, account_id: &str, nym_hex: &str) -> String {
    let d = Sha256::digest(format!("pop-code-v1|{platform}|{account_id}|{nym_hex}").as_bytes());
    let mut bits: u64 = 0;
    for b in &d[..8] {
        bits = bits << 8 | *b as u64;
    }
    let chars: String = (0..12).map(|i| B32[((bits >> (59 - 5 * i)) & 31) as usize] as char).collect();
    format!("pop1-{}-{}-{}", &chars[0..4], &chars[4..8], &chars[8..12])
}

/// Find binding codes in free text (a bio or a post).
pub fn find_codes(text: &str) -> Vec<String> {
    let mut out = vec![];
    let lower = text.to_lowercase();
    let mut rest = lower.as_str();
    while let Some(i) = rest.find("pop1-") {
        let cand: String = rest[i..].chars().take(19).collect();
        if is_code(&cand) {
            out.push(cand);
        }
        rest = &rest[i + 5..];
    }
    out
}

pub fn is_code(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 19
        && s.starts_with("pop1-")
        && b[9] == b'-'
        && b[14] == b'-'
        && [5..9, 10..14, 15..19].iter().all(|r| b[r.clone()].iter().all(|c| B32.contains(c)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codes() {
        let c = binding_code("bluesky", "did:plc:abc", "00ff");
        assert!(is_code(&c), "{c}");
        assert_eq!(find_codes(&format!("Hello! Human here {c}. bye")), vec![c.clone()]);
        assert_ne!(c, binding_code("bluesky", "did:plc:abd", "00ff"));
        assert!(find_codes("pop1-xxxx").is_empty());
    }
}
