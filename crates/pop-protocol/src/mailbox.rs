//! Likes from a computer without the app (docs/pairing.md).
//!
//! A computer that has no secret, say a library computer, is paired for a period the person chooses.
//! Its browser extension draws nine words from [`words`] and shows them; the person types them into
//! the app on their phone (or writes them down and types them later). From the words both sides derive
//! the same keys ([`PairingKeys`]): a mailbox id, an encryption key and a key that vouches for the end of
//! the period. The computer leaves each like, encrypted, in the mailbox; the app collects it, shows it
//! for approval (or queues it at once, if the person chose that), deletes it from the mailbox, and
//! sends it with its own proof like any other like.
//!
//! The mailbox server sees only the mailbox id, the times of deposits and collections, and padded
//! ciphertexts of equal length. It refuses deposits after the end of the period; the app also ignores
//! anything that arrived later.
//!
//! The words are 9 of 1024 (90 bits), stretched by PBKDF2-HMAC-SHA256 with [`KDF_ITERATIONS`], so a
//! guess costs as much as that many hashes. Every word of the list has its own first four letters,
//! so the app accepts a word from its first four letters and a typo after them does no harm.
use crate::api::ApiError;
use async_trait::async_trait;
use ring::{aead, hkdf, hmac, pbkdf2, rand::SecureRandom};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;

/// The word list: 1024 common English words, sorted, each with its own first four letters (three-letter
/// words are matched whole). The extension carries the same list (`extension/src/words.js`).
pub static WORDS_TXT: &str = include_str!("pairing-words.txt");

pub fn words() -> &'static [&'static str] {
    static W: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    W.get_or_init(|| WORDS_TXT.lines().map(str::trim).filter(|l| !l.is_empty()).collect())
}

/// How many words a pairing has: 9 × 10 bits = 90 bits.
pub const WORD_COUNT: usize = 9;
/// PBKDF2-HMAC-SHA256 iterations: the OWASP Password Storage Cheat Sheet's figure for this hash.
/// About a second in a browser.
pub const KDF_ITERATIONS: u32 = 600_000;
const SALT: &[u8] = b"pop-pairing-v1";
/// Every item is padded to this many bytes before encryption, so that items all have one length.
pub const ITEM_PLAIN_BYTES: usize = 512;
/// The longest pairing the server accepts.
pub const MAX_PERIOD_MS: u64 = 30 * 86_400_000;
/// Items not collected are deleted this long after the end of the period.
pub const KEEP_AFTER_END_MS: u64 = 30 * 86_400_000;
/// Items one mailbox holds at most.
pub const MAX_ITEMS: usize = 256;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum WordsError {
    #[error("{0} words given, {WORD_COUNT} needed")]
    Count(usize),
    #[error("word {0} (\"{1}\") is not on the list")]
    Unknown(usize, String),
}

/// Nine random words, joined by spaces.
pub fn generate() -> String {
    let rng = ring::rand::SystemRandom::new();
    let mut b = [0u8; 2 * WORD_COUNT];
    rng.fill(&mut b).expect("system random");
    // 1024 divides 65536, so the low ten bits are uniform
    b.chunks(2).map(|c| words()[(u16::from_le_bytes([c[0], c[1]]) & 1023) as usize]).collect::<Vec<_>>().join(" ")
}

/// The words as the list spells them. Case, punctuation, and anything after a word's first four letters
/// do not matter; three-letter words must be whole.
pub fn parse(input: &str) -> Result<Vec<&'static str>, WordsError> {
    let toks: Vec<String> = input.split(|c: char| !c.is_ascii_alphabetic()).filter(|t| !t.is_empty()).map(|t| t.to_ascii_lowercase()).collect();
    if toks.len() != WORD_COUNT {
        return Err(WordsError::Count(toks.len()));
    }
    toks.iter()
        .enumerate()
        .map(|(i, t)| {
            let found = if t.len() >= 4 {
                words().iter().find(|w| w.len() >= 4 && w[..4] == t[..4])
            } else {
                words().iter().find(|w| *w == t)
            };
            found.copied().ok_or_else(|| WordsError::Unknown(i + 1, t.clone()))
        })
        .collect()
}

/// The keys both sides derive from the words.
#[derive(Clone)]
pub struct PairingKeys {
    /// the mailbox id, hex: whoever holds it can deposit, list and close, so it travels only in request bodies
    pub mailbox: String,
    enc: [u8; 32],
    auth: [u8; 32],
}

impl std::fmt::Debug for PairingKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingKeys(..)")
    }
}

/// Stored by the holder app, which keeps the keys, not the words.
#[derive(Serialize, Deserialize)]
struct KeysRepr {
    mailbox: String,
    enc: String,
    auth: String,
}

impl Serialize for PairingKeys {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        KeysRepr { mailbox: self.mailbox.clone(), enc: hex::encode(self.enc), auth: hex::encode(self.auth) }.serialize(s)
    }
}

impl<'de> Deserialize<'de> for PairingKeys {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let r = KeysRepr::deserialize(d)?;
        let k32 = |h: &str| -> Result<[u8; 32], D::Error> { hex::decode(h).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| D::Error::custom("key must be 32 bytes of hex")) };
        if !is_mailbox_id(&r.mailbox) {
            return Err(D::Error::custom("bad mailbox id"));
        }
        Ok(PairingKeys { mailbox: r.mailbox, enc: k32(&r.enc)?, auth: k32(&r.auth)? })
    }
}

struct Len32;
impl hkdf::KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

fn expand(prk: &hkdf::Prk, info: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let parts = [info.as_bytes()];
    prk.expand(&parts, Len32).expect("32 bytes").fill(&mut out).expect("32 bytes");
    out
}

impl PairingKeys {
    /// Slow on purpose (about [`KDF_ITERATIONS`] hashes): run it off the async threads.
    pub fn derive(words_input: &str) -> Result<Self, WordsError> {
        let w = parse(words_input)?;
        Ok(Self::derive_canonical(&w.join(" "), KDF_ITERATIONS))
    }

    /// From words already spelled as the list does, with a chosen work factor (tests use fewer).
    pub fn derive_canonical(words: &str, iterations: u32) -> Self {
        let mut seed = [0u8; 32];
        pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, NonZeroU32::new(iterations.max(1)).unwrap(), SALT, words.as_bytes(), &mut seed);
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&seed);
        PairingKeys { mailbox: hex::encode(expand(&prk, "pop-pairing-v1 mailbox")), enc: expand(&prk, "pop-pairing-v1 enc"), auth: expand(&prk, "pop-pairing-v1 auth") }
    }

    /// Vouches for the end of the period: the server stores it and shows it, and cannot move the end
    /// later without the words.
    pub fn end_tag(&self, end_ms: u64) -> String {
        let k = hmac::Key::new(hmac::HMAC_SHA256, &self.auth);
        hex::encode(hmac::sign(&k, format!("end|{end_ms}").as_bytes()).as_ref())
    }

    pub fn check_end_tag(&self, end_ms: u64, tag: &str) -> bool {
        let k = hmac::Key::new(hmac::HMAC_SHA256, &self.auth);
        hex::decode(tag).map(|t| hmac::verify(&k, format!("end|{end_ms}").as_bytes(), &t).is_ok()).unwrap_or(false)
    }

    fn aad(&self) -> Vec<u8> {
        [b"pop-pairing-v1 item|".as_slice(), self.mailbox.as_bytes()].concat()
    }

    /// Encrypt a like. Returns the deposit: the item, and the hash of its deletion code (the code is inside).
    pub fn seal(&self, like: &PairedLike) -> Result<(String, String), String> {
        let mut plain = serde_json::to_vec(like).map_err(|e| e.to_string())?;
        if plain.len() > ITEM_PLAIN_BYTES {
            return Err("like too long".into());
        }
        plain.resize(ITEM_PLAIN_BYTES, b' ');
        let rng = ring::rand::SystemRandom::new();
        let mut n = [0u8; 12];
        rng.fill(&mut n).map_err(|_| "random")?;
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &self.enc).map_err(|_| "key")?);
        key.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key(n), aead::Aad::from(self.aad()), &mut plain).map_err(|_| "seal")?;
        Ok((hex::encode([n.as_slice(), &plain].concat()), deletion_hash(&like.d).ok_or("bad deletion code")?))
    }

    /// Decrypt and check an item.
    pub fn open(&self, item: &str) -> Result<PairedLike, String> {
        let b = hex::decode(item).map_err(|_| "not hex")?;
        if b.len() != 12 + ITEM_PLAIN_BYTES + 16 {
            return Err("wrong item length".into());
        }
        let (n, ct) = b.split_at(12);
        let mut ct = ct.to_vec();
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &self.enc).map_err(|_| "key")?);
        let nonce = aead::Nonce::try_assume_unique_for_key(n).map_err(|_| "nonce")?;
        let plain = key.open_in_place(nonce, aead::Aad::from(self.aad()), &mut ct).map_err(|_| "item does not decrypt with these words")?;
        let like: PairedLike = serde_json::from_slice(plain.trim_ascii_end()).map_err(|e| e.to_string())?;
        like.check()?;
        Ok(like)
    }
}

/// What the paired computer sends: the like, when it was clicked (that computer's clock, shown to the
/// person only), and the code that deletes it from the mailbox.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PairedLike {
    pub platform: String,
    pub post: String,
    pub at: u64,
    /// deletion code, 32 random bytes in hex; the server keeps its SHA-256
    pub d: String,
}

impl PairedLike {
    pub fn new(platform: &str, post: &str, at: u64) -> Self {
        let rng = ring::rand::SystemRandom::new();
        let mut d = [0u8; 32];
        rng.fill(&mut d).expect("system random");
        PairedLike { platform: platform.into(), post: post.into(), at, d: hex::encode(d) }
    }

    pub fn check(&self) -> Result<(), String> {
        let ok_platform = !self.platform.is_empty() && self.platform.len() <= 32 && self.platform.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
        if !ok_platform || self.post.is_empty() || self.post.len() > 256 || self.post.chars().any(char::is_control) || deletion_hash(&self.d).is_none() {
            return Err("malformed like".into());
        }
        Ok(())
    }
}

/// SHA-256 of a deletion code, hex; `None` unless the code is 32 bytes of hex.
pub fn deletion_hash(code: &str) -> Option<String> {
    use sha2::Digest;
    let b = hex::decode(code).ok().filter(|b| b.len() == 32)?;
    Some(hex::encode(sha2::Sha256::digest(&b)))
}

/// Whether a string is a mailbox id: 32 bytes of lowercase hex.
pub fn is_mailbox_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

// ------------------------------------------------------------------ wire

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenRequest {
    pub mailbox: String,
    pub end_ms: u64,
    pub tag: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositRequest {
    pub mailbox: String,
    pub item: String,
    /// [`deletion_hash`] of the code inside the item
    pub dh: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListRequest {
    pub mailbox: String,
    /// only items with a larger number
    #[serde(default)]
    pub after: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredItem {
    pub seq: u64,
    /// when the server received it, by the server's clock
    pub received_ms: u64,
    pub item: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MailboxState {
    /// the end the pairing was opened with, and its [`PairingKeys::end_tag`]
    pub end_ms: u64,
    pub tag: String,
    /// set when either side ended the pairing early
    #[serde(default)]
    pub closed_ms: Option<u64>,
    pub items: Vec<StoredItem>,
}

impl MailboxState {
    /// The end in force: the earlier of the vouched end and an early close.
    pub fn end(&self) -> u64 {
        self.closed_ms.map_or(self.end_ms, |c| c.min(self.end_ms))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub mailbox: String,
    pub codes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloseRequest {
    pub mailbox: String,
}

/// The mailbox server, as the holder app uses it. `pop-mailbox` serves it; [`crate::http::HttpClient`]
/// implements it under `/v1/mailbox/`.
#[async_trait]
pub trait MailboxApi: Send + Sync {
    async fn open(&self, req: &OpenRequest) -> Result<(), ApiError>;
    async fn deposit(&self, req: &DepositRequest) -> Result<u64, ApiError>;
    async fn list(&self, req: &ListRequest) -> Result<MailboxState, ApiError>;
    async fn delete(&self, req: &DeleteRequest) -> Result<u64, ApiError>;
    async fn close(&self, req: &CloseRequest) -> Result<(), ApiError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_has_1024_distinct_prefixes() {
        let w = words();
        assert_eq!(w.len(), 1024);
        let mut p: Vec<&str> = w.iter().map(|x| &x[..x.len().min(4)]).collect();
        p.sort();
        p.dedup();
        assert_eq!(p.len(), 1024);
        // a three-letter word is not the start of another word
        for s in w.iter().filter(|x| x.len() == 3) {
            assert_eq!(w.iter().filter(|x| x.starts_with(*s)).count(), 1, "{s}");
        }
        assert!(w.iter().all(|x| x.bytes().all(|c| c.is_ascii_lowercase())));
    }

    #[test]
    fn extension_carries_the_same_list() {
        let js = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../extension/src/words.js")).unwrap();
        let start = js.find('`').unwrap();
        let end = js.rfind('`').unwrap();
        let theirs: Vec<&str> = js[start + 1..end].split_whitespace().collect();
        assert_eq!(theirs, words());
    }

    #[test]
    fn parse_forgives_case_and_typos_after_four_letters() {
        let g = generate();
        assert_eq!(parse(&g).unwrap().join(" "), g);
        let typed = "ACORX, zoo-ZEBRAA able anvil ink jazz koala lynx";
        assert_eq!(parse(typed).unwrap(), vec!["acorn", "zoo", "zebra", "able", "anvil", "ink", "jazz", "koala", "lynx"]);
        assert_eq!(parse("able able"), Err(WordsError::Count(2)));
        assert_eq!(parse("able able able able able able able able qqqq"), Err(WordsError::Unknown(9, "qqqq".into())));
        assert_eq!(parse("able able able able able able able able in"), Err(WordsError::Unknown(9, "in".into())));
    }

    #[test]
    fn seal_open_and_tag() {
        let k = PairingKeys::derive_canonical("able acid acorn actor adapt admit adult advice aerial", 10);
        let like = PairedLike::new("mockfeed", "post-1", 5);
        let (item, dh) = k.seal(&like).unwrap();
        assert_eq!(item.len(), 2 * (12 + ITEM_PLAIN_BYTES + 16));
        assert_eq!(deletion_hash(&like.d).unwrap(), dh);
        assert_eq!(k.open(&item).unwrap(), like);
        let other = PairingKeys::derive_canonical("able acid acorn actor adapt admit adult advice zoo", 10);
        assert!(other.open(&item).is_err());
        assert_ne!(other.mailbox, k.mailbox);
        assert!(k.check_end_tag(123, &k.end_tag(123)));
        assert!(!k.check_end_tag(124, &k.end_tag(123)));
        assert!(!other.check_end_tag(123, &k.end_tag(123)));
        let back: PairingKeys = serde_json::from_value(serde_json::to_value(&k).unwrap()).unwrap();
        assert_eq!(back.open(&item).unwrap(), like);
        // a flipped bit is refused
        let mut b = hex::decode(&item).unwrap();
        b[40] ^= 1;
        assert!(k.open(&hex::encode(b)).is_err());
    }

    /// Fixed vector, also computed with Python's hashlib/hmac and checked by the extension's test (extension/test/pairing.mjs).
    #[test]
    fn known_answer() {
        let k = PairingKeys::derive_canonical("able acid acorn actor adapt admit adult advice aerial", 1000);
        assert_eq!(k.mailbox, KAT_MAILBOX);
        assert_eq!(k.end_tag(1_700_000_000_000), KAT_TAG);
    }

    /// An item sealed by the extension's pairing.js (printed by `node extension/test/pairing.mjs --print`).
    #[test]
    fn opens_an_item_sealed_by_the_extension() {
        let k = PairingKeys::derive_canonical("able acid acorn actor adapt admit adult advice aerial", 1000);
        let like = k.open(JS_ITEM).unwrap();
        assert_eq!((like.platform.as_str(), like.post.as_str(), like.at), ("mockfeed", "p1", 5));
        assert_eq!(deletion_hash(&like.d).unwrap(), JS_DH);
    }

    const JS_ITEM: &str = "3f4df2606f48aa90f6935c6f485edbee648b150ffffd2537fcad01415d2e8f4f291224f382fa5549205bf64bbc90875232c154cd380dba1f22ca4b3dcae5bbec3145156d3057a6425b6cce2f59f01b3ff57e792935b6cbde0a22d22c3181feb2349c89be03bf40a9ebcfefdda85cbb79c4d2db5920e5ca63dfdc92003134a103e2e4fca97e9f8a2a2584c7ba38c1c24db25df252071b115e47e8f114119ba256a95c64b9b74b1192bf87d269944ad5f1edd9e20c16a20bfc45a7dea54e74e046057685d8258e6efdc2fed24f76f6412d47dd9c12e5906827781cc6dbb8714990923062ec9fabc27026bba67d6556b40fe313d6d6bb0440ccf0bc1a0ce6811092abe58a890a7129706178fa05fb2f6c4ff55ed71bb495f07bd25248b5e43e6087b48244e6b8f1ee660d7abf0e3a2c2ce7b78559c81d00953f8e94284e357652e65027ed1bd800fa91818eb55a628de22e1b75bc19d2d3a31659adc9f622948bbb56d3f8b6f7508c466fe9c4d0e5368aee7e35ba63afc8ffe0b973f8d9407f23a8ab870894556be3a56d12e3a03dda1dea1e89faa21f6ad4d4a18e4b31aea4e584d644a5583e40046fc2619afbb3ffe339aa430a6cc16d9e6b0fec7b9b015bef70a9360b4e15686c24fec349006c1cc5e977306562809692d811d5764d4b56cd9300bfa2f015454767271903fed8020fb11cfb26e5e2a6e2280a4a0001019f2f27a0c7bffb871b821b47393576ed97466a20f8d89c91f8255ce280dad4";
    const JS_DH: &str = "26ef80522142d9940007103fa97b060532e084c2e3b136079790f44303a178a8";
    const KAT_MAILBOX: &str = "4784938d8f14ee5b1471c245314ccd36d99b7afd135acf635dcd9ea3e4069b5d";
    const KAT_TAG: &str = "aff17ae9d7f65f8495c3bd427d48b6bc8385ae04ec4de1489f2c81e835e2b909";
}
