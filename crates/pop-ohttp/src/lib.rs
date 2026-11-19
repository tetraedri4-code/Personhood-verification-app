//! Oblivious HTTP (RFC 9458) for the prototype's servers.
//!
//! A request goes from the client, encrypted to the server's gateway key, through a relay run by someone
//! else. The relay sees who sends it but not what it says; the server sees what it says but only the
//! relay's address. Neither alone can tie a like or a claim to an internet address.
//!
//! * [`gateway`]: put in front of any axum service, unchanged: it adds `POST /ohttp` (an encrypted
//!   request, answered by the service's own routes) and `GET /ohttp/keys` (the gateway's key).
//! * [`relay`]: forwards encrypted requests to the gateways it is set up for, with nothing of the
//!   sender's (no address, no headers). A hosted relay that speaks RFC 9458 can replace it.
//! * [`Oblivious`]: a [`pop_protocol::http::Transport`], so any client of the protocol can send its
//!   requests through a relay.
//!
//! Suite: X25519, HKDF-SHA256, AES-128-GCM (the one RFC 9458's example uses); messages are known-length
//! binary HTTP (RFC 9292).
pub mod gateway;
pub mod relay;
mod client;

pub use client::Oblivious;

pub const REQ_TYPE: &str = "message/ohttp-req";
pub const RES_TYPE: &str = "message/ohttp-res";
pub const KEYS_TYPE: &str = "application/ohttp-keys";
/// The body of the gateway's answer to a request it cannot decrypt: the client fetches the key again
/// and retries once (the request never reached the service).
pub const BAD_KEY: &str = "ohttp: cannot decrypt (key changed?)";

/// Size classes a message is padded to with zero bytes (RFC 9292 allows padding at the end): the
/// smallest class that fits, or beyond the largest a multiple of it. Encryption hides content, not
/// length: without padding the relay could tell a like report from a download by size, or match an
/// answer to a public bucket of counts by its length. Every message of one class looks the same.
///
/// The issuer sets the classes (`policy.pad_sizes`); the gateways pad answers with them and tell
/// clients in the header [`PAD_HEADER`] of every answer, and clients pad requests with the classes of
/// the last answer (the defaults until then).
pub const DEFAULT_PAD_SIZES: [u32; 6] = [1024, 4096, 16384, 65536, 262144, 1048576];
/// Inside an encrypted answer: the size classes, comma-separated.
pub const PAD_HEADER: &str = "pop-pad-sizes";

/// Check a list of size classes: 1 to 16 classes, strictly increasing, each from 256 bytes to 16 MiB.
pub fn check_pad_sizes(s: &[u32]) -> Result<(), String> {
    if s.is_empty() || s.len() > 16 || s.windows(2).any(|w| w[0] >= w[1]) || s.iter().any(|&n| !(256..=16 << 20).contains(&n)) {
        return Err("pad sizes: 1 to 16 increasing sizes, each from 256 bytes to 16 MiB".into());
    }
    Ok(())
}

pub fn pad(m: &mut Vec<u8>, sizes: &[u32]) {
    let sizes: &[u32] = if check_pad_sizes(sizes).is_ok() { sizes } else { &DEFAULT_PAD_SIZES };
    let target = match sizes.iter().find(|&&s| s as usize >= m.len()) {
        Some(&s) => s as usize,
        None => {
            let top = *sizes.last().unwrap() as usize;
            m.len().div_ceil(top) * top
        }
    };
    m.resize(target, 0);
}

pub(crate) fn parse_pad_sizes(v: &[u8]) -> Option<Vec<u32>> {
    let s: Vec<u32> = std::str::from_utf8(v).ok()?.split(',').map(|x| x.trim().parse().ok()).collect::<Option<_>>()?;
    check_pad_sizes(&s).ok()?;
    Some(s)
}
