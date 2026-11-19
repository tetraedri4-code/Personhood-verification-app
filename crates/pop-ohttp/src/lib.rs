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
