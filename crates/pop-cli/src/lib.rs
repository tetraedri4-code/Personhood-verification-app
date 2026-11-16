//! Wiring. This is the only crate that knows every part; it builds them and hands each one the
//! interfaces it needs. Used by the `pop` binary and by the end-to-end tests.
pub mod devnet;
pub mod wiring;
