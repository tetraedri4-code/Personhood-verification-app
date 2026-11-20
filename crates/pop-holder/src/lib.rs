//! # pop-holder
//!
//! The app on the person's device (the design's "component"). It generates and keeps the secret, and
//! is the only part that ever sees it.
//!
//! The holder is written against four interfaces and nothing else:
//!
//! | Interface | From | Shipped implementations |
//! |---|---|---|
//! | [`IssuerApi`](pop_protocol::api::IssuerApi) | `pop-protocol` | HTTP client; in tests, any mock |
//! | [`DirectoryApi`](pop_protocol::api::DirectoryApi) | `pop-protocol` | HTTP client |
//! | [`Platform`](pop_protocol::platform::Platform) | `pop-protocol` | mock feed, Bluesky |
//! | [`WalletStore`] | this crate | JSON file, memory |
//!
//! It never talks to an identity provider: it only opens the URL the issuer hands it.
//!
//! [`local_api`] exposes a small HTTP API on 127.0.0.1 for the browser extension.
pub mod help;
pub mod holder;
pub mod local_api;
pub mod paired;
pub mod recovery;
pub mod wallet;

pub use holder::{BindOutcome, Holder, HolderError, Status, RESET_EID_HELP, RESET_EID_PATH};
pub use paired::{Approved, PairingInfo};
pub use recovery::ReplaceOutcome;
pub use wallet::{FileWallet, MemoryWallet, WalletStore};
