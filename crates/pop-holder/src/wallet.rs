//! Where the holder keeps its state. The prototype writes a JSON file readable only by the user.
//! A real app implements [`WalletStore`] with the secret wrapped by a non-exportable hardware key
//! (Android Keystore, iOS Secure Enclave; design §4.8).
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WalletState {
    /// `pop_crypto::Credential::to_json`
    pub credential: Option<serde_json::Value>,
    /// Ed25519 guardian key, PKCS#8, hex
    pub guardian_pkcs8: Option<String>,
    /// enrolment in progress: (session, holder secrets as hex rho, s, delta)
    pub pending: Option<PendingEnrolment>,
    pub bindings: Vec<LocalBinding>,
    /// posts this person reported a like for: "platform|post"
    pub liked: Vec<String>,
    /// likes waiting for their random wait to end before they are proved and sent: "platform|post"
    #[serde(default)]
    pub queued_likes: Vec<String>,
    /// keys of the encrypted backup, derived from the paper code (the code itself is not kept)
    #[serde(default)]
    pub backup: Option<BackupKeys>,
    /// one-time ticket from the issuer for creating a backup
    #[serde(default)]
    pub backup_ticket: Option<String>,
    /// a replacement of the secret that waits for its veto period to pass
    #[serde(default)]
    pub claim: Option<PendingClaim>,
    /// computers paired to leave likes in a mailbox (crate::paired)
    #[serde(default)]
    pub pairings: Vec<Pairing>,
    /// likes collected from paired computers, waiting for the person's approval
    #[serde(default)]
    pub inbox: Vec<InboxLike>,
    #[serde(default)]
    pub next_inbox_id: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pairing {
    pub name: String,
    pub keys: pop_protocol::mailbox::PairingKeys,
    /// the end in force (Unix ms): the vouched end, or an earlier close
    pub end_ms: u64,
    /// queue collected likes at once instead of asking first
    pub auto: bool,
    /// the last item number collected
    pub after: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct InboxLike {
    pub id: u64,
    /// the pairing it came from
    pub from: String,
    pub platform: String,
    pub post: String,
    /// when it was clicked, by the paired computer's clock
    pub clicked_ms: u64,
    /// why it was not queued at once, when automatic sending failed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupKeys {
    pub id: String,
    pub write_key: String,
    pub enc_key: String,
}

/// The new secret of a replacement that is not issued yet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingClaim {
    pub claim_token: String,
    pub rho: String,
    pub s: String,
    pub delta: u64,
    pub guardian_pkcs8: String,
    pub claim_after: u32,
    pub claim_before: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingEnrolment {
    pub session: String,
    pub rho: String,
    pub s: String,
    pub delta: u64,
    /// what the login is for (enrolment, re-check, replacement)
    #[serde(default)]
    pub purpose: pop_protocol::api::Purpose,
    /// replacement only: the new guardian key, saved before the issuer hears of it
    #[serde(default)]
    pub new_guardian_pkcs8: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LocalBinding {
    pub platform: String,
    pub account_id: String,
    pub handle: String,
    pub slot: u32,
    pub code: String,
    pub lease_until: u32,
}

pub trait WalletStore: Send + Sync {
    fn load(&self) -> std::io::Result<WalletState>;
    fn save(&self, state: &WalletState) -> std::io::Result<()>;
    /// Cache for public data (proving keys). Returns None if absent.
    fn cache_get(&self, name: &str) -> Option<Vec<u8>>;
    fn cache_put(&self, name: &str, data: &[u8]);
}

#[derive(Default)]
pub struct MemoryWallet {
    state: Mutex<WalletState>,
    cache: Mutex<std::collections::HashMap<String, Vec<u8>>>,
}

impl WalletStore for MemoryWallet {
    fn load(&self) -> std::io::Result<WalletState> {
        Ok(self.state.lock().unwrap().clone())
    }
    fn save(&self, state: &WalletState) -> std::io::Result<()> {
        *self.state.lock().unwrap() = state.clone();
        Ok(())
    }
    fn cache_get(&self, name: &str) -> Option<Vec<u8>> {
        self.cache.lock().unwrap().get(name).cloned()
    }
    fn cache_put(&self, name: &str, data: &[u8]) {
        self.cache.lock().unwrap().insert(name.into(), data.to_vec());
    }
}

pub struct FileWallet {
    dir: PathBuf,
}

impl FileWallet {
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(dir.join("cache"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(FileWallet { dir })
    }
    fn path(&self) -> PathBuf {
        self.dir.join("wallet.json")
    }
}

impl WalletStore for FileWallet {
    fn load(&self) -> std::io::Result<WalletState> {
        match std::fs::read(self.path()) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(WalletState::default()),
            Err(e) => Err(e),
        }
    }
    fn save(&self, state: &WalletState) -> std::io::Result<()> {
        let tmp = self.dir.join(".wallet.json.tmp");
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            use std::io::Write;
            opts.open(&tmp)?.write_all(&serde_json::to_vec_pretty(state).unwrap())?;
        }
        std::fs::rename(tmp, self.path())
    }
    fn cache_get(&self, name: &str) -> Option<Vec<u8>> {
        std::fs::read(self.dir.join("cache").join(name)).ok()
    }
    fn cache_put(&self, name: &str, data: &[u8]) {
        let _ = std::fs::write(self.dir.join("cache").join(name), data);
    }
}
