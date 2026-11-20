//! Likes from a computer without the app (`pop_protocol::mailbox`, docs/pairing.md).
//!
//! The person pairs a computer for a period they choose: its browser extension shows nine words, and
//! the person gives them to this app ([`Holder::pair`]), at once or later from paper. The app then
//! collects the computer's likes from the mailbox every few minutes ([`Holder::collect_pairings`]).
//! A collected like waits in the inbox until the person approves it ([`Holder::approve`]); a pairing
//! made with `auto` queues its likes at once instead. Approved likes go through the usual schedule and
//! proof ([`Holder::like_later`]): the paired computer never holds the secret.
//!
//! When the period is over (or either side ends it early), the app collects what arrived before the end
//! and forgets the pairing. Anything the server reports as arriving after the end is dropped.
use crate::holder::{Holder, HolderError};
use crate::wallet::{InboxLike, Pairing};
use pop_protocol::api::ApiError;
use pop_protocol::mailbox::*;
use serde::Serialize;
use std::sync::Arc;

type Result<T> = std::result::Result<T, HolderError>;

/// How often the mailboxes are collected (plus up to a minute at random).
pub const COLLECT_EVERY: std::time::Duration = std::time::Duration::from_secs(180);
/// A pairing is forgotten this long after its end, so that a deposit the server accepted just before
/// its end, by a clock a little behind this app's, is still collected.
const END_MARGIN_MS: u64 = 300_000;
/// Likes the inbox holds at most; more are dropped (and logged) until the person approves or rejects some.
pub const MAX_INBOX: usize = 1000;

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct PairingInfo {
    pub name: String,
    pub end_ms: u64,
    pub ended: bool,
    pub auto: bool,
}

impl PairingInfo {
    fn of(p: &Pairing, now: u64) -> Self {
        PairingInfo { name: p.name.clone(), end_ms: p.end_ms, ended: now > p.end_ms, auto: p.auto }
    }
}

/// What approving did with each like.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Approved {
    pub id: u64,
    pub queued: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn perr(m: impl Into<String>) -> HolderError {
    HolderError::Pairing(m.into())
}

fn check_name(n: &str) -> Result<()> {
    if n.trim().is_empty() || n.chars().count() > 40 || n.chars().any(char::is_control) {
        return Err(perr("a name has 1 to 40 characters"));
    }
    Ok(())
}

impl Holder {
    fn mailbox_api(&self) -> Result<Arc<dyn MailboxApi>> {
        self.mailbox.clone().ok_or_else(|| perr("no mailbox server is set up for this app"))
    }

    /// Pair a computer from the words it shows. `name` tells pairings apart (default "computer N").
    /// Works after the end of the period too: the likes left before the end are collected once.
    pub async fn pair(self: &Arc<Self>, words: &str, name: Option<&str>, auto: bool) -> Result<PairingInfo> {
        let mb = self.mailbox_api()?;
        let w = words.to_string();
        let keys = tokio::task::spawn_blocking(move || PairingKeys::derive(&w)).await.map_err(|e| HolderError::Internal(e.to_string()))?.map_err(|e| perr(e.to_string()))?;
        let st = match mb.list(&ListRequest { mailbox: keys.mailbox.clone(), after: 0 }).await {
            Ok(st) => st,
            Err(ApiError::Server { status: 404, .. }) => return Err(perr("no pairing has these words: check them, or pair the computer again")),
            Err(e) => return Err(e.into()),
        };
        if !keys.check_end_tag(st.end_ms, &st.tag) {
            return Err(perr("the server shows an end time the paired computer did not set"));
        }
        let info = {
            let _g = self.busy.lock().await;
            let mut s = self.wallet.load()?;
            if s.pairings.iter().any(|p| p.keys.mailbox == keys.mailbox) {
                return Err(perr("this computer is already paired"));
            }
            let name = match name {
                Some(n) => {
                    check_name(n)?;
                    n.trim().to_string()
                }
                None => (1..).map(|i| format!("computer {i}")).find(|n| !s.pairings.iter().any(|p| &p.name == n)).unwrap(),
            };
            if s.pairings.iter().any(|p| p.name == name) {
                return Err(perr(format!("a pairing named \"{name}\" exists")));
            }
            let p = Pairing { name, keys, end_ms: st.end(), auto, after: 0 };
            let info = PairingInfo::of(&p, self.clock.now_ms());
            s.pairings.push(p);
            self.wallet.save(&s)?;
            info
        };
        self.collect_pairings().await?;
        Ok(info)
    }

    pub fn pairings(&self) -> Result<Vec<PairingInfo>> {
        let now = self.clock.now_ms();
        Ok(self.wallet.load()?.pairings.iter().map(|p| PairingInfo::of(p, now)).collect())
    }

    pub async fn set_auto(&self, name: &str, auto: bool) -> Result<()> {
        let _g = self.busy.lock().await;
        let mut s = self.wallet.load()?;
        s.pairings.iter_mut().find(|p| p.name == name).ok_or_else(|| perr(format!("no pairing named \"{name}\"")))?.auto = auto;
        self.wallet.save(&s)?;
        Ok(())
    }

    /// End a pairing now: collect what is there, close the mailbox so that the computer can leave no
    /// more, and forget the keys. If the server cannot be reached the pairing is kept, so that it can be
    /// ended again later; it ends by itself at its end time anyway.
    pub async fn unpair(self: &Arc<Self>, name: &str) -> Result<()> {
        let mb = self.mailbox_api()?;
        let keys = self.wallet.load()?.pairings.iter().find(|p| p.name == name).map(|p| p.keys.clone()).ok_or_else(|| perr(format!("no pairing named \"{name}\"")))?;
        if let Err(e) = self.collect_pairings().await {
            tracing::warn!("collecting before unpairing: {e}");
        }
        match mb.close(&CloseRequest { mailbox: keys.mailbox.clone() }).await {
            Ok(()) | Err(ApiError::Server { status: 404, .. }) => {}
            Err(e) => return Err(e.into()),
        }
        let _g = self.busy.lock().await;
        let mut s = self.wallet.load()?;
        s.pairings.retain(|p| p.keys.mailbox != keys.mailbox);
        self.wallet.save(&s)?;
        Ok(())
    }

    /// Collect every pairing's mailbox once. Returns how many likes arrived (in the inbox, or queued for
    /// pairings with `auto`).
    pub async fn collect_pairings(self: &Arc<Self>) -> Result<usize> {
        let Some(mb) = self.mailbox.clone() else { return Ok(0) };
        let _c = self.collecting.lock().await;
        let pairings = self.wallet.load()?.pairings;
        struct Got {
            mailbox: String,
            after: u64,
            end_ms: u64,
            done: bool,
            likes: Vec<PairedLike>,
            codes: Vec<String>,
            auto: bool,
            name: String,
        }
        let mut got = vec![];
        for p in &pairings {
            let st = match mb.list(&ListRequest { mailbox: p.keys.mailbox.clone(), after: p.after }).await {
                Ok(st) => st,
                // kept no longer than KEEP_AFTER_END_MS: nothing more to collect
                Err(ApiError::Server { status: 404, .. }) => {
                    got.push(Got { mailbox: p.keys.mailbox.clone(), after: p.after, end_ms: p.end_ms, done: true, likes: vec![], codes: vec![], auto: p.auto, name: p.name.clone() });
                    continue;
                }
                Err(e) => {
                    tracing::warn!("mailbox of {} not collected: {e}", p.name);
                    continue;
                }
            };
            // the end only moves earlier (a close); a later one would need the words
            let end_ms = if p.keys.check_end_tag(st.end_ms, &st.tag) { st.end().min(p.end_ms) } else { p.end_ms };
            let mut g = Got { mailbox: p.keys.mailbox.clone(), after: p.after, end_ms, done: false, likes: vec![], codes: vec![], auto: p.auto, name: p.name.clone() };
            for it in st.items {
                if it.seq <= p.after {
                    continue;
                }
                g.after = g.after.max(it.seq);
                match p.keys.open(&it.item) {
                    Ok(like) => {
                        g.codes.push(like.d.clone());
                        if it.received_ms <= end_ms {
                            g.likes.push(like);
                        } else {
                            tracing::warn!("a like for {} arrived after the end of the pairing; dropped", p.name);
                        }
                    }
                    // not made with these words: it stays until the server deletes it
                    Err(e) => tracing::warn!("an item in the mailbox of {} is not readable: {e}", p.name),
                }
            }
            // listed after the end (with a margin for the server's clock): nothing more can arrive
            g.done = self.clock.now_ms() > end_ms.saturating_add(END_MARGIN_MS);
            got.push(g);
        }

        let mut n = 0;
        let mut auto = vec![];
        {
            let _g = self.busy.lock().await;
            let mut s = self.wallet.load()?;
            for g in &got {
                if let Some(p) = s.pairings.iter_mut().find(|p| p.keys.mailbox == g.mailbox) {
                    p.after = g.after;
                    p.end_ms = g.end_ms;
                }
                for like in &g.likes {
                    n += 1;
                    if g.auto {
                        auto.push((g.name.clone(), like.clone()));
                    } else if s.inbox.len() < MAX_INBOX {
                        s.next_inbox_id += 1;
                        s.inbox.push(InboxLike { id: s.next_inbox_id, from: g.name.clone(), platform: like.platform.clone(), post: like.post.clone(), clicked_ms: like.at, note: None });
                    } else {
                        tracing::warn!("the inbox is full; a like from {} was dropped", g.name);
                    }
                }
            }
            s.pairings.retain(|p| !got.iter().any(|g| g.done && g.mailbox == p.keys.mailbox));
            self.wallet.save(&s)?;
        }
        // saved first: a like is never lost between collecting and deleting, and `after` keeps it from
        // being collected twice
        for g in &got {
            if !g.codes.is_empty() {
                if let Err(e) = mb.delete(&DeleteRequest { mailbox: g.mailbox.clone(), codes: g.codes.clone() }).await {
                    tracing::warn!("collected likes not deleted from the mailbox of {}: {e}", g.name);
                }
            }
        }
        for (from, like) in auto {
            if let Err(e) = self.like_later(&like.platform, &like.post).await {
                // not lost: it waits in the inbox with the reason
                let _g = self.busy.lock().await;
                let mut s = self.wallet.load()?;
                if s.inbox.len() < MAX_INBOX {
                    s.next_inbox_id += 1;
                    s.inbox.push(InboxLike { id: s.next_inbox_id, from, platform: like.platform, post: like.post, clicked_ms: like.at, note: Some(e.to_string()) });
                    self.wallet.save(&s)?;
                }
            }
        }
        Ok(n)
    }

    /// Likes waiting for approval, oldest first.
    pub fn inbox(&self) -> Result<Vec<InboxLike>> {
        Ok(self.wallet.load()?.inbox)
    }

    /// Queue these likes (by inbox id). A like that cannot be queued stays in the inbox with the reason.
    pub async fn approve(self: &Arc<Self>, ids: &[u64]) -> Result<Vec<Approved>> {
        let items: Vec<InboxLike> = self.wallet.load()?.inbox.into_iter().filter(|i| ids.contains(&i.id)).collect();
        let mut out = vec![];
        for i in items {
            let r = self.like_later(&i.platform, &i.post).await;
            let _g = self.busy.lock().await;
            let mut s = self.wallet.load()?;
            match &r {
                Ok(_) => s.inbox.retain(|x| x.id != i.id),
                Err(e) => {
                    if let Some(x) = s.inbox.iter_mut().find(|x| x.id == i.id) {
                        x.note = Some(e.to_string());
                    }
                }
            }
            self.wallet.save(&s)?;
            out.push(Approved { id: i.id, queued: r.is_ok(), error: r.err().map(|e| e.to_string()) });
        }
        Ok(out)
    }

    /// Drop these likes (by inbox id) without sending them. Returns how many were dropped.
    pub async fn reject(&self, ids: &[u64]) -> Result<usize> {
        let _g = self.busy.lock().await;
        let mut s = self.wallet.load()?;
        let before = s.inbox.len();
        s.inbox.retain(|x| !ids.contains(&x.id));
        self.wallet.save(&s)?;
        Ok(before - s.inbox.len())
    }

    /// Collect the mailboxes every [`COLLECT_EVERY`] (plus a random part) while the app runs.
    pub fn spawn_pairing_collector(self: &Arc<Self>) {
        if self.mailbox.is_none() {
            return;
        }
        let h = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let jitter = std::time::Duration::from_millis(rand::random::<u64>() % 60_000);
                tokio::time::sleep(COLLECT_EVERY + jitter).await;
                let Some(h) = h.upgrade() else { return };
                if h.wallet.load().map(|s| s.pairings.is_empty()).unwrap_or(true) {
                    continue;
                }
                if let Err(e) = h.collect_pairings().await {
                    tracing::warn!("collecting from paired computers: {e}");
                }
            }
        });
    }
}
