//! Storage for encrypted backups (recovery level 1, docs/recovery.md).
//!
//! The holder encrypts its wallet under a key derived from a 130-bit code that only the person has
//! (on paper). This server keeps the ciphertext under an id derived from the same code. It cannot
//! read a backup, and it cannot tell whose a backup is except through the ticket that paid for it.
//!
//! This is plain blob storage and has nothing to do with issuing; it lives in the issuer process
//! only because the prototype has no other always-on server. A deployment can put these two routes
//! on another host: the only shared state is the ticket table.
use crate::service::{ct_eq, err, now_secs, ApiErr, Issuer, St};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use pop_protocol::api::{BackupBlob, BackupPut};
use serde_json::json;
use sha2::{Digest, Sha256};

const T_BACKUPS: &str = "backups";
const T_TICKETS: &str = "backup_tickets";
/// base64 characters; a wallet with a few bindings is about 3 kB
pub const MAX_BLOB_CHARS: usize = 44_000;

fn sha_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A one-time ticket for creating one backup. Tickets are handed out where the issuer has just seen
/// an identity check, so backups cannot be created by anonymous strangers to fill the disk.
pub(crate) async fn new_ticket(s: &Issuer) -> Result<String, ApiErr> {
    let t = s.rand_hex(16);
    s.store.put(T_TICKETS, &sha_hex(&t), json!({"issued": now_secs()})).await?;
    Ok(t)
}

pub(crate) async fn put(State(s): State<St>, Json(req): Json<BackupPut>) -> Result<Json<serde_json::Value>, ApiErr> {
    if !is_hex(&req.id, 32) || !is_hex(&req.write_key, 64) {
        return Err(err(StatusCode::BAD_REQUEST, "bad backup id or write key"));
    }
    if req.blob.len() > MAX_BLOB_CHARS || !req.blob.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=') {
        return Err(err(StatusCode::PAYLOAD_TOO_LARGE, "backup too large or not base64"));
    }
    let key_hash = sha_hex(&req.write_key);
    // one writer at a time: a ticket must not pay for two backups
    let _g = s.backups.lock().await;
    match s.store.get(T_BACKUPS, &req.id).await? {
        Some(old) => {
            if !ct_eq(old["write_key_hash"].as_str().unwrap_or_default().as_bytes(), key_hash.as_bytes()) {
                return Err(err(StatusCode::FORBIDDEN, "wrong write key"));
            }
            if req.blob.is_empty() {
                s.store.delete(T_BACKUPS, &req.id).await?;
                // the freed place can be used for one new backup (a new paper code)
                return Ok(Json(json!({"deleted": true, "ticket": new_ticket(&s).await?})));
            }
        }
        None => {
            if req.blob.is_empty() {
                return Err(err(StatusCode::NOT_FOUND, "no such backup"));
            }
            let ticket = req.ticket.as_deref().filter(|t| t.len() <= 64).map(sha_hex).ok_or_else(|| err(StatusCode::FORBIDDEN, "a new backup needs a ticket"))?;
            if s.store.get(T_TICKETS, &ticket).await?.is_none() {
                return Err(err(StatusCode::FORBIDDEN, "unknown or used ticket"));
            }
            s.store.delete(T_TICKETS, &ticket).await?;
        }
    }
    s.store.put(T_BACKUPS, &req.id, json!({"write_key_hash": key_hash, "blob": req.blob, "updated": s.today()})).await?;
    Ok(Json(json!({"stored": true})))
}

pub(crate) async fn get(State(s): State<St>, Path(id): Path<String>) -> Result<Json<BackupBlob>, ApiErr> {
    if !is_hex(&id, 32) {
        return Err(err(StatusCode::BAD_REQUEST, "bad backup id"));
    }
    let v = s.store.get(T_BACKUPS, &id).await?.ok_or_else(|| err(StatusCode::NOT_FOUND, "no such backup"))?;
    Ok(Json(BackupBlob { blob: v["blob"].as_str().unwrap_or_default().to_string() }))
}
