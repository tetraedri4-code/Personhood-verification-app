//! Lookups of enrolment records by something other than their key d, without reading every record.
//!
//! Three small tables in the same [`pop_storage::Store`], so that any storage backend keeps working:
//!
//! | table | key | value | used by |
//! |---|---|---|---|
//! | `enrol_by_handle` | current handle | d | `POST /v1/revoke` |
//! | `enrol_by_claim` | SHA-256 of a claim token | d | `POST /v1/replace/claim` |
//! | `enrol_pending` | d | `{}` | `GET /v1/replace/pending` |
//!
//! They hold nothing the records do not already hold (each record is keyed by d and contains its handle
//! and claim hash). Every record write goes through [`put_record`], which updates them; lookups check
//! the record they lead to, so a stale entry (a crash between two writes) is ignored, and the issuer
//! rebuilds all three at start ([`rebuild`]), which also indexes data written before they existed.
use crate::service::{Enrolment, Issuer, T_ENROL};
use pop_storage::{Result, Store};
use serde_json::json;

pub(crate) const T_BY_HANDLE: &str = "enrol_by_handle";
pub(crate) const T_BY_CLAIM: &str = "enrol_by_claim";
pub(crate) const T_PENDING: &str = "enrol_pending";

fn claim_of(rec: &Enrolment) -> Option<&str> {
    rec.pending.as_ref().map(|p| p.claim_hash.as_str())
}

/// Bring the index entries of record `d` from `old` to `new` (None: no record).
pub(crate) async fn reindex(store: &dyn Store, d: &str, old: Option<&Enrolment>, new: Option<&Enrolment>) -> Result<()> {
    let (oh, nh) = (old.map(|r| r.handle), new.map(|r| r.handle));
    if let Some(h) = oh.filter(|h| Some(*h) != nh) {
        delete_if_points_to(store, T_BY_HANDLE, &h.to_string(), d).await?;
    }
    if let Some(h) = nh {
        store.put(T_BY_HANDLE, &h.to_string(), json!(d)).await?;
    }
    let (oc, nc) = (old.and_then(claim_of), new.and_then(claim_of));
    if let Some(c) = oc.filter(|c| Some(*c) != nc) {
        delete_if_points_to(store, T_BY_CLAIM, c, d).await?;
    }
    if let Some(c) = nc {
        store.put(T_BY_CLAIM, c, json!(d)).await?;
    }
    if nc.is_some() {
        store.put(T_PENDING, d, json!({})).await?;
    } else if oc.is_some() || old.is_none() {
        store.delete(T_PENDING, d).await?;
    }
    Ok(())
}

async fn delete_if_points_to(store: &dyn Store, table: &str, key: &str, d: &str) -> Result<()> {
    if store.get(table, key).await?.as_ref().and_then(|v| v.as_str()) == Some(d) {
        store.delete(table, key).await?;
    }
    Ok(())
}

/// Write a record and its index entries. Call with the records lock held.
pub(crate) async fn put_record(s: &Issuer, d: &str, rec: &Enrolment) -> Result<()> {
    let old: Option<Enrolment> = s.store.get(T_ENROL, d).await?.and_then(|v| serde_json::from_value(v).ok());
    s.store.put(T_ENROL, d, serde_json::to_value(rec).map_err(|e| pop_storage::StoreError::Io(e.to_string()))?).await?;
    reindex(&*s.store, d, old.as_ref(), Some(rec)).await
}

/// The record whose key the index `table` gives for `key`, if it is still the one asked for.
async fn follow(s: &Issuer, table: &str, key: &str, check: impl Fn(&Enrolment) -> bool) -> Result<Option<(String, Enrolment)>> {
    let Some(d) = s.store.get(table, key).await?.and_then(|v| v.as_str().map(String::from)) else { return Ok(None) };
    let Some(v) = s.store.get(T_ENROL, &d).await? else { return Ok(None) };
    Ok(serde_json::from_value::<Enrolment>(v).ok().filter(|r| check(r)).map(|r| (d, r)))
}

pub(crate) async fn by_handle(s: &Issuer, handle: u64) -> Result<Option<(String, Enrolment)>> {
    follow(s, T_BY_HANDLE, &handle.to_string(), |r| r.handle == handle).await
}

pub(crate) async fn by_claim(s: &Issuer, claim_hash: &str) -> Result<Option<(String, Enrolment)>> {
    follow(s, T_BY_CLAIM, claim_hash, |r| claim_of(r) == Some(claim_hash)).await
}

/// Records with a waiting replacement.
pub(crate) async fn pending(s: &Issuer) -> Result<Vec<(String, Enrolment)>> {
    let mut out = vec![];
    for (d, _) in s.store.list(T_PENDING).await? {
        if let Some(v) = s.store.get(T_ENROL, &d).await? {
            if let Ok(r) = serde_json::from_value::<Enrolment>(v) {
                if r.pending.is_some() {
                    out.push((d, r));
                }
            }
        }
    }
    Ok(out)
}

/// Drop and rebuild the three tables from the records (at start).
pub(crate) async fn rebuild(store: &dyn Store) -> Result<()> {
    for t in [T_BY_HANDLE, T_BY_CLAIM, T_PENDING] {
        for (k, _) in store.list(t).await? {
            store.delete(t, &k).await?;
        }
    }
    for (d, v) in store.list(T_ENROL).await? {
        if let Ok(r) = serde_json::from_value::<Enrolment>(v) {
            reindex(store, &d, None, Some(&r)).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn rec(handle: u64, claim: Option<&str>) -> Enrolment {
        let mut v = json!({"handle": handle, "guardian": "g", "status": "active", "enrolled_on": 1, "key_version": "k1"});
        if let Some(c) = claim {
            v["pending"] = json!({"requested_on": 1, "claim_hash": c, "nonce": "n", "guardian": "g2"});
        }
        serde_json::from_value(v).unwrap()
    }

    async fn table(store: &dyn Store, t: &str) -> Vec<(String, Value)> {
        store.list(t).await.unwrap()
    }

    #[tokio::test]
    async fn entries_follow_the_records_and_are_rebuilt_at_start() {
        let store = pop_storage::MemoryStore::new();
        // records written before the index existed
        store.put(T_ENROL, "d1", serde_json::to_value(rec(11, None)).unwrap()).await.unwrap();
        store.put(T_ENROL, "d2", serde_json::to_value(rec(22, Some("c2"))).unwrap()).await.unwrap();
        // and a stale entry left by a crash
        store.put(T_BY_HANDLE, "99", json!("d1")).await.unwrap();
        rebuild(&store).await.unwrap();
        assert_eq!(table(&store, T_BY_HANDLE).await, vec![("11".into(), json!("d1")), ("22".into(), json!("d2"))]);
        assert_eq!(table(&store, T_BY_CLAIM).await, vec![("c2".into(), json!("d2"))]);
        assert_eq!(table(&store, T_PENDING).await, vec![("d2".into(), json!({}))]);

        // a replacement: new handle, the waiting request is gone
        reindex(&store, "d2", Some(&rec(22, Some("c2"))), Some(&rec(23, None))).await.unwrap();
        assert_eq!(table(&store, T_BY_HANDLE).await, vec![("11".into(), json!("d1")), ("23".into(), json!("d2"))]);
        assert!(table(&store, T_BY_CLAIM).await.is_empty());
        assert!(table(&store, T_PENDING).await.is_empty());

        // a record moved to a new key (key migration): the entries point to the new key
        reindex(&store, "d1new", None, Some(&rec(11, Some("c1")))).await.unwrap();
        reindex(&store, "d1", Some(&rec(11, Some("c1"))), None).await.unwrap();
        assert_eq!(store.get(T_BY_HANDLE, "11").await.unwrap(), Some(json!("d1new")));
        assert_eq!(store.get(T_BY_CLAIM, "c1").await.unwrap(), Some(json!("d1new")));
        assert_eq!(table(&store, T_PENDING).await, vec![("d1new".into(), json!({}))]);
    }
}
