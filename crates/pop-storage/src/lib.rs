//! # pop-storage
//!
//! The servers keep all state through the [`Store`] trait: named tables of JSON documents keyed by
//! strings. Two implementations ship: [`MemoryStore`] (tests, demo) and [`JsonFileStore`] (one JSON file
//! per table, enough for a pilot on one machine). docs/real-servers.md shows how to add PostgreSQL or
//! another database: implement these six methods.
use async_trait::async_trait;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("storage I/O: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[async_trait]
pub trait Store: Send + Sync {
    async fn get(&self, table: &str, key: &str) -> Result<Option<Value>>;
    /// Insert or replace.
    async fn put(&self, table: &str, key: &str, value: Value) -> Result<()>;
    /// Insert only if the key is absent; returns false if it existed. Must be atomic: uniqueness of
    /// enrolments, badge tags and like tags rests on it.
    async fn insert_new(&self, table: &str, key: &str, value: Value) -> Result<bool>;
    async fn delete(&self, table: &str, key: &str) -> Result<()>;
    async fn list(&self, table: &str) -> Result<Vec<(String, Value)>>;
    async fn count(&self, table: &str) -> Result<u64> {
        Ok(self.list(table).await?.len() as u64)
    }
}

pub type SharedStore = Arc<dyn Store>;

type Tables = BTreeMap<String, BTreeMap<String, Value>>;

#[derive(Default)]
pub struct MemoryStore {
    t: Mutex<Tables>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn shared() -> SharedStore {
        Arc::new(Self::new())
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn get(&self, table: &str, key: &str) -> Result<Option<Value>> {
        Ok(self.t.lock().await.get(table).and_then(|t| t.get(key)).cloned())
    }
    async fn put(&self, table: &str, key: &str, value: Value) -> Result<()> {
        self.t.lock().await.entry(table.into()).or_default().insert(key.into(), value);
        Ok(())
    }
    async fn insert_new(&self, table: &str, key: &str, value: Value) -> Result<bool> {
        let mut g = self.t.lock().await;
        let t = g.entry(table.into()).or_default();
        if t.contains_key(key) {
            return Ok(false);
        }
        t.insert(key.into(), value);
        Ok(true)
    }
    async fn delete(&self, table: &str, key: &str) -> Result<()> {
        if let Some(t) = self.t.lock().await.get_mut(table) {
            t.remove(key);
        }
        Ok(())
    }
    async fn list(&self, table: &str) -> Result<Vec<(String, Value)>> {
        Ok(self.t.lock().await.get(table).map(|t| t.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default())
    }
}

/// One JSON file per table under `dir`, rewritten on every change (write to a temp file, then rename).
/// Fine for thousands of records; not for production.
pub struct JsonFileStore {
    dir: PathBuf,
    mem: Mutex<Tables>,
}

impl JsonFileStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).map_err(|e| StoreError::Io(e.to_string()))?;
        let mut tables = Tables::new();
        for ent in std::fs::read_dir(&dir).map_err(|e| StoreError::Io(e.to_string()))? {
            let p = ent.map_err(|e| StoreError::Io(e.to_string()))?.path();
            if p.extension().and_then(|e| e.to_str()) == Some("json") {
                let name = p.file_stem().unwrap().to_string_lossy().to_string();
                let text = std::fs::read_to_string(&p).map_err(|e| StoreError::Io(e.to_string()))?;
                let t: BTreeMap<String, Value> = serde_json::from_str(&text).map_err(|e| StoreError::Io(e.to_string()))?;
                tables.insert(name, t);
            }
        }
        Ok(JsonFileStore { dir, mem: Mutex::new(tables) })
    }

    fn flush(&self, tables: &Tables, table: &str) -> Result<()> {
        let empty = BTreeMap::new();
        let t = tables.get(table).unwrap_or(&empty);
        let path = self.dir.join(format!("{table}.json"));
        let tmp = self.dir.join(format!(".{table}.json.tmp"));
        std::fs::write(&tmp, serde_json::to_vec_pretty(t).unwrap()).map_err(|e| StoreError::Io(e.to_string()))?;
        std::fs::rename(&tmp, &path).map_err(|e| StoreError::Io(e.to_string()))
    }
}

fn check_name(table: &str) {
    assert!(table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'), "bad table name");
}

#[async_trait]
impl Store for JsonFileStore {
    async fn get(&self, table: &str, key: &str) -> Result<Option<Value>> {
        Ok(self.mem.lock().await.get(table).and_then(|t| t.get(key)).cloned())
    }
    async fn put(&self, table: &str, key: &str, value: Value) -> Result<()> {
        check_name(table);
        let mut g = self.mem.lock().await;
        g.entry(table.into()).or_default().insert(key.into(), value);
        self.flush(&g, table)
    }
    async fn insert_new(&self, table: &str, key: &str, value: Value) -> Result<bool> {
        check_name(table);
        let mut g = self.mem.lock().await;
        let t = g.entry(table.into()).or_default();
        if t.contains_key(key) {
            return Ok(false);
        }
        t.insert(key.into(), value);
        self.flush(&g, table)?;
        Ok(true)
    }
    async fn delete(&self, table: &str, key: &str) -> Result<()> {
        let mut g = self.mem.lock().await;
        if let Some(t) = g.get_mut(table) {
            t.remove(key);
        }
        self.flush(&g, table)
    }
    async fn list(&self, table: &str) -> Result<Vec<(String, Value)>> {
        Ok(self.mem.lock().await.get(table).map(|t| t.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn exercise(s: &dyn Store) {
        assert!(s.insert_new("t", "a", json!(1)).await.unwrap());
        assert!(!s.insert_new("t", "a", json!(2)).await.unwrap());
        assert_eq!(s.get("t", "a").await.unwrap(), Some(json!(1)));
        s.put("t", "b", json!({"x": 2})).await.unwrap();
        assert_eq!(s.count("t").await.unwrap(), 2);
        s.delete("t", "a").await.unwrap();
        assert_eq!(s.list("t").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn memory() {
        exercise(&MemoryStore::new()).await;
    }

    #[tokio::test]
    async fn file_persists() {
        let dir = std::env::temp_dir().join(format!("pop-store-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            let s = JsonFileStore::open(&dir).unwrap();
            exercise(&s).await;
        }
        let s = JsonFileStore::open(&dir).unwrap();
        assert_eq!(s.get("t", "b").await.unwrap(), Some(json!({"x": 2})));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
