use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const CACHE_SCHEMA_VERSION: &str = "scan-cache-v1";

pub struct ScanCache {
    connection: Connection,
}

impl ScanCache {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let connection =
            Connection::open(path).with_context(|| format!("abrindo cache {}", path.display()))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS clean_scan_cache (
                 path TEXT PRIMARY KEY,
                 file_size INTEGER NOT NULL,
                 modified_ns INTEGER NOT NULL,
                 engine_key TEXT NOT NULL,
                 checked_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_clean_scan_cache_engine ON clean_scan_cache(engine_key);",
        )?;
        Ok(Self { connection })
    }

    pub fn default_path() -> PathBuf {
        crate::default_data_dir().join("scan-cache.db")
    }

    pub fn lookup_clean(&self, path: &Path, engine_key: &str) -> Result<bool> {
        let metadata = fs::metadata(path)?;
        let key = cache_path_key(path);
        let size = i64::try_from(metadata.len()).unwrap_or(i64::MAX);
        let modified_ns = modified_ns(&metadata);
        let hit = self
            .connection
            .query_row(
                "SELECT 1 FROM clean_scan_cache
             WHERE path = ?1 AND file_size = ?2 AND modified_ns = ?3 AND engine_key = ?4",
                params![key, size, modified_ns, engine_key],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        Ok(hit)
    }

    pub fn record_clean(&mut self, path: &Path, engine_key: &str) -> Result<()> {
        let metadata = fs::metadata(path)?;
        let key = cache_path_key(path);
        let size = i64::try_from(metadata.len()).unwrap_or(i64::MAX);
        let modified_ns = modified_ns(&metadata);
        self.connection.execute(
            "INSERT OR REPLACE INTO clean_scan_cache
             (path, file_size, modified_ns, engine_key, checked_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![key, size, modified_ns, engine_key, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn invalidate(&mut self, path: &Path) -> Result<()> {
        self.connection.execute(
            "DELETE FROM clean_scan_cache WHERE path = ?1",
            params![cache_path_key(path)],
        )?;
        Ok(())
    }

    pub fn clear(&mut self) -> Result<()> {
        self.connection
            .execute("DELETE FROM clean_scan_cache", [])?;
        Ok(())
    }
}

fn cache_path_key(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn modified_ns(metadata: &fs::Metadata) -> i64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .and_then(|duration| i64::try_from(duration.as_nanos()).ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX))
                .unwrap_or_default()
        })
}
