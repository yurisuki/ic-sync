//! SQLite state, schema-compatible with the reference project.
//!
//! Tables: `entries`, `pending_ops` (including
//! `retry_count INTEGER NOT NULL DEFAULT 0`) and `sync_state`.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};

use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub path: String,
    pub entry_type: String,
    pub parent_path: String,
    pub remote_drivewsid: Option<String>,
    pub remote_docwsid: Option<String>,
    pub remote_etag: Option<String>,
    pub remote_zone: Option<String>,
    pub remote_shareid: Option<String>,
    pub size: i64,
    pub mtime: i64,
    pub hydrated: bool,
    pub dirty: bool,
    pub tombstone: bool,
    pub local_sha256: Option<String>,
    pub last_synced_at: Option<i64>,
    pub synced_path: Option<String>,
}

impl Entry {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            path: row.get("path")?,
            entry_type: row.get("type")?,
            parent_path: row.get("parent_path")?,
            remote_drivewsid: row.get("remote_drivewsid")?,
            remote_docwsid: row.get("remote_docwsid")?,
            remote_etag: row.get("remote_etag")?,
            remote_zone: row.get("remote_zone")?,
            remote_shareid: row.get("remote_shareid")?,
            size: row.get("size")?,
            mtime: row.get("mtime")?,
            hydrated: row.get::<_, i64>("hydrated")? != 0,
            dirty: row.get::<_, i64>("dirty")? != 0,
            tombstone: row.get::<_, i64>("tombstone")? != 0,
            local_sha256: row.get("local_sha256")?,
            last_synced_at: row.get("last_synced_at")?,
            synced_path: row.get("synced_path")?,
        })
    }

    pub fn is_dir(&self) -> bool {
        matches!(self.entry_type.as_str(), "folder" | "app_library")
    }
}

#[derive(Debug, Clone)]
pub struct PendingOp {
    pub id: i64,
    pub op: String,
    pub path: String,
    pub target_path: Option<String>,
    pub retry_count: i64,
    pub last_error: Option<String>,
}

pub struct Database {
    connection: Mutex<Connection>,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        connection.execute_batch("PRAGMA busy_timeout=5000;")?;
        let db = Self {
            connection: Mutex::new(connection),
        };
        db.init()?;
        Ok(db)
    }

    fn init(&self) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS entries (
                path TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                parent_path TEXT NOT NULL,
                remote_drivewsid TEXT,
                remote_docwsid TEXT,
                remote_etag TEXT,
                remote_zone TEXT,
                remote_shareid TEXT,
                size INTEGER NOT NULL DEFAULT 0,
                mtime INTEGER NOT NULL DEFAULT 0,
                hydrated INTEGER NOT NULL DEFAULT 0,
                dirty INTEGER NOT NULL DEFAULT 0,
                tombstone INTEGER NOT NULL DEFAULT 0,
                local_sha256 TEXT,
                last_synced_at INTEGER,
                synced_path TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_entries_remote_drivewsid ON entries(remote_drivewsid);
            CREATE INDEX IF NOT EXISTS idx_entries_dirty ON entries(dirty, tombstone);
            CREATE TABLE IF NOT EXISTS pending_ops (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                op TEXT NOT NULL,
                path TEXT NOT NULL,
                target_path TEXT,
                queued_at INTEGER NOT NULL,
                retry_count INTEGER NOT NULL DEFAULT 0,
                last_error TEXT
            );
            CREATE TABLE IF NOT EXISTS sync_state (
                key TEXT PRIMARY KEY,
                value TEXT
            );",
        )?;
        let has_shareid: bool = conn
            .prepare("PRAGMA table_info(entries)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .filter_map(|name| name.ok())
            .any(|name| name == "remote_shareid");
        if !has_shareid {
            conn.execute("ALTER TABLE entries ADD COLUMN remote_shareid TEXT", [])?;
        }
        Ok(())
    }

    // -- sync_state -------------------------------------------------------

    pub fn sync_state_get(&self, key: &str) -> Result<Option<String>> {
        let conn = self.connection.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT value FROM sync_state WHERE key=?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn sync_state_set(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "INSERT INTO sync_state (key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    // -- counts -----------------------------------------------------------

    pub fn count_entries(&self) -> Result<i64> {
        let conn = self.connection.lock().unwrap();
        Ok(conn.query_row("SELECT COUNT(*) FROM entries", [], |r| r.get(0))?)
    }

    pub fn count_synced(&self) -> Result<i64> {
        let conn = self.connection.lock().unwrap();
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM entries WHERE dirty=0 AND tombstone=0",
            [],
            |r| r.get(0),
        )?)
    }

    pub fn count_unhydrated(&self) -> Result<i64> {
        let conn = self.connection.lock().unwrap();
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM entries WHERE type='file' AND tombstone=0 AND hydrated=0",
            [],
            |r| r.get(0),
        )?)
    }

    pub fn count_pending_ops(&self) -> Result<i64> {
        let conn = self.connection.lock().unwrap();
        Ok(conn.query_row("SELECT COUNT(*) FROM pending_ops", [], |r| r.get(0))?)
    }

    // -- entries ----------------------------------------------------------

    pub fn list_entries(&self) -> Result<Vec<Entry>> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare("SELECT * FROM entries ORDER BY path")?;
        let rows = stmt.query_map([], Entry::from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn list_pending_ops(&self) -> Result<Vec<PendingOp>> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, op, path, target_path, retry_count, last_error FROM pending_ops ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PendingOp {
                id: row.get(0)?,
                op: row.get(1)?,
                path: row.get(2)?,
                target_path: row.get(3)?,
                retry_count: row.get(4)?,
                last_error: row.get(5)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn delete_op(&self, id: i64) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute("DELETE FROM pending_ops WHERE id=?1", params![id])?;
        Ok(())
    }

    pub fn bump_op_retry(&self, id: i64, error: &str) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "UPDATE pending_ops SET retry_count=retry_count+1, last_error=?2 WHERE id=?1",
            params![id, error],
        )?;
        Ok(())
    }

    pub fn queue_op(&self, op: &str, path: &str, target_path: Option<&str>) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        if op == "delete" {
            let pending_create: i64 = conn.query_row(
                "SELECT COUNT(*) FROM pending_ops \
                 WHERE path=?1 AND op IN ('create','mkdir','conflict-copy')",
                params![path],
                |row| row.get(0),
            )?;
            if pending_create > 0 {
                conn.execute(
                    "DELETE FROM pending_ops WHERE path=?1 OR target_path=?1",
                    params![path],
                )?;
                return Ok(());
            }
        }
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO pending_ops (op, path, target_path, queued_at) VALUES (?1, ?2, ?3, ?4)",
            params![op, path, target_path, now],
        )?;
        Ok(())
    }

    pub fn update_remote_fields(
        &self,
        path: &str,
        drivewsid: Option<&str>,
        docwsid: Option<&str>,
        etag: Option<&str>,
        zone: Option<&str>,
    ) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "UPDATE entries SET remote_drivewsid=COALESCE(?2, remote_drivewsid), \
             remote_docwsid=COALESCE(?3, remote_docwsid), remote_etag=COALESCE(?4, remote_etag), \
             remote_zone=COALESCE(?5, remote_zone) WHERE path=?1",
            params![path, drivewsid, docwsid, etag, zone],
        )?;
        Ok(())
    }

    pub fn upsert_entry(&self, entry: &Entry) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "INSERT INTO entries (
                path, type, parent_path, remote_drivewsid, remote_docwsid, remote_etag,
                remote_zone, remote_shareid, size, mtime, hydrated, dirty, tombstone,
                local_sha256, last_synced_at, synced_path
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
            ON CONFLICT(path) DO UPDATE SET
                type=excluded.type, parent_path=excluded.parent_path,
                remote_drivewsid=excluded.remote_drivewsid, remote_docwsid=excluded.remote_docwsid,
                remote_etag=excluded.remote_etag, remote_zone=excluded.remote_zone,
                remote_shareid=excluded.remote_shareid, size=excluded.size, mtime=excluded.mtime,
                hydrated=excluded.hydrated, dirty=excluded.dirty, tombstone=excluded.tombstone,
                local_sha256=excluded.local_sha256, last_synced_at=excluded.last_synced_at,
                synced_path=excluded.synced_path",
            params![
                entry.path,
                entry.entry_type,
                entry.parent_path,
                entry.remote_drivewsid,
                entry.remote_docwsid,
                entry.remote_etag,
                entry.remote_zone,
                entry.remote_shareid,
                entry.size,
                entry.mtime,
                entry.hydrated as i64,
                entry.dirty as i64,
                entry.tombstone as i64,
                entry.local_sha256,
                entry.last_synced_at,
                entry.synced_path,
            ],
        )?;
        Ok(())
    }

    pub fn get_entry(&self, path: &str) -> Result<Option<Entry>> {
        let conn = self.connection.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT * FROM entries WHERE path=?1",
                params![path],
                Entry::from_row,
            )
            .optional()?)
    }

    pub fn get_entry_by_remote_id(&self, id: &str) -> Result<Option<Entry>> {
        let conn = self.connection.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT * FROM entries WHERE remote_drivewsid=?1 ORDER BY path LIMIT 1",
                params![id],
                Entry::from_row,
            )
            .optional()?)
    }

    pub fn list_subtree(&self, path: &str) -> Result<Vec<Entry>> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT * FROM entries WHERE path=?1 OR path LIKE ?2 ORDER BY LENGTH(path), path",
        )?;
        let rows = stmt.query_map(params![path, format!("{path}/%")], Entry::from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn list_children(&self, parent: &str) -> Result<Vec<Entry>> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare("SELECT * FROM entries WHERE parent_path=?1 ORDER BY path")?;
        let rows = stmt.query_map(params![parent], Entry::from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn list_unhydrated(&self) -> Result<Vec<Entry>> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT * FROM entries WHERE type='file' AND tombstone=0 AND hydrated=0 ORDER BY path",
        )?;
        let rows = stmt.query_map([], Entry::from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn list_dirty(&self) -> Result<Vec<Entry>> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT * FROM entries WHERE dirty=1 OR tombstone=1 ORDER BY tombstone DESC, path",
        )?;
        let rows = stmt.query_map([], Entry::from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Move a locally modified subtree out of the way after a remote conflict.
    /// The copy has no remote identity, so the upload loop recreates it.
    pub fn detach_subtree_as_conflict(&self, from: &str, to: &str) -> Result<()> {
        let entries = self.list_subtree(from)?;
        let prefix = format!("{}/", from.trim_end_matches('/'));
        for entry in entries {
            let suffix = if entry.path == from {
                ""
            } else {
                &entry.path[prefix.len()..]
            };
            let new_path = if suffix.is_empty() {
                to.to_string()
            } else {
                format!("{}/{}", to.trim_end_matches('/'), suffix)
            };
            let new_parent = if entry.path == from {
                parent_path(to)
            } else {
                let parent_suffix = &entry.parent_path[prefix.len().saturating_sub(1)..];
                format!("{}{}", to.trim_end_matches('/'), parent_suffix)
            };
            let conn = self.connection.lock().unwrap();
            conn.execute(
                "UPDATE entries SET path=?2, parent_path=?3, remote_drivewsid=NULL, \
                 remote_docwsid=NULL, remote_etag=NULL, remote_zone=NULL, \
                 remote_shareid=NULL, synced_path=NULL, dirty=1, tombstone=0 \
                 WHERE path=?1",
                params![entry.path, new_path, new_parent],
            )?;
            conn.execute(
                "UPDATE pending_ops SET path=?2 WHERE path=?1",
                params![entry.path, new_path],
            )?;
        }
        Ok(())
    }

    pub fn clear_remote_identity(&self, path: &str) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "UPDATE entries SET remote_drivewsid=NULL, remote_docwsid=NULL, \
             remote_etag=NULL, remote_zone=NULL, remote_shareid=NULL, \
             synced_path=NULL, dirty=1, tombstone=0 WHERE path=?1",
            params![path],
        )?;
        Ok(())
    }

    pub fn mark_synced_subtree(&self, path: &str) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "UPDATE entries SET synced_path=path, \
             dirty=CASE WHEN path=?1 THEN 0 ELSE dirty END, \
             tombstone=CASE WHEN path=?1 THEN 0 ELSE tombstone END, \
             last_synced_at=?2 WHERE path=?1 OR path LIKE ?3",
            params![path, chrono::Utc::now().timestamp(), format!("{path}/%")],
        )?;
        Ok(())
    }

    pub fn update_synced_path(&self, path: &str) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "UPDATE entries SET synced_path=?2, last_synced_at=?3 WHERE path=?1",
            params![path, path, chrono::Utc::now().timestamp()],
        )?;
        Ok(())
    }

    pub fn mark_hydrated(
        &self,
        path: &str,
        sha256: Option<&str>,
        size: i64,
        mtime: i64,
    ) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "UPDATE entries SET hydrated=1, local_sha256=?2, size=?3, mtime=?4 WHERE path=?1",
            params![path, sha256, size, mtime],
        )?;
        Ok(())
    }

    pub fn mark_dirty(
        &self,
        path: &str,
        sha256: Option<&str>,
        size: i64,
        mtime: i64,
    ) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "UPDATE entries SET dirty=1, tombstone=0, hydrated=1, local_sha256=?2, size=?3, mtime=?4 WHERE path=?1",
            params![path, sha256, size, mtime],
        )?;
        Ok(())
    }

    pub fn mark_tombstone(&self, path: &str) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "UPDATE entries SET tombstone=1, dirty=1 WHERE path=?1",
            params![path],
        )?;
        Ok(())
    }

    pub fn clear_all_conflict_pending(&self) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "DELETE FROM pending_ops WHERE path LIKE '%.local-conflict-%' \
             OR target_path LIKE '%.local-conflict-%'",
            [],
        )?;
        Ok(())
    }

    /// Remove queued operations for a local-only subtree (e.g. conflict copies)
    /// without touching the entries themselves.
    pub fn clear_pending_subtree(&self, path: &str) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        let like = format!("{path}/%");
        conn.execute(
            "DELETE FROM pending_ops WHERE path=?1 OR path LIKE ?2 \
             OR target_path=?1 OR target_path LIKE ?2",
            params![path, like],
        )?;
        Ok(())
    }

    pub fn mark_clean(&self, path: &str, last_synced_at: i64, sha256: Option<&str>) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "UPDATE entries SET dirty=0, tombstone=0, last_synced_at=?2, \
             local_sha256=COALESCE(?3, local_sha256), synced_path=path WHERE path=?1",
            params![path, last_synced_at, sha256],
        )?;
        conn.execute(
            "DELETE FROM pending_ops WHERE path=?1 OR target_path=?1",
            params![path],
        )?;
        Ok(())
    }

    pub fn remove_subtree(&self, path: &str) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "DELETE FROM entries WHERE path=?1 OR path LIKE ?2",
            params![path, format!("{path}/%")],
        )?;
        conn.execute(
            "DELETE FROM pending_ops WHERE path=?1 OR path LIKE ?2 \
             OR target_path=?1 OR target_path LIKE ?2",
            params![path, format!("{path}/%")],
        )?;
        Ok(())
    }

    pub fn rename_tree(&self, from: &str, to: &str, update_synced: bool) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        let rows: Vec<(String, String)> = conn
            .prepare("SELECT path, parent_path FROM entries WHERE path=?1 OR path LIKE ?2")?
            .query_map(params![from, format!("{from}/%")], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let prefix = format!("{}/", from.trim_end_matches('/'));
        for (old_path, old_parent) in rows {
            let suffix = if old_path == from {
                ""
            } else {
                &old_path[prefix.len()..]
            };
            let new_path = if suffix.is_empty() {
                to.to_string()
            } else {
                format!("{}/{}", to.trim_end_matches('/'), suffix)
            };
            let new_parent = if old_path == from {
                parent_path(to)
            } else {
                let parent_suffix = &old_parent[prefix.len().saturating_sub(1)..];
                format!("{}{}", to.trim_end_matches('/'), parent_suffix)
            };
            if update_synced {
                conn.execute(
                    "UPDATE entries SET path=?2, parent_path=?3, synced_path=CASE \
                         WHEN synced_path=?1 THEN ?2 \
                         WHEN synced_path LIKE ?4 THEN ?5 || substr(synced_path, ?6) \
                         ELSE synced_path END, \
                     dirty=0, tombstone=0 WHERE path=?1",
                    params![
                        old_path,
                        new_path,
                        new_parent,
                        format!("{prefix}%"),
                        format!("{}/", to.trim_end_matches('/')),
                        (prefix.len() + 1) as i64,
                    ],
                )?;
            } else {
                conn.execute(
                    "UPDATE entries SET path=?2, parent_path=?3 WHERE path=?1",
                    params![old_path, new_path, new_parent],
                )?;
            }
            conn.execute(
                "UPDATE pending_ops SET path=CASE \
                     WHEN path=?1 THEN ?2 \
                     WHEN path LIKE ?3 THEN ?4 || substr(path, ?5) \
                     ELSE path END, \
                 target_path=CASE \
                     WHEN target_path=?1 THEN ?2 \
                     WHEN target_path LIKE ?3 THEN ?4 || substr(target_path, ?5) \
                     ELSE target_path END \
                 WHERE path=?1 OR path LIKE ?3 OR target_path=?1 OR target_path LIKE ?3",
                params![
                    old_path,
                    new_path,
                    format!("{prefix}%"),
                    format!("{}/", to.trim_end_matches('/')),
                    (prefix.len() + 1) as i64,
                ],
            )?;
        }
        Ok(())
    }
}

pub fn parent_path(path: &str) -> String {
    match path.rfind('/') {
        Some(0) | None => "/".into(),
        Some(index) => path[..index].to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    fn entry(path: &str, entry_type: &str, remote_id: Option<&str>) -> Entry {
        Entry {
            path: path.into(),
            entry_type: entry_type.into(),
            parent_path: parent_path(path),
            remote_drivewsid: remote_id.map(str::to_string),
            remote_docwsid: None,
            remote_etag: Some("etag".into()),
            remote_zone: None,
            remote_shareid: None,
            size: 0,
            mtime: 0,
            hydrated: true,
            dirty: true,
            tombstone: false,
            local_sha256: None,
            last_synced_at: Some(1),
            synced_path: Some(path.into()),
        }
    }

    #[test]
    fn schema_is_compatible_with_reference() {
        let dir = TempDir::new();
        let db = Database::open(&dir.path.join("state.sqlite3")).unwrap();
        let conn = db.connection.lock().unwrap();

        let mut stmt = conn.prepare("PRAGMA table_info(pending_ops)").unwrap();
        let columns = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .unwrap()
            .filter_map(|row| row.ok())
            .collect::<Vec<_>>();
        let retry = columns
            .iter()
            .find(|(name, _, _)| name == "retry_count")
            .unwrap();
        assert_eq!(retry.1, 1);
        assert_eq!(retry.2, "0");

        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|row| row.ok())
            .collect();
        assert!(tables.iter().any(|t| t == "entries"));
        assert!(tables.iter().any(|t| t == "pending_ops"));
        assert!(tables.iter().any(|t| t == "sync_state"));
    }

    #[test]
    fn counts_and_sync_state() {
        let dir = TempDir::new();
        let db = Database::open(&dir.path.join("state.sqlite3")).unwrap();
        db.upsert_entry(&entry("/a.txt", "file", Some("id")))
            .unwrap();
        assert_eq!(db.count_entries().unwrap(), 1);
        assert_eq!(db.count_synced().unwrap(), 0);
        db.mark_clean("/a.txt", 1, None).unwrap();
        assert_eq!(db.count_synced().unwrap(), 1);
        assert_eq!(db.count_pending_ops().unwrap(), 0);
        db.sync_state_set("cursor", "42").unwrap();
        assert_eq!(db.sync_state_get("cursor").unwrap().as_deref(), Some("42"));
    }

    #[test]
    fn delete_cancels_pending_create() {
        let dir = TempDir::new();
        let db = Database::open(&dir.path.join("state.sqlite3")).unwrap();
        db.queue_op("create", "/note.txt", None).unwrap();
        db.queue_op("delete", "/note.txt", None).unwrap();
        assert!(db.list_pending_ops().unwrap().is_empty());
    }

    #[test]
    fn conflict_detach_clears_remote_identity() {
        let dir = TempDir::new();
        let db = Database::open(&dir.path.join("state.sqlite3")).unwrap();
        db.upsert_entry(&entry("/docs", "folder", Some("folder-id")))
            .unwrap();
        db.upsert_entry(&entry("/docs/a.txt", "file", Some("file-id")))
            .unwrap();
        db.detach_subtree_as_conflict("/docs", "/docs.local-conflict-1")
            .unwrap();

        let root = db.get_entry("/docs.local-conflict-1").unwrap().unwrap();
        assert!(root.remote_drivewsid.is_none());
        assert!(root.dirty);
        assert_eq!(root.parent_path, "/");
        let child = db
            .get_entry("/docs.local-conflict-1/a.txt")
            .unwrap()
            .unwrap();
        assert!(child.remote_drivewsid.is_none());
        assert!(child.dirty);
    }

    #[test]
    fn rename_tree_rewrites_pending_targets() {
        let dir = TempDir::new();
        let db = Database::open(&dir.path.join("state.sqlite3")).unwrap();
        db.upsert_entry(&entry("/old", "folder", Some("id")))
            .unwrap();
        db.queue_op("rename", "/old", Some("/old")).unwrap();
        db.rename_tree("/old", "/new", false).unwrap();
        let ops = db.list_pending_ops().unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].path, "/new");
        assert_eq!(ops[0].target_path.as_deref(), Some("/new"));
    }
}
