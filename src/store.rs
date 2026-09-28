//! SQLite-backed event-sourced store.
//!
//! Source materials (PE bytes, params, DLL snapshots) and their
//! interpretations live in separate tables. Every mutation is an append-only
//! event; derived runs are never edited in place, only superseded by new runs
//! whose invalidation scope is computed from dependency diffs.

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::loader::Interpretation;

pub const SCHEMA_V1: &str = r#"
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  parent_seq INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE materials(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  version INTEGER NOT NULL,
  raw BLOB NOT NULL,
  raw_repr TEXT NOT NULL,
  event_seq INTEGER NOT NULL
);
CREATE TABLE runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_seq INTEGER NOT NULL,
  rule_version INTEGER NOT NULL,
  deps TEXT NOT NULL,
  interpretation TEXT NOT NULL
);
CREATE TABLE rulings(
  id TEXT PRIMARY KEY,
  event_seq INTEGER NOT NULL,
  target TEXT NOT NULL,
  decision TEXT NOT NULL,
  candidate TEXT,
  base_head INTEGER NOT NULL,
  forced INTEGER NOT NULL DEFAULT 0
);
INSERT INTO meta(key, value) VALUES ('head', '0');
"#;

pub const MIGRATION_V2: &str = r#"
ALTER TABLE events ADD COLUMN actor TEXT NOT NULL DEFAULT 'system';
CREATE TABLE invalidations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL,
  uid TEXT NOT NULL,
  kind TEXT NOT NULL,
  reason TEXT NOT NULL
);
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub seq: i64,
    pub kind: String,
    pub payload: Value,
    pub parent_seq: i64,
    pub actor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Material {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub version: i64,
    pub raw: Vec<u8>,
    pub raw_repr: String,
    pub event_seq: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub id: i64,
    pub event_seq: i64,
    pub rule_version: i64,
    pub deps: Value,
    pub interpretation: Interpretation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ruling {
    pub id: String,
    pub event_seq: i64,
    pub target: String,
    pub decision: String,
    pub candidate: Option<String>,
    pub base_head: i64,
    pub forced: bool,
    pub undone: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Conflict {
    pub current_head: i64,
    pub base_head: i64,
    pub target: String,
    pub current: Vec<Ruling>,
    pub attempted: Value,
}

pub struct Store {
    pub conn: Connection,
}

#[derive(Debug)]
pub enum StoreErr {
    Sql(rusqlite::Error),
    Conflict(Conflict),
    Missing(String),
}

impl From<rusqlite::Error> for StoreErr {
    fn from(e: rusqlite::Error) -> Self {
        StoreErr::Sql(e)
    }
}

pub type SResult<T> = Result<T, StoreErr>;

impl Store {
    pub fn open(path: &str) -> SResult<Store> {
        let conn = Connection::open(path)?;
        let s = Store { conn };
        s.migrate()?;
        Ok(s)
    }

    pub fn open_memory() -> SResult<Store> {
        let conn = Connection::open_in_memory()?;
        let s = Store { conn };
        s.migrate()?;
        Ok(s)
    }

    pub fn migrate(&self) -> SResult<()> {
        let v: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if v < 1 {
            self.conn.execute_batch(SCHEMA_V1)?;
            self.conn.execute_batch("PRAGMA user_version = 1")?;
        }
        if v < 2 {
            self.conn.execute_batch(MIGRATION_V2)?;
            self.conn.execute_batch("PRAGMA user_version = 2")?;
        }
        Ok(())
    }

    pub fn head(&self) -> SResult<i64> {
        let h: String = self
            .conn
            .query_row("SELECT value FROM meta WHERE key='head'", [], |r| r.get(0))?;
        Ok(h.parse().unwrap_or(0))
    }

    fn set_head_tx(tx: &Connection, seq: i64) -> SResult<()> {
        tx.execute(
            "INSERT INTO meta(key,value) VALUES('head',?1)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![seq.to_string()],
        )?;
        Ok(())
    }

    pub fn set_head(&self, seq: i64) -> SResult<()> {
        Self::set_head_tx(&self.conn, seq)
    }

    fn add_event_tx(tx: &Connection, kind: &str, payload: Value, actor: &str) -> SResult<i64> {
        let head: i64 = tx
            .query_row("SELECT value FROM meta WHERE key='head'", [], |r| {
                r.get::<_, String>(0)
            })?
            .parse()
            .unwrap_or(0);
        tx.execute(
            "INSERT INTO events(kind, payload, parent_seq, actor) VALUES (?1, ?2, ?3, ?4)",
            params![kind, payload.to_string(), head, actor],
        )?;
        let seq = tx.last_insert_rowid();
        Self::set_head_tx(tx, seq)?;
        Ok(seq)
    }

    pub fn add_event(&self, kind: &str, payload: Value, actor: &str) -> SResult<i64> {
        Self::add_event_tx(&self.conn, kind, payload, actor)
    }

    /// Import a source material atomically: event + material row commit
    /// together or roll back together.
    pub fn import_material(
        &self,
        name: &str,
        kind: &str,
        raw: &[u8],
        raw_repr: &str,
        actor: &str,
    ) -> SResult<String> {
        let tx = self.conn.unchecked_transaction()?;
        let version: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(version),0)+1 FROM materials WHERE name=?1",
                params![name],
                |r| r.get(0),
            )
            .unwrap_or(1);
        let id = format!("{}#v{}", name, version);
        let seq = Self::add_event_tx(
            &tx,
            "import_material",
            json!({
                "material_id": id,
                "name": name,
                "kind": kind,
                "version": version,
                "byte_len": raw.len(),
                "unit": "byte",
                "basis": "file_offset",
            }),
            actor,
        )?;
        tx.execute(
            "INSERT INTO materials(id,name,kind,version,raw,raw_repr,event_seq)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![id, name, kind, version, raw, raw_repr, seq],
        )?;
        tx.commit()?;
        Ok(id)
    }

    pub fn events(&self) -> SResult<Vec<Event>> {
        let mut st = self
            .conn
            .prepare("SELECT seq,kind,payload,parent_seq,actor FROM events ORDER BY seq")?;
        let rows = st.query_map([], |r| {
            Ok(Event {
                seq: r.get(0)?,
                kind: r.get(1)?,
                payload: serde_json::from_str(&r.get::<_, String>(2)?).unwrap_or(Value::Null),
                parent_seq: r.get(3)?,
                actor: r.get(4)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn materials_visible(&self, head: i64) -> SResult<Vec<Material>> {
        let mut st = self.conn.prepare(
            "SELECT m.id,m.name,m.kind,m.version,m.raw,m.raw_repr,m.event_seq
             FROM materials m
             JOIN (SELECT name, MAX(version) v FROM materials WHERE event_seq<=?1 GROUP BY name) latest
               ON latest.name=m.name AND latest.v=m.version
             ORDER BY m.name",
        )?;
        let rows = st.query_map(params![head], |r| {
            Ok(Material {
                id: r.get(0)?,
                name: r.get(1)?,
                kind: r.get(2)?,
                version: r.get(3)?,
                raw: r.get(4)?,
                raw_repr: r.get(5)?,
                event_seq: r.get(6)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn all_materials(&self) -> SResult<Vec<Material>> {
        let mut st = self.conn.prepare(
            "SELECT id,name,kind,version,raw,raw_repr,event_seq FROM materials ORDER BY name,version",
        )?;
        let rows = st.query_map([], |r| {
            Ok(Material {
                id: r.get(0)?,
                name: r.get(1)?,
                kind: r.get(2)?,
                version: r.get(3)?,
                raw: r.get(4)?,
                raw_repr: r.get(5)?,
                event_seq: r.get(6)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Store a derived run and record the dependency-based invalidation scope
    /// relative to the previously visible run.
    pub fn add_run(
        &self,
        interp: &Interpretation,
        deps: Value,
        actor: &str,
    ) -> SResult<(i64, Vec<Value>)> {
        let prev = self.visible_run(self.head()?)?;
        let invalidated = diff_interpretations(prev.as_ref().map(|r| &r.interpretation), interp);
        let tx = self.conn.unchecked_transaction()?;
        let seq = Self::add_event_tx(
            &tx,
            "derive",
            json!({
                "rule_version": interp.rule_version,
                "deps": deps,
                "invalidated": invalidated,
            }),
            actor,
        )?;
        tx.execute(
            "INSERT INTO runs(event_seq, rule_version, deps, interpretation) VALUES (?1,?2,?3,?4)",
            params![
                seq,
                interp.rule_version as i64,
                deps.to_string(),
                serde_json::to_string(interp).unwrap()
            ],
        )?;
        let run_id = tx.last_insert_rowid();
        for inv in &invalidated {
            tx.execute(
                "INSERT INTO invalidations(run_id, uid, kind, reason) VALUES (?1,?2,?3,?4)",
                params![
                    run_id,
                    inv["uid"].as_str().unwrap_or(""),
                    inv["kind"].as_str().unwrap_or(""),
                    inv["reason"].as_str().unwrap_or("")
                ],
            )?;
        }
        tx.commit()?;
        Ok((run_id, invalidated))
    }

    pub fn visible_run(&self, head: i64) -> SResult<Option<Run>> {
        let row = self.conn.query_row(
            "SELECT r.id, r.event_seq, r.rule_version, r.deps, r.interpretation
             FROM runs r JOIN events e ON e.seq=r.event_seq
             WHERE e.seq<=?1 ORDER BY r.event_seq DESC LIMIT 1",
            params![head],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            },
        );
        match row {
            Ok((id, event_seq, rule_version, deps, interp)) => Ok(Some(Run {
                id,
                event_seq,
                rule_version,
                deps: serde_json::from_str(&deps).unwrap_or(Value::Null),
                interpretation: serde_json::from_str(&interp).map_err(|e| {
                    StoreErr::Missing(format!("run {} interpretation corrupt: {}", id, e))
                })?,
            })),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StoreErr::Sql(e)),
        }
    }

    pub fn run_by_id(&self, id: i64) -> SResult<Option<Run>> {
        let row = self.conn.query_row(
            "SELECT id,event_seq,rule_version,deps,interpretation FROM runs WHERE id=?1",
            params![id],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            },
        );
        match row {
            Ok((id, event_seq, rule_version, deps, interp)) => Ok(Some(Run {
                id,
                event_seq,
                rule_version,
                deps: serde_json::from_str(&deps).unwrap_or(Value::Null),
                interpretation: serde_json::from_str(&interp).unwrap(),
            })),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StoreErr::Sql(e)),
        }
    }

    pub fn invalidations_for(&self, run_id: i64) -> SResult<Vec<Value>> {
        let mut st = self.conn.prepare(
            "SELECT uid,kind,reason FROM invalidations WHERE run_id=?1 ORDER BY id",
        )?;
        let rows = st.query_map(params![run_id], |r| {
            Ok(json!({
                "uid": r.get::<_, String>(0)?,
                "kind": r.get::<_, String>(1)?,
                "reason": r.get::<_, String>(2)?,
            }))
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
