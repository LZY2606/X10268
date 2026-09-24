//! SQLite 存储：事件溯源 + 分支；所有身份在导出/删除/再导入后保持稳定。
//! 迁移从 user_version=1 开始，后续迁移递增（见 tests/migration.rs）。

use crate::model::{ByteSource, Decision, Diagnostic, Event, Material, RuleSet};
use rusqlite::{params, Connection};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in parts { h.update(p.as_bytes()); h.update([0x1F]); }
    let d = hex::encode(h.finalize());
    format!("{prefix}_{}", &d[..16])
}

pub fn open(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    migrate(&conn)?;
    Ok(conn)}

pub fn open_in_memory() -> rusqlite::Result<Connection> {
    let mut conn = Connection::open_in_memory()?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    migrate(&mut conn)?;
    Ok(conn)
}

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if v >= 1 { return Ok(()); }
    conn.execute_batch(r#"
    CREATE TABLE cases (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        exported_version INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE artifacts (
        id TEXT NOT NULL,
        case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        kind TEXT NOT NULL,            -- pe_bytes | export_snapshot | expected_base
        content BLOB,                  -- 原始字节（不做清洗）
        json_content TEXT,
        sha256 TEXT NOT NULL,
        ordinal INTEGER NOT NULL,
        UNIQUE(case_id, id)
    );
    CREATE TABLE materials (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        kind TEXT NOT NULL,
        ordinal INTEGER NOT NULL,
        payload TEXT NOT NULL,
        byte_sources TEXT NOT NULL,
        diagnostics TEXT NOT NULL,
        superseded_by TEXT,
        UNIQUE(case_id, id)
    );
    CREATE TABLE rulesets (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        version INTEGER NOT NULL,
        params TEXT NOT NULL,
        note TEXT NOT NULL,
        superseded_by TEXT
    );
    CREATE TABLE branches (
        id TEXT NOT NULL,
        case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        parent_branch_id TEXT,
        created_at TEXT NOT NULL,
        PRIMARY KEY (case_id, id)
    );
    CREATE TABLE events (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        branch_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        kind TEXT NOT NULL,
        parent_event_id TEXT,
        timestamp TEXT NOT NULL,
        payload TEXT NOT NULL,
        UNIQUE(case_id, branch_id, seq)
    );
    CREATE TABLE decisions (
        case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        branch_id TEXT NOT NULL,
        fact_id TEXT NOT NULL,
        candidate_id TEXT NOT NULL,
        action TEXT NOT NULL,
        rationale TEXT NOT NULL,
        event_id TEXT NOT NULL,
        revoked_at TEXT,
        PRIMARY KEY (case_id, branch_id, fact_id, candidate_id, event_id)
    );
    CREATE TABLE derived_cache (
        case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        branch_id TEXT NOT NULL,
        fact_id TEXT NOT NULL,
        fact_json TEXT NOT NULL,
        ruleset_id TEXT NOT NULL,
        PRIMARY KEY (case_id, branch_id, fact_id)
    );
    "#)?;
    conn.execute_batch("PRAGMA user_version = 1;")?;
    Ok(())
}

/* ---------------- 序列化辅助 ---------------- */

pub fn to_json<T: serde::Serialize>(v: &T) -> String { serde_json::to_string(v).unwrap() }
pub fn from_json<'a, T: serde::Deserialize<'a>>(s: &'a str) -> T { serde_json::from_str(s).unwrap() }

pub fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    // 固定可读的 ISO（UTC 近似秒级），身份由哈希决定，时间戳不参与身份。
    format!("{}Z", chrono_like(secs))
}
fn chrono_like(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}", rem / 3600, (rem % 3600) / 60, rem % 60)
}
// Howard Hinnant days-from-civil
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

/* ---------------- case / artifact ---------------- */

pub fn create_case(conn: &Connection, id: &str, name: &str) -> rusqlite::Result<()> {
    conn.execute("INSERT OR IGNORE INTO cases(id,name,created_at) VALUES(?1,?2,?3)",
        params![id, name, now_iso()])?;
    Ok(())
}

pub fn case_exists(conn: &Connection, id: &str) -> bool {
    conn.query_row("SELECT 1 FROM cases WHERE id=?1", params![id], |_| Ok(())).is_ok()
}

pub fn list_cases(conn: &Connection) -> rusqlite::Result<Vec<Value>> {
    let mut stmt = conn.prepare("SELECT id,name,created_at FROM cases ORDER BY created_at,id")?;
    let rows = stmt.query_map([], |r| {
        Ok(serde_json::json!({"id": r.get::<_,String>(0)?, "name": r.get::<_,String>(1)?,
            "created_at": r.get::<_,String>(2)?}))
    })?;
    rows.collect()
}

pub fn insert_artifact(conn: &Connection, case_id: &str, id: &str, kind: &str,
                       content: Option<&[u8]>, json_content: Option<&str>,
                       sha: &str, ordinal: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO artifacts(id,case_id,kind,content,json_content,sha256,ordinal)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![id, case_id, kind, content, json_content, sha, ordinal])?;
    Ok(())
}

pub fn insert_material(conn: &Connection, case_id: &str, m: &Material) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO materials(id,case_id,kind,ordinal,payload,byte_sources,diagnostics,superseded_by)
         VALUES(?1,?2,?3,?4,?5,?6,?7,NULL)",
        params![m.id, case_id, m.kind, m.ordinal, to_json(&m.payload),
                to_json(&m.byte_sources), to_json(&m.diagnostics)])?;
    Ok(())
}

pub fn mark_superseded(conn: &Connection, case_id: &str, old_id: &str, new_id: &str) -> rusqlite::Result<()> {
    conn.execute("UPDATE materials SET superseded_by=?1 WHERE case_id=?2 AND id=?3",
        params![new_id, case_id, old_id])?;
    Ok(())
}

pub fn load_materials(conn: &Connection, case_id: &str, include_superseded: bool) -> rusqlite::Result<Vec<Material>> {
    let sql = if include_superseded {
        "SELECT id,kind,ordinal,payload,byte_sources,diagnostics FROM materials WHERE case_id=?1 ORDER BY ordinal,id"
    } else {
        "SELECT id,kind,ordinal,payload,byte_sources,diagnostics FROM materials WHERE case_id=?1 AND superseded_by IS NULL ORDER BY ordinal,id"
    };
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(params![case_id], |r| {
        Ok(Material {
            id: r.get(0)?, kind: r.get(1)?, ordinal: r.get(2)?,
            payload: from_json(&r.get::<_,String>(3)?),
            byte_sources: from_json(&r.get::<_,String>(4)?),
            diagnostics: from_json(&r.get::<_,String>(5)?),
        })
    })?;
    rows.collect()
}

pub fn upsert_ruleset(conn: &Connection, case_id: &str, rs: &RuleSet) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO rulesets(id,case_id,version,params,note,superseded_by) VALUES(?1,?2,?3,?4,?5,NULL)
         ON CONFLICT(id) DO UPDATE SET params=excluded.params,note=excluded.note",
        params![rs.id, case_id, rs.version, to_json(&rs.params), rs.note])?;
    Ok(())
}

pub fn current_ruleset(conn: &Connection, case_id: &str) -> rusqlite::Result<Option<RuleSet>> {
    conn.query_row(
        "SELECT id,version,params,note FROM rulesets WHERE case_id=?1 ORDER BY version DESC LIMIT 1",
        params![case_id], |r| Ok(RuleSet {
            id: r.get(0)?, version: r.get(1)?, params: from_json(&r.get::<_,String>(2)?), note: r.get(3)?,
        })).optional()
}

pub fn ruleset_at_version(conn: &Connection, case_id: &str, version: i64) -> rusqlite::Result<Option<RuleSet>> {
    conn.query_row(
        "SELECT id,version,params,note FROM rulesets WHERE case_id=?1 AND version<=?2 ORDER BY version DESC LIMIT 1",
        params![case_id, version], |r| Ok(RuleSet {
            id: r.get(0)?, version: r.get(1)?, params: from_json(&r.get::<_,String>(2)?), note: r.get(3)?,
        })).optional()
}

pub fn mark_ruleset_superseded(conn: &Connection, case_id: &str, old_id: &str, new_id: &str) -> rusqlite::Result<()> {
    conn.execute("UPDATE rulesets SET superseded_by=?1 WHERE case_id=?2 AND id=?3",
        params![new_id, case_id, old_id])?;
    Ok(())
}

/* ---------------- 分支与事件（append only） ---------------- */

pub fn create_branch(conn: &Connection, case_id: &str, id: &str, name: &str,
                     parent_branch: Option<&str>) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO branches(id,case_id,name,parent_branch_id,created_at) VALUES(?1,?2,?3,?4,?5)",
        params![id, case_id, name, parent_branch, now_iso()])?;
    Ok(())
}

pub fn list_branches(conn: &Connection, case_id: &str) -> rusqlite::Result<Vec<Value>> {
    let mut stmt = conn.prepare(
        "SELECT id,name,parent_branch_id,created_at FROM branches WHERE case_id=?1 ORDER BY created_at,id")?;
    let rows = stmt.query_map(params![case_id], |r| {
        Ok(json!({"id": r.get::<_,String>(0)?, "name": r.get::<_,String>(1)?,
            "parent_branch_id": r.get::<_,Option<String>>(2)?, "created_at": r.get::<_,String>(3)?}))
    })?;
    rows.collect()
}

/// 分支最后事件 seq（乐观锁版本）。
pub fn branch_version(conn: &Connection, case_id: &str, branch_id: &str) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COALESCE(MAX(seq),0) FROM events WHERE case_id=?1 AND branch_id=?2",
        params![case_id, branch_id], |r| r.get(0))
}

pub fn append_event(conn: &mut Connection, case_id: &str, branch_id: &str, kind: &str,
                    payload: &Value, expected_parent_seq: Option<i64>) -> rusqlite::Result<Event> {
    let tx = conn.transaction()?;
    let cur: i64 = tx.query_row(
        "SELECT COALESCE(MAX(seq),0) FROM events WHERE case_id=?1 AND branch_id=?2",
        params![case_id, branch_id], |r| r.get(0))?;
    if let Some(exp) = expected_parent_seq {
        if exp != cur {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(2021 /* SQLITE_CONSTRAINT */),
                Some(format!("version_conflict expected={exp} actual={cur}"))));
        }
    }
    let seq = cur + 1;
    let parent: Option<String> = tx.query_row(
        "SELECT id FROM events WHERE case_id=?1 AND branch_id=?2 ORDER BY seq DESC LIMIT 1",
        params![case_id, branch_id], |r| r.get(0)).optional()?.flatten();
    let id = stable_id("evt", &[case_id, branch_id, &seq.to_string(), kind,
        &canonical_json(payload)]);
    let ts = now_iso();
    tx.execute(
        "INSERT INTO events(id,case_id,branch_id,seq,kind,parent_event_id,timestamp,payload)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![id, case_id, branch_id, seq, kind, parent, ts, to_json(payload)])?;
    tx.commit()?;
    Ok(Event { id, branch_id: branch_id.into(), seq, kind: kind.into(),
        parent_event_id: parent, timestamp: ts, payload: payload.clone() })
}

pub fn list_events(conn: &Connection, case_id: &str, branch_id: &str) -> rusqlite::Result<Vec<Event>> {
    let mut stmt = conn.prepare(
        "SELECT id,branch_id,seq,kind,parent_event_id,timestamp,payload FROM events
         WHERE case_id=?1 AND branch_id=?2 ORDER BY seq")?;
    let rows = stmt.query_map(params![case_id, branch_id], |r| Ok(Event {
        id: r.get(0)?, branch_id: r.get(1)?, seq: r.get(2)?, kind: r.get(3)?,
        parent_event_id: r.get(4)?, timestamp: r.get(5)?,
        payload: from_json(&r.get::<_,String>(6)?),
    }))?;
    rows.collect()
}

pub fn record_decision(conn: &mut Connection, case_id: &str, branch_id: &str,
                       d: &Decision, event_id: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO decisions(case_id,branch_id,fact_id,candidate_id,action,rationale,event_id,revoked_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,NULL)",
        params![case_id, branch_id, d.fact_id, d.candidate_id, d.action, d.rationale, event_id])?;
    Ok(())
}

pub fn active_decisions(conn: &Connection, case_id: &str, branch_id: &str) -> rusqlite::Result<Vec<(String, String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT fact_id,candidate_id,action FROM decisions
         WHERE case_id=?1 AND branch_id=?2 AND revoked_at IS NULL ORDER BY rowid")?;
    let rows = stmt.query_map(params![case_id, branch_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    rows.collect()
}

pub fn revoke_decisions_at(conn: &Connection, case_id: &str, branch_id: &str,
                           after_event_seq: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE decisions SET revoked_at=?1 WHERE case_id=?2 AND branch_id=?3 AND event_id IN
          (SELECT id FROM events WHERE case_id=?2 AND branch_id=?3 AND seq>?4)",
        params![now_iso(), case_id, branch_id, after_event_seq])
}

use serde_json::json;

/// 规范化 JSON（对象键排序），保证身份哈希跨导入导出稳定。
pub fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys.iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical_json(&map[*k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => format!("[{}]", a.iter().map(canonical_json).collect::<Vec<_>>().join(",")),
        other => other.to_string(),
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn byte_sources_json(bs: &[ByteSource]) -> String { to_json(bs) }
pub fn diagnostics_json(ds: &[Diagnostic]) -> String { to_json(ds) }

use rusqlite::OptionalExtension;

/* ---------------- 导出 / 删除 / 再导入：身份、顺序、来源关系保持 ---------------- */

pub fn export_case(conn: &Connection, case_id: &str) -> rusqlite::Result<Value> {
    let case: Value = conn.query_row("SELECT id,name,created_at FROM cases WHERE id=?1",
        params![case_id], |r| Ok(json!({"id": r.get::<_,String>(0)?, "name": r.get::<_,String>(1)?,
            "created_at": r.get::<_,String>(2)?})))?;
    let artifacts = {
        let mut stmt = conn.prepare(
            "SELECT id,kind,content,json_content,sha256,ordinal FROM artifacts
             WHERE case_id=?1 ORDER BY ordinal,id")?;
        let rows = stmt.query_map(params![case_id], |r| {
            let content: Option<Vec<u8>> = r.get(2)?;
            Ok(json!({
                "id": r.get::<_,String>(0)?, "kind": r.get::<_,String>(1)?,
                "content_b64": content.map(hex::encode),
                "json_content": from_json_opt(&r.get::<_,Option<String>>(3)?),
                "sha256": r.get::<_,String>(4)?, "ordinal": r.get::<_,i64>(5)?,
            }))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let materials = {
        let mut stmt = conn.prepare(
            "SELECT id,kind,ordinal,payload,byte_sources,diagnostics,superseded_by
             FROM materials WHERE case_id=?1 ORDER BY ordinal,id")?;
        let rows = stmt.query_map(params![case_id], |r| {
            Ok(json!({
                "id": r.get::<_,String>(0)?, "kind": r.get::<_,String>(1)?,
                "ordinal": r.get::<_,i64>(2)?, "payload": from_json(&r.get::<_,String>(3)?),
                "byte_sources": from_json::<Vec<ByteSource>>(&r.get::<_,String>(4)?),
                "diagnostics": from_json::<Vec<Diagnostic>>(&r.get::<_,String>(5)?),
                "superseded_by": r.get::<_,Option<String>>(6)?,
            }))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let rulesets = {
        let mut stmt = conn.prepare(
            "SELECT id,version,params,note,superseded_by FROM rulesets
             WHERE case_id=?1 ORDER BY version,id")?;
        let rows = stmt.query_map(params![case_id], |r| {
            Ok(json!({"id": r.get::<_,String>(0)?, "version": r.get::<_,i64>(1)?,
                "params": from_json::<Value>(&r.get::<_,String>(2)?),
                "note": r.get::<_,String>(3)?, "superseded_by": r.get::<_,Option<String>>(4)?}))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let branches = {
        let mut stmt = conn.prepare(
            "SELECT id,name,parent_branch_id,created_at FROM branches WHERE case_id=?1 ORDER BY created_at,id")?;
        let rows = stmt.query_map(params![case_id], |r| {
            Ok(json!({"id": r.get::<_,String>(0)?, "name": r.get::<_,String>(1)?,
                "parent_branch_id": r.get::<_,Option<String>>(2)?, "created_at": r.get::<_,String>(3)?}))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let events = {
        let mut stmt = conn.prepare(
            "SELECT id,branch_id,seq,kind,parent_event_id,timestamp,payload
             FROM events WHERE case_id=?1 ORDER BY branch_id,seq")?;
        let rows = stmt.query_map(params![case_id], |r| {
            Ok(json!({"id": r.get::<_,String>(0)?, "branch_id": r.get::<_,String>(1)?,
                "seq": r.get::<_,i64>(2)?, "kind": r.get::<_,String>(3)?,
                "parent_event_id": r.get::<_,Option<String>>(4)?, "timestamp": r.get::<_,String>(5)?,
                "payload": from_json::<Value>(&r.get::<_,String>(6)?)}))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let decisions = {
        let mut stmt = conn.prepare(
            "SELECT branch_id,fact_id,candidate_id,action,rationale,event_id,revoked_at
             FROM decisions WHERE case_id=?1 ORDER BY rowid")?;
        let rows = stmt.query_map(params![case_id], |r| {
            Ok(json!({"branch_id": r.get::<_,String>(0)?, "fact_id": r.get::<_,String>(1)?,
                "candidate_id": r.get::<_,String>(2)?, "action": r.get::<_,String>(3)?,
                "rationale": r.get::<_,String>(4)?, "event_id": r.get::<_,String>(5)?,
                "revoked_at": r.get::<_,Option<String>>(6)?}))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    Ok(json!({
        "format": "pe-loader-bench-case", "format_version": 1,
        "case": case, "artifacts": artifacts, "materials": materials, "rulesets": rulesets,
        "branches": branches, "events": events, "decisions": decisions,
    }))
}

fn from_json_opt(s: &Option<String>) -> Option<Value> { s.as_ref().map(|v| from_json(v)) }

/// 原子导入：任何失败都回滚，不留下半份记录。
pub fn import_case(conn: &mut Connection, doc: &Value) -> rusqlite::Result<String> {
    let tx = conn.transaction()?;
    let case_id = doc.pointer("/case/id").and_then(|v| v.as_str())
        .ok_or_else(|| rusqlite::Error::InvalidQuery)?;
    let case_name = doc.pointer("/case/name").and_then(|v| v.as_str()).unwrap_or("imported");
    let created = doc.pointer("/case/created_at").and_then(|v| v.as_str()).unwrap_or("");
    // 再导入相同身份必须可重复：先删除旧 case（级联），身份随后重建。
    tx.execute("DELETE FROM cases WHERE id=?1", params![case_id])?;
    tx.execute("INSERT INTO cases(id,name,created_at) VALUES(?1,?2,?3)",
        params![case_id, case_name, created])?;

    for a in doc.get("artifacts").and_then(|v| v.as_array()).unwrap_or(&vec![]) {
        let content = a.get("content_b64").and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok());
        tx.execute(
            "INSERT INTO artifacts(id,case_id,kind,content,json_content,sha256,ordinal)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![a["id"].as_str(), case_id, a["kind"].as_str(),
                content.as_deref(),
                a.get("json_content").map(to_json),
                a["sha256"].as_str(), a["ordinal"].as_i64()])?;
    }
    for m in doc.get("materials").and_then(|v| v.as_array()).unwrap_or(&vec![]) {
        tx.execute(
            "INSERT INTO materials(id,case_id,kind,ordinal,payload,byte_sources,diagnostics,superseded_by)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![m["id"].as_str(), case_id, m["kind"].as_str(), m["ordinal"].as_i64(),
                to_json(&m["payload"]), to_json(&m["byte_sources"]),
                to_json(&m["diagnostics"]),
                m.get("superseded_by").and_then(|v| v.as_str())])?;
    }
    for r in doc.get("rulesets").and_then(|v| v.as_array()).unwrap_or(&vec![]) {
        tx.execute(
            "INSERT INTO rulesets(id,case_id,version,params,note,superseded_by)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![r["id"].as_str(), case_id, r["version"].as_i64(),
                to_json(&r["params"]), r["note"].as_str(),
                r.get("superseded_by").and_then(|v| v.as_str())])?;
    }
    for b in doc.get("branches").and_then(|v| v.as_array()).unwrap_or(&vec![]) {
        tx.execute(
            "INSERT INTO branches(id,case_id,name,parent_branch_id,created_at)
             VALUES(?1,?2,?3,?4,?5)",
            params![b["id"].as_str(), case_id, b["name"].as_str(),
                b.get("parent_branch_id").and_then(|v| v.as_str()),
                b["created_at"].as_str()])?;
    }
    for e in doc.get("events").and_then(|v| v.as_array()).unwrap_or(&vec![]) {
        tx.execute(
            "INSERT INTO events(id,case_id,branch_id,seq,kind,parent_event_id,timestamp,payload)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![e["id"].as_str(), case_id, e["branch_id"].as_str(), e["seq"].as_i64(),
                e["kind"].as_str(),
                e.get("parent_event_id").and_then(|v| v.as_str()),
                e["timestamp"].as_str(), to_json(&e["payload"])])?;
    }
    for d in doc.get("decisions").and_then(|v| v.as_array()).unwrap_or(&vec![]) {
        tx.execute(
            "INSERT INTO decisions(case_id,branch_id,fact_id,candidate_id,action,rationale,event_id,revoked_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![case_id, d["branch_id"].as_str(), d["fact_id"].as_str(),
                d["candidate_id"].as_str(), d["action"].as_str(), d["rationale"].as_str(),
                d["event_id"].as_str(), d.get("revoked_at").and_then(|v| v.as_str())])?;
    }
    tx.commit()?;
    Ok(case_id.to_string())
}

pub fn delete_case(conn: &mut Connection, case_id: &str) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM cases WHERE id=?1", params![case_id])?;
    Ok(())
}
