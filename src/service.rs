//! 用例装载与叙事编排：导入 PE 字节+预期 base+DLL 导出快照，
//! 按事件序列建立 main 分支（含一次参数修订、一次局部源改动）和 alt-ruling 分支（冲突人工决定）。

use crate::db;
use crate::fixture::*;
use crate::model::{Decision, RuleSet};
use crate::pe;
use rusqlite::Connection;
use serde_json::{json, Value};

pub const MAIN_BRANCH: &str = "main";
pub const ALT_BRANCH: &str = "alt-ruling";

/// 完整初始导入（事务：失败回滚，不留半份记录）。
pub fn seed_fixture(conn: &mut Connection) -> rusqlite::Result<String> {
    let tx = conn.transaction()?;
    if !db::case_exists(&tx, CASE_ID) {
        db::create_case(&tx, CASE_ID, CASE_NAME)?;
        let built = build_pe();
        let sha = db::sha256_hex(&built.bytes);
        db::insert_artifact(&tx, CASE_ID, PE_ARTIFACT_ID, "pe_bytes",
            Some(&built.bytes), None, &sha, 1)?;
        db::insert_artifact(&tx, CASE_ID, "art:input:expected_image_base", "expected_base",
            None, Some(&db::to_json(&json!({"value": EXPECTED_BASE, "unit": "va",
                "raw_repr": format!("0x{EXPECTED_BASE:016X}")}))),
            &db::sha256_hex(db::canonical_json(&json!({"expected_image_base": EXPECTED_BASE})).as_bytes()), 2)?;
        // 初始材料解析
        let parsed = pe::parse_pe(PE_ARTIFACT_ID, &built.bytes, EXPECTED_BASE);
        for m in &parsed.materials {
            db::insert_material(&tx, CASE_ID, m)?;
        }
        let mut art_ord = 10;
        for snap in export_snapshots() {
            let aid = snap.get("artifact_id").and_then(|v| v.as_str()).unwrap_or("snap");
            let body = db::canonical_json(&snap);
            db::insert_artifact(&tx, CASE_ID, aid, "export_snapshot", None,
                Some(&body), &db::sha256_hex(body.as_bytes()), art_ord)?;
            art_ord += 1;
            let mat = pe::parse_export_snapshot(aid, &snap, 100 + art_ord);
            db::insert_material(&tx, CASE_ID, &mat)?;
        }
        let rules = RuleSet {
            id: db::stable_id("rules", &[CASE_ID, "1"]), version: 1,
            params: rules_v1(), note: "初始装载参数 v1".into(),
        };
        db::upsert_ruleset(&tx, CASE_ID, &rules)?;
        db::create_branch(&tx, CASE_ID, MAIN_BRANCH, "初始复核主线", None)?;
        db::create_branch(&tx, CASE_ID, ALT_BRANCH, "冲突人工决定支线", Some(MAIN_BRANCH))?;
        // main 初始导入事件
        let init_payload = json!({
            "narrative": "逆向工程小组导入 PE 字节、预期 image base 与 DLL export 快照",
            "pe_artifact_id": PE_ARTIFACT_ID,
            "expected_image_base": {"value": EXPECTED_BASE, "unit": "va"},
            "material_ids": parsed.materials.iter().map(|m| m.id.clone()).collect::<Vec<_>>(),
            "ruleset_id": rules.id, "ruleset_version": 1,
        });
        append(&tx, CASE_ID, MAIN_BRANCH, "import", &init_payload, None)?;
    }
    tx.commit()?;
    Ok(CASE_ID.into())
}

fn append(conn: &Connection, case_id: &str, branch: &str, kind: &str, payload: &Value,
          expected: Option<i64>) -> rusqlite::Result<crate::model::Event> {
    let mut c = unsafe { conn.try_clone()? };
    db::append_event(&mut c, case_id, branch, kind, payload, expected)
}

/// 追加一次参数修订（v1 -> v2），保留旧规则可读，失效范围由依赖闭包计算。
pub fn revise_rules(conn: &mut Connection, case_id: &str, branch: &str) -> rusqlite::Result<Value> {
    let old = db::current_ruleset(conn, case_id)?.unwrap();
    let new = RuleSet {
        id: db::stable_id("rules", &[case_id, "2"]), version: 2,
        params: rules_v2(), note: "参数修订 v2：显式零填充策略 + 新增探针".into(),
    };
    db::upsert_ruleset(conn, case_id, &new)?;
    db::mark_ruleset_superseded(conn, case_id, &old.id, &new.id)?;
    let payload = json!({
        "narrative": "一次参数修订：零填充策略显式化，新增 deep 探针",
        "old_ruleset_id": old.id, "ruleset_id": new.id, "ruleset_version": 2,
    });
    let e = db::append_event(conn, case_id, branch, "rule_revise", &payload, None)?;
    Ok(json!({"event_id": e.id, "seq": e.seq, "old_ruleset_id": old.id, "new_ruleset_id": new.id}))
}

/// 追加一次只影响局部依赖的源数据改动（user32 快照 v1 -> v2）。
pub fn revise_local_source(conn: &mut Connection, case_id: &str, branch: &str) -> rusqlite::Result<Value> {
    let snap = user32_snapshot_v2();
    let aid = snap.get("artifact_id").and_then(|v| v.as_str()).unwrap();
    // 旧材料标记 superseded，原始字节行(artifact)仍保留可继续读取
    let old_ids: Vec<String> = {
        let all = db::load_materials(conn, case_id, true)?;
        all.into_iter().filter(|m| m.kind == "export_snapshot"
            && m.pointer("/dll").and_then(|v| v.as_str()) == Some("USER32.dll"))
            .map(|m| m.id).collect()
    };
    let new_mat = pe::parse_export_snapshot(aid, &snap, 200);
    let body = db::canonical_json(&snap);
    db::insert_artifact(conn, case_id, aid, "export_snapshot", None, Some(&body),
        &db::sha256_hex(body.as_bytes()), 11)?;
    db::insert_material(conn, case_id, &new_mat)?;
    for old in &old_ids {
        db::mark_superseded(conn, case_id, old, &new_mat.id)?;
    }
    let payload = json!({
        "narrative": "局部源数据改动：仅 USER32.dll 导出快照修订（DefWindowProcW RVA）",
        "add_material_ids": [new_mat.id], "superseded_material_ids": old_ids,
        "affected_scope": "import_binding(USER32.dll) only",
    });
    let e = db::append_event(conn, case_id, branch, "material_update", &payload, None)?;
    Ok(json!({"event_id": e.id, "seq": e.seq, "new_material_id": new_mat.id, "old_material_ids": old_ids}))
}

/// 人工裁定（接受/否定一个候选），并写决定；视图选择不改原数据。
pub fn submit_decision(conn: &mut Connection, case_id: &str, branch: &str, decision: Decision,
                       expected_version: Option<i64>) -> rusqlite::Result<Value> {
    let payload = json!({"decision": &decision});
    let e = db::append_event(conn, case_id, branch, "decision", &payload, expected_version)?;
    db::record_decision(conn, case_id, branch, &decision, &e.id)?;
    Ok(json!({"event_id": e.id, "seq": e.seq, "decision": decision}))
}

/// 撤销：裁定只在 event 链上追加“回退到前一分支点”事件；旧分支与原始字节不删。
pub fn undo_last_decision(conn: &mut Connection, case_id: &str, branch: &str) -> rusqlite::Result<Value> {
    let events = db::list_events(conn, case_id, branch)?;
    let last = events.iter().rev().find(|e| e.kind == "decision");
    let Some(last) = last else {
        return Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some("no decision to undo".into())));
    };
    db::revoke_decisions_at(conn, case_id, branch, last.seq - 1)?;
    let payload = json!({"narrative": "撤销最近一次裁定，恢复前一分支状态", "revoked_after_event_seq": last.seq});
    let e = db::append_event(conn, case_id, branch, "decision_undo", &payload, None)?;
    Ok(json!({"event_id": e.id, "seq": e.seq}))
}

/// 在 alt-ruling 分支上安排一个互相冲突的人工决定（同一 fact 选择不同候选）。
pub fn seed_alt_conflict(conn: &mut Connection) -> rusqlite::Result<()> {
    let existing = db::list_events(conn, CASE_ID, ALT_BRANCH)?;
    if existing.iter().any(|e| e.kind == "decision") {
        return Ok(());
    }
    // 重叠探针 fact：main 上若未裁定，则 alt 直接接受一个与 main 相反的候选。
    let view = crate::state::view_at(conn, CASE_ID, ALT_BRANCH, None)?;
    let fact = view.facts.iter().find(|f| f.subject.contains("overlap_rdata_ovr"))
        .or_else(|| view.facts.iter().find(|f| f.kind == "rva_resolution"));
    if let Some(fact) = fact {
        let pick = fact.candidates.iter().find(|c| c.kind == "mapped" && c.label.contains(".ovr"))
            .or_else(|| fact.candidates.first());
        if let Some(pick) = pick {
            let d = Decision { fact_id: fact.id.clone(), candidate_id: pick.id.clone(),
                action: "accept".into(), rationale: "alt 分支：重叠 RVA 优先采用 .ovr 节映射（与 main 冲突）".into() };
            let payload = json!({"decision": d, "conflicts_with_branch": MAIN_BRANCH});
            let e = db::append_event(conn, CASE_ID, ALT_BRANCH, "decision", &payload, None)?;
            db::record_decision(conn, CASE_ID, ALT_BRANCH, &d, &e.id)?;
        }
    }
    Ok(())
}
