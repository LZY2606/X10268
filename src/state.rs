//! 分支状态：重放事件得到某个时点的材料版本、规则版本与裁定，
//! 再由 engine 派生结论。历史事件永远引用当时版本，不被最新计算覆盖。

use crate::db;
use crate::engine::{invalidation_scope, stale_decisions, AnalysisResult, Fact};
use crate::model::{Decision, Material, RuleSet};
use rusqlite::Connection;
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct BranchView {
    pub case_id: String,
    pub branch_id: String,
    pub version: i64,
    pub rules: RuleSet,
    pub materials: Vec<Material>,
    pub facts: Vec<Fact>,
    pub decisions: Vec<(String, String, String)>, // fact_id, candidate_id, action
    pub events: Vec<Value>,
    pub invalidations: Vec<Value>,
}

pub fn view_at(conn: &Connection, case_id: &str, branch_id: &str, upto_seq: Option<i64>)
    -> rusqlite::Result<BranchView> {
    let events_all = db::list_events(conn, case_id, branch_id)?;
    let max_seq = upto_seq.unwrap_or(i64::MAX);
    let events: Vec<_> = events_all.iter().filter(|e| e.seq <= max_seq).cloned().collect();
    let version = events.last().map(|e| e.seq).unwrap_or(0);

    // 材料状态：material_update 事件声明新增材料与被取代材料。
    let mut materials = db::load_materials(conn, case_id, true)?;
    let mut alive: std::collections::HashSet<String> = materials.iter().map(|m| m.id.clone()).collect();
    let mut rules: Option<RuleSet> = None;
    let mut invalidations: Vec<Value> = Vec::new();
    let mut prev_analysis: Option<AnalysisResult> = None;
    let mut cur_analysis: Option<AnalysisResult> = None;
    let mut decision_facts: Vec<String> = Vec::new();

    let pe_art_id = materials.first().map(|m| m.id.split(":mat:").next().unwrap_or("pe").to_string());
    let file_len = pe_art_bytes_len(conn, case_id, pe_art_id.as_deref())?;

    for e in &events {
        match e.kind.as_str() {
            "material_update" => {
                if let Some(adds) = e.payload.get("add_material_ids").and_then(|v| v.as_array()) {
                    for a in adds {
                        if let Some(s) = a.as_str() { alive.insert(s.into()); }
                    }
                }
                if let Some(sups) = e.payload.get("superseded_material_ids").and_then(|v| v.as_array()) {
                    for s in sups {
                        if let Some(s) = s.as_str() { alive.remove(s); }
                    }
                }
            }
            "rule_revise" => {
                let rid = e.payload.get("ruleset_id").and_then(|v| v.as_str()).unwrap_or_default();
                rules = Some(db::ruleset_at_version(conn, case_id,
                    e.payload.get("ruleset_version").and_then(|v| v.as_i64()).unwrap_or(0))?
                    .or_else(|| db::current_ruleset(conn, case_id).ok().flatten())
                    .unwrap_or_else(|| fallback_rules(rid)));
            }
            "decision" => {
                if let Some(fid) = e.payload.pointer("/decision/fact_id").and_then(|v| v.as_str()) {
                    decision_facts.push(fid.into());
                }
            }
            _ => {}
        }

        // 在每个改变输入的事件后计算失效范围（依赖闭包，非全局替换）。
        if matches!(e.kind.as_str(), "material_update" | "rule_revise") {
            let active: Vec<Material> = materials.iter().filter(|m| alive.contains(&m.id)).cloned().collect();
            let eff_rules = rules.clone()
                .or_else(|| db::current_ruleset(conn, case_id).ok().flatten())
                .unwrap_or_else(|| fallback_rules("auto"));
            let new_result = crate::engine::analyze(&active, &eff_rules, file_len);
            let changed: Vec<String> = if e.kind == "rule_revise" {
                vec![format!("ruleset:{}", e.payload.get("old_ruleset_id")
                    .and_then(|v| v.as_str()).unwrap_or(""))]
            } else {
                e.payload.get("add_material_ids").and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| format!("material:{s}"))).collect())
                    .unwrap_or_default()
            };
            let (aff, unaff) = match &cur_analysis {
                Some(prev) => invalidation_scope(prev, &changed),
                None => (new_result.facts.iter().map(|f| f.id.clone()).collect(), vec![]),
            };
            let stale = match (&cur_analysis, &prev_analysis) {
                (Some(o), _) => stale_decisions(o, &new_result, &decision_facts),
                _ => vec![],
            };
            invalidations.push(json!({
                "event_id": e.id, "event_seq": e.seq, "changed_input": changed,
                "recomputed_fact_ids": aff, "unaffected_fact_ids": unaff,
                "invalidated_decision_fact_ids": stale,
            }));
            prev_analysis = cur_analysis;
            cur_analysis = Some(new_result);
        }
    }

    let active: Vec<Material> = materials.into_iter().filter(|m| alive.contains(&m.id)).collect();
    let eff_rules = rules.or_else(|| db::current_ruleset(conn, case_id).ok().flatten())
        .unwrap_or_else(|| fallback_rules("auto"));
    let analysis = cur_analysis.unwrap_or_else(|| crate::engine::analyze(&active, &eff_rules, file_len));

    // 历史时点的裁定：仅统计 upto_seq 之前、且候选仍存在的决定。
    let all_decisions = decisions_at(conn, case_id, branch_id)?;
    let seqs: std::collections::HashMap<String, i64> = events_all.iter().map(|e| (e.id.clone(), e.seq)).collect();
    let mut decisions = Vec::new();
    for (ev_id, d) in &all_decisions {
        let s = seqs.get(ev_id).copied().unwrap_or(i64::MAX);
        if s <= max_seq {
            let still_exists = analysis.facts.iter().any(|f| f.id == d.fact_id
                && f.candidates.iter().any(|c| c.id == d.candidate_id));
            if still_exists { decisions.push((d.fact_id.clone(), d.candidate_id.clone(), d.action.clone())); }
        }
    }

    Ok(BranchView {
        case_id: case_id.into(), branch_id: branch_id.into(), version,
        rules: eff_rules, materials: active, facts: analysis.facts,
        decisions,
        events: events.iter().map(|e| json!({
            "id": e.id, "seq": e.seq, "kind": e.kind, "parent_event_id": e.parent_event_id,
            "timestamp": e.timestamp, "payload": e.payload,
        })).collect(),
        invalidations,
    })
}

fn decisions_at(conn: &Connection, case_id: &str, branch_id: &str)
    -> rusqlite::Result<Vec<(String, Decision)>> {
    let mut stmt = conn.prepare(
        "SELECT event_id,fact_id,candidate_id,action,rationale FROM decisions
         WHERE case_id=?1 AND branch_id=?2 AND revoked_at IS NULL ORDER BY rowid")?;
    let rows = stmt.query_map(params![case_id, branch_id], |r| {
        let ev: String = r.get(0)?;
        let d = Decision { fact_id: r.get(1)?, candidate_id: r.get(2)?, action: r.get(3)?, rationale: r.get(4)? };
        Ok((ev, d))
    })?;
    rows.collect()
}

fn pe_art_bytes_len(conn: &Connection, case_id: &str, art_id: Option<&str>) -> rusqlite::Result<i64> {
    if let Some(id) = art_id {
        let len: Option<i64> = conn.query_row(
            "SELECT length(content) FROM artifacts WHERE case_id=?1 AND id=?2 AND kind='pe_bytes'",
            params![case_id, id], |r| r.get(0))?;
        return Ok(len.unwrap_or(0));
    }
    Ok(0)
}

pub fn fallback_rules(id: &str) -> RuleSet {
    RuleSet {
        id: id.to_string(), version: 1, note: "fallback".into(),
        params: json!({"zero_fill_beyond_raw": true, "reloc_delta_base": "preferred", "available_dlls": []}),
    }
}
