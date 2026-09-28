use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

use crate::fixture::*;
use crate::model::*;
use crate::engine::generate_candidates;

#[derive(Debug)]
pub struct Store {
    conn: Mutex<Connection>,
}

#[derive(Debug)]
pub struct SubmitResult {
    pub event: EventRecord,
    pub candidates: Vec<Candidate>,
}

impl Store {
    pub fn replace_all(&self, bundle: Bundle) -> Result<(), String> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        tx.execute_batch("DELETE FROM event_invalidation_scope; DELETE FROM candidates; DELETE FROM branches; DELETE FROM events; DELETE FROM materials; DELETE FROM schema_migrations;").map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO schema_migrations(version) VALUES (1),(2)", []).map_err(|e| e.to_string())?;
        for material in &bundle.materials {
            tx.execute(
                "INSERT INTO materials(material_id,revision,kind,label,original_representation,bytes,byte_encoding,supersedes) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    material.material_id, material.revision, material.kind, material.label,
                    serde_json::to_string(&material.original_representation).map_err(|e| e.to_string())?,
                    material.bytes, material.byte_encoding, material.supersedes
                ],
            ).map_err(|e| e.to_string())?;
        }
        for event in &bundle.events {
            tx.execute(
                "INSERT INTO events(event_id,parent_event_id,sequence,kind,label,rule_version,params_revision,material_revision,branch_id,payload,actor) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    event.event_id, event.parent_event_id, event.sequence, event.kind, event.label,
                    event.rule_version, event.params_revision, event.material_revision, event.branch_id,
                    serde_json::to_string(&event.payload).map_err(|e| e.to_string())?, event.actor
                ],
            ).map_err(|e| e.to_string())?;
            for subject in &event.invalidation_scope {
                tx.execute("INSERT INTO event_invalidation_scope(event_id,subject_id) VALUES(?1,?2)", params![event.event_id, subject]).map_err(|e| e.to_string())?;
            }
        }
        for candidate in &bundle.candidates {
            tx.execute(
                "INSERT INTO candidates(candidate_id,event_id,subject_id,subject_kind,subject_label,option_id,option_label,status,value,evidence,source_refs,invalidated_by,depends_on,rule_version,params_revision,material_revision,batch) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                params![
                    candidate.candidate_id, candidate.created_by_event, candidate.subject_id, candidate.subject_kind,
                    candidate.subject_label, candidate.option_id, candidate.option_label, candidate.status,
                    serde_json::to_string(&candidate.value).map_err(|e| e.to_string())?,
                    serde_json::to_string(&candidate.evidence).map_err(|e| e.to_string())?,
                    serde_json::to_string(&candidate.source_refs).map_err(|e| e.to_string())?,
                    candidate.invalidated_by, serde_json::to_string(&candidate.depends_on).map_err(|e| e.to_string())?,
                    candidate.rule_version, candidate.params_revision, candidate.material_revision, candidate.batch
                ],
            ).map_err(|e| e.to_string())?;
        }
        for branch in &bundle.branches {
            tx.execute("INSERT INTO branches(branch_id,label,head_event_id,created_from_event_id) VALUES(?1,?2,?3,?4)", params![branch.branch_id, branch.label, branch.head_event_id, branch.created_from_event_id]).map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn export_bundle(&self) -> Result<Bundle, String> {
        let conn = self.conn.lock().unwrap();
        let materials = load_materials(&conn)?;
        let events = load_events(&conn)?;
        let candidates = load_all_candidates(&conn)?;
        let branches = load_branches(&conn)?;
        Ok(Bundle { schema_version: 3, materials, events, candidates, branches })
    }

    pub fn list_materials(&self) -> Result<Vec<Material>, String> {
        let conn = self.conn.lock().unwrap();
        load_materials(&conn)
    }

    pub fn list_branches(&self) -> Result<Vec<Branch>, String> {
        let conn = self.conn.lock().unwrap();
        load_branches(&conn)
    }

    pub fn branch_events(&self, branch_id: &str) -> Result<Vec<EventRecord>, String> {
        let conn = self.conn.lock().unwrap();
        let branch = load_branch(&conn, branch_id)?.ok_or_else(|| "unknown branch".to_string())?;
        let all = load_events(&conn)?;
        let mut ancestors = std::collections::HashSet::new();
        let mut cursor = Some(branch.head_event_id.clone());
        while let Some(id) = cursor {
            ancestors.insert(id.clone());
            cursor = all.iter().find(|e| e.event_id == id).and_then(|e| e.parent_event_id.clone());
        }
        let mut events: Vec<_> = all.into_iter().filter(|e| ancestors.contains(&e.event_id)).collect();
        events.sort_by(|a, b| a.sequence.cmp(&b.sequence).then_with(|| a.event_id.cmp(&b.event_id)));
        Ok(events)
    }

    pub fn branch_state(&self, branch_id: &str, at_event_id: Option<&str>) -> Result<serde_json::Value, String> {
        let mut events = self.branch_events(branch_id)?;
        if let Some(at) = at_event_id {
            if let Some(index) = events.iter().position(|e| e.event_id == at) {
                events.truncate(index + 1);
            }
        }
        let conn = self.conn.lock().unwrap();
        let all_candidates = load_all_candidates(&conn)?;
        let event_ids: std::collections::HashSet<_> = events.iter().map(|e| e.event_id.clone()).collect();
        let mut selected: std::collections::BTreeMap<String, Vec<Candidate>> = std::collections::BTreeMap::new();
        for event in &events {
            for candidate in all_candidates.iter().filter(|c| c.created_by_event == event.event_id) {
                let group = selected.entry(candidate.subject_id.clone()).or_default();
                if !group.iter().any(|g| g.option_id == candidate.option_id) {
                    group.push(candidate.clone());
                }
            }
            for scope in &event.invalidation_scope {
                if let Some(group) = selected.get_mut(scope) {
                    for candidate in group.iter_mut() {
                        candidate.invalidated_by = Some(event.event_id.clone());
                    }
                }
            }
            if event.kind == "decision" {
                let subject = event.payload["subject_id"].as_str().unwrap_or_default();
                let accepted = event.payload["accepted_option_id"].as_str().unwrap_or_default();
                if let Some(group) = selected.get_mut(subject) {
                    for candidate in group.iter_mut() {
                        candidate.status = if candidate.option_id == accepted { "accepted".into() } else { "rejected".into() };
                    }
                }
            }
        }
        let mut candidates: Vec<_> = selected.into_values().flatten().collect();
        candidates.sort_by(|a, b| a.subject_id.cmp(&b.subject_id).then_with(|| a.option_id.cmp(&b.option_id)));
        let materials = load_materials(&conn)?;
        let branches = load_branches(&conn)?;
        Ok(serde_json::json!({
            "branch_id": branch_id,
            "at_event_id": at_event_id,
            "events": events,
            "candidates": candidates,
            "materials": materials,
            "branches": branches
        }))
    }

    pub fn submit_decision(&self, input: DecisionInput) -> Result<SubmitResult, ConflictResponse> {
        let parent_id = input.parent_event_id.clone();
        self.submit(input.parent_event_id, input.branch_id.clone(), input.expected_parent_event_id, |parent, sequence, params, mats| {
            Ok(EventRecord {
                event_id: format!("evt-{sequence:02}-decision-{}-{}", input.subject_id, input.accepted_option_id),
                parent_event_id: Some(parent.event_id.clone()),
                sequence,
                kind: "decision".into(),
                label: input.label.clone(),
                rule_version: parent.rule_version.clone(),
                params_revision: params,
                material_revision: mats,
                branch_id: input.branch_id.clone(),
                payload: serde_json::json!({"subject_id":input.subject_id,"accepted_option_id":input.accepted_option_id,"label":input.label,"rationale":input.rationale,"original_input_unchanged":true}),
                invalidation_scope: vec![],
                actor: "reviewer".into(),
            })
        }).map(|event| {
            let _ = parent_id;
            SubmitResult { event, candidates: vec![] }
        })
    }

    pub fn submit_parameter_revision(&self, input: ParameterInput) -> Result<SubmitResult, ConflictResponse> {
        let result = self.submit(input.parent_event_id, input.branch_id.clone(), input.expected_parent_event_id, |parent, sequence, _, mats| {
            let params = parent.params_revision + 1;
            Ok(EventRecord {
                event_id: format!("evt-{sequence:02}-parameters-{params}"),
                parent_event_id: Some(parent.event_id.clone()),
                sequence,
                kind: "parameter-revision".into(),
                label: input.label.clone(),
                rule_version: parent.rule_version.clone(),
                params_revision: params,
                material_revision: mats,
                branch_id: input.branch_id.clone(),
                payload: serde_json::json!({"expected_image_base":format!("0x{:x}[VA-byte]",input.expected_image_base),"label":input.label,"rationale":input.rationale}),
                invalidation_scope: dependency_scope_for_parameters(),
                actor: "reviewer".into(),
            })
        })?;
        let material = revised_base_material(input.expected_image_base);
        let mut materials = self.list_materials().map_err(conflict_error)?;
        materials.push(material.clone());
        let candidates = generate_candidates(&materials, result.event.params_revision, result.event.material_revision, &result.event.event_id);
        self.persist_submitted(&result.event, &candidates, Some(material)).map_err(conflict_error)?;
        Ok(SubmitResult { event: result.event, candidates })
    }

    pub fn submit_source_revision(&self, input: SourceChangeInput) -> Result<SubmitResult, ConflictResponse> {
        let result = self.submit(input.parent_event_id, input.branch_id.clone(), input.expected_parent_event_id, |parent, sequence, params, _| {
            let mats = parent.material_revision + 1;
            Ok(EventRecord {
                event_id: format!("evt-{sequence:02}-source-{mats}"),
                parent_event_id: Some(parent.event_id.clone()),
                sequence,
                kind: "source-revision".into(),
                label: input.label.clone(),
                rule_version: parent.rule_version.clone(),
                params_revision: params,
                material_revision: mats,
                branch_id: input.branch_id.clone(),
                payload: serde_json::json!({"label":input.label,"rationale":input.rationale,"changed_material":format!("{SNAPSHOT_ID}:{mats}"),"scope":"local dependency exports only"}),
                invalidation_scope: vec!["import-feature.dll-0".into(), "import-feature.dll-1".into()],
                actor: "dependency-team".into(),
            })
        })?;
        let material = build_revised_snapshot_material();
        let mut materials = self.list_materials().map_err(conflict_error)?;
        materials.push(material.clone());
        let candidates = generate_candidates(&materials, result.event.params_revision, result.event.material_revision, &result.event.event_id);
        self.persist_submitted(&result.event, &candidates, Some(material)).map_err(conflict_error)?;
        Ok(SubmitResult { event: result.event, candidates })
    }

    pub fn undo_branch_head(&self, branch_id: &str) -> Result<EventRecord, String> {
        let conn = self.conn.lock().unwrap();
        let head_id: String = conn.query_row("SELECT head_event_id FROM branches WHERE branch_id=?1", params![branch_id], |r| r.get(0))?;
        let parent: String = conn.query_row("SELECT parent_event_id FROM events WHERE event_id=?1", params![head_id], |r| r.get::<_, Option<String>>(0))?.ok_or_else(|| "initial import cannot be undone".to_string())?;
        conn.execute("UPDATE branches SET head_event_id=?1 WHERE branch_id=?2", params![parent, branch_id])?;
        load_event(&conn, &parent)?.ok_or_else(|| "parent disappeared".to_string())
    }

    fn submit<F>(&self, parent_id: String, branch_id: String, expected: Option<String>, make_event: F) -> Result<EventRecord, ConflictResponse>
    where F: FnOnce(&EventRecord, i64, u32, u32) -> Result<EventRecord, String> {
        let conn = self.conn.lock().unwrap();
        let branch = load_branch(&conn, &branch_id).map_err(conflict_error)?.ok_or_else(|| conflict_error("unknown branch"))?;
        if branch.head_event_id != parent_id {
            return Err(self.conflict(&conn, &parent_id, &branch.head_event_id));
        }
        if let Some(expected) = expected {
            if expected != branch.head_event_id {
                return Err(self.conflict(&conn, &expected, &branch.head_event_id));
            }
        }
        let parent = load_event(&conn, &parent_id).map_err(conflict_error)?.ok_or_else(|| conflict_error("unknown parent event"))?;
        make_event(&parent, parent.sequence + 1, parent.params_revision, parent.material_revision).map_err(conflict_error)
    }

    fn persist_submitted(&self, event: &EventRecord, candidates: &[Candidate], extra_material: Option<Material>) -> Result<(), String> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        if let Some(material) = extra_material {
            tx.execute(
                "INSERT OR IGNORE INTO materials(material_id,revision,kind,label,original_representation,bytes,byte_encoding,supersedes) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![material.material_id,material.revision,material.kind,material.label,serde_json::to_string(&material.original_representation)?,material.bytes,material.byte_encoding,material.supersedes]
            ).map_err(|e| e.to_string())?;
        }
        tx.execute(
            "INSERT INTO events(event_id,parent_event_id,sequence,kind,label,rule_version,params_revision,material_revision,branch_id,payload,actor) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![event.event_id,event.parent_event_id,event.sequence,event.kind,event.label,event.rule_version,event.params_revision,event.material_revision,event.branch_id,serde_json::to_string(&event.payload)?,event.actor]
        ).map_err(|e| e.to_string())?;
        for scope in &event.invalidation_scope {
            tx.execute("INSERT INTO event_invalidation_scope(event_id,subject_id) VALUES(?1,?2)", params![event.event_id, scope]).map_err(|e| e.to_string())?;
        }
        for candidate in candidates {
            tx.execute(
                "INSERT INTO candidates(candidate_id,event_id,subject_id,subject_kind,subject_label,option_id,option_label,status,value,evidence,source_refs,invalidated_by,depends_on,rule_version,params_revision,material_revision,batch) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                params![candidate.candidate_id,candidate.created_by_event,candidate.subject_id,candidate.subject_kind,candidate.subject_label,candidate.option_id,candidate.option_label,candidate.status,serde_json::to_string(&candidate.value)?,serde_json::to_string(&candidate.evidence)?,serde_json::to_string(&candidate.source_refs)?,candidate.invalidated_by,serde_json::to_string(&candidate.depends_on)?,candidate.rule_version,candidate.params_revision,candidate.material_revision,candidate.batch]
            ).map_err(|e| e.to_string())?;
        }
        tx.execute("UPDATE branches SET head_event_id=?1 WHERE branch_id=?2", params![event.event_id, event.branch_id]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    fn conflict(&self, conn: &Connection, your_parent: &str, current: &str) -> ConflictResponse {
        let your_event = load_event(conn, your_parent).ok().flatten();
        let current_event = load_event(conn, current).ok().flatten();
        ConflictResponse {
            error: "optimistic version conflict".into(),
            code: "VERSION_CONFLICT".into(),
            details: ConflictDetail {
                your_parent: your_parent.into(),
                current_head: current.into(),
                your_summary: your_event.map(|e| e.label).unwrap_or_else(|| your_parent.into()),
                current_summary: current_event.map(|e| e.label).unwrap_or_else(|| current.into()),
                differing_subjects: vec!["rva-0x3100".into(), "branch-head".into()],
            },
        }
    }

    pub fn open(path: &str) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        let store = Self { conn: Mutex::new(conn) };
        store.migrate()?;
        Ok(store)
    }

    pub fn in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        let store = Self { conn: Mutex::new(conn) };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").ok();
        conn.execute_batch(r#"
        CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT 'fixed-offline-timestamp');
        CREATE TABLE IF NOT EXISTS materials(
          material_id TEXT NOT NULL,
          revision INTEGER NOT NULL,
          kind TEXT NOT NULL,
          label TEXT NOT NULL,
          original_representation TEXT NOT NULL,
          bytes TEXT NOT NULL,
          byte_encoding TEXT NOT NULL,
          supersedes TEXT,
          PRIMARY KEY(material_id, revision)
        );
        CREATE TABLE IF NOT EXISTS events(
          event_id TEXT PRIMARY KEY,
          parent_event_id TEXT,
          sequence INTEGER NOT NULL,
          kind TEXT NOT NULL,
          label TEXT NOT NULL,
          rule_version TEXT NOT NULL,
          params_revision INTEGER NOT NULL,
          material_revision INTEGER NOT NULL,
          branch_id TEXT NOT NULL,
          payload TEXT NOT NULL,
          actor TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS branches(
          branch_id TEXT PRIMARY KEY,
          label TEXT NOT NULL,
          head_event_id TEXT NOT NULL,
          created_from_event_id TEXT NOT NULL
        );
        "#).map_err(|e| e.to_string())?;
        let has_v1: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='candidates'", [], |r| r.get(0)).unwrap_or(0);
        if has_v1 == 0 {
            conn.execute_batch(r#"
            CREATE TABLE candidates(
              candidate_id TEXT NOT NULL,
              event_id TEXT NOT NULL,
              subject_id TEXT NOT NULL,
              subject_kind TEXT NOT NULL,
              subject_label TEXT NOT NULL,
              option_id TEXT NOT NULL,
              option_label TEXT NOT NULL,
              status TEXT NOT NULL,
              value TEXT NOT NULL,
              evidence TEXT NOT NULL,
              source_refs TEXT NOT NULL,
              invalidated_by TEXT,
              depends_on TEXT NOT NULL,
              rule_version TEXT NOT NULL,
              params_revision INTEGER NOT NULL,
              material_revision INTEGER NOT NULL,
              batch TEXT NOT NULL,
              PRIMARY KEY(candidate_id, event_id)
            );
            "#).map_err(|e| e.to_string())?;
            conn.execute("INSERT INTO schema_migrations(version) VALUES (1)", []).map_err(|e| e.to_string())?;
        }
        let has_v2: i64 = conn.query_row("SELECT COUNT(*) FROM schema_migrations WHERE version=2", [], |r| r.get(0)).unwrap_or(0);
        if has_v2 == 0 {
            conn.execute_batch(r#"
            CREATE TABLE IF NOT EXISTS event_invalidation_scope(event_id TEXT PRIMARY KEY, subject_id TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_candidates_subject_event ON candidates(subject_id, event_id);
            CREATE INDEX IF NOT EXISTS idx_events_branch ON events(branch_id, sequence);
            "#).map_err(|e| e.to_string())?;
            conn.execute("INSERT INTO schema_migrations(version) VALUES (2)", []).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn schema_version(&self) -> Result<i64, String> {
        self.conn.lock().unwrap().query_row("SELECT MAX(version) FROM schema_migrations", [], |r| r.get(0)).map_err(|e| e.to_string())
    }

    pub fn seed_bundle_if_empty(&self) -> Result<(), String> {
        let count: i64 = self.conn.lock().unwrap().query_row("SELECT COUNT(*) FROM materials", [], |r| r.get(0)).map_err(|e| e.to_string())?;
        if count > 0 { return Ok(()); }
        let materials = build_initial_materials();
        let initial_candidates = generate_candidates(&materials, 1, 1, "evt-01-import");
        let mut candidates = initial_candidates;
        candidates.extend(generate_candidates(&materials, 2, 1, "evt-02-parameters"));
        let mut revised_materials = materials.clone();
        revised_materials.push(build_revised_snapshot_material());
        candidates.extend(generate_candidates(&revised_materials, 2, 2, "evt-03-local-source"));

        let events = vec![
            EventRecord {
                event_id: "evt-01-import".into(), parent_event_id: None, sequence: 1,
                kind: "import".into(), label: "Initial intake: PE bytes, expected image base, DLL export snapshot".into(),
                rule_version: RULE_VERSION_1.into(), params_revision: 1, material_revision: 1,
                branch_id: "branch-main".into(), payload: serde_json::json!({"mode":"narrative-intake"}),
                invalidation_scope: vec![], actor: "system".into(),
            },
            EventRecord {
                event_id: "evt-02-parameters".into(), parent_event_id: Some("evt-01-import".into()), sequence: 2,
                kind: "parameter-revision".into(), label: "Parameter revision: expected image base changes to 0x180000000".into(),
                rule_version: RULE_VERSION_1.into(), params_revision: 2, material_revision: 1,
                branch_id: "branch-main".into(),
                payload: serde_json::json!({"expected_image_base":"0x180000000[VA-byte]","change":"parameter only; original material retained"}),
                invalidation_scope: vec!["rva-0x1008".into(), "rva-0x2008".into(), "rva-0x3100".into(), "rva-0x5000".into(), "file-offset-0x408".into(), "reloc-block-0-entry-0".into(), "reloc-block-1-entry-0".into(), "reloc-block-2-entry-0".into()],
                actor: "reviewer".into(),
            },
            EventRecord {
                event_id: "evt-03-local-source".into(), parent_event_id: Some("evt-02-parameters".into()), sequence: 3,
                kind: "source-revision".into(), label: "Local dependency source change: feature.dll!DoThing export RVA changes".into(),
                rule_version: RULE_VERSION_1.into(), params_revision: 2, material_revision: 2,
                branch_id: "branch-main".into(),
                payload: serde_json::json!({"changed_material":"material-dll-export-snapshot:2","scope":"feature.dll!DoThing and forwarded chain only"}),
                invalidation_scope: vec!["import-feature.dll-0".into(), "import-feature.dll-1".into()],
                actor: "dependency-team".into(),
            },
            EventRecord {
                event_id: "evt-04a-accept-overlap".into(), parent_event_id: Some("evt-03-local-source".into()), sequence: 4,
                kind: "decision".into(), label: "Conflicting human decision A: accept .ovlp source at zero-fill overlap".into(),
                rule_version: RULE_VERSION_1.into(), params_revision: 2, material_revision: 2,
                branch_id: "branch-main".into(),
                payload: serde_json::json!({"subject_id":"rva-0x3100","accepted_option_id":"zero-fill-1"}),
                invalidation_scope: vec![], actor: "window-one".into(),
            },
            EventRecord {
                event_id: "evt-04b-reject-overlap".into(), parent_event_id: Some("evt-03-local-source".into()), sequence: 4,
                kind: "decision".into(), label: "Conflicting human decision B: require mapped .reloc source".into(),
                rule_version: RULE_VERSION_1.into(), params_revision: 2, material_revision: 2,
                branch_id: "branch-alt".into(),
                payload: serde_json::json!({"subject_id":"rva-0x3100","accepted_option_id":"mapped-file-bytes-0"}),
                invalidation_scope: vec![], actor: "window-two".into(),
            },
        ];
        let branches = vec![
            Branch { branch_id: "branch-main".into(), label: "Review window one".into(), head_event_id: "evt-04a-accept-overlap".into(), created_from_event_id: "evt-01-import".into() },
            Branch { branch_id: "branch-alt".into(), label: "Review window two".into(), head_event_id: "evt-04b-reject-overlap".into(), created_from_event_id: "evt-01-import".into() },
        ];
        self.replace_all(Bundle { schema_version: 3, materials: revised_materials, events, candidates, branches })?;
        Ok(())
    }
