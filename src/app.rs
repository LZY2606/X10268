//! HTTP 层：Axum 路由。所有裁定走事件追加；乐观锁在并发保存时返回 409 + 双方差异。

use crate::db;
use crate::model::Decision;
use crate::service;
use crate::state;
use axum::{extract::State, http::StatusCode, response::{Html, IntoResponse, Response}, routing::{get, post}, Json, Router};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AppState {
    pub conn: Arc<Mutex<Connection>>,
}

pub fn router(conn: Connection) -> Router {
    let st = AppState { conn: Arc::new(Mutex::new(conn)) };
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/style.css", get(style_css))
        .route("/api/health", get(health))
        .route("/api/cases", get(list_cases).post(import_case_doc))
        .route("/api/fixture/load", post(load_fixture))
        .route("/api/fixture/pack", get(fixture_pack))
        .route("/api/cases/{id}/export", get(export_case))
        .route("/api/cases/{id}", get(get_case).delete(delete_case_route))
        .route("/api/cases/{id}/branches", get(list_branches).post(create_branch_route))
        .route("/api/cases/{id}/branches/{branch}/view", get(view_branch))
        .route("/api/cases/{id}/branches/{branch}/revise-rules", post(revise_rules_route))
        .route("/api/cases/{id}/branches/{branch}/revise-source", post(revise_source_route))
        .route("/api/cases/{id}/branches/{branch}/decide", post(decide_route))
        .route("/api/cases/{id}/branches/{branch}/undo", post(undo_route))
        .route("/api/cases/{id}/branches/{branch}/seed-alt", post(seed_alt))
        .with_state(st)
}

async fn health() -> Json<Value> { Json(json!({"ok": true})) }
async fn index() -> Html<&'static str> { Html(include_str!("web/index.html")) }
async fn app_js() -> Response {
    ([("content-type", "application/javascript; charset=utf-8")], include_str!("web/app.js")).into_response()
}
async fn style_css() -> Response {
    ([("content-type", "text/css; charset=utf-8")], include_str!("web/style.css")).into_response()
}

async fn list_cases(State(st): State<AppState>) -> ApiResult<Json<Value>> {
    let conn = st.conn.lock().unwrap();
    Ok(Json(json!({"cases": db::list_cases(&conn)?})))
}

async fn load_fixture(State(st): State<AppState>) -> ApiResult<(StatusCode, Json<Value>)> {
    let mut conn = st.conn.lock().unwrap();
    let id = service::seed_fixture(&mut conn)?;
    service::seed_alt_conflict(&mut conn)?;
    Ok((StatusCode::OK, Json(json!({"case_id": id, "branch": service::MAIN_BRANCH}))))
}

async fn fixture_pack() -> Json<Value> {
    let pe = crate::fixture::build_pe();
    Json(json!({
        "format": "pe-loader-bench-fixture-pack",
        "case": {"id": crate::fixture::CASE_ID, "name": crate::fixture::CASE_NAME},
        "pe_bytes_sha256": db::sha256_hex(&pe.bytes),
        "pe_bytes_len": pe.bytes.len(),
        "expected_image_base": {"value": crate::fixture::EXPECTED_BASE, "unit": "va"},
        "sections": crate::fixture::sections().iter().map(|(n,vs,va,rs,rp)| json!({
            "name": n, "virtual_size": {"value": vs, "unit": "byte"},
            "virtual_address": {"value": va, "unit": "rva"},
            "size_of_raw_data": {"value": rs, "unit": "byte"},
            "pointer_to_raw_data": {"value": rp, "unit": "byte"}})).collect::<Vec<_>>(),
        "rules_v1": crate::fixture::rules_v1(),
        "rules_v2": crate::fixture::rules_v2(),
        "export_snapshots": crate::fixture::export_snapshots(),
        "edge_cases": ["section_overlap", "virtual_size_gt_raw", "relocation_overflow",
                       "ordinal_import", "forwarded_export", "missing_dll", "corrupt_directory_range"],
    }))
}

async fn get_case(State(st): State<AppState>, axum::extract::Path(id): axum::extract::Path<String>)
    -> ApiResult<Json<Value>> {
    let conn = st.conn.lock().unwrap();
    if !db::case_exists(&conn, &id) { return Err(ApiError::not_found("case")); }
    let branches = db::list_branches(&conn, &id)?;
    Ok(Json(json!({"id": id, "branches": branches})))
}

async fn list_branches(State(st): State<AppState>, axum::extract::Path(id): axum::extract::Path<String>)
    -> ApiResult<Json<Value>> {
    let conn = st.conn.lock().unwrap();
    Ok(Json(json!({"branches": db::list_branches(&conn, &id)?})))
}

async fn create_branch_route(State(st): State<AppState>, axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<Value>) -> ApiResult<(StatusCode, Json<Value>)> {
    let conn = st.conn.lock().unwrap();
    let bid = body.get("branch_id").and_then(|v| v.as_str()).unwrap_or("branch-new");
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("新分支");
    let parent = body.get("parent_branch_id").and_then(|v| v.as_str());
    db::create_branch(&conn, &id, bid, name, parent)?;
    Ok((StatusCode::CREATED, Json(json!({"branch_id": bid}))))
}

#[derive(serde::Deserialize)]
struct ViewQuery { upto_seq: Option<i64> }

async fn view_branch(State(st): State<AppState>,
    axum::extract::Path((id, branch)): axum::extract::Path<(String, String)>,
    axum::extract::Query(q): axum::extract::Query<ViewQuery>) -> ApiResult<Json<Value>> {
    let conn = st.conn.lock().unwrap();
    let view = state::view_at(&conn, &id, &branch, q.upto_seq)?;
    let facts: Vec<Value> = view.facts.iter().map(|f| json!({
        "id": f.id, "kind": f.kind, "subject": f.subject, "ordinal": f.ordinal,
        "status": f.status, "candidates": f.candidates, "deps": f.deps,
        "evidence": f.evidence, "diagnostics": f.diagnostics,
    })).collect();
    Ok(Json(json!({
        "case_id": view.case_id, "branch_id": view.branch_id, "version": view.version,
        "rules": {"id": view.rules.id, "version": view.rules.version, "params": view.rules.params, "note": view.rules.note},
        "materials": view.materials, "facts": facts, "decisions": view.decisions,
        "events": view.events, "invalidations": view.invalidations,
    })))
}

async fn revise_rules_route(State(st): State<AppState>,
    axum::extract::Path((id, branch)): axum::extract::Path<(String, String)>)
    -> ApiResult<(StatusCode, Json<Value>)> {
    let mut conn = st.conn.lock().unwrap();
    let r = service::revise_rules(&mut conn, &id, &branch)?;
    Ok((StatusCode::CREATED, Json(r)))
}

async fn revise_source_route(State(st): State<AppState>,
    axum::extract::Path((id, branch)): axum::extract::Path<(String, String)>)
    -> ApiResult<(StatusCode, Json<Value>)> {
    let mut conn = st.conn.lock().unwrap();
    let r = service::revise_local_source(&mut conn, &id, &branch)?;
    Ok((StatusCode::CREATED, Json(r)))
}

#[derive(serde::Deserialize)]
struct DecideBody {
    fact_id: String,
    candidate_id: String,
    action: String,
    rationale: Option<String>,
    expected_version: Option<i64>,
}

async fn decide_route(State(st): State<AppState>,
    axum::extract::Path((id, branch)): axum::extract::Path<(String, String)>,
    Json(body): Json<DecideBody>) -> ApiResult<Response> {
    let mut conn = st.conn.lock().unwrap();
    let before = state::view_at(&conn, &id, &branch, None)?;
    let decision = Decision {
        fact_id: body.fact_id, candidate_id: body.candidate_id, action: body.action,
        rationale: body.rationale.unwrap_or_default(),
    };
    match service::submit_decision(&mut conn, &id, &branch, decision, body.expected_version) {
        Ok(r) => Ok((StatusCode::CREATED, Json(r)).into_response()),
        Err(e) if is_conflict(&e) => {
            let after = state::view_at(&conn, &id, &branch, None)?;
            let payload = json!({
                "error": "version_conflict",
                "message": "后提交者检测到版本冲突",
                "your_base_version": body.expected_version,
                "current_version": after.version,
                "diff": {
                    "events_only_on_server": after.events.iter()
                        .filter(|e| e.get("seq").and_then(|v| v.as_i64()).unwrap_or(0) > before.version)
                        .cloned().collect::<Vec<_>>(),
                    "your_pending_decision": body.fact_id,
                },
            });
            Ok((StatusCode::CONFLICT, Json(payload)).into_response())
        }
        Err(e) => Err(e.into()),
    }
}

async fn undo_route(State(st): State<AppState>,
    axum::extract::Path((id, branch)): axum::extract::Path<(String, String)>)
    -> ApiResult<(StatusCode, Json<Value>)> {
    let mut conn = st.conn.lock().unwrap();
    let r = service::undo_last_decision(&mut conn, &id, &branch)?;
    Ok((StatusCode::CREATED, Json(r)))
}

async fn seed_alt(State(st): State<AppState>,
    axum::extract::Path((id, branch)): axum::extract::Path<(String, String)>)
    -> ApiResult<(StatusCode, Json<Value>)> {
    let mut conn = st.conn.lock().unwrap();
    service::seed_alt_conflict(&mut conn)?;
    Ok((StatusCode::CREATED, Json(json!({"case_id": id, "branch": branch}))))
}

async fn export_case(State(st): State<AppState>, axum::extract::Path(id): axum::extract::Path<String>)
    -> ApiResult<Json<Value>> {
    let conn = st.conn.lock().unwrap();
    Ok(Json(db::export_case(&conn, &id)?))
}

async fn import_case_doc(State(st): State<AppState>, Json(doc): Json<Value>)
    -> ApiResult<(StatusCode, Json<Value>)> {
    let mut conn = st.conn.lock().unwrap();
    let id = db::import_case(&mut conn, &doc)?;
    Ok((StatusCode::CREATED, Json(json!({"case_id": id}))))
}

async fn delete_case_route(State(st): State<AppState>, axum::extract::Path(id): axum::extract::Path<String>)
    -> ApiResult<Json<Value>> {
    let mut conn = st.conn.lock().unwrap();
    db::delete_case(&mut conn, &id)?;
    Ok(Json(json!({"deleted": id})))
}

fn is_conflict(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(_, Some(msg)) if msg.contains("version_conflict"))
}

type ApiResult<T> = Result<T, ApiError>;
struct ApiError { status: StatusCode, message: String }
impl ApiError {
    fn not_found(what: &str) -> Self { ApiError { status: StatusCode::NOT_FOUND, message: format!("{what} not found") } }
}
impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        let status = if is_conflict(&e) { StatusCode::CONFLICT } else { StatusCode::INTERNAL_SERVER_ERROR };
        ApiError { status, message: e.to_string() }
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.message}))).into_response()
    }
}
