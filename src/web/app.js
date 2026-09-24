"use strict";
// 完全本地前端。所有显示值带 data-fact-id / data-candidate-id 稳定身份。
const CASE_ID = "case-pe-loader-mirror";
const state = { view: null, branch: "main", uptoSeq: "", baseVersion: null };

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };

async function api(path, opts = {}) {
  const res = await fetch(path, { headers: { "content-type": "application/json" }, ...opts });
  const body = await res.json().catch(() => ({}));
  return { status: res.status, body };
}

async function loadFixture() {
  await api("/api/fixture/load", { method: "POST", body: "{}" });
  await refreshBranches();
}

async function refreshBranches() {
  const { body } = await api(`/api/cases/${CASE_ID}`);
  const sel = $("#branch-select");
  sel.innerHTML = "";
  (body.branches || []).forEach((b) => {
    const o = el("option", null, `${b.name} (${b.id})`);
    o.value = b.id;
    if (b.id === state.branch) o.selected = true;
    sel.appendChild(o);
  });
  await loadView();
}

async function loadView() {
  const q = state.uptoSeq ? `?upto_seq=${state.uptoSeq}` : "";
  const { body } = await api(`/api/cases/${CASE_ID}/branches/${state.branch}/view${q}`);
  state.view = body;
  state.baseVersion = body.version;
  $("#version-badge").textContent = `branch=${state.branch} v=${body.version}`;
  renderEvents();
  renderAddress();
  renderSections();
  renderRelocs();
  renderImports();
  renderUnresolved();
  renderMaterials();
}

function factCandidatesHtml(fact) {
  const wrap = el("div", "candidates");
  fact.candidates.forEach((c) => {
    const decision = (state.view.decisions || []).find(
      (d) => d[0] === fact.id && d[1] === c.id);
    const row = el("div", `candidate ${c.valid ? "" : "invalid"} ${decision ? decision[2] : ""}`);
    row.dataset.factId = fact.id;
    row.dataset.candidateId = c.id;
    const tag = el("span", `tag ${c.kind}`, c.kind);
    row.appendChild(tag);
    const body = el("div");
    body.appendChild(el("div", null, c.label));
    body.appendChild(el("div", "basis", "判定依据: " + c.basis));
    const pre = el("pre", "small");
    pre.textContent = JSON.stringify(c.value, null, 1);
    body.appendChild(pre);
    row.appendChild(body);
    const btns = el("div");
    const accept = el("button", null, "接受");
    const reject = el("button", null, "否定");
    accept.onclick = () => decide(fact, c, "accept");
    reject.onclick = () => decide(fact, c, "reject");
    btns.append(accept, reject);
    if (decision) {
      btns.appendChild(el("span", "small", ` 已${decision[2] === "accept" ? "接受" : "否定"}`));
    }
    row.appendChild(btns);
    wrap.appendChild(row);
  });
  return wrap;
}

function factCard(fact) {
  const card = el("div", "fact");
  card.dataset.factId = fact.id;
  const head = el("div", "head");
  head.appendChild(el("span", `status ${fact.status}`, fact.status));
  head.appendChild(el("strong", null, fact.subject));
  head.appendChild(el("span", "small", fact.kind));
  head.appendChild(el("code", "evidence", fact.id));
  const detail = el("div", "hidden");
  detail.appendChild(factCandidatesHtml(fact));
  if (fact.diagnostics && fact.diagnostics.length) {
    const ul = el("div", "card");
    fact.diagnostics.forEach((d) => {
      ul.appendChild(el("div", null, `[${d.severity}] ${d.code}: ${d.message}`));
    });
    detail.appendChild(ul);
  }
  if (fact.evidence && fact.evidence.length) {
    detail.appendChild(el("div", "evidence",
      "字节来源: " + fact.evidence.map((b) => `${b.artifact_id}@0x${b.offset.toString(16)}+${b.len}(${b.field})`).join("; ")));
  }
  head.onclick = () => detail.classList.toggle("hidden");
  card.append(head, detail);
  return card;
}

function factsOfKind(kind) { return (state.view.facts || []).filter((f) => f.kind === kind); }

function renderAddress() {
  const host = $("#tab-address");
  host.innerHTML = "";
  host.appendChild(el("p", "small",
    "RVA→文件偏移：无映射 / 节重叠 / 仅零填充 均保留为候选，系统不强行选一。"));
  // 文件/虚拟地址对照表来自 section_map
  factsOfKind("section_map").forEach((f) => {
    const card = factCard(f);
    host.appendChild(card);
  });
  factsOfKind("rva_resolution").forEach((f) => host.appendChild(factCard(f)));
  factsOfKind("image_summary").forEach((f) => host.appendChild(factCard(f)));
}

function renderSections() {
  const host = $("#tab-sections");
  host.innerHTML = "";
  const barHost = el("div", "card");
  barHost.appendChild(el("strong", null, "虚拟区间 (RVA, 单位 byte)"));
  const bar = el("div", "rangebar");
  const maxRva = 0x6000;
  factsOfKind("section_map").forEach((f) => {
    const mapped = f.candidates.find((c) => c.kind === "mapped");
    if (!mapped) return;
    const fo = mapped.value.file_offset, mb = mapped.value.mapped_bytes;
    const mat = (state.view.materials || []).find((m) => m.kind === "section_header" && m.payload.name === f.subject);
    if (!mat) return;
    const va = mat.payload.virtual_address.value, vs = mat.payload.virtual_size.value;
    const seg = el("div", "seg");
    seg.style.left = `${(va / maxRva) * 100}%`;
    seg.style.width = `${(vs / maxRva) * 100}%`;
    seg.style.background = "#90cdf4";
    seg.title = `${f.subject} RVA 0x${va.toString(16)} vs 0x${(va + vs).toString(16)}`;
    seg.textContent = f.subject;
    seg.dataset.factId = f.id;
    bar.appendChild(seg);
  });
  barHost.appendChild(bar);
  host.appendChild(barHost);
  const tableCard = el("div", "card");
  const table = el("table");
  table.innerHTML = "<tr><th>section</th><th>virtual address (rva)</th><th>virtual size</th><th>raw ptr (byte)</th><th>raw size</th><th>映射/零填充</th></tr>";
  factsOfKind("section_map").forEach((f) => {
    const mat = (state.view.materials || []).find((m) => m.kind === "section_header" && m.payload.name === f.subject);
    if (!mat) return;
    const tr = el("tr");
    tr.dataset.factId = f.id;
    const kinds = f.candidates.map((c) => c.kind).join(",");
    tr.innerHTML = `<td><code>${f.subject}</code></td><td>0x${mat.payload.virtual_address.value.toString(16)}</td>
      <td>0x${mat.payload.virtual_size.value.toString(16)}</td>
      <td>0x${mat.payload.pointer_to_raw_data.value.toString(16)}</td>
      <td>0x${mat.payload.size_of_raw_data.value.toString(16)}</td><td>${kinds}</td>`;
    table.appendChild(tr);
  });
  tableCard.appendChild(table);
  host.appendChild(tableCard);
}

function renderRelocs() {
  const host = $("#tab-relocs");
  host.innerHTML = "";
  host.appendChild(el("p", "small", "重定位按类型与位宽执行；溢出与越界作为无效候选保留，不静默打补丁。"));
  factsOfKind("reloc_patch").forEach((f) => host.appendChild(factCard(f)));
}

function renderImports() {
  const host = $("#tab-imports");
  host.innerHTML = "";
  // import 图：DLL -> 符号节点
  const graph = el("div", "card");
  graph.appendChild(el("strong", null, "import 图"));
  factsOfKind("import_binding").forEach((f) => {
    const line = el("div", "edge");
    line.dataset.factId = f.id;
    const dll = f.subject.split("!")[0];
    const c = f.candidates[0];
    const kind = c ? c.kind : "none";
    line.textContent = `main.exe ── ${f.subject} [${kind}]`;
    graph.appendChild(line);
  });
  host.appendChild(graph);
  factsOfKind("import_binding").forEach((f) => host.appendChild(factCard(f)));
}

function renderUnresolved() {
  const host = $("#tab-unresolved");
  host.innerHTML = "";
  const list = factsOfKind("import_binding").filter((f) => f.status === "unresolved" || f.status === "error");
  if (!list.length) host.appendChild(el("p", "small", "没有未解析符号。"));
  list.forEach((f) => host.appendChild(factCard(f)));
}

function renderMaterials() {
  const host = $("#tab-materials");
  host.innerHTML = "";
  host.appendChild(el("p", "small", "来源与解释分开保存；以下为当前分支可见原始材料（旧版本仍在数据库中可读）。"));
  (state.view.materials || []).forEach((m) => {
    const card = el("div", "fact");
    card.dataset.materialId = m.id;
    const head = el("div", "head");
    head.appendChild(el("strong", null, m.kind));
    head.appendChild(el("code", "evidence", m.id));
    const detail = el("div", "hidden");
    const pre = el("pre", "small");
    pre.textContent = JSON.stringify({ payload: m.payload, byte_sources: m.byte_sources, diagnostics: m.diagnostics }, null, 1);
    detail.appendChild(pre);
    head.onclick = () => detail.classList.toggle("hidden");
    card.append(head, detail);
    host.appendChild(card);
  });
}

function renderEvents() {
  const sel = $("#event-select");
  sel.innerHTML = '<option value="">最新</option>';
  (state.view.events || []).forEach((e) => {
    const o = el("option", null, `#${e.seq} ${e.kind}`);
    o.value = e.seq;
    if (String(e.seq) === String(state.uptoSeq)) o.selected = true;
    sel.appendChild(o);
  });
  const host = $("#tab-events");
  host.innerHTML = "";
  const rules = el("div", "card");
  rules.appendChild(el("strong", null, `当前规则版本: v${state.view.rules.version} (${state.view.rules.id})`));
  const pre = el("pre", "small"); pre.textContent = JSON.stringify(state.view.rules.params, null, 1);
  rules.appendChild(pre);
  host.appendChild(rules);
  (state.view.events || []).forEach((e) => {
    const card = el("div", "fact");
    card.dataset.eventId = e.id;
    const head = el("div", "head");
    head.appendChild(el("strong", null, `#${e.seq} ${e.kind}`));
    head.appendChild(el("code", "evidence", e.id));
    const detail = el("div", "hidden");
    detail.appendChild(el("pre", "small", JSON.stringify(e.payload, null, 1)));
    head.onclick = () => detail.classList.toggle("hidden");
    card.append(head, detail);
    host.appendChild(card);
  });
  (state.view.invalidations || []).forEach((inv) => {
    const card = el("div", "card");
    card.dataset.invalidationEventId = inv.event_id;
    card.appendChild(el("strong", null, `失效范围 @event #${inv.event_seq}`));
    const pre = el("pre", "small");
    pre.textContent = JSON.stringify(inv, null, 1);
    card.appendChild(pre);
    host.appendChild(card);
  });
}

async function decide(fact, candidate, action) {
  const rationale = prompt(`裁定理由 (${action})`, action === "accept" ? "审阅接受该候选" : "审阅否定该候选");
  if (rationale === null) return;
  const { status, body } = await api(
    `/api/cases/${CASE_ID}/branches/${state.branch}/decide`, {
      method: "POST",
      body: JSON.stringify({ fact_id: fact.id, candidate_id: candidate.id, action, rationale,
        expected_version: state.baseVersion }),
    });
  if (status === 409) {
    $("#conflict-detail").textContent = JSON.stringify(body, null, 2);
    $("#conflict-dialog").showModal();
  }
  await loadView();
}
