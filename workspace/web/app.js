// ECO 签核工作台前端（零依赖原生 JS）
const $ = (id) => document.getElementById(id);
const STATUS_CN = {
  DRAFT: "草稿", FROZEN: "已冻结/验证中", QUEUED: "排队等待",
  REBASE_REQUIRED: "需基于新基线刷新", RELEASING: "发布中断(待恢复)",
  RELEASED: "已发布", ABORTED: "已中止", MERGED: "已并入他单",
};
const CHECK_CN = {TIMING_STA: "时序STA", POWER_ANALYSIS: "功耗", FORMAL_EQUIV: "形式验证",
                  LAYOUT_DRC: "版图DRC", LINT_INFO: "Lint(非必需)"};
const ROLE_CN = {TIMING_LEAD: "时序负责人", METHODOLOGY_LEAD: "方法学负责人"};
const DG_STATUS = {ACTIVE: "生效中", PENDING: "未生效", EXPIRED: "已过期", REVOKED: "已撤销"};

function toast(msg, kind="") {
  const t = document.createElement("div");
  t.className = "toast " + kind; t.innerHTML = msg;
  $("toast").appendChild(t);
  setTimeout(() => t.remove(), 6000);
}

async function api(path, method="GET", body) {
  const opt = {method, headers: {"Content-Type": "application/json"}};
  if (body) opt.body = JSON.stringify(body);
  const r = await fetch(path, opt);
  const j = await r.json();
  if (!r.ok) throw Object.assign(new Error(j.message), {resp: j});
  return j;
}

// ---- Runner 侧自行计算指纹（与服务端 Python canon 完全一致的紧凑规范序列化）----
function canon(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return JSON.stringify(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  return "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
}
async function sha16(obj) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canon(obj)));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,"0")).join("").slice(0,16);
}
async function runnerFp(check) {
  // 不偷看服务端 expected_fingerprint：只凭冻结输入包自行哈希
  const spec = window.CATALOG.find(c => c.type === check);
  const obj = {verification_matrix: window.MATRIX};
  if (spec.scopes.includes("netlist")) obj.modules = Object.fromEntries(
    Object.entries(window.SNAP_MODULES).sort().map(([m,d])=>[m,{netlist:d.netlist,version:d.version}]));
  if (spec.scopes.includes("sdc")) obj.constraints = window.SNAP_CONS;
  if (spec.scopes.includes("modules")) obj.affected_modules = window.SNAP_AFFECTED;
  return sha16(obj);
}

async function runOne(ecoId, type, verdict="PASS", opts={}) {
  const pkt = await api(`/api/ecos/${ecoId}/checks/${type}/inputs`);
  window.MATRIX = pkt.inputs.verification_matrix;
  window.SNAP_MODULES = pkt.inputs.modules || {};
  window.SNAP_CONS = pkt.inputs.constraints || {};
  window.SNAP_AFFECTED = pkt.inputs.affected_modules || [];
  let fp = await runnerFp(type);
  if (opts.tamper) fp = (fp + "deadbeef").slice(0,16);
  const runId = opts.staleRunId || pkt.run_id;
  return api(`/api/ecos/${ecoId}/checks/${type}/results`, "POST",
             {run_id: runId, fingerprint: fp, verdict,
              result: {note: verdict==="PASS"?"模拟通过":"模拟违例"}, runner_id: "runner-0"});
}

// 依赖图顺序执行所有 PENDING
async function runAll(ecoId, failType=null) {
  for (let i=0;i<20;i++) {
    const d = await api(`/api/ecos/${ecoId}`);
    const pend = d.gate.checks.filter(c => c.status === "PENDING").map(c => c.type);
    if (!pend.length) break;
    for (const t of pend) {
      try { await runOne(ecoId, t, t === failType ? "FAIL":"PASS"); }
      catch(e) { toast("检查拒收: "+e.message, "err"); throw e; }
    }
  }
  await refresh();
}

// 模拟迟到结果：约束刷新后，用旧 run_id 回传
async function lateResult(ecoId) {
  const old = await api(`/api/ecos/${ecoId}`);
  const t = "TIMING_STA";
  try {
    // 先让一次通过拿到 run id 历史；迟到提交直接对当前已作废 run 尝试
    const pkt = await api(`/api/ecos/${ecoId}/checks/${t}/inputs`).catch(()=>null);
    if (!pkt) { toast("该 ECO 当前无活动检查（已被作废）——这正是防串用的体现", "err"); return; }
    await runOne(ecoId, t, "PASS", {staleRunId: pkt.run_id + ":OLD"});
  } catch(e) {
    toast("⛔ 迟到/串用结果被拒收：" + (e.resp?.detail?.reason || e.message), "err");
  }
  await refresh();
}

// ---- 操作 ----
async function createEco() {
  const mods = $("f-mods").value.split(",").map(s=>s.trim()).filter(Boolean);
  let edits = {};
  try { edits = JSON.parse($("f-edits").value || "{}"); }
  catch { toast("编辑 JSON 不合法", "err"); return; }
  const d = await api("/api/ecos","POST",{title:$("f-title").value, owner:$("f-owner").value,
                                          affected_modules:mods, edits});
  toast(`已创建 ${d.id}（草稿）`); await refresh();
}
const act = async (p,b,msg) => { try { const d = await api(p,"POST",b||{}); toast(msg||"操作成功","ok"); await refresh(); return d; }
  catch(e){ toast("⛔ "+e.message+(e.resp?.detail?.reason?` [${e.resp.detail.reason}]`:""),"err"); await refresh(); } };

async function refresh() {
  const w = await api("/api/workbench"); window.WB = w;
  $("trunk").textContent = `当前发布基线 ${w.constraints.base_id}(rev ${w.constraints.base_revision}) · 约束版本 v${w.constraints.constraints_version}`;
  renderEcos(w); renderBaselines(w); renderMisc(w); renderDelegations(w);
}

function esc(s){return String(s??"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}

function checkTable(gate) {
  return `<table><tr><th>检查</th><th>状态</th><th>依赖</th><th>指纹</th><th>提交</th></tr>` +
    gate.checks.map(c => `<tr>
      <td>${CHECK_CN[c.type]||c.type}${c.required?"":' <span class="chip">非必需</span>'}</td>
      <td class="c-${c.status}"><b>${c.status}</b>${c.satisfied?' ✓':''}</td>
      <td class="mut">${c.depends_on.length?c.depends_on.map(d=>`${CHECK_CN[d]||d}:${c.dep_status[d]}`).join("，"):"—"}</td>
      <td>${c.fingerprint_ok?'<span class="ok">一致</span>':c.status==='PASS'?'<span class="bad">不符</span>':'<span class="mut">待提交</span>'}</td>
      <td class="mut">${esc(c.runner_id||"")}</td></tr>`).join("") + "</table>";
}

// 每个签核角色一个身份选择：本人直接签，或以生效中的代理身份签（代理链随签核留痕）
function signoffControls(e, w) {
  const g = e.gate;
  const defs = {TIMING_LEAD: "timing.zhang", METHODOLOGY_LEAD: "method.li"};
  return Object.entries(defs).map(([role, defUser]) => {
    const dels = (w.delegations||[]).filter(d => d.role===role && d.status==="ACTIVE");
    const opts = [`<option value="">本人 ${defUser}</option>`].concat(
      dels.map(d => `<option value="${d.id}">代理 ${esc(d.delegate)} 代 ${esc(d.delegator)}</option>`)).join("");
    return `<span class="chip">${ROLE_CN[role]}</span><select id="so-${e.id}-${role}">${opts}</select>
      <button ${g.green?"":"disabled"} onclick="doSignoff('${e.id}','${role}','${defUser}')">签核</button>`;
  }).join(" ");
}

async function doSignoff(ecoId, role, defUser) {
  const v = $(`so-${ecoId}-${role}`).value;
  let body = {role, user: defUser};
  if (v) {
    const d = window.WB.delegations.find(x => String(x.id) === v);
    body = {role, user: d.delegate, on_behalf_of: d.delegator};
  }
  await act(`/api/ecos/${ecoId}/signoff`, body,
            body.on_behalf_of ? `代理签核完成：${body.user} 代 ${body.on_behalf_of}` : "签核完成");
}

function renderEcos(w) {
  $("ecos").innerHTML = w.ecos.map(e => {
    const g = e.gate;
    let btns = "";
    if (["DRAFT","REBASE_REQUIRED"].includes(e.status))
      btns += `<button onclick="act('/api/ecos/${e.id}/freeze',{by:'${e.owner}'},'${e.id} 已冻结，验证矩阵已触发')">${e.status==="REBASE_REQUIRED"?"刷新冻结(rebase)":"提交并冻结"}</button>`;
    if (e.status==="FROZEN")
      btns += `<button onclick="runAll('${e.id}')">Runner 执行全部检查</button>
        <button class="sec" onclick="runAll('${e.id}','TIMING_STA')">模拟时序失败</button>`;
    if (e.status==="FROZEN" && g.checks.some(c=>c.status==="FAIL"))
      btns += `<button class="sec" onclick="act('/api/ecos/${e.id}/checks/TIMING_STA/rerun',{by:'${e.owner}'},'旧尝试已作废，已按当前基线重跑')">重跑时序</button>`;
    if (e.status==="FROZEN") {
      btns += `<span style="margin-left:6px"></span>` + signoffControls(e, w) +
        `<button ${g.releasable?"":"disabled"} onclick="act('/api/ecos/${e.id}/release',{by:'${e.owner}'},'新基线已发布')">发布基线</button>
        <button class="danger" onclick="act('/api/ecos/${e.id}/release',{by:'${e.owner}',failpoint:'AFTER_PHASE1'}).then(()=>{}).catch(()=>{})">模拟发布中断</button>`;
    }
    if (e.status==="RELEASING")
      btns += `<button onclick="act('/api/ecos/${e.id}/release/resume',{by:'${e.owner}'},'已从中断恢复并完成发布')">恢复发布</button>`;
    if (e.status==="QUEUED") {
      const blockers = e.queue.map(q=>q.blocker_eco_id+":"+q.module).join("，");
      btns += `<span class="warn">阻塞于 ${esc(blockers)}</span>
        <button class="sec" onclick="mergeInto('${e.id}')">裁决：合并到占用方</button>
        <button class="danger" onclick="act('/api/ecos/${e.id}/abort',{by:'${e.owner}'},'已中止并让出排队')">中止</button>`;
    }
    if (["DRAFT","FROZEN","REBASE_REQUIRED"].includes(e.status))
      btns += `<button class="danger" onclick="act('/api/ecos/${e.id}/abort',{by:'${e.owner}'},'已中止，模块锁释放')">中止</button>`;
    if (e.status==="FROZEN")
      btns += `<button class="sec" onclick="lateResult('${e.id}')">模拟迟到结果</button>
        <button class="sec" onclick="tamperResult('${e.id}')">模拟串用他单指纹</button>`;
    const sigs = g.valid_signoffs.map(s=>`<span class="chip">${ROLE_CN[s.role]||s.role}: ${esc(s.user)}${s.delegator?`（代 ${esc(s.delegator)}）`:""} ✓</span>`).join(" ");
    const voided = (g.signoffs||[]).filter(s=>s.voided_at);
    return `<div class="card">
      <div class="row"><b class="mono">${e.id}</b> ${esc(e.title)}
        <span class="tag s-${e.status}">${STATUS_CN[e.status]||e.status}</span>
        <span style="flex:1"></span><span class="mut">owner ${esc(e.owner)}</span></div>
      <div class="row mut">受影响模块: ${e.affected_modules.map(m=>`<span class="chip">${m}</span>`).join(" ")}
        &nbsp;|&nbsp; 冻结基线: ${e.parent_baseline_id||"—"}
        &nbsp;|&nbsp; 纪元 e${e.freeze_epoch}
        &nbsp;|&nbsp; 门禁: <b class="${g.green?'ok':'bad'}">${g.green?'必需检查全绿':'未全绿'}</b>
        &nbsp;|&nbsp; 双签: <b class="${g.dual_role_complete?'ok':'warn'}">${g.dual_role_complete?'完成':'待签'}</b></div>
      <div class="row">${sigs||'<span class="mut">（暂无有效签核）</span>'}</div>
      ${voided.length?`<div class="row mut">已失效签核（保留审计）: ${voided.map(s=>`${ROLE_CN[s.role]||s.role}:${esc(s.user)}${s.delegator?`(代${esc(s.delegator)})`:""}·${esc(s.void_reason||"")}`).join("，")}</div>`:""}
      ${e.fingerprint?`<div class="row mut mono">基线指纹 ${e.fingerprint} · 约束v${e.constraints_version_at_freeze}</div>`:""}
      ${e.queue?.length?`<div class="row warn">排队中，等待模块: ${e.queue.map(q=>q.module).join(", ")}</div>`:""}
      ${e.blocks?.length?`<div class="row mut">后续排队 ECO: ${e.blocks.map(q=>q.eco_id).join(", ")}</div>`:""}
      ${e.status==="FROZEN"||e.status==="RELEASING"?checkTable(g):""}
      <div class="row">${btns}</div></div>`;
  }).join("") || '<div class="mut">暂无 ECO</div>';
}

async function tamperResult(ecoId) {
  try { await runOne(ecoId, "TIMING_STA", "PASS", {tamper:true}); }
  catch(e) { toast("⛔ 指纹不符被拒收：" + (e.resp?.detail?.reason||e.message), "err"); }
  await refresh();
}

async function mergeInto(srcId) {
  const w = window.WB;
  const q = w.ecos.find(e=>e.id===srcId).queue[0];
  await act(`/api/ecos/${srcId}/merge-into/${q.blocker_eco_id}`, {by:"ccb.chair",
    module_winners:{[q.module]:"TARGET_WINS"}}, `已裁决合并：${srcId} → ${q.blocker_eco_id}，旧结果全部作废重跑`);
}

function renderBaselines(w) {
  $("baselines").innerHTML = w.baselines.map(b =>
    `<div class="row"><b class="mono">${b.id}</b> <span class="mut">rev ${b.revision}</span>
      <span class="chip">${b.affected_modules.join(",")||"全量"}</span>
      <span class="mono mut">${b.fingerprint.slice(0,10)}…</span>
      <span style="flex:1"></span><span class="mut">${b.eco_id?("来源 "+b.eco_id):"初始基线"}</span></div>`).join("");
  const ids = w.baselines.map(b=>b.id);
  for (const [sel,val] of [["d-from",ids[0]],["d-to",ids[ids.length-1]]]) {
    const cur = $(sel).value;
    $(sel).innerHTML = ids.map(i=>`<option ${i===(cur||val)?"selected":""}>${i}</option>`).join("");
  }
}

async function showDiff() {
  const d = await api(`/api/baselines/diff?from=${$("d-from").value}&to=${$("d-to").value}`);
  $("diff").textContent = JSON.stringify(d, null, 2);
}
async function downloadZip() {
  const r = await fetch(`/api/baselines/diff.zip?from=${$("d-from").value}&to=${$("d-to").value}`);
  const blob = await r.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = "baseline-diff.zip"; a.click();
}

// ---- 临时代理签核 ----
async function createDelegation() {
  const from = $("dg-from").value, to = $("dg-to").value;
  if (!from || !to) { toast("请填写生效/失效时间", "err"); return; }
  try {
    const d = await api("/api/delegations", "POST", {
      role: $("dg-role").value,
      delegator: $("dg-delegator").value.trim(),
      delegate: $("dg-delegate").value.trim(),
      effective_from: new Date(from).toISOString(),
      effective_to: new Date(to).toISOString(),
      by: $("dg-by").value.trim() || "admin"});
    toast(d.deduplicated
      ? `相同配置已存在（#${d.id}），幂等返回，未生成重复记录`
      : `已配置代理 #${d.id}：${esc(d.delegate)} 代 ${esc(d.delegator)}（${ROLE_CN[d.role]}）`, "ok");
    await refresh();
  } catch(e) { toast("⛔ " + e.message, "err"); }
}

async function revokeDelegation(id) {
  await act(`/api/delegations/${id}/revoke`,
            {by: $("dg-by").value.trim() || "admin"}, `代理 #${id} 已撤销，即刻不可再签`);
}

const fmtT = t => (t||"").slice(0,16).replace("T"," ");

function renderDelegations(w) {
  // 当前可签人员：角色负责人本人 + 生效中代理（含代理来源与有效期）
  $("signers").innerHTML = Object.values(w.current_signers||{}).map(r => {
    const ds = r.delegates.map(d =>
      `<span class="chip">${esc(d.delegate)} ⇐ ${esc(d.delegator)}（至 ${fmtT(d.effective_to)} UTC）</span>`).join(" ");
    return `<div class="row"><b>${ROLE_CN[r.role]||r.role}</b>
      <span class="mut">当前可签：角色负责人本人${r.delegates.length?"，及代理：":"（暂无生效中代理）"}</span>${ds}</div>`;
  }).join("");
  $("delegations").innerHTML = (w.delegations||[]).length
    ? `<table><tr><th>#</th><th>角色</th><th>代理链（代理人⇐被代理人）</th><th>有效期(UTC)</th><th>状态</th><th></th></tr>` +
      w.delegations.map(d => `<tr>
        <td>${d.id}</td><td>${ROLE_CN[d.role]||d.role}</td>
        <td class="mono">${esc(d.delegate)} ⇐ ${esc(d.delegator)}</td>
        <td class="mut mono">${fmtT(d.effective_from)} → ${fmtT(d.effective_to)}</td>
        <td><span class="tag dg-${d.status}">${DG_STATUS[d.status]||d.status}</span></td>
        <td>${["ACTIVE","PENDING"].includes(d.status)
             ? `<button class="danger" onclick="revokeDelegation(${d.id})">撤销</button>` : ""}</td>
      </tr>`).join("") + "</table>"
    : '<div class="mut">（暂无代理配置）</div>';
}

function renderMisc(w) {
  $("locks").innerHTML = w.locks.length
    ? w.locks.map(l=>`<span class="chip">${l.module}→${l.eco_id}</span>`).join(" ")
    : '<span class="mut">（无模块锁）</span>';
  $("rejects").innerHTML = w.rejected_results.length
    ? `<table><tr><th>#</th><th>ECO/检查</th><th>拒收原因</th><th>时间</th></tr>` +
      w.rejected_results.map(r=>`<tr><td>${r.seq}</td><td class="mono">${r.eco_id||""} ${r.check_type||""}</td>
        <td class="bad">${r.reason}</td><td class="mut">${(r.received_at||"").slice(11)}</td></tr>`).join("")+"</table>"
    : '<div class="mut">（暂无拒收记录）</div>';
}

// 默认代理窗口：现在 → 7 天后
const isoLocal = d => { const p = n => String(n).padStart(2,"0");
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`; };
$("dg-from").value = isoLocal(new Date());
$("dg-to").value = isoLocal(new Date(Date.now() + 7*864e5));

refresh().catch(e=>toast(e.message,"err"));
