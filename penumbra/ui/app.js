/* Penumbra tactical workspace: vanilla JS, no build step. */
(() => {
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const AGENTS = {
    triage: { label: "Triage & Router", color: "#22d3ee" },
    forensics: { label: "Behavioral Forensics", color: "#fbbf24" },
    osint: { label: "OSINT & Attribution", color: "#a78bfa" },
    deception: { label: "Deception", color: "#34d399" },
    lead: { label: "Lead Investigator", color: "#60a5fa" },
  };
  const NODE = {
    person: { shape: "ellipse", c: "#94a3b8" },
    service_account: { shape: "round-rectangle", c: "#94a3b8" },
    access_key: { shape: "diamond", c: "#fbbf24" },
    repo: { shape: "rectangle", c: "#64748b" },
    bucket: { shape: "barrel", c: "#38bdf8" },
    model: { shape: "star", c: "#c084fc" },
    domain: { shape: "hexagon", c: "#fb7185" },
    persona: { shape: "ellipse", c: "#f472b6" },
    asn: { shape: "triangle", c: "#f97316" },
    external_account: { shape: "octagon", c: "#ef4444" },
    device: { shape: "round-tag", c: "#64748b" },
    injection: { shape: "vee", c: "#e879f9" },
    canary: { shape: "tag", c: "#2dd4bf" },
  };
  const PH = { think: "·", act: "→", observe: "←", conclude: "■", blocked: "✖" };

  let es = null, invId = null, cy = null, layoutTimer = null;
  const st = { findings: [], quarantine: {}, cards: {}, timeline: [], blocked: 0, inj: 0, fp: 0, filter: new Set(), approvers: [] };

  // ------------------------------------------------------------ graph
  function initGraph() {
    if (!window.cytoscape) { $("#empty").querySelector(".sub").textContent = "Graph library failed to load (offline?). The reasoning stream and approvals still work."; return; }
    cy = cytoscape({
      container: $("#cy"), minZoom: 0.25, maxZoom: 2.5,
      style: [
        { selector: "node", style: {
            "background-color": "data(color)", "shape": "data(shape)", "width": "data(size)", "height": "data(size)",
            "label": "data(label)", "color": "#cbd5e1", "font-family": "IBM Plex Mono, Menlo, Consolas, DejaVu Sans Mono, monospace", "font-size": 9,
            "text-valign": "bottom", "text-margin-y": 5, "text-wrap": "ellipsis", "text-max-width": 140,
            "border-width": 2, "border-color": "data(ring)", "background-opacity": 0.92,
            "text-outline-color": "#0b0f17", "text-outline-width": 2 } },
        { selector: "node[type='persona']", style: { "border-style": "dashed", "border-width": 2.5 } },
        { selector: "node[type='injection']", style: { "border-color": "#f0abfc", "border-width": 3, "color": "#f5d0fe" } },
        { selector: "node[contained]", style: { "border-color": "#2dd4bf", "border-width": 4, "border-style": "double" } },
        { selector: "node:selected", style: { "overlay-color": "#f5a524", "overlay-opacity": 0.15 } },
        { selector: "edge", style: {
            "width": 1.3, "line-color": "#334155", "target-arrow-color": "#475569", "target-arrow-shape": "triangle",
            "arrow-scale": 0.8, "curve-style": "bezier", "label": "data(rel)", "font-size": 7.5, "color": "#64748b",
            "font-family": "IBM Plex Mono, Menlo, Consolas, DejaVu Sans Mono, monospace", "text-rotation": "autorotate", "text-background-color": "#0b0f17",
            "text-background-opacity": 0.8, "text-background-padding": 1 } },
        { selector: "edge.fresh", style: { "line-color": "#f5a524", "target-arrow-color": "#f5a524", "width": 2.2 } },
      ],
    });
    cy.on("tap", "node", (e) => inspect(e.target.id()));
    cy.on("tap", (e) => { if (e.target === cy) $("#inspector").classList.add("hidden"); });
    $("#legend").innerHTML = Object.entries(NODE).map(([k, v]) => `<span><i style="background:${v.c}"></i>${k.replace("_", " ")}</span>`).join("");
  }

  const riskColor = (r) => r >= 0.8 ? "#ff4d5e" : r >= 0.55 ? "#f59e0b" : r >= 0.3 ? "#eab308" : "#334155";

  function upsertNode(n) {
    if (!cy) return;
    $("#empty").classList.add("hidden");
    const t = NODE[n.type] || { shape: "ellipse", c: "#94a3b8" };
    const data = { id: n.id, label: n.label, type: n.type, shape: t.shape, color: t.c,
      ring: riskColor(n.risk), size: 18 + n.risk * 26, risk: n.risk, props: n.props };
    if (n.props && n.props.contained) data.contained = n.props.contained;
    const ex = cy.getElementById(n.id);
    if (ex.nonempty()) { ex.data(data); if (!data.contained) ex.removeData("contained"); }
    else cy.add({ group: "nodes", data, position: { x: (Math.random() - .5) * 300, y: (Math.random() - .5) * 200 } });
    relayout();
    radar();
  }

  function addEdge(e) {
    if (!cy) return;
    const ex = cy.getElementById(e.id);
    if (ex.nonempty()) { ex.data(e); return; }
    if (cy.getElementById(e.src).empty() || cy.getElementById(e.dst).empty()) return;
    const el = cy.add({ group: "edges", data: { id: e.id, source: e.src, target: e.dst, rel: e.rel, evidence: e.evidence, by: e.asserted_by } });
    el.addClass("fresh"); setTimeout(() => el.removeClass("fresh"), 2200);
    relayout();
  }

  function relayout() {
    clearTimeout(layoutTimer);
    layoutTimer = setTimeout(() => {
      cy.layout({ name: "cose", animate: true, animationDuration: 600, randomize: false, fit: true, padding: 40,
        nodeRepulsion: () => 14000, idealEdgeLength: () => 95, gravity: 0.35, numIter: 900,
        stop: () => { if (cy.zoom() > 1.15) { cy.zoom(1.15); cy.center(); } } }).run();
    }, 450);
  }

  function inspect(id) {
    const n = cy.getElementById(id); if (n.empty()) return;
    const d = n.data();
    const rels = n.connectedEdges().map((e) => {
      const out = e.source().id() === id;
      return `<div class="rel">${out ? "→" : "←"} <b>${esc(e.data("rel"))}</b> ${esc(out ? e.target().id() : e.source().id())} <span class="muted">${esc((e.data("evidence") || []).slice(0, 3).join(", "))}</span></div>`;
    }).join("");
    const fds = st.findings.filter((f) => (f.subjects || []).includes(id) || f.title.includes(id)).map((f) =>
      `<div class="fd"><b>${esc(f.title)}</b><br><span class="muted">${esc(f.agent)} · conf ${f.confidence.toFixed(2)} · ${esc(f.ttps.join(", "))}</span></div>`).join("");
    let q = "";
    if (d.type === "injection") {
      const r = st.quarantine[id.split(":")[1]];
      if (r) q = `<h2 style="margin-top:10px">Quarantine verdict: ${esc(r.verdict)}</h2>` +
        r.detections.map((x) => `<div class="det">${esc(x.technique)} <span class="muted">via ${esc(x.channel)}</span></div>`).join("") +
        `<h2 style="margin-top:10px">What the agent actually saw</h2><div class="sanitized">${esc(r.sanitized_preview)}</div>`;
    }
    $("#inspector").innerHTML = `<span class="close" onclick="this.parentNode.classList.add('hidden')">✕</span>
      <div class="type">${esc(d.type)} · risk ${(+d.risk).toFixed(2)}${d.contained ? " · <span style='color:#2dd4bf'>" + esc(d.contained) + "</span>" : ""}</div>
      <h3>${esc(d.label)}</h3>${rels}${q}${fds ? "<h2 style='margin-top:10px'>Findings</h2>" + fds : ""}`;
    $("#inspector").classList.remove("hidden");
  }

  // ------------------------------------------------------------ radar
  function hash(s) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) >>> 0; return h; }
  function radar() {
    if (!cy) return;
    const g = $("#blips");
    const nodes = cy.nodes().filter((n) => ["person", "service_account", "persona", "domain", "external_account", "access_key"].includes(n.data("type")));
    const top = new Set(nodes.sort((a, b) => b.data("risk") - a.data("risk")).slice(0, 7).map((n) => n.id()));
    g.innerHTML = nodes.map((n) => {
      const r = n.data("risk"), a = (hash(n.id()) % 360) * Math.PI / 180, d = 16 + (1 - r) * 82;
      const x = Math.cos(a) * d, y = Math.sin(a) * d, c = n.data("contained") ? "#2dd4bf" : riskColor(r);
      return `<g class="blip"><circle cx="${x}" cy="${y}" r="${2.5 + r * 3}" fill="${c}" opacity=".9"><animate attributeName="opacity" values=".9;.35;.9" dur="${2 + (hash(n.id()) % 20) / 10}s" repeatCount="indefinite"/></circle>
        ${top.has(n.id()) ? `<text x="${x + 5}" y="${y + 2}">${esc(n.id().split("@")[0].slice(0, 16))}</text>` : ""}</g>`;
    }).join("");
  }

  // ------------------------------------------------------------ stream
  function stepEl(d) {
    const a = AGENTS[d.agent] || { color: "#cbd5e1", label: d.agent };
    const div = document.createElement("div");
    div.className = `step ${d.phase}`;
    div.dataset.agent = d.agent;
    div.style.setProperty("--c", a.color);
    const cf = d.confidence ? `<span class="cf">conf ${(+d.confidence).toFixed(2)}</span>` : "";
    div.innerHTML = `<div class="ph">${PH[d.phase] || "·"}</div><div><div class="who">${esc(a.label)}${cf}</div><div class="txt">${esc(d.text)}</div></div>`;
    if (st.filter.size && !st.filter.has(d.agent)) div.classList.add("hidden");
    return div;
  }
  function pushStream(el) {
    const s = $("#stream");
    const stick = s.scrollHeight - s.scrollTop - s.clientHeight < 60;
    s.appendChild(el);
    if (stick) s.scrollTop = s.scrollHeight;
  }
  function alertStep(text, agent = "quarantine") {
    const div = document.createElement("div");
    div.className = "step alert"; div.style.setProperty("--c", "#e879f9");
    div.innerHTML = `<div class="ph">◆</div><div><div class="who">${esc(agent)}</div><div class="txt">${text}</div></div>`;
    pushStream(div);
  }
  function filters() {
    $("#filters").innerHTML = Object.entries(AGENTS).map(([k, v]) => `<button data-a="${k}" style="--c:${v.color}">${k}</button>`).join("");
    $("#filters").onclick = (e) => {
      const a = e.target.dataset.a; if (!a) return;
      st.filter.has(a) ? st.filter.delete(a) : st.filter.add(a);
      e.target.classList.toggle("on");
      document.querySelectorAll(".step[data-agent]").forEach((el) => el.classList.toggle("hidden", st.filter.size > 0 && !st.filter.has(el.dataset.agent)));
    };
  }

  // ------------------------------------------------------------ cards
  function renderCard(c) {
    st.cards[c.id] = c;
    const box = $("#cards");
    box.querySelector(".muted")?.remove();
    let el = document.getElementById(c.id);
    if (!el) { el = document.createElement("div"); el.id = c.id; box.appendChild(el); requestAnimationFrame(() => box.scrollTo({ left: box.scrollWidth, behavior: "smooth" })); }
    const r = c.request, br = c.blast_radius || {};
    el.className = `card ${c.status}`;
    const sig = `${r.tool}(${Object.values(r.args).map((v) => JSON.stringify(v)).join(", ")})`;
    const approvals = c.approvals.map((a) => a.approver).join(", ");
    let actions = "";
    if (c.status === "pending") {
      actions = `<button class="btn approve" data-act="approve">Approve</button><button class="btn reject" data-act="reject">Reject</button>
        <span class="need">${c.approvals.length}/${c.needed} approvals${approvals ? " · " + esc(approvals) : ""}</span>`;
    } else if (c.status === "denied_by_policy") {
      actions = `<span class="policy" style="color:#fda4af">✖ policy gate: ${esc(c.policy.rules.join(" "))}</span>`;
    } else if (c.status === "executed") {
      actions = `<span class="policy">approved by ${esc(approvals)}</span>`;
    } else if (c.status === "rejected") actions = `<span class="policy">rejected</span>`;
    const reasons = c.status === "denied_by_policy" ? c.policy.reasons.join(" · ") : r.justification;
    el.innerHTML = `
      <div class="top"><span class="tier ${c.tier}">${c.tier}</span><span class="mono" style="font-size:10.5px;color:#7d8aa3">${c.id}</span><span class="by">by ${esc(r.proposed_by)}</span></div>
      <div class="sig">${esc(sig)}</div>
      <div class="conf" title="confidence ${r.confidence}"><i style="width:${r.confidence * 100}%"></i></div>
      <div class="why">${esc(reasons)}</div>
      ${br.summary ? `<div class="blast"><div class="blast-text"><b>Blast radius:</b> ${esc(br.summary)}${(br.alternatives || []).map((a) => `<div class="alt">↳ ${esc(a)}</div>`).join("")}</div></div>` : ""}
      <div class="policy">evidence: ${esc(r.evidence.slice(0, 4).join(", "))}${r.evidence.length > 4 ? "…" : ""}</div>
      <div class="actions">${actions}</div>`;
    el.querySelectorAll("button[data-act]").forEach((b) => b.onclick = () => decide(c.id, b.dataset.act));
  }

  async function decide(id, act) {
    const approver = $("#approver").value;
    const body = act === "approve" ? { approver } : { approver, reason: "rejected in workspace" };
    const res = await fetch(`/api/cards/${id}/${act}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (!res.ok) { const j = await res.json(); toast("Two-person rule", j.detail, "red"); }
  }

  // ------------------------------------------------------------ misc ui
  function toast(title, text, cls = "") {
    const t = document.createElement("div");
    t.className = `toast ${cls}`; t.innerHTML = `<b>${esc(title)}</b>${esc(text)}`;
    const box = $("#toasts");
    box.appendChild(t); setTimeout(() => t.remove(), 6500);
    while (box.children.length > 3) box.firstChild.remove();
  }
  function setStatus(s) {
    const p = $("#status"); p.textContent = s.replace("_", " ");
    p.className = "pill " + ({ ingesting: "live", investigating: "live", awaiting_approval: "await", closed: "closed", error: "err" }[s] || "");
    $("#run").disabled = s === "ingesting" || s === "investigating";
    if (s === "closed") { loadBrief(); loadAudit(); toast("Investigation closed", "After-action brief compiled and lessons written back to the knowledge store.", "green"); }
  }
  function agentRow(d) {
    let li = document.getElementById("ag-" + d.agent);
    const a = AGENTS[d.agent] || { color: "#ccc", label: d.title };
    if (!li) { li = document.createElement("li"); li.id = "ag-" + d.agent; $("#agents").appendChild(li); }
    if (d.model) li.dataset.model = d.model;
    li.className = d.status;
    li.innerHTML = `<span class="dot" style="background:${a.color}"></span><span><span class="name">${esc(a.label)}</span><span class="model">${esc(li.dataset.model || "")}</span></span><span class="st">${d.status === "done" ? d.steps + " steps" : d.status}</span>`;
  }
  function ingest(d) {
    $("#k-events").textContent = d.ingested; $("#k-window").textContent = d.window_events;
    const max = Math.max(...Object.values(d.by_source));
    $("#ingest").innerHTML = Object.entries(d.by_source).sort((a, b) => b[1] - a[1]).map(([k, v]) =>
      `<div class="row"><span>${k}</span><span class="bar"><i style="width:${(v / max) * 100}%"></i></span><b>${v}</b></div>`).join("");
  }
  function renderTimeline() {
    $("#timeline").innerHTML = st.timeline.map((t) => `<li><div class="t">${esc(t.ts.slice(5, 16).replace("T", " "))}</div>
      <div><div class="s">${esc(t.summary)}</div><div class="m">${esc(t.actor)}</div>
      <div>${t.ttps.map((x) => `<span class="ttp">${esc(x)}</span>`).join("")}<span class="m">${esc(t.evidence.slice(0, 3).join(", "))}</span></div></div></li>`).join("");
  }
  async function loadBrief() {
    const r = await fetch("/api/report"); const md = await r.text();
    $("#brief").innerHTML = window.marked ? marked.parse(md) : `<pre>${esc(md)}</pre>`;
  }
  async function loadAudit() {
    const r = await fetch("/api/audit"); if (!r.ok) return; const j = await r.json();
    const v = $("#audit-verify");
    v.className = "verify " + (j.verify.ok ? "ok" : "bad");
    v.textContent = j.verify.ok ? `✔ ${j.verify.records} records · hash chain + Ed25519 signatures verified` : `✖ BROKEN at seq ${j.verify.first_bad_seq}: ${j.verify.reason}`;
    $("#audit").innerHTML = `<tr><th>#</th><th>actor</th><th>kind</th><th>detail</th><th>model</th><th>prompt-state</th><th>hash</th></tr>` +
      j.records.slice().reverse().map((x) => {
        const p = x.payload || {};
        const detail = p.tool || p.verdict || (p.decision && (p.decision.allowed ? "allow " : "deny ") + (p.request?.tool || p.card || "")) || p.card || "";
        const deny = p.decision && !p.decision.allowed ? " deny" : "";
        return `<tr class="k-${x.kind}${deny}"><td>${x.seq}</td><td>${esc(x.actor)}</td><td class="k-${x.kind}${deny}">${esc(x.kind)}</td><td>${esc(detail)}</td><td>${esc(x.model || "")}</td><td>${esc((x.prompt_state_sha256 || "").slice(0, 10))}</td><td>${x.hash.slice(0, 14)}…</td></tr>`;
      }).join("");
  }

  // ------------------------------------------------------------ event dispatch
  function handle(rec) {
    const d = rec.data;
    switch (rec.type) {
      case "status": setStatus(d.status); $("#backend").textContent = d.backend + (d.red_team ? " · red-team" : ""); break;
      case "radar": ingest(d); break;
      case "agent": agentRow(d); break;
      case "step": pushStream(stepEl(d)); break;
      case "graph_node": upsertNode(d); break;
      case "graph_edge": addEdge(d); break;
      case "finding": st.findings.push(d); $("#k-findings").textContent = st.findings.length; break;
      case "lead": break;
      case "dismissed":
        st.fp++; $("#k-fp").textContent = st.fp;
        alertStep(`False positive cleared: <b>${esc(d.subject)}</b>, ${esc(d.reason)}`, "triage");
        break;
      case "quarantine":
        st.quarantine[d.event_id] = d;
        if (d.verdict === "malicious") {
          st.inj++; $("#k-inj").textContent = st.inj;
          alertStep(`<b>Prompt injection neutralized</b> in ${esc(d.event_id)} (${esc(d.source)}): ${d.detections.length} detections across ${esc([...new Set(d.detections.map((x) => x.channel))].join(", "))}. Hidden directives were stripped before any model saw the text.`);
          toast("Prompt injection neutralized", `${d.event_id}: ${[...new Set(d.detections.map((x) => x.technique))].slice(0, 5).join(", ")}…`);
        } else if (d.red_team) {
          alertStep(`<b>RED-TEAM:</b> quarantine disabled. Raw content of ${esc(d.event_id)} passed straight to the agent.`);
        }
        break;
      case "guardrail":
        st.blocked++; $("#k-blocked").textContent = st.blocked;
        toast(`Blocked by ${d.layer === "scope" ? "scope guard" : "policy gate"}`, `${d.agent} → ${d.tool}: ${d.reason}`, "red");
        break;
      case "card": renderCard(d); break;
      case "timeline": st.timeline.push(d); st.timeline.sort((a, b) => a.ts.localeCompare(b.ts)); renderTimeline(); break;
      case "hypothesis":
        $("#hypothesis").innerHTML = `<b>HYPOTHESIS ${(+d.confidence).toFixed(2)}</b>${esc(d.statement)}`;
        $("#hypothesis").classList.remove("hidden"); break;
      case "trust": break;
      case "error": toast("Error", d.message, "red"); break;
    }
  }

  // ------------------------------------------------------------ run
  function reset() {
    Object.assign(st, { findings: [], quarantine: {}, cards: {}, timeline: [], blocked: 0, inj: 0, fp: 0 });
    $("#stream").innerHTML = ""; $("#cards").innerHTML = ""; $("#timeline").innerHTML = ""; $("#agents").innerHTML = "";
    $("#blips").innerHTML = ""; $("#hypothesis").classList.add("hidden"); $("#inspector").classList.add("hidden");
    $("#brief").innerHTML = `<p class="muted">The brief is compiled when every approval card is resolved.</p>`;
    ["#k-events", "#k-window", "#k-findings", "#k-inj", "#k-blocked", "#k-fp"].forEach((k) => $(k).textContent = "0");
    if (cy) cy.elements().remove();
  }
  async function run() {
    reset();
    if (es) es.close();
    const res = await fetch("/api/investigations", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ red_team: $("#redteam").checked, pace: +$("#pace").value }) });
    const j = await res.json(); invId = j.id;
    es = new EventSource(`/api/stream?inv_id=${encodeURIComponent(invId)}`);
    es.onmessage = (m) => handle(JSON.parse(m.data));
  }

  // tabs
  document.querySelectorAll(".tabs button").forEach((b) => b.onclick = () => {
    document.querySelectorAll(".tabs button").forEach((x) => x.classList.toggle("active", x === b));
    document.querySelectorAll(".tabview").forEach((v) => v.classList.toggle("hidden", v.id !== "tab-" + b.dataset.tab));
    if (b.dataset.tab === "graph" && cy) { cy.resize(); cy.fit(undefined, 40); }
    if (b.dataset.tab === "audit" && invId) loadAudit();
    if (b.dataset.tab === "brief" && invId) loadBrief();
  });
  $("#tamper").onclick = async () => {
    const r = await fetch("/api/audit/tamper-test", { method: "POST" }); const j = await r.json();
    $("#tamper-out").innerHTML = j.verify ? `Edited a copy of record #${j.tampered_seq} → verification: <b style="color:${j.verify.ok ? "#2dd4bf" : "#ff4d5e"}">${j.verify.ok ? "passed" : "FAILED at seq " + j.verify.first_bad_seq + " (" + esc(j.verify.reason) + ")"}</b>. The real log is untouched.` : esc(j.detail);
  };
  $("#run").onclick = run;

  fetch("/api/config").then((r) => r.json()).then((c) => {
    $("#backend").textContent = c.default_backend;
    $("#approver").innerHTML = c.approvers.map((a) => `<option value="${a.id}">${a.id} (${a.role})</option>`).join("");
  });
  initGraph(); filters();
  window.penumbra = { graph: () => cy, inspect }; // handy for debugging / scripted demos
})();
