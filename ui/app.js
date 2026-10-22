/* AuditOS Frontend Application — Masterful UI/UX Devtools Engine */
const state = {
  snapshot: null,
  activeProjectId: null,
  activeAgentId: localStorage.getItem("auditos_active_agent") || "",
  selectedSystemId: null,
  activeTab: "systems",
  modalSubmitHandler: null,
  lastDossier: null,
  dossierTab: "overview",
  collapsedSystems: new Set(),
};

function esc(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
    .replace(/\\/g, "&#92;");
}

function fmtTime(iso) {
  if (!iso) return "—";
  return iso.replace("T", " ").replace("Z", " UTC");
}

function showToast(msg) {
  const container = document.getElementById("toastContainer");
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (state.activeAgentId) {
    headers["X-Agent-Id"] = state.activeAgentId;
  }
  const res = await fetch(path, { ...options, headers });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

async function loadSnapshot(projectId = state.activeProjectId) {
  try {
    let snap;
    if (window.location.protocol === "file:" && window.__AUDIT_SNAPSHOT__) {
      snap = window.__AUDIT_SNAPSHOT__;
    } else {
      const query = projectId ? `?project=${encodeURIComponent(projectId)}` : "";
      snap = await api(`/api/snapshot${query}`);
    }
    state.snapshot = snap;
    state.activeProjectId = snap.project.id;

    if (snap.agents.length > 0) {
      const exists = snap.agents.some((a) => a.id === state.activeAgentId);
      if (!exists) {
        state.activeAgentId = snap.agents[0].id;
        localStorage.setItem("auditos_active_agent", state.activeAgentId);
      }
    }

    if (snap.systems.length > 0) {
      const sysExists = snap.systems.some((s) => s.id === state.selectedSystemId);
      if (!sysExists) {
        state.selectedSystemId = snap.systems[0].id;
      }
    } else {
      state.selectedSystemId = null;
    }

    renderAll();
  } catch (err) {
    if (window.__AUDIT_SNAPSHOT__) {
      state.snapshot = window.__AUDIT_SNAPSHOT__;
      state.activeProjectId = state.snapshot.project.id;
      state.selectedSystemId = state.snapshot.systems[0]?.id || null;
      renderAll();
    } else {
      showToast(`Error loading snapshot: ${err.message}`);
    }
  }
}

function renderAll() {
  if (!state.snapshot) return;
  renderTopbar();
  renderMetrics();
  renderPortfolioTab();
  renderSystemsExplorer();
  renderTopologyTab();
  renderWorkforceTab();
  renderFindingsTab();
  renderLogsTab();
}

function renderTopbar() {
  const { project, projects, agents } = state.snapshot;
  document.getElementById("projectRootLabel").textContent =
    `${project.name} (${project.id}) · ${project.root_path || "local workspace"}`;

  const projSel = document.getElementById("projectSelect");
  projSel.innerHTML = projects
    .map(
      (p) =>
        `<option value="${esc(p.id)}" ${p.id === project.id ? "selected" : ""}>${esc(p.name)} (${esc(p.slug)})</option>`
    )
    .join("");

  const agentSel = document.getElementById("activeAgentSelect");
  if (agents.length === 0) {
    agentSel.innerHTML = `<option value="">(No agent registered)</option>`;
  } else {
    agentSel.innerHTML = agents
      .map(
        (a) =>
          `<option value="${esc(a.id)}" ${a.id === state.activeAgentId ? "selected" : ""}>${esc(a.id)} — ${esc(a.name)} [${esc(a.role)}]</option>`
      )
      .join("");
  }
}

function renderMetrics() {
  const m = state.snapshot.metrics;
  const pct =
    m.total_components > 0
      ? Math.round((m.reviewed_components / m.total_components) * 100)
      : 0;
  document.getElementById("metricSystems").textContent =
    `${m.total_systems} sys / ${m.total_subsystems} sub`;
  document.getElementById("metricCoverage").textContent =
    `${m.reviewed_components}/${m.total_components} reviewed (${pct}%)`;

  document.getElementById("metricRelations").textContent = String(m.total_relations);

  const healthEl = document.getElementById("metricHealth");
  healthEl.textContent = m.avg_health_score !== null ? `${m.avg_health_score}/100` : "—";
  healthEl.style.color =
    m.avg_health_score === null
      ? "var(--text-main)"
      : m.avg_health_score >= 85
      ? "var(--healthy)"
      : m.avg_health_score >= 70
      ? "var(--medium)"
      : "var(--critical)";

  document.getElementById("metricAgents").textContent = String(m.total_agents);
  document.getElementById("metricAgentsSub").textContent = `${m.active_agents} active workers`;

  const totalTasks =
    m.task_counts.open + m.task_counts.claimed + m.task_counts.completed + m.task_counts.blocked;
  document.getElementById("metricTasks").textContent =
    `${m.task_counts.completed} / ${totalTasks}`;
  document.getElementById("metricTasksSub").textContent =
    `${m.task_counts.open} open · ${m.task_counts.claimed} claimed · ${m.task_counts.blocked} blocked`;

  document.getElementById("metricFindings").textContent = `${m.open_findings} open`;
  document.getElementById("metricFindingsSub").textContent =
    `${m.severity_counts.critical} crit · ${m.severity_counts.high} high · ${m.severity_counts.medium} med`;
}

function statusBadge(status) {
  const s = (status || "unreviewed").toLowerCase();
  const labels = {
    reviewed: "Reviewed",
    healthy: "Healthy",
    needs_attention: "Needs Attention",
    in_progress: "In Progress",
    unreviewed: "Unreviewed",
  };
  const label = labels[s] || s;
  return `<span class="badge badge-${esc(s)}">${esc(label)}</span>`;
}

function severityBadge(sev) {
  const s = (sev || "info").toLowerCase();
  return `<span class="badge badge-${esc(s)}">${esc(s.toUpperCase())}</span>`;
}

function healthBadge(score) {
  if (score === null || score === undefined || score === "") {
    return `<span class="health-badge" style="background:var(--bg-elevated);color:var(--text-dim);border:1px solid var(--border-subtle)">—</span>`;
  }
  const n = Number(score);
  const cls = n >= 85 ? "health-high" : n >= 70 ? "health-med" : "health-low";
  return `<span class="health-badge ${cls}">${n}/100</span>`;
}

/* =========================================================================
   TAB 0: TARGET REPOSITORIES PORTFOLIO
   ========================================================================= */
async function renderPortfolioTab() {
  const container = document.getElementById("portfolioContainer");
  if (!container) return;

  let portfolioList = [];
  try {
    if (window.location.protocol !== "file:") {
      const res = await api("/api/portfolio");
      portfolioList = res.portfolio || [];
    }
  } catch (err) {
    // fallback to snapshot projects
  }

  if (portfolioList.length === 0 && state.snapshot?.projects) {
    portfolioList = state.snapshot.projects.map((p) => {
      const isCurrent = p.id === state.snapshot.project.id;
      return {
        project: p,
        metrics: isCurrent
          ? state.snapshot.metrics
          : {
              total_systems: 0,
              total_subsystems: 0,
              total_components: 0,
              reviewed_components: 0,
              coverage_pct: 0,
              avg_health_score: null,
              total_findings: 0,
              open_findings: 0,
              severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
              total_tasks: 0,
              task_counts: { open: 0, claimed: 0, completed: 0, blocked: 0 },
              total_agents: 0,
              active_agents: 0,
            },
      };
    });
  }

  const cardsHtml = portfolioList
    .map((item) => {
      const p = item.project;
      const m = item.metrics;
      const isActive = p.id === state.activeProjectId;
      const sc = m.severity_counts || {};
      const tc = m.task_counts || {};

      let healthBadgeClass = "badge-unreviewed";
      let healthBadgeText = "Unscored";
      if (m.avg_health_score !== null && m.avg_health_score !== undefined) {
        if (m.avg_health_score >= 85) {
          healthBadgeClass = "badge-healthy";
          healthBadgeText = `${m.avg_health_score} / 100`;
        } else if (m.avg_health_score >= 70) {
          healthBadgeClass = "badge-reviewed";
          healthBadgeText = `${m.avg_health_score} / 100`;
        } else {
          healthBadgeClass = "badge-attention";
          healthBadgeText = `${m.avg_health_score} / 100`;
        }
      }

      return `
        <div class="portfolio-card ${isActive ? "active-target" : ""}" data-id="${esc(p.id)}">
          <div class="portfolio-card-header">
            <div>
              <div class="portfolio-card-title">${esc(p.name)}</div>
              <div class="portfolio-card-slug">${esc(p.slug)} · <code>${esc(p.id)}</code></div>
            </div>
            <span class="badge ${healthBadgeClass}">${healthBadgeText}</span>
          </div>

          ${p.root_path ? `<div class="portfolio-card-path" title="${esc(p.root_path)}">📁 ${esc(p.root_path)}</div>` : ""}
          ${p.description ? `<p style="font-size:12px;color:var(--text-dim);margin:0;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;">${esc(p.description)}</p>` : ""}

          <div class="portfolio-stats-row">
            <div>
              <div class="portfolio-stat-val">${m.total_systems} / ${m.total_subsystems}</div>
              <div class="portfolio-stat-lbl">Sys / Sub</div>
            </div>
            <div>
              <div class="portfolio-stat-val" style="color:${m.open_findings > 0 ? (sc.critical > 0 ? 'var(--badge-crit-text, #ef4444)' : 'var(--badge-high-text, #f59e0b)') : 'var(--text-main)'}">
                ${m.open_findings}
              </div>
              <div class="portfolio-stat-lbl">Open Bugs</div>
            </div>
            <div>
              <div class="portfolio-stat-val">${m.active_agents} / ${m.total_agents}</div>
              <div class="portfolio-stat-lbl">Agents</div>
            </div>
          </div>

          <div style="font-size:11.5px;color:var(--text-dim);display:flex;justify-content:space-between;">
            <span>Coverage: <strong>${m.coverage_pct}%</strong></span>
            <span>Tasks: <strong>${tc.completed || 0}/${m.total_tasks}</strong></span>
          </div>

          <div class="portfolio-card-footer">
            ${
              isActive
                ? `<span style="font-size:11.5px;color:var(--badge-healthy-text);font-weight:600;">● Active Workbench</span>`
                : `<button class="btn btn-sm btn-primary" data-action="focus-workbench" data-id="${esc(p.id)}">🎯 Open Workbench</button>`
            }
            <button class="btn btn-sm btn-ghost" data-action="export-portfolio-project" data-id="${esc(p.id)}" title="Download Markdown Report">↓ Export</button>
          </div>
        </div>
      `;
    })
    .join("");

  const addCardHtml = `
    <div class="portfolio-card portfolio-add-card" id="cardAddProject">
      <div style="font-size:32px;margin-bottom:8px;">+</div>
      <div style="font-weight:600;font-size:14px;">Add Target Repository</div>
      <div style="font-size:12px;color:var(--text-dim);margin-top:4px;">Configure a new codebase for multi-agent auditing</div>
    </div>
  `;

  container.innerHTML = cardsHtml + addCardHtml;
}

/* =========================================================================
   TAB 1: SYSTEMS & SUBSYSTEMS EXPLORER
   ========================================================================= */
function renderSystemsExplorer() {
  const systems = state.snapshot.systems;
  const query = (document.getElementById("systemSearchInput").value || "").trim().toLowerCase();
  const treeContainer = document.getElementById("systemTreeContainer");

  if (systems.length === 0) {
    treeContainer.innerHTML = `<div class="empty-state">No systems mapped yet. Click "+ Add System" or "⚡ Load Demo Data".</div>`;
    document.getElementById("systemDossierPane").innerHTML =
      `<div class="empty-state">Add a system or load demo data to inspect architecture details.</div>`;
    return;
  }

  const byParent = {};
  systems.forEach((s) => {
    const pid = s.parent_id || "ROOT";
    if (!byParent[pid]) byParent[pid] = [];
    byParent[pid].push(s);
  });

  const matchesQuery = (s) => {
    if (!query) return true;
    return (
      s.name.toLowerCase().includes(query) ||
      s.slug.toLowerCase().includes(query) ||
      (s.path_scope || "").toLowerCase().includes(query) ||
      (s.description || "").toLowerCase().includes(query)
    );
  };

  const html = [];
  const visitedNodes = new Set();

  function renderNode(sys, depth) {
    if (visitedNodes.has(sys.id)) return;
    visitedNodes.add(sys.id);

    const children = byParent[sys.id] || [];
    const selfMatch = matchesQuery(sys);
    const childMatches = children.some((c) => matchesQuery(c) || (byParent[c.id] || []).some(matchesQuery));
    if (!selfMatch && !childMatches) return;

    const isSelected = sys.id === state.selectedSystemId;
    const isCollapsed = state.collapsedSystems ? state.collapsedSystems.has(sys.id) : false;
    const hasChildren = children.length > 0;

    const claimPill = sys.claimed_by
      ? `<span class="badge badge-claimed" style="font-size:10px;padding:1px 5px" title="Claimed until ${esc(sys.lease_until)}">🔒 @${esc(sys.claimed_by)}</span>`
      : "";
    const findingsPill =
      sys.open_findings_count > 0
        ? `<span class="badge ${sys.high_findings_count > 0 ? "badge-critical" : "badge-medium"}" style="font-size:10px;padding:1px 5px">${sys.open_findings_count} finding${sys.open_findings_count > 1 ? "s" : ""}</span>`
        : "";

    const expanderBtn = hasChildren
      ? `<span class="tree-expander" data-action="toggle-system-collapse" data-id="${esc(sys.id)}" style="cursor:pointer;padding:0 4px;color:var(--text-dim);font-size:10px;user-select:none" title="${isCollapsed ? 'Expand children' : 'Collapse children'}">${isCollapsed ? '▶' : '▼'}</span>`
      : `<span style="display:inline-block;width:16px"></span>`;

    html.push(`
      <div class="tree-node ${depth > 0 ? "child-node" : ""} ${isSelected ? "selected" : ""}"
           data-action="select-system" data-id="${esc(sys.id)}">
        <div class="tree-node-top">
          <div class="tree-node-title">
            ${expanderBtn}
            <span class="node-icon">${depth === 0 ? "📦" : "↳"}</span>
            <span>${esc(sys.name)}</span>
          </div>
          ${healthBadge(sys.health_score)}
        </div>
        <div class="tree-node-meta" style="${depth > 0 ? 'padding-left:18px' : 'padding-left:16px'}">
          <span class="slug-label">${esc(sys.slug)}</span>
          <span>·</span>
          <span>${esc(sys.system_type)}</span>
          ${statusBadge(sys.status)}
          ${claimPill}
          ${findingsPill}
        </div>
      </div>
    `);

    if (!isCollapsed) {
      children.forEach((child) => renderNode(child, depth + 1));
    }
  }

  (byParent["ROOT"] || []).forEach((rootSys) => renderNode(rootSys, 0));
  treeContainer.innerHTML = html.join("") || `<div class="empty-state">No matching systems found.</div>`;

  if (state.selectedSystemId) {
    loadAndRenderDossier(state.selectedSystemId);
  }
}

window.selectSystem = function (systemId) {
  state.selectedSystemId = systemId;
  if (state.activeTab !== "systems") {
    switchTab("systems");
  }
  renderSystemsExplorer();
};

function buildLocalSystemDossier(systemId) {
  const snap = state.snapshot;
  const sys = snap.systems.find((x) => x.id === systemId || x.slug === systemId);
  if (!sys) throw new Error(`System ${systemId} not found`);
  const parent = sys.parent_id ? snap.systems.find((x) => x.id === sys.parent_id) || null : null;
  const subsystems = snap.systems.filter((x) => x.parent_id === sys.id);
  const outbound_relations = snap.relations.filter((r) => r.source_system_id === sys.id);
  const inbound_relations = snap.relations.filter((r) => r.target_system_id === sys.id);
  const findings = snap.findings.filter((f) => f.system_id === sys.id || f.related_system_id === sys.id);
  const tasks = snap.tasks.filter((t) => t.system_id === sys.id);
  return { ...sys, parent, subsystems, outbound_relations, inbound_relations, findings, tasks };
}

async function loadAndRenderDossier(systemId) {
  const pane = document.getElementById("systemDossierPane");
  try {
    let s;
    if (window.location.protocol === "file:" && state.snapshot) {
      s = buildLocalSystemDossier(systemId);
    } else {
      try {
        s = await api(`/api/systems/${encodeURIComponent(systemId)}?project=${encodeURIComponent(state.activeProjectId)}`);
      } catch (_e) {
        s = buildLocalSystemDossier(systemId);
      }
    }
    state.lastDossier = s;
    const isClaimed = Boolean(s.claimed_by);
    const curTab = state.dossierTab || "overview";

    const subsystemsHtml =
      s.subsystems.length === 0
        ? `<div style="color:var(--text-dim);font-size:12.5px;padding:8px 0">No child subsystems registered under this component.</div>`
        : `<div class="rel-grid">
            ${s.subsystems
              .map(
                (sub) => `
              <div class="rel-card" style="cursor:pointer" data-action="select-system" data-id="${esc(sub.id)}">
                <div class="rel-card-top">
                  <strong>↳ ${esc(sub.name)} <span style="font-family:var(--font-mono);font-weight:400;color:var(--text-muted)">(${esc(sub.slug)})</span></strong>
                  <div style="display:flex;gap:6px;align-items:center">${statusBadge(sub.status)} ${healthBadge(sub.health_score)}</div>
                </div>
                <div style="font-size:12px;color:var(--text-muted)">${esc(sub.description || "No description provided")}</div>
                <div style="font-size:11px;font-family:var(--font-mono);color:var(--text-dim)">Scope: ${esc(sub.path_scope || "—")} · Updated: ${esc(fmtTime(sub.updated_at))}</div>
              </div>
            `
              )
              .join("")}
          </div>`;

    const outboundHtml =
      s.outbound_relations.length === 0
        ? `<div style="color:var(--text-dim);font-size:12.5px;padding:6px 0">No outbound dependencies recorded.</div>`
        : s.outbound_relations
            .map(
              (r) => `
            <div class="rel-card">
              <div class="rel-card-top">
                <span>
                  <strong>${esc(s.name)}</strong>
                  <span class="badge badge-info">${esc(r.relation_type)} ${r.direction === "bidirectional" ? "↔" : "→"}</span>
                  <button class="link-btn" data-action="select-system" data-id="${esc(r.target_system_id)}"><strong>${esc(r.target_name)}</strong></button>
                </span>
                ${severityBadge(r.criticality)}
              </div>
              <div style="font-size:11.5px;font-family:var(--font-mono);color:var(--accent-light)">Interface/Protocol: ${esc(r.interface_or_protocol || "Direct")}</div>
              <div style="font-size:12.5px;color:var(--text-secondary)">${esc(r.description)}</div>
              ${r.details ? `<div style="font-size:11.5px;color:var(--text-muted)">${esc(r.details)}</div>` : ""}
              <div style="font-size:11px;color:var(--text-dim)">Recorded by ${esc(r.recorded_by || "system")} · ${esc(fmtTime(r.updated_at))}</div>
            </div>
          `
            )
            .join("");

    const inboundHtml =
      s.inbound_relations.length === 0
        ? `<div style="color:var(--text-dim);font-size:12.5px;padding:6px 0">No inbound callers or dependents recorded.</div>`
        : s.inbound_relations
            .map(
              (r) => `
            <div class="rel-card">
              <div class="rel-card-top">
                <span>
                  <button class="link-btn" data-action="select-system" data-id="${esc(r.source_system_id)}"><strong>${esc(r.source_name)}</strong></button>
                  <span class="badge badge-info">${esc(r.relation_type)} →</span>
                  <strong>${esc(s.name)}</strong>
                </span>
                ${severityBadge(r.criticality)}
              </div>
              <div style="font-size:11.5px;font-family:var(--font-mono);color:var(--accent-light)">Interface/Protocol: ${esc(r.interface_or_protocol || "Direct")}</div>
              <div style="font-size:12.5px;color:var(--text-secondary)">${esc(r.description)}</div>
              ${r.details ? `<div style="font-size:11.5px;color:var(--text-muted)">${esc(r.details)}</div>` : ""}
              <div style="font-size:11px;color:var(--text-dim)">Recorded by ${esc(r.recorded_by || "system")} · ${esc(fmtTime(r.updated_at))}</div>
            </div>
          `
            )
            .join("");

    const findingsHtml =
      s.findings.length === 0
        ? `<div style="color:var(--text-dim);font-size:12.5px;padding:8px 0">No open findings logged for this system.</div>`
        : s.findings
            .map(
              (f) => `
            <div class="finding-card">
              <div class="finding-card-top">
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
                  ${severityBadge(f.severity)}
                  <span class="badge">${esc(f.category)}</span>
                  <span class="finding-title">${esc(f.title)}</span>
                </div>
                <div style="display:flex;align-items:center;gap:8px">
                  ${statusBadge(f.status)}
                  <select data-action="update-finding-status" data-id="${esc(f.id)}" style="padding:2px 8px;font-size:11px">
                    <option value="open" ${f.status === 'open' ? 'selected' : ''}>Open</option>
                    <option value="confirmed" ${f.status === 'confirmed' ? 'selected' : ''}>Confirmed</option>
                    <option value="mitigated" ${f.status === 'mitigated' ? 'selected' : ''}>Mitigated</option>
                    <option value="resolved" ${f.status === 'resolved' ? 'selected' : ''}>Resolved</option>
                    <option value="wont_fix" ${f.status === 'wont_fix' ? 'selected' : ''}>Won't Fix</option>
                  </select>
                </div>
              </div>
              ${
                f.file_path
                  ? `
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
                  <span class="finding-loc">${esc(f.file_path)}${f.line_range ? ":" + esc(f.line_range) : ""}</span>
                  ${f.commit_sha ? `<span class="badge" style="font-family:var(--font-mono);font-size:10.5px">commit <code>${esc(f.commit_sha.slice(0, 8))}</code></span>` : ""}
                  ${f.span_hash ? `<span class="badge" style="font-family:var(--font-mono);font-size:10.5px" title="Evidence snippet SHA256">span <code>${esc(f.span_hash.slice(0, 8))}</code></span>` : ""}
                </div>
              `
                  : ""
              }
              <div style="font-size:12.5px;color:var(--text-secondary)">${esc(f.description)}</div>
              ${f.details ? `<div style="font-size:12px;color:var(--text-muted)"><strong>Details:</strong> ${esc(f.details)}</div>` : ""}
              ${f.recommendation ? `<div class="finding-rec-box"><strong>💡 Recommendation:</strong> ${esc(f.recommendation)}</div>` : ""}
              <div style="font-size:11px;color:var(--text-dim)">Logged by @${esc(f.agent_id || "unknown")} · ${esc(fmtTime(f.created_at))}</div>
            </div>
          `
            )
            .join("");

    const tasksHtml =
      s.tasks.length === 0
        ? `<div style="color:var(--text-dim);font-size:12.5px;padding:8px 0">No audit tasks currently queued for this component.</div>`
        : `<div class="rel-grid">
            ${s.tasks
              .map(
                (t) => `
              <div class="rel-card">
                <div class="rel-card-top">
                  <strong style="font-size:12.5px">${esc(t.title)}</strong>
                  <div style="display:flex;gap:6px;align-items:center">
                    ${severityBadge(t.priority)}
                    ${statusBadge(t.status)}
                  </div>
                </div>
                <div style="font-size:12px;color:var(--text-muted)">${esc(t.description || "Standard audit review task")}</div>
                <div style="font-size:11px;font-family:var(--font-mono);color:var(--text-dim)">
                  Type: ${esc(t.task_type)} · Claimed: ${t.claimed_by ? "@" + esc(t.claimed_by) : "Unassigned"}
                </div>
                <div style="display:flex;gap:6px;margin-top:4px">
                  ${
                    t.status === "open"
                      ? `<button class="btn btn-xs btn-primary" data-action="claim-task" data-id="${esc(t.id)}">🔒 Claim Task</button>`
                      : t.status === "claimed"
                      ? `<button class="btn btn-xs btn-accent" data-action="complete-task" data-id="${esc(t.id)}">✓ Complete</button>`
                      : `<span style="font-size:11px;color:var(--healthy);font-weight:600">✓ Completed</span>`
                  }
                </div>
              </div>
            `
              )
              .join("")}
          </div>`;

    // Sections definitions
    const overviewSection = `
      <div class="dossier-section">
        <div class="meta-grid">
          <div class="meta-item">
            <span class="meta-label">Component ID</span>
            <div style="display:flex;align-items:center;gap:6px">
              <span class="meta-val">${esc(s.id)}</span>
              <button class="btn btn-xs btn-ghost" data-action="copy-text" data-text="${esc(s.id)}" title="Copy Component ID">📋</button>
            </div>
          </div>
          <div class="meta-item">
            <span class="meta-label">Parent System</span>
            <span class="meta-val">${
              s.parent
                ? `<button class="link-btn" data-action="select-system" data-id="${esc(s.parent.id)}">${esc(s.parent.name)} (${esc(s.parent.slug)})</button>`
                : "Top-Level Root System"
            }</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Codebase Path Scope</span>
            <div style="display:flex;align-items:center;gap:6px">
              <span class="meta-val">${esc(s.path_scope || "—")}</span>
              ${s.path_scope ? `<button class="btn btn-xs btn-ghost" data-action="copy-text" data-text="${esc(s.path_scope)}" title="Copy Path Scope">📋</button>` : ""}
            </div>
          </div>
          <div class="meta-item">
            <span class="meta-label">Active Agent Lock</span>
            <span class="meta-val">${s.claimed_by ? `@${esc(s.claimed_by)} (until ${esc(fmtTime(s.lease_until))})` : "Unclaimed"}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Last Audited By</span>
            <span class="meta-val">${esc(s.last_audited_by || "—")} (${esc(fmtTime(s.last_audited_at))})</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Created / Updated</span>
            <span class="meta-val">${esc(fmtTime(s.created_at))}<br/>${esc(fmtTime(s.updated_at))}</span>
          </div>
        </div>
      </div>

      <div class="dossier-section">
        <div class="dossier-section-header">
          <h4>Architectural Details, Invariants & Review Notes</h4>
        </div>
        <div class="details-box">${esc(s.details || "No detailed architectural notes recorded yet. Click 'Edit Specs' or release a claim with review notes.")}</div>
      </div>
    `;

    const subsystemsSection = `
      <div class="dossier-section">
        <div class="dossier-section-header">
          <h4>Child Subsystems (${s.subsystems.length})</h4>
          <button class="btn btn-xs btn-ghost" data-action="add-subsystem" data-id="${esc(s.id)}">+ New Subsystem</button>
        </div>
        ${subsystemsHtml}
      </div>
    `;

    const relationsSection = `
      <div class="dossier-section">
        <div class="dossier-section-header">
          <h4>Cross-System Interactions — How "${esc(s.name)}" Works With Other Systems</h4>
          <button class="btn btn-xs btn-ghost" data-action="add-relation" data-slug="${esc(s.slug)}">+ Add Interaction</button>
        </div>
        <div class="rel-grid">
          <div>
            <div style="font-size:11px;font-weight:700;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.04em;margin-bottom:8px">OUTBOUND (Calls / Depends On / Publishes To) — ${s.outbound_relations.length}</div>
            <div style="display:flex;flex-direction:column;gap:8px">${outboundHtml}</div>
          </div>
          <div>
            <div style="font-size:11px;font-weight:700;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.04em;margin-bottom:8px">INBOUND (Used By / Consumed By) — ${s.inbound_relations.length}</div>
            <div style="display:flex;flex-direction:column;gap:8px">${inboundHtml}</div>
          </div>
        </div>
      </div>
    `;

    const findingsSection = `
      <div class="dossier-section">
        <div class="dossier-section-header">
          <h4>Audit Findings & Defects (${s.findings.length})</h4>
          <button class="btn btn-xs btn-danger" data-action="add-finding" data-slug="${esc(s.slug)}">+ Log Finding</button>
        </div>
        <div style="display:flex;flex-direction:column;gap:8px">${findingsHtml}</div>
      </div>
    `;

    const tasksSection = `
      <div class="dossier-section">
        <div class="dossier-section-header">
          <h4>Scoped Audit Tasks (${s.tasks.length})</h4>
          <button class="btn btn-xs btn-ghost" data-action="add-task">+ Create Task</button>
        </div>
        ${tasksHtml}
      </div>
    `;

    let activeContent = "";
    if (curTab === "overview") {
      activeContent = overviewSection;
    } else if (curTab === "subsystems") {
      activeContent = subsystemsSection;
    } else if (curTab === "relations") {
      activeContent = relationsSection;
    } else if (curTab === "findings") {
      activeContent = findingsSection;
    } else if (curTab === "tasks") {
      activeContent = tasksSection;
    } else {
      // "all"
      activeContent = overviewSection + subsystemsSection + relationsSection + findingsSection + tasksSection;
    }

    pane.innerHTML = `
      <div class="dossier-breadcrumbs">
        <span>Projects</span>
        <span>/</span>
        <span>${esc(state.snapshot.project.name)}</span>
        <span>/</span>
        <span style="color:var(--text-main)">${esc(s.name)}</span>
      </div>

      <div class="dossier-header">
        <div>
          <div class="dossier-title-row">
            <span class="dossier-title">${esc(s.name)}</span>
            <span class="dossier-slug">${esc(s.slug)}</span>
            <span class="badge">${esc(s.system_type)}</span>
            ${statusBadge(s.status)}
            ${healthBadge(s.health_score)}
          </div>
          <div class="dossier-desc">${esc(s.description || "No architectural description recorded for this component.")}</div>
        </div>

        <div class="dossier-actions">
          ${
            isClaimed
              ? `<button class="btn btn-sm btn-secondary" data-action="release-system" data-id="${esc(s.id)}">🔓 Release Claim (@${esc(s.claimed_by)})</button>`
              : `<button class="btn btn-sm btn-primary" data-action="claim-system" data-id="${esc(s.id)}">🔒 Claim System</button>`
          }
          <button class="btn btn-sm" data-action="edit-system" data-id="${esc(s.id)}">✎ Edit Specs</button>
          <button class="btn btn-sm" data-action="add-subsystem" data-id="${esc(s.id)}">+ Subsystem</button>
          <button class="btn btn-sm" data-action="add-relation" data-slug="${esc(s.slug)}">+ Contract Link</button>
          <button class="btn btn-sm btn-danger" data-action="add-finding" data-slug="${esc(s.slug)}">+ Log Finding</button>
        </div>
      </div>

      <!-- Dossier Multi-Section Navigation Bar -->
      <div class="dossier-nav">
        <button class="dossier-nav-btn ${curTab === 'overview' ? 'active' : ''}" data-action="switch-dossier-tab" data-tab="overview">
          📋 Specs & Invariants
        </button>
        <button class="dossier-nav-btn ${curTab === 'subsystems' ? 'active' : ''}" data-action="switch-dossier-tab" data-tab="subsystems">
          ↳ Subsystems <span class="tab-badge">${s.subsystems.length}</span>
        </button>
        <button class="dossier-nav-btn ${curTab === 'relations' ? 'active' : ''}" data-action="switch-dossier-tab" data-tab="relations">
          🔗 Interactions <span class="tab-badge">${s.outbound_relations.length + s.inbound_relations.length}</span>
        </button>
        <button class="dossier-nav-btn ${curTab === 'findings' ? 'active' : ''}" data-action="switch-dossier-tab" data-tab="findings">
          🛡️ Findings <span class="tab-badge ${s.findings.length > 0 ? 'tab-badge-danger' : ''}">${s.findings.length}</span>
        </button>
        <button class="dossier-nav-btn ${curTab === 'tasks' ? 'active' : ''}" data-action="switch-dossier-tab" data-tab="tasks">
          ⚡ Tasks <span class="tab-badge">${s.tasks.length}</span>
        </button>
        <button class="dossier-nav-btn ${curTab === 'all' ? 'active' : ''}" data-action="switch-dossier-tab" data-tab="all" style="margin-left:auto">
          👁️ View All Sections
        </button>
      </div>

      ${activeContent}
    `;
  } catch (err) {
    pane.innerHTML = `<div class="empty-state">Could not load system dossier: ${esc(err.message)}</div>`;
  }
}

window.claimSystemAction = async function (systemId) {
  if (!state.activeAgentId) {
    showToast("Please register or select an Acting Agent first.");
    openRegisterAgentModal();
    return;
  }
  try {
    await api("/api/systems/claim", {
      method: "POST",
      body: JSON.stringify({
        project_id: state.activeProjectId,
        system_ref: systemId,
        agent_id: state.activeAgentId,
        lease_minutes: 30,
        force: true,
      }),
    });
    showToast(`Claimed system for @${state.activeAgentId}`);
    await loadSnapshot();
  } catch (err) {
    showToast(err.message);
  }
};

window.releaseSystemPromptById = function (systemId) {
  const s =
    (state.lastDossier && state.lastDossier.id === systemId ? state.lastDossier : null) ||
    (state.snapshot?.systems || []).find((x) => x.id === systemId);
  if (!s) return;
  const currentStatus = s.status || "reviewed";
  const currentHealth = s.health_score ?? "";

  openModal(
    `Release Claim on "${s.name}"`,
    `
      <div class="form-row-2">
        <div class="form-row">
          <label>Updated Status</label>
          <select name="status">
            <option value="reviewed" ${currentStatus === "reviewed" ? "selected" : ""}>reviewed</option>
            <option value="healthy" ${currentStatus === "healthy" ? "selected" : ""}>healthy</option>
            <option value="needs_attention" ${currentStatus === "needs_attention" ? "selected" : ""}>needs_attention</option>
            <option value="in_progress" ${currentStatus === "in_progress" ? "selected" : ""}>in_progress</option>
          </select>
        </div>
        <div class="form-row">
          <label>Health Score (0–100)</label>
          <input type="number" name="health_score" min="0" max="100" value="${esc(currentHealth)}" />
        </div>
      </div>
      <div class="form-row">
        <label>Append Timestamped Audit Note (optional)</label>
        <textarea name="details_append" rows="3" placeholder="Summarize what was verified or updated during this review session..."></textarea>
      </div>
    `,
    async (formData) => {
      await api("/api/systems/release", {
        method: "POST",
        body: JSON.stringify({
          project_id: state.activeProjectId,
          system_ref: systemId,
          agent_id: state.activeAgentId,
          status: formData.get("status"),
          health_score: formData.get("health_score"),
          details_append: formData.get("details_append"),
          force: true,
        }),
      });
      showToast(`Released claim on ${s.name}`);
      await loadSnapshot();
    }
  );
};

/* =========================================================================
   TAB 2: CROSS-SYSTEM TOPOLOGY & INTERACTION GRAPH
   ========================================================================= */
function renderTopologyTab() {
  const { systems, relations } = state.snapshot;
  const filterSel = document.getElementById("relationSystemFilter");
  const currentFilter = filterSel.value;

  filterSel.innerHTML =
    `<option value="">All Systems & Subsystems (${systems.length})</option>` +
    systems
      .map(
        (s) =>
          `<option value="${esc(s.id)}" ${s.id === currentFilter ? "selected" : ""}>${s.parent_id ? "↳ " : ""}${esc(s.name)} (${esc(s.slug)})</option>`
      )
      .join("");

  const filteredRels = currentFilter
    ? relations.filter((r) => r.source_system_id === currentFilter || r.target_system_id === currentFilter)
    : relations;

  document.getElementById("relationsCountBadge").textContent = `${filteredRels.length} interactions`;

  const tbody = document.getElementById("relationsTableBody");
  if (filteredRels.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-state">No cross-system interactions match the filter.</td></tr>`;
  } else {
    tbody.innerHTML = filteredRels
      .map(
        (r) => `
        <tr>
          <td>
            <button class="link-btn" data-action="select-system" data-id="${esc(r.source_system_id)}"><strong>${esc(r.source_name)}</strong></button>
            <div style="font-size:11px;font-family:var(--font-mono);color:var(--text-dim)">${esc(r.source_slug)} (${esc(r.source_type)})</div>
          </td>
          <td>
            <span class="badge badge-info">${esc(r.relation_type)} ${r.direction === "bidirectional" ? "↔" : "→"}</span>
          </td>
          <td>
            <button class="link-btn" data-action="select-system" data-id="${esc(r.target_system_id)}"><strong>${esc(r.target_name)}</strong></button>
            <div style="font-size:11px;font-family:var(--font-mono);color:var(--text-dim)">${esc(r.target_slug)} (${esc(r.target_type)})</div>
          </td>
          <td style="font-family:var(--font-mono);color:var(--accent)">${esc(r.interface_or_protocol || "direct")}</td>
          <td>${severityBadge(r.criticality)}</td>
          <td>
            <div>${esc(r.description)}</div>
            ${r.details ? `<div style="font-size:11.5px;color:var(--text-muted);margin-top:3px">${esc(r.details)}</div>` : ""}
          </td>
          <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">
            @${esc(r.recorded_by || "system")}<br/>${esc(fmtTime(r.updated_at))}
          </td>
        </tr>
      `
      )
      .join("");
  }

  renderTopologySvg(systems, filteredRels);
}

function renderTopologySvg(systems, relations) {
  const wrapper = document.getElementById("topologySvgWrapper");
  if (systems.length === 0) {
    wrapper.innerHTML = `<div class="empty-state">No systems to visualize.</div>`;
    return;
  }

  const roots = systems.filter((s) => !s.parent_id);
  const byParent = {};
  systems.forEach((s) => {
    if (s.parent_id) {
      if (!byParent[s.parent_id]) byParent[s.parent_id] = [];
      byParent[s.parent_id].push(s);
    }
  });

  const colWidth = 270;
  const nodeW = 220;
  const nodeH = 54;
  const padX = 36;
  const padY = 36;
  const rowGap = 86;

  const coords = {};
  let maxRows = 1;

  roots.forEach((r, colIdx) => {
    const x = padX + colIdx * colWidth;
    const y = padY;
    coords[r.id] = { x, y, sys: r, isRoot: true };
    const children = byParent[r.id] || [];
    if (children.length + 1 > maxRows) maxRows = children.length + 1;
    children.forEach((ch, rowIdx) => {
      coords[ch.id] = {
        x: x + 12,
        y: padY + (rowIdx + 1) * rowGap,
        sys: ch,
        isRoot: false,
      };
    });
  });

  let extraIdx = 0;
  systems.forEach((s) => {
    if (!coords[s.id]) {
      coords[s.id] = {
        x: padX + (extraIdx % Math.max(1, roots.length)) * colWidth,
        y: padY + maxRows * rowGap,
        sys: s,
        isRoot: false,
      };
      extraIdx++;
    }
  });

  const width = Math.max(920, padX * 2 + roots.length * colWidth);
  const height = Math.max(320, padY * 2 + (maxRows + (extraIdx ? 1 : 0)) * rowGap);

  const svgParts = [
    `<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg" style="display:block;font-family:var(--font-sans)">`,
    `<defs>
      <marker id="arrow-critical" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
        <path d="M0,0 L8,4 L0,8 Z" fill="#f43f5e" />
      </marker>
      <marker id="arrow-high" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
        <path d="M0,0 L8,4 L0,8 Z" fill="#fb923c" />
      </marker>
      <marker id="arrow-medium" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
        <path d="M0,0 L8,4 L0,8 Z" fill="#38bdf8" />
      </marker>
    </defs>`,
  ];

  systems.forEach((s) => {
    if (s.parent_id && coords[s.parent_id] && coords[s.id]) {
      const p = coords[s.parent_id];
      const c = coords[s.id];
      const x1 = p.x + 18;
      const y1 = p.y + nodeH;
      const x2 = c.x;
      const y2 = c.y + nodeH / 2;
      svgParts.push(
        `<path d="M${x1},${y1} L${x1},${y2} L${x2},${y2}" stroke="#334155" stroke-width="1.5" stroke-dasharray="3,3" fill="none" />`
      );
    }
  });

  relations.forEach((r, idx) => {
    const src = coords[r.source_system_id];
    const tgt = coords[r.target_system_id];
    if (!src || !tgt) return;

    const sx = src.x + nodeW / 2;
    const sy = src.y + nodeH / 2;
    const tx = tgt.x + nodeW / 2;
    const ty = tgt.y + nodeH / 2;

    const dy = ty - sy;
    const curveOffset = (idx % 2 === 0 ? 1 : -1) * 26;
    const cx = (sx + tx) / 2 + (Math.abs(dy) > 40 ? curveOffset : 0);
    const cy = (sy + ty) / 2 - 22;

    const crit = r.criticality === "critical" ? "critical" : r.criticality === "high" ? "high" : "medium";
    const stroke = crit === "critical" ? "#f43f5e" : crit === "high" ? "#fb923c" : "#38bdf8";

    svgParts.push(
      `<path d="M${sx},${sy} Q${cx},${cy} ${tx},${ty}" stroke="${stroke}" stroke-width="2" fill="none" marker-end="url(#arrow-${crit})" opacity="0.85" />`
    );
    svgParts.push(
      `<rect x="${cx - 48}" y="${cy - 9}" width="96" height="17" rx="4" fill="#0f172a" stroke="${stroke}" stroke-width="0.8" />`,
      `<text x="${cx}" y="${cy + 3}" fill="#e2e8f0" font-size="9.5" text-anchor="middle" font-family="var(--font-mono)">${esc(r.relation_type)}</text>`
    );
  });

  Object.values(coords).forEach(({ x, y, sys, isRoot }) => {
    const fill = isRoot ? "#1e293b" : "#111827";
    const stroke =
      sys.status === "needs_attention"
        ? "#f43f5e"
        : sys.status === "healthy"
        ? "#10b981"
        : isRoot
        ? "#38bdf8"
        : "#475569";

    const healthTxt = sys.health_score !== null ? `${sys.health_score}%` : "—";
    svgParts.push(`
      <g style="cursor:pointer" data-action="select-system" data-id="${esc(sys.id)}">
        <rect x="${x}" y="${y}" width="${nodeW}" height="${nodeH}" rx="8" fill="${fill}" stroke="${stroke}" stroke-width="${isRoot ? 2 : 1.3}" />
        <text x="${x + 10}" y="${y + 20}" fill="#f8fafc" font-size="12" font-weight="700">${esc(sys.name.slice(0, 24))}</text>
        <text x="${x + 10}" y="${y + 38}" fill="#94a3b8" font-size="10" font-family="var(--font-mono)">${esc(sys.system_type)} · ${esc(sys.status)}</text>
        <text x="${x + nodeW - 10}" y="${y + 20}" fill="#38bdf8" font-size="10.5" font-weight="700" text-anchor="end" font-family="var(--font-mono)">${esc(healthTxt)}</text>
        ${
          sys.claimed_by
            ? `<text x="${x + nodeW - 10}" y="${y + 38}" fill="#d8b4fe" font-size="9.5" text-anchor="end" font-family="var(--font-mono)">@${esc(sys.claimed_by.slice(0, 14))}</text>`
            : ""
        }
      </g>
    `);
  });

  svgParts.push(`</svg>`);
  wrapper.innerHTML = svgParts.join("");
}

/* =========================================================================
   TAB 3: MULTI-AGENT WORKFORCE & TASK QUEUE
   ========================================================================= */
function renderWorkforceTab() {
  const { agents, tasks } = state.snapshot;
  const grid = document.getElementById("agentsGrid");

  if (agents.length === 0) {
    grid.innerHTML = `<div class="empty-state">No agents registered yet. Click "+ Register New Agent".</div>`;
  } else {
    grid.innerHTML = agents
      .map((a) => {
        const isCurrent = a.id === state.activeAgentId;
        return `
          <div class="agent-card ${isCurrent ? "active-identity" : ""}">
            <div class="agent-card-top">
              <div>
                <div class="agent-name">${esc(a.name)}</div>
                <div class="agent-id">@${esc(a.id)}</div>
              </div>
              <span class="badge ${a.status === "active" ? "badge-healthy" : ""}">${esc(a.status)}</span>
            </div>
            <div style="display:flex;gap:6px;flex-wrap:wrap">
              <span class="badge badge-info">${esc(a.role)}</span>
              ${a.model ? `<span class="badge">${esc(a.model)}</span>` : ""}
            </div>
            ${
              a.capabilities
                ? `<div style="font-size:11.5px;color:var(--text-muted)"><strong>Capabilities:</strong> ${esc(a.capabilities)}</div>`
                : ""
            }
            <div style="font-size:12px;background:var(--bg-surface);padding:7px 9px;border-radius:6px;border:1px solid var(--border-subtle)">
              <div><strong>System Lock:</strong> ${a.current_system_name ? `${esc(a.current_system_name)} (${esc(a.current_system_slug)})` : "None"}</div>
              <div><strong>Active Task:</strong> ${esc(a.current_task_title || "Idle / Ready")}</div>
            </div>
            <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text-dim);font-family:var(--font-mono)">
              <span>Done: ${a.completed_tasks_count || 0} · Findings: ${a.findings_count || 0}</span>
              <span>HB: ${esc(fmtTime(a.last_heartbeat).slice(11, 19))}</span>
            </div>
            <div style="display:flex;gap:6px;margin-top:2px">
              ${
                isCurrent
                  ? `<span class="badge badge-low" style="flex:1;justify-content:center">✓ Acting Identity</span>`
                  : `<button class="btn btn-xs" style="flex:1;justify-content:center" data-action="set-active-agent" data-id="${esc(a.id)}">Act as @${esc(a.id)}</button>`
              }
              <button class="btn btn-xs btn-ghost" data-action="send-heartbeat" data-id="${esc(a.id)}">♥ Heartbeat</button>
            </div>
          </div>
        `;
      })
      .join("");
  }

  const openTasks = tasks.filter((t) => t.status === "open" || t.status === "blocked");
  const claimedTasks = tasks.filter((t) => t.status === "claimed");
  const completedTasks = tasks.filter((t) => t.status === "completed");

  document.getElementById("countTasksOpen").textContent = String(openTasks.length);
  document.getElementById("countTasksClaimed").textContent = String(claimedTasks.length);
  document.getElementById("countTasksCompleted").textContent = String(completedTasks.length);

  const renderTaskCard = (t) => `
    <div class="task-card">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:6px">
        ${severityBadge(t.priority)}
        <div style="display:flex;gap:4px">
          ${t.status === "blocked" ? `<span class="badge badge-critical">BLOCKED</span>` : ""}
          <span class="badge">${esc(t.task_type)}</span>
        </div>
      </div>
      <div class="task-card-title">${esc(t.title)}</div>
      ${t.description ? `<div style="font-size:12px;color:var(--text-muted)">${esc(t.description)}</div>` : ""}
      ${t.blocked_reason && t.status === "blocked" ? `<div style="font-size:11.5px;color:#fda4af"><strong>Blocked:</strong> ${esc(t.blocked_reason)}</div>` : ""}
      <div style="font-size:11.5px;font-family:var(--font-mono);color:var(--accent)">
        Target: ${t.system_name ? `<button class="link-btn" data-action="select-system" data-id="${esc(t.system_id)}">${esc(t.system_name)}</button>` : "Project-wide"}
      </div>
      ${
        t.claimed_by
          ? `<div style="font-size:11.5px;color:#d8b4fe">Worker: <strong>@${esc(t.claimed_by)}</strong> (Attempts: ${t.attempt_count || 1}/${t.max_attempts || 3})</div>`
          : ""
      }
      ${
        t.deliverable_summary
          ? `<div style="font-size:11.5px;background:var(--bg-surface);padding:6px 8px;border-radius:4px;color:#6ee7b7"><strong>Deliverable:</strong> ${esc(t.deliverable_summary)}</div>`
          : ""
      }
      <div style="font-size:10.5px;color:var(--text-dim);font-family:var(--font-mono)">
        ID: ${esc(t.id)} · Updated: ${esc(fmtTime(t.updated_at))}
      </div>
      <div style="display:flex;gap:6px;margin-top:4px;flex-wrap:wrap">
        ${
          t.status === "open" || t.status === "blocked"
            ? `<button class="btn btn-xs btn-secondary" data-action="claim-task" data-id="${esc(t.id)}">🔒 Claim Task</button>`
            : ""
        }
        ${
          t.status === "claimed"
            ? `<button class="btn btn-xs btn-primary" data-action="complete-task" data-id="${esc(t.id)}">✓ Complete</button>
               <button class="btn btn-xs btn-danger" data-action="block-task" data-id="${esc(t.id)}">⊘ Block</button>`
            : ""
        }
      </div>
    </div>
  `;

  document.getElementById("kanbanOpen").innerHTML =
    openTasks.map(renderTaskCard).join("") || `<div class="empty-state">No open tasks</div>`;
  document.getElementById("kanbanClaimed").innerHTML =
    claimedTasks.map(renderTaskCard).join("") || `<div class="empty-state">No claimed tasks</div>`;
  document.getElementById("kanbanCompleted").innerHTML =
    completedTasks.map(renderTaskCard).join("") || `<div class="empty-state">No completed tasks</div>`;
}

window.setActiveAgent = function (agentId) {
  state.activeAgentId = agentId;
  localStorage.setItem("auditos_active_agent", agentId);
  showToast(`Now acting as @${agentId}`);
  renderAll();
};

window.sendAgentHeartbeat = async function (agentId) {
  try {
    await api("/api/agents/heartbeat", {
      method: "POST",
      body: JSON.stringify({ id: agentId, lease_minutes: 30 }),
    });
    showToast(`Heartbeat refreshed for @${agentId}`);
    await loadSnapshot();
  } catch (err) {
    showToast(err.message);
  }
};

window.claimTaskAction = async function (taskId) {
  if (!state.activeAgentId) {
    showToast("Register or select an Acting Agent first.");
    openRegisterAgentModal();
    return;
  }
  try {
    await api("/api/tasks/claim", {
      method: "POST",
      body: JSON.stringify({ task_id: taskId, agent_id: state.activeAgentId, force: true }),
    });
    showToast(`Task ${taskId} claimed by @${state.activeAgentId}`);
    await loadSnapshot();
  } catch (err) {
    showToast(err.message);
  }
};

window.completeTaskPromptById = function (taskId) {
  const t = (state.snapshot?.tasks || []).find((x) => x.id === taskId);
  const title = t ? t.title : taskId;
  openModal(
    `Complete Task: ${title}`,
    `
      <div class="form-row">
        <label>Deliverable Summary & Findings Overview *</label>
        <textarea name="deliverable_summary" rows="3" required placeholder="Summarize what was audited, verified, or fixed..."></textarea>
      </div>
      <div class="form-row-2">
        <div class="form-row">
          <label>Target System Status (optional)</label>
          <select name="system_status">
            <option value="">(Auto-compute from open findings)</option>
            <option value="reviewed">reviewed</option>
            <option value="healthy">healthy</option>
            <option value="needs_attention">needs_attention</option>
          </select>
        </div>
        <div class="form-row">
          <label>Target System Health Score (optional, 0-100)</label>
          <input type="number" name="system_health_score" min="0" max="100" placeholder="e.g. 88" />
        </div>
      </div>
    `,
    async (fd) => {
      await api("/api/tasks/complete", {
        method: "POST",
        body: JSON.stringify({
          task_id: taskId,
          agent_id: state.activeAgentId,
          deliverable_summary: fd.get("deliverable_summary"),
          system_status: fd.get("system_status") || null,
          system_health_score: fd.get("system_health_score") || null,
          force: true,
        }),
      });
      showToast(`Completed task ${taskId}`);
      await loadSnapshot();
    }
  );
};

window.blockTaskPromptById = function (taskId) {
  const t = (state.snapshot?.tasks || []).find((x) => x.id === taskId);
  const title = t ? t.title : taskId;
  openModal(
    `Block Task: ${title}`,
    `
      <div class="form-row">
        <label>Blocked Reason *</label>
        <textarea name="reason" rows="3" required placeholder="Explain what dependency or issue is blocking this audit task..."></textarea>
      </div>
    `,
    async (fd) => {
      await api("/api/tasks/block", {
        method: "POST",
        body: JSON.stringify({
          task_id: taskId,
          agent_id: state.activeAgentId,
          reason: fd.get("reason"),
          force: true,
        }),
      });
      showToast(`Blocked task ${taskId}`);
      await loadSnapshot();
    }
  );
};

/* =========================================================================
   TAB 4: FINDINGS & REVIEW LEDGER
   ========================================================================= */
function renderFindingsTab() {
  const findings = state.snapshot.findings;
  const q = (document.getElementById("findingSearchInput").value || "").trim().toLowerCase();
  const sev = document.getElementById("findingSeverityFilter").value;
  const cat = document.getElementById("findingCategoryFilter").value;
  const st = document.getElementById("findingStatusFilter").value;

  const filtered = findings.filter((f) => {
    if (sev && f.severity !== sev) return false;
    if (cat && f.category !== cat) return false;
    if (st && f.status !== st) return false;
    if (q) {
      const hay = `${f.title} ${f.description} ${f.details} ${f.file_path} ${f.recommendation} ${f.system_name || ""} ${f.agent_id || ""}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const container = document.getElementById("findingsListContainer");
  if (filtered.length === 0) {
    container.innerHTML = `<div class="empty-state">No findings match the current filters.</div>`;
    return;
  }

  container.innerHTML = filtered
    .map(
      (f) => `
      <div class="finding-card">
        <div class="finding-card-top">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            ${severityBadge(f.severity)}
            <span class="badge badge-info">${esc(f.category)}</span>
            <span class="finding-title">${esc(f.title)}</span>
          </div>
          <div style="display:flex;align-items:center;gap:8px">
            <select data-action="update-finding-status" data-id="${esc(f.id)}" style="padding:3px 8px;font-size:12px">
              ${["open", "confirmed", "mitigated", "resolved", "wont_fix"]
                .map((opt) => `<option value="${opt}" ${f.status === opt ? "selected" : ""}>Status: ${opt}</option>`)
                .join("")}
            </select>
          </div>
        </div>

        <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:center;font-size:12px">
          <span><strong>System:</strong> ${
            f.system_id
              ? `<button class="link-btn" data-action="select-system" data-id="${esc(f.system_id)}">${esc(f.system_name)} (${esc(f.system_slug)})</button>`
              : "Project-wide"
          }</span>
          ${
            f.related_system_id
              ? `<span><strong>Works With / Affects:</strong> <button class="link-btn" data-action="select-system" data-id="${esc(f.related_system_id)}">${esc(f.related_system_name)}</button></span>`
              : ""
          }
          ${f.file_path ? `<span class="finding-loc">${esc(f.file_path)}${f.line_range ? ":" + esc(f.line_range) : ""}</span>` : ""}
          ${f.commit_sha ? `<span class="badge" style="font-family:var(--font-mono);font-size:10.5px">commit <code>${esc(f.commit_sha.slice(0, 8))}</code></span>` : ""}
          ${f.span_hash ? `<span class="badge" style="font-family:var(--font-mono);font-size:10.5px" title="Evidence snippet SHA256">span <code>${esc(f.span_hash.slice(0, 8))}</code></span>` : ""}
        </div>

        <div style="font-size:13px;color:var(--text-secondary)">${esc(f.description)}</div>
        ${
          f.details
            ? `<div style="background:var(--bg-base);padding:10px 14px;border-radius:var(--radius-sm);border:1px solid var(--border-subtle);font-size:12.5px;color:var(--text-muted)"><strong>Technical Details:</strong> ${esc(f.details)}</div>`
            : ""
        }
        ${
          f.recommendation
            ? `<div class="finding-rec-box"><strong>💡 Recommendation:</strong> ${esc(f.recommendation)}</div>`
            : ""
        }

        <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text-dim);font-family:var(--font-mono)">
          <span>Finding ID: ${esc(f.id)} · Logged by @${esc(f.agent_id || "unknown")} (${esc(f.agent_role || "auditor")})</span>
          <span>Created: ${esc(fmtTime(f.created_at))} · Updated: ${esc(fmtTime(f.updated_at))}</span>
        </div>
      </div>
    `
    )
    .join("");
}

window.updateFindingStatusAction = async function (findingId, newStatus) {
  try {
    await api("/api/findings/status", {
      method: "POST",
      body: JSON.stringify({
        finding_id: findingId,
        status: newStatus,
        agent_id: state.activeAgentId,
      }),
    });
    showToast(`Finding ${findingId} marked ${newStatus}`);
    await loadSnapshot();
  } catch (err) {
    showToast(err.message);
  }
};

/* =========================================================================
   TAB 5: CHRONOLOGICAL AUDIT TRAIL
   ========================================================================= */
function renderLogsTab() {
  const logs = state.snapshot.logs;
  const q = (document.getElementById("logSearchInput").value || "").trim().toLowerCase();
  const filtered = logs.filter((l) => {
    if (!q) return true;
    return `${l.agent_id || ""} ${l.action} ${l.entity_type} ${l.summary} ${l.details_json}`.toLowerCase().includes(q);
  });

  const tbody = document.getElementById("logsTableBody");
  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No audit trail events match filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered
    .map(
      (l) => `
      <tr>
        <td style="font-family:var(--font-mono);font-size:11.5px;color:var(--text-muted);white-space:nowrap">${esc(fmtTime(l.created_at))}</td>
        <td>
          ${
            l.agent_id
              ? `<span class="badge badge-claimed">@${esc(l.agent_id)}</span>`
              : `<span class="badge">system</span>`
          }
        </td>
        <td style="font-family:var(--font-mono);color:var(--accent)">${esc(l.action)}</td>
        <td style="font-family:var(--font-mono);font-size:11.5px">${esc(l.entity_type)}:${esc(l.entity_id)}</td>
        <td>
          <div>${esc(l.summary)}</div>
          ${
            l.details_json && l.details_json !== "{}"
              ? `<div style="font-family:var(--font-mono);font-size:11px;color:var(--text-dim)">${esc(l.details_json)}</div>`
              : ""
          }
        </td>
      </tr>
    `
    )
    .join("");
}

/* =========================================================================
   MODALS & FORMS
   ========================================================================= */
function openModal(title, bodyHtml, onSubmit) {
  document.getElementById("modalTitle").textContent = title;
  document.getElementById("modalBody").innerHTML = bodyHtml;
  state.modalSubmitHandler = onSubmit;
  document.getElementById("modalBackdrop").classList.remove("hidden");
}

function closeModal() {
  document.getElementById("modalBackdrop").classList.add("hidden");
  state.modalSubmitHandler = null;
}

function systemOptionsHtml(selectedRef = "", includeEmpty = true) {
  const systems = state.snapshot ? state.snapshot.systems : [];
  const opts = includeEmpty ? [`<option value="">(None / Top-Level System)</option>`] : [];
  systems.forEach((s) => {
    const isSel = s.id === selectedRef || s.slug === selectedRef;
    opts.push(
      `<option value="${esc(s.id)}" ${isSel ? "selected" : ""}>${s.parent_id ? "↳ " : ""}${esc(s.name)} (${esc(s.slug)})</option>`
    );
  });
  return opts.join("");
}

window.openNewProjectModal = function () {
  openModal(
    "Create New Project Audit",
    `
      <div class="form-row">
        <label>Project Name *</label>
        <input type="text" name="name" required placeholder="e.g. Core Payment Platform" />
      </div>
      <div class="form-row">
        <label>Codebase Root Path</label>
        <input type="text" name="root_path" placeholder="e.g. /Users/dev/repos/payment-platform" />
      </div>
      <div class="form-row">
        <label>High-Level Description</label>
        <textarea name="description" rows="3" placeholder="Brief summary of the project architecture and audit goals..."></textarea>
      </div>
    `,
    async (fd) => {
      const p = await api("/api/projects", {
        method: "POST",
        body: JSON.stringify({
          name: fd.get("name"),
          root_path: fd.get("root_path"),
          description: fd.get("description"),
        }),
      });
      state.activeProjectId = p.id;
      showToast(`Created project ${p.name}`);
      await loadSnapshot(p.id);
    }
  );
};

window.openRegisterAgentModal = function () {
  openModal(
    "Register Worker / Agent Identity",
    `
      <div class="form-row-2">
        <div class="form-row">
          <label>Agent ID (unique slug) *</label>
          <input type="text" name="id" required pattern="[a-zA-Z0-9_-]{1,64}" placeholder="e.g. agent-sec-01" />
        </div>
        <div class="form-row">
          <label>Display Name *</label>
          <input type="text" name="name" required placeholder="e.g. Sentinel (Security)" />
        </div>
      </div>
      <div class="form-row-2">
        <div class="form-row">
          <label>Specialty Role</label>
          <select name="role">
            <option value="architecture-mapper">architecture-mapper</option>
            <option value="security-auditor">security-auditor</option>
            <option value="performance-reviewer">performance-reviewer</option>
            <option value="integration-verifier">integration-verifier</option>
            <option value="bug-hunter">bug-hunter</option>
            <option value="general-auditor">general-auditor</option>
          </select>
        </div>
        <div class="form-row">
          <label>Model / Runtime</label>
          <input type="text" name="model" placeholder="e.g. gemini-2.5-pro / claude-3.7" />
        </div>
      </div>
      <div class="form-row">
        <label>Capabilities / Focus Scope</label>
        <input type="text" name="capabilities" placeholder="e.g. auth-flows, concurrency, sql-locks" />
      </div>
    `,
    async (fd) => {
      const agent = await api("/api/agents/register", {
        method: "POST",
        body: JSON.stringify({
          id: fd.get("id"),
          name: fd.get("name"),
          role: fd.get("role"),
          model: fd.get("model"),
          capabilities: fd.get("capabilities"),
          project_id: state.activeProjectId,
        }),
      });
      state.activeAgentId = agent.id;
      localStorage.setItem("auditos_active_agent", agent.id);
      showToast(`Registered agent @${agent.id}`);
      await loadSnapshot();
    }
  );
};

window.openAddSystemModalById = function (parentId = "") {
  const parentObj = (state.snapshot?.systems || []).find((x) => x.id === parentId);
  openAddSystemModal(parentId, parentObj ? parentObj.name : "");
};

window.openAddSystemModal = function (parentId = "", parentName = "") {
  const isSub = Boolean(parentId);
  openModal(
    isSub ? `Add Subsystem under "${parentName}"` : "Add System or Subsystem",
    `
      <div class="form-row-2">
        <div class="form-row">
          <label>Name *</label>
          <input type="text" name="name" required placeholder="e.g. Auth Token Service" />
        </div>
        <div class="form-row">
          <label>Slug (optional)</label>
          <input type="text" name="slug" pattern="[a-zA-Z0-9_-]{1,64}" placeholder="auto-generated if blank" />
        </div>
      </div>
      <div class="form-row-2">
        <div class="form-row">
          <label>Parent System</label>
          <select name="parent_id">${systemOptionsHtml(parentId, true)}</select>
        </div>
        <div class="form-row">
          <label>Component Type</label>
          <select name="system_type">
            <option value="${isSub ? "subsystem" : "system"}">${isSub ? "subsystem" : "system"}</option>
            <option value="service">service</option>
            <option value="module">module</option>
            <option value="pipeline">pipeline</option>
            <option value="datastore">datastore</option>
            <option value="external">external</option>
          </select>
        </div>
      </div>
      <div class="form-row-2">
        <div class="form-row">
          <label>Codebase Path Scope</label>
          <input type="text" name="path_scope" placeholder="e.g. services/auth/**" />
        </div>
        <div class="form-row">
          <label>Initial Health Score (0–100)</label>
          <input type="number" name="health_score" min="0" max="100" placeholder="e.g. 85" />
        </div>
      </div>
      <div class="form-row">
        <label>Summary Description</label>
        <input type="text" name="description" placeholder="Concise purpose of this system/subsystem" />
      </div>
      <div class="form-row">
        <label>Detailed Architecture & Behavior Notes</label>
        <textarea name="details" rows="4" placeholder="Tech stack, state invariants, concurrency model, key files..."></textarea>
      </div>
    `,
    async (fd) => {
      const created = await api("/api/systems", {
        method: "POST",
        body: JSON.stringify({
          project_id: state.activeProjectId,
          name: fd.get("name"),
          slug: fd.get("slug") || null,
          parent_id: fd.get("parent_id") || null,
          system_type: fd.get("system_type"),
          path_scope: fd.get("path_scope"),
          health_score: fd.get("health_score"),
          description: fd.get("description"),
          details: fd.get("details"),
        }),
      });
      state.selectedSystemId = created.id;
      showToast(`Saved ${created.name}`);
      await loadSnapshot();
    }
  );
};

window.openEditSystemModalById = function (systemId) {
  const s =
    (state.lastDossier && state.lastDossier.id === systemId ? state.lastDossier : null) ||
    (state.snapshot?.systems || []).find((x) => x.id === systemId);
  if (!s) return;

  openModal(
    `Edit ${s.name} (${s.slug})`,
    `
      <div class="form-row-2">
        <div class="form-row">
          <label>Name *</label>
          <input type="text" name="name" required value="${esc(s.name)}" />
        </div>
        <div class="form-row">
          <label>Component Type</label>
          <select name="system_type">
            ${["system", "subsystem", "service", "module", "pipeline", "datastore", "external"]
              .map((t) => `<option value="${t}" ${s.system_type === t ? "selected" : ""}>${t}</option>`)
              .join("")}
          </select>
        </div>
      </div>
      <div class="form-row-2">
        <div class="form-row">
          <label>Audit Status</label>
          <select name="status">
            ${["unreviewed", "in_progress", "reviewed", "needs_attention", "healthy"]
              .map((st) => `<option value="${st}" ${s.status === st ? "selected" : ""}>${st}</option>`)
              .join("")}
          </select>
        </div>
        <div class="form-row">
          <label>Health Score (0–100)</label>
          <input type="number" name="health_score" min="0" max="100" value="${esc(s.health_score ?? "")}" />
        </div>
      </div>
      <div class="form-row">
        <label>Codebase Path Scope</label>
        <input type="text" name="path_scope" value="${esc(s.path_scope)}" />
      </div>
      <div class="form-row">
        <label>Summary Description</label>
        <input type="text" name="description" value="${esc(s.description)}" />
      </div>
      <div class="form-row">
        <label>Architectural Details & Invariants</label>
        <textarea name="details" rows="5">${esc(s.details)}</textarea>
      </div>
    `,
    async (fd) => {
      await api("/api/systems", {
        method: "POST",
        body: JSON.stringify({
          project_id: state.activeProjectId,
          id: s.id,
          slug: s.slug,
          name: fd.get("name"),
          system_type: fd.get("system_type"),
          status: fd.get("status"),
          health_score: fd.get("health_score"),
          path_scope: fd.get("path_scope"),
          description: fd.get("description"),
          details: fd.get("details"),
        }),
      });
      showToast(`Updated ${s.name}`);
      await loadSnapshot();
    }
  );
};

window.openAddRelationModal = function (defaultSourceRef = "") {
  openModal(
    "Record Cross-System Interaction ('Works With')",
    `
      <div class="form-row-2">
        <div class="form-row">
          <label>Source System / Subsystem *</label>
          <select name="source_ref" required>${systemOptionsHtml(defaultSourceRef, false)}</select>
        </div>
        <div class="form-row">
          <label>Target System / Subsystem *</label>
          <select name="target_ref" required>${systemOptionsHtml("", false)}</select>
        </div>
      </div>
      <div class="form-row-2">
        <div class="form-row">
          <label>Interaction Type</label>
          <select name="relation_type">
            <option value="calls">calls</option>
            <option value="depends_on">depends_on</option>
            <option value="authenticates_via">authenticates_via</option>
            <option value="publishes_to">publishes_to</option>
            <option value="consumes_from">consumes_from</option>
            <option value="orchestrates">orchestrates</option>
            <option value="reads_writes">reads_writes</option>
            <option value="syncs_with">syncs_with</option>
          </select>
        </div>
        <div class="form-row">
          <label>Criticality & Direction</label>
          <div style="display:flex;gap:6px">
            <select name="criticality" style="flex:1">
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium" selected>medium</option>
              <option value="low">low</option>
            </select>
            <select name="direction" style="flex:1">
              <option value="unidirectional">unidirectional (→)</option>
              <option value="bidirectional">bidirectional (↔)</option>
            </select>
          </div>
        </div>
      </div>
      <div class="form-row">
        <label>Interface / Protocol / Contract</label>
        <input type="text" name="interface_or_protocol" placeholder="e.g. gRPC (OrderService), Kafka topic: orders.v1, REST, Shared SQL" />
      </div>
      <div class="form-row">
        <label>Interaction Description *</label>
        <input type="text" name="description" required placeholder="How do these systems work together?" />
      </div>
      <div class="form-row">
        <label>Technical Details (SLAs, Failure Modes, Payloads)</label>
        <textarea name="details" rows="3" placeholder="Retry policies, circuit breakers, schema contracts..."></textarea>
      </div>
    `,
    async (fd) => {
      await api("/api/relations", {
        method: "POST",
        body: JSON.stringify({
          project_id: state.activeProjectId,
          source_ref: fd.get("source_ref"),
          target_ref: fd.get("target_ref"),
          relation_type: fd.get("relation_type"),
          criticality: fd.get("criticality"),
          direction: fd.get("direction"),
          interface_or_protocol: fd.get("interface_or_protocol"),
          description: fd.get("description"),
          details: fd.get("details"),
        }),
      });
      showToast("Recorded cross-system interaction");
      await loadSnapshot();
    }
  );
};

window.openAddTaskModal = function () {
  openModal(
    "Create Multi-Agent Audit Task",
    `
      <div class="form-row">
        <label>Task Title *</label>
        <input type="text" name="title" required placeholder="e.g. Audit JWT token rotation race conditions" />
      </div>
      <div class="form-row-2">
        <div class="form-row">
          <label>Target System / Subsystem</label>
          <select name="system_ref">${systemOptionsHtml("", true)}</select>
        </div>
        <div class="form-row">
          <label>Task Type & Priority</label>
          <div style="display:flex;gap:6px">
            <select name="task_type" style="flex:1">
              <option value="subsystem_audit">subsystem_audit</option>
              <option value="architecture_map">architecture_map</option>
              <option value="security_review">security_review</option>
              <option value="performance_review">performance_review</option>
              <option value="integration_trace">integration_trace</option>
              <option value="bug_hunt">bug_hunt</option>
              <option value="verification">verification</option>
            </select>
            <select name="priority" style="flex:1">
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium" selected>medium</option>
              <option value="low">low</option>
            </select>
          </div>
        </div>
      </div>
      <div class="form-row">
        <label>Task Scope & Instructions</label>
        <textarea name="description" rows="3" placeholder="Specific files, invariants, or interactions for the claiming agent to verify..."></textarea>
      </div>
    `,
    async (fd) => {
      await api("/api/tasks", {
        method: "POST",
        body: JSON.stringify({
          project_id: state.activeProjectId,
          title: fd.get("title"),
          system_ref: fd.get("system_ref") || null,
          task_type: fd.get("task_type"),
          priority: fd.get("priority"),
          description: fd.get("description"),
        }),
      });
      showToast("Added task to queue");
      await loadSnapshot();
    }
  );
};

window.openAddFindingModal = function (defaultSystemRef = "") {
  openModal(
    "Log Audit Finding / Issue",
    `
      <div class="form-row">
        <label>Finding Title *</label>
        <input type="text" name="title" required placeholder="Concise description of the bug, risk, or architectural issue" />
      </div>
      <div class="form-row-2">
        <div class="form-row">
          <label>Severity</label>
          <select name="severity">
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium" selected>medium</option>
            <option value="low">low</option>
            <option value="info">info</option>
          </select>
        </div>
        <div class="form-row">
          <label>Category</label>
          <select name="category">
            <option value="security">security</option>
            <option value="architecture">architecture</option>
            <option value="performance">performance</option>
            <option value="integration">integration</option>
            <option value="reliability">reliability</option>
            <option value="bug">bug</option>
            <option value="maintainability">maintainability</option>
            <option value="documentation">documentation</option>
          </select>
        </div>
      </div>
      <div class="form-row-2">
        <div class="form-row">
          <label>Primary System / Subsystem</label>
          <select name="system_ref">${systemOptionsHtml(defaultSystemRef, true)}</select>
        </div>
        <div class="form-row">
          <label>Related System (if cross-system issue)</label>
          <select name="related_system_ref">${systemOptionsHtml("", true)}</select>
        </div>
      </div>
      <div class="form-row-2">
        <div class="form-row">
          <label>File Path</label>
          <input type="text" name="file_path" placeholder="e.g. services/identity/src/tokens.rs" />
        </div>
        <div class="form-row">
          <label>Line Range</label>
          <input type="text" name="line_range" placeholder="e.g. 142-189" />
        </div>
      </div>
      <div class="form-row">
        <label>Summary Description *</label>
        <textarea name="description" rows="2" required placeholder="What is the issue and its impact?"></textarea>
      </div>
      <div class="form-row">
        <label>Technical Details & Root Cause</label>
        <textarea name="details" rows="3" placeholder="Code flow, race window, failure conditions..."></textarea>
      </div>
      <div class="form-row">
        <label>Remediation Recommendation</label>
        <textarea name="recommendation" rows="2" placeholder="Concrete fix or architectural adjustment..."></textarea>
      </div>
    `,
    async (fd) => {
      await api("/api/findings", {
        method: "POST",
        body: JSON.stringify({
          project_id: state.activeProjectId,
          title: fd.get("title"),
          severity: fd.get("severity"),
          category: fd.get("category"),
          system_ref: fd.get("system_ref") || null,
          related_system_ref: fd.get("related_system_ref") || null,
          file_path: fd.get("file_path"),
          line_range: fd.get("line_range"),
          description: fd.get("description"),
          details: fd.get("details"),
          recommendation: fd.get("recommendation"),
        }),
      });
      showToast("Logged audit finding");
      await loadSnapshot();
    }
  );
};

/* =========================================================================
   EVENT LISTENERS & DELEGATED DOM HANDLERS (RF-03)
   ========================================================================= */
function switchTab(tabName) {
  state.activeTab = tabName;
  document.querySelectorAll(".tab-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === tabName);
  });
  document.querySelectorAll(".tab-panel").forEach((p) => {
    p.classList.toggle("active", p.id === `tab-${tabName}`);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  // Delegated click handler for all dynamic UI elements (eliminates inline onclick XSS vectors - RF-03)
  document.addEventListener("click", (e) => {
    const target = e.target.closest("[data-action]");
    if (!target) return;
    const action = target.dataset.action;
    const id = target.dataset.id || "";
    const slug = target.dataset.slug || "";

    switch (action) {
      case "select-system":
        selectSystem(id);
        break;
      case "claim-system":
        claimSystemAction(id);
        break;
      case "release-system":
        releaseSystemPromptById(id);
        break;
      case "edit-system":
        openEditSystemModalById(id);
        break;
      case "add-subsystem":
        openAddSystemModalById(id);
        break;
      case "add-relation":
        openAddRelationModal(slug);
        break;
      case "add-finding":
        openAddFindingModal(slug);
        break;
      case "set-active-agent":
        setActiveAgent(id);
        break;
      case "send-heartbeat":
        sendAgentHeartbeat(id);
        break;
      case "claim-task":
        claimTaskAction(id);
        break;
      case "complete-task":
        completeTaskPromptById(id);
        break;
      case "block-task":
        blockTaskPromptById(id);
        break;
      case "focus-workbench":
        state.activeProjectId = id;
        state.selectedSystemId = null;
        switchTab("systems");
        loadSnapshot(id);
        break;
      case "switch-dossier-tab":
        state.dossierTab = target.dataset.tab;
        if (state.selectedSystemId) {
          loadAndRenderDossier(state.selectedSystemId);
        }
        break;
      case "toggle-system-collapse":
        e.stopPropagation();
        const collapseId = target.dataset.id;
        if (!state.collapsedSystems) state.collapsedSystems = new Set();
        if (state.collapsedSystems.has(collapseId)) {
          state.collapsedSystems.delete(collapseId);
        } else {
          state.collapsedSystems.add(collapseId);
        }
        renderSystemsExplorer();
        break;
      case "copy-text":
        e.stopPropagation();
        const copyVal = target.dataset.text;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(copyVal).then(() => {
            showToast(`Copied to clipboard: ${copyVal}`);
          }).catch(() => {
            showToast(`Copied: ${copyVal}`);
          });
        } else {
          showToast(`Copied: ${copyVal}`);
        }
        break;
      case "export-portfolio-project":
        window.open(`/api/export/markdown?project=${encodeURIComponent(id)}`, "_blank");
        break;
      default:
        break;
    }
  });

  // Delegated change handler for dynamic selects
  document.addEventListener("change", (e) => {
    const target = e.target.closest("[data-action='update-finding-status']");
    if (!target) return;
    updateFindingStatusAction(target.dataset.id, target.value);
  });

  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  document.getElementById("projectSelect").addEventListener("change", (e) => {
    state.activeProjectId = e.target.value;
    state.selectedSystemId = null;
    loadSnapshot(state.activeProjectId);
  });

  document.getElementById("activeAgentSelect").addEventListener("change", (e) => {
    state.activeAgentId = e.target.value;
    localStorage.setItem("auditos_active_agent", state.activeAgentId);
    renderAll();
  });

  document.getElementById("btnNewProject").addEventListener("click", openNewProjectModal);
  const btnNewProjPort = document.getElementById("btnNewProjectFromPortfolio");
  if (btnNewProjPort) {
    btnNewProjPort.addEventListener("click", openNewProjectModal);
  }
  document.addEventListener("click", (e) => {
    if (e.target.closest("#cardAddProject")) {
      openNewProjectModal();
    }
  });
  document.getElementById("btnRegisterAgent").addEventListener("click", openRegisterAgentModal);
  document.getElementById("btnRegisterAgent2").addEventListener("click", openRegisterAgentModal);
  document.getElementById("btnRefresh").addEventListener("click", () => loadSnapshot());

  document.getElementById("btnExportMd").addEventListener("click", () => {
    const q = state.activeProjectId ? `?project=${encodeURIComponent(state.activeProjectId)}` : "";
    window.open(`/api/export/markdown${q}`, "_blank");
  });

  document.getElementById("btnSeedDemo").addEventListener("click", async () => {
    try {
      const snap = await api("/api/seed-demo", {
        method: "POST",
        body: JSON.stringify({ reset_first: true, confirm: "RESET" }),
      });
      state.activeProjectId = snap.project.id;
      state.selectedSystemId = snap.systems[0]?.id || null;
      showToast("Loaded demo multi-agent project audit!");
      await loadSnapshot(snap.project.id);
    } catch (err) {
      showToast(err.message);
    }
  });

  document.getElementById("btnAddRootSystem").addEventListener("click", () => openAddSystemModal());
  document.getElementById("btnAddRelationTop").addEventListener("click", () => openAddRelationModal());
  document.getElementById("btnAddTask").addEventListener("click", openAddTaskModal);
  document.getElementById("btnAddFinding").addEventListener("click", () => openAddFindingModal());

  document.getElementById("btnClaimNextTask").addEventListener("click", async () => {
    if (!state.activeAgentId) {
      showToast("Register or select an Acting Agent first.");
      openRegisterAgentModal();
      return;
    }
    try {
      const res = await api("/api/tasks/next", {
        method: "POST",
        body: JSON.stringify({ project_id: state.activeProjectId, agent_id: state.activeAgentId }),
      });
      if (!res.task) {
        showToast("No open tasks available in queue.");
      } else {
        showToast(`@${state.activeAgentId} claimed: ${res.task.title}`);
      }
      await loadSnapshot();
    } catch (err) {
      showToast(err.message);
    }
  });

  document.getElementById("systemSearchInput").addEventListener("input", renderSystemsExplorer);
  document.getElementById("relationSystemFilter").addEventListener("change", renderTopologyTab);
  document.getElementById("findingSearchInput").addEventListener("input", renderFindingsTab);
  document.getElementById("findingSeverityFilter").addEventListener("change", renderFindingsTab);
  document.getElementById("findingCategoryFilter").addEventListener("change", renderFindingsTab);
  document.getElementById("findingStatusFilter").addEventListener("change", renderFindingsTab);
  document.getElementById("logSearchInput").addEventListener("input", renderLogsTab);

  document.getElementById("modalCloseBtn").addEventListener("click", closeModal);
  document.getElementById("modalCancelBtn").addEventListener("click", closeModal);
  document.getElementById("modalForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!state.modalSubmitHandler) return;
    try {
      const fd = new FormData(e.target);
      await state.modalSubmitHandler(fd);
      closeModal();
    } catch (err) {
      showToast(`Error: ${err.message}`);
    }
  });

  loadSnapshot();
});
