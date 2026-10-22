"""
Report generator mixin for Markdown audit reports.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from auditos.core.utils import utc_now_iso


class MarkdownReportMixin:
    """Generates human-readable Markdown audit summaries."""

    def export_markdown_report(self, project_ref: Optional[str] = None) -> str:
        snap = self.get_project_snapshot(project_ref)
        proj = snap["project"]
        m = snap["metrics"]
        systems = snap["systems"]
        relations = snap["relations"]
        agents = snap["agents"]
        tasks = snap["tasks"]
        findings = snap["findings"]

        lines: List[str] = []
        lines.append(f"# System & Subsystem Audit Report: {proj['name']}")
        lines.append("")
        lines.append(f"- **Project ID**: `{proj['id']}` (`{proj['slug']}`)")
        if proj.get("root_path"):
            lines.append(f"- **Root Path**: `{proj['root_path']}`")
        lines.append(f"- **Generated At**: `{utc_now_iso()}`")
        lines.append(
            f"- **Coverage**: {m['reviewed_components']}/{m['total_components']} components reviewed "
            f"({m['total_systems']} top-level systems, {m['total_subsystems']} subsystems)"
        )
        lines.append(
            f"- **Average Health Score**: {m['avg_health_score'] if m['avg_health_score'] is not None else 'N/A'}/100"
        )
        lines.append(
            f"- **Findings Summary**: {m['total_findings']} total ({m['severity_counts']['critical']} Critical, "
            f"{m['severity_counts']['high']} High, {m['severity_counts']['medium']} Medium, "
            f"{m['severity_counts']['low']} Low, {m['severity_counts']['info']} Info)"
        )
        lines.append("")

        if proj.get("description"):
            lines.append("## Executive Overview")
            lines.append(proj["description"])
            lines.append("")

        lines.append("## Multi-Agent Audit Workforce")
        lines.append("")
        if agents:
            lines.append("| Agent ID | Name | Role | Status | Tasks Completed | Findings Logged | Last Heartbeat |")
            lines.append("| :--- | :--- | :--- | :--- | :---: | :---: | :--- |")
            for a in agents:
                lines.append(
                    f"| `{a['id']}` | {a['name']} | `{a['role']}` | `{a['status']}` | "
                    f"{a.get('completed_tasks_count', 0)} | {a.get('findings_count', 0)} | `{a['last_heartbeat']}` |"
                )
        else:
            lines.append("_No agents registered._")
        lines.append("")

        lines.append("## Systems & Subsystems Hierarchy")
        lines.append("")
        by_parent: Dict[Optional[str], List[Dict[str, Any]]] = {}
        for s in systems:
            by_parent.setdefault(s["parent_id"], []).append(s)

        visited_nodes = set()

        def render_sys(sys_item: Dict[str, Any], depth: int = 0) -> None:
            if sys_item["id"] in visited_nodes:
                return
            visited_nodes.add(sys_item["id"])
            indent = "  " * depth
            health = f"{sys_item['health_score']}/100" if sys_item["health_score"] is not None else "Unscored"
            claim_tag = f" | Claimed by `{sys_item['claimed_by']}`" if sys_item.get("claimed_by") else ""
            lines.append(
                f"{indent}- **{sys_item['name']}** (`{sys_item['slug']}` | `{sys_item['system_type']}`) — "
                f"Status: `{sys_item['status']}` | Health: **{health}**{claim_tag}"
            )
            if sys_item.get("path_scope"):
                lines.append(f"{indent}  - **Scope**: `{sys_item['path_scope']}`")
            if sys_item.get("description"):
                lines.append(f"{indent}  - **Description**: {sys_item['description']}")
            if sys_item.get("details"):
                lines.append(f"{indent}  - **Details**: {sys_item['details']}")
            lines.append(
                f"{indent}  - **Timestamps**: Created `{sys_item['created_at']}` | Updated `{sys_item['updated_at']}`"
            )
            for child in by_parent.get(sys_item["id"], []):
                render_sys(child, depth + 1)

        for root_sys in by_parent.get(None, []):
            render_sys(root_sys, 0)
        lines.append("")

        lines.append("## Cross-System Interactions & Dependencies")
        lines.append("")
        if relations:
            lines.append("| Source System | Relation | Target System | Protocol / Interface | Criticality | Description |")
            lines.append("| :--- | :---: | :--- | :--- | :---: | :--- |")
            for r in relations:
                arrow = "<-->" if r["direction"] == "bidirectional" else "-->"
                lines.append(
                    f"| **{r['source_name']}** (`{r['source_slug']}`) | `{r['relation_type']}` {arrow} | "
                    f"**{r['target_name']}** (`{r['target_slug']}`) | `{r['interface_or_protocol'] or 'direct'}` | "
                    f"`{r['criticality']}` | {r['description']} |"
                )
        else:
            lines.append("_No cross-system relations recorded._")
        lines.append("")

        lines.append("## Audit Findings & Recommendations")
        lines.append("")
        if findings:
            for f in findings:
                lines.append(
                    f"### [{f['severity'].upper()}] {f['title']} (`{f['id']}`)"
                )
                lines.append(
                    f"- **Category**: `{f['category']}` | **Status**: `{f['status']}` | "
                    f"**System**: {f.get('system_name') or 'Project-wide'} (`{f.get('system_slug') or 'n/a'}`) | "
                    f"**Logged By**: `{f.get('agent_id') or 'unknown'}` at `{f['created_at']}`"
                )
                if f.get("file_path"):
                    loc = f"{f['file_path']}:{f['line_range']}" if f.get("line_range") else f["file_path"]
                    lines.append(f"- **Location**: `{loc}`")
                if f.get("commit_sha") or f.get("span_hash"):
                    ev_items = []
                    if f.get("commit_sha"):
                        ev_items.append(f"commit `{f['commit_sha'][:8]}`")
                    if f.get("span_hash"):
                        ev_items.append(f"span `{f['span_hash'][:10]}`")
                    lines.append(f"- **Reconstruction Key**: {', '.join(ev_items)}")
                if f.get("description"):
                    lines.append(f"- **Summary**: {f['description']}")
                if f.get("details"):
                    lines.append(f"- **Technical Details**: {f['details']}")
                if f.get("recommendation"):
                    lines.append(f"- **Recommendation**: {f['recommendation']}")
                lines.append("")
        else:
            lines.append("_No findings logged._")

        lines.append("## Audit Task Queue")
        lines.append("")
        if tasks:
            lines.append("| Task ID | Priority | Type | Title | System | Status | Agent | Deliverable Summary |")
            lines.append("| :--- | :---: | :--- | :--- | :--- | :---: | :--- | :--- |")
            for t in tasks:
                lines.append(
                    f"| `{t['id']}` | `{t['priority']}` | `{t['task_type']}` | {t['title']} | "
                    f"`{t.get('system_slug') or 'project'}` | `{t['status']}` | `{t.get('claimed_by') or '-'}` | "
                    f"{t.get('deliverable_summary') or '-'} |"
                )
        lines.append("")
        return "\n".join(lines)
