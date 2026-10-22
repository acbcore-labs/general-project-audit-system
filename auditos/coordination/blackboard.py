"""
Blackboard coordinator mixin for computing the 2D coverage field matrix (Systems x Disciplines).
"""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional


class BlackboardCoordinatorMixin:
    """Derives the centralized mission blackboard matrix across architecture, security, performance, integration, and verification."""

    def get_blackboard(self, project_ref: Optional[str] = None) -> Dict[str, Any]:
        """Generate a unified multi-agent blackboard showing systems x review facets, claims, and open work."""
        pid = self.resolve_project_id(project_ref)
        with self.connect() as conn:
            proj = conn.execute("SELECT * FROM projects WHERE id = ?", (pid,)).fetchone()
            if not proj:
                raise ValueError(f"Project '{pid}' not found.")
            proj_dict = dict(proj)

            systems = [dict(r) for r in conn.execute(
                """
                SELECT s.*,
                       p.slug AS parent_slug, p.name AS parent_name
                FROM systems s
                LEFT JOIN systems p ON s.parent_id = p.id
                WHERE s.project_id = ?
                ORDER BY s.parent_id IS NOT NULL, s.name ASC
                """,
                (pid,),
            ).fetchall()]

            tasks = [dict(r) for r in conn.execute(
                """
                SELECT t.*, a.name AS claimed_by_name, a.role AS claimed_by_role
                FROM tasks t
                LEFT JOIN agents a ON t.claimed_by = a.id
                WHERE t.project_id = ?
                """,
                (pid,),
            ).fetchall()]

            findings = [dict(r) for r in conn.execute(
                "SELECT * FROM findings WHERE project_id = ?",
                (pid,),
            ).fetchall()]

            relations = [dict(r) for r in conn.execute(
                "SELECT * FROM system_relations WHERE project_id = ?",
                (pid,),
            ).fetchall()]

        matrix = []
        for s in systems:
            sid = s["id"]
            sys_tasks = [t for t in tasks if t["system_id"] == sid]
            sys_findings = [f for f in findings if f["system_id"] == sid or f.get("related_system_id") == sid]
            sys_rels = [r for r in relations if r["source_system_id"] == sid or r["target_system_id"] == sid]

            def facet_status(types: tuple) -> Dict[str, Any]:
                matching_done = [t for t in sys_tasks if t["task_type"] in types and t["status"] == "completed"]
                matching_claimed = [t for t in sys_tasks if t["task_type"] in types and t["status"] == "claimed"]
                matching_open = [t for t in sys_tasks if t["task_type"] in types and t["status"] == "open"]
                matching_blocked = [t for t in sys_tasks if t["task_type"] in types and t["status"] == "blocked"]
                if matching_done:
                    status = "completed"
                elif matching_claimed:
                    status = "in_progress"
                elif matching_blocked:
                    status = "blocked"
                elif matching_open:
                    status = "pending"
                else:
                    status = "unassigned"
                return {
                    "status": status,
                    "completed_count": len(matching_done),
                    "open_count": len(matching_open) + len(matching_claimed),
                }

            facets = {
                "arch": facet_status(("architecture_map", "subsystem_audit")),
                "sec": facet_status(("security_review", "bug_hunt")),
                "perf": facet_status(("performance_review",)),
                "integ": facet_status(("integration_trace",)),
                "verify": facet_status(("verification",)),
            }
            if facets["integ"]["status"] == "unassigned" and sys_rels:
                facets["integ"]["status"] = "documented"

            open_crit_findings = sum(1 for f in sys_findings if f["severity"] == "critical" and f["status"] == "open")
            open_high_findings = sum(1 for f in sys_findings if f["severity"] == "high" and f["status"] == "open")

            matrix.append({
                "id": sid,
                "slug": s["slug"],
                "name": s["name"],
                "system_type": s["system_type"],
                "parent_id": s["parent_id"],
                "parent_slug": s.get("parent_slug"),
                "path_scope": s.get("path_scope") or "",
                "status": s["status"],
                "health_score": s["health_score"],
                "claimed_by": s.get("claimed_by"),
                "lease_until": s.get("lease_until"),
                "facets": facets,
                "relations_count": len(sys_rels),
                "open_findings_count": len([f for f in sys_findings if f["status"] == "open"]),
                "critical_findings_count": open_crit_findings,
                "high_findings_count": open_high_findings,
            })

        roster = self.list_roles(pid)

        open_tasks = [
            {
                "id": t["id"],
                "title": t["title"],
                "priority": t["priority"],
                "task_type": t["task_type"],
                "system_id": t["system_id"],
                "created_at": t["created_at"],
            }
            for t in tasks if t["status"] == "open"
        ]

        recommendations = []
        unreviewed = [m["name"] for m in matrix if m["status"] == "unreviewed"]
        if unreviewed:
            recommendations.append(f"{len(unreviewed)} components unreviewed ({', '.join(unreviewed[:3])}{'...' if len(unreviewed) > 3 else ''}). Run 'audit task scaffold --system <slug>'.")
        if roster["vacant_roles"]:
            recommendations.append(f"Vacant roles needing agents: {', '.join(roster['vacant_roles'])}.")
        crit_sys = [m["name"] for m in matrix if m["critical_findings_count"] > 0]
        if crit_sys:
            recommendations.append(f"Critical findings requiring verification in: {', '.join(crit_sys[:3])}.")

        return {
            "project": proj_dict,
            "roster": roster,
            "matrix": matrix,
            "open_tasks": open_tasks,
            "total_open_tasks": len(open_tasks),
            "recommendations": recommendations,
        }
