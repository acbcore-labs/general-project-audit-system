"""
Sweep orchestrator mixin for macro sweeps, task scaffolding, zombie reaping, and milestone sign-off.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional

from auditos.core.utils import utc_now_iso


class SweepOrchestratorMixin:
    """Orchestrates macro audit sweeps, coverage gap detection, and auto-remediation."""

    def scaffold_system_tasks(
        self,
        project_id: str,
        system_ref: str,
        created_by: Optional[str] = None,
        include_verification: bool = True,
    ) -> List[Dict[str, Any]]:
        """Automatically scaffold standard multi-disciplinary audit tasks for a system/subsystem."""
        pid = self.resolve_project_id(project_id)
        sys_obj = self.get_system(pid, system_ref)
        sname = sys_obj["name"]
        sid = sys_obj["id"]

        standard_pack = [
            (
                f"Map boundaries, components & path scope for {sname}",
                "architecture_map",
                "high",
                f"Inspect source directory ({sys_obj.get('path_scope') or 'codebase'}), catalog internal modules, and verify subsystem hierarchy.",
            ),
            (
                f"Audit authentication, data boundaries & permissions for {sname}",
                "security_review",
                "critical",
                f"Check RBAC, input sanitization, token validation, cryptographic invariants, and secret exposure for {sname}.",
            ),
            (
                f"Review latency, async concurrency & throughput for {sname}",
                "performance_review",
                "medium",
                f"Check database query patterns, async deadlock risks, resource cleanup, and rate limiting for {sname}.",
            ),
            (
                f"Trace cross-system contracts, protocols & failure modes for {sname}",
                "integration_trace",
                "high",
                f"Document inbound/outbound relations, schema contracts (gRPC/REST/Kafka), retry backoff, and circuit breaker behavior.",
            ),
        ]
        if include_verification:
            standard_pack.append(
                (
                    f"Verify findings, edge cases & test quality for {sname}",
                    "verification",
                    "medium",
                    f"Verify and reproduce logged findings, inspect test suite coverage/mutations, and sign off on subsystem health for {sname}.",
                )
            )

        created_tasks = []
        with self.connect() as conn:
            existing_tasks = [dict(r) for r in conn.execute(
                "SELECT task_type FROM tasks WHERE project_id = ? AND system_id = ? AND status IN ('open', 'claimed')",
                (pid, sid),
            ).fetchall()]
            existing_types = {t["task_type"] for t in existing_tasks}

        for title, ttype, prio, desc in standard_pack:
            if ttype in existing_types:
                continue
            task = self.create_task(
                project_id=pid,
                title=title,
                system_ref=sid,
                task_type=ttype,
                priority=prio,
                description=desc,
                created_by=created_by,
            )
            created_tasks.append(task)

        return created_tasks

    def run_sweep(
        self,
        project_ref: Optional[str] = None,
        auto_fix: bool = False,
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Conduct a macro-level sweep: detect zombie leases, unscaffolded systems, duplicates, and sign-off candidates."""
        pid = self.resolve_project_id(project_ref)
        now = utc_now_iso()
        actions_taken = []

        with self.connect() as conn:
            proj = conn.execute("SELECT * FROM projects WHERE id = ?", (pid,)).fetchone()
            if not proj:
                raise ValueError(f"Project '{pid}' not found.")
            proj_dict = dict(proj)

            systems = [dict(r) for r in conn.execute("SELECT * FROM systems WHERE project_id = ?", (pid,)).fetchall()]
            tasks = [dict(r) for r in conn.execute("SELECT * FROM tasks WHERE project_id = ?", (pid,)).fetchall()]
            agents = [dict(r) for r in conn.execute("SELECT * FROM agents WHERE project_id = ? OR project_id IS NULL", (pid,)).fetchall()]
            findings = [dict(r) for r in conn.execute("SELECT * FROM findings WHERE project_id = ?", (pid,)).fetchall()]

            agent_by_id = {a["id"]: a for a in agents}

            # 1. Zombie Leases & Stalled Claims
            zombies = []
            for t in tasks:
                if t["status"] == "claimed":
                    is_expired = t.get("lease_until") and t["lease_until"] < now
                    assigned_agent = agent_by_id.get(t.get("claimed_by"))
                    is_offline = assigned_agent and assigned_agent.get("status") == "offline"
                    if is_expired or is_offline:
                        zombies.append({
                            "type": "task",
                            "id": t["id"],
                            "title": t["title"],
                            "claimed_by": t.get("claimed_by"),
                            "lease_until": t.get("lease_until"),
                            "reason": "Offline agent" if is_offline else "Lease expired",
                        })

            for s in systems:
                if s.get("claimed_by"):
                    is_expired = s.get("lease_until") and s["lease_until"] < now
                    assigned_agent = agent_by_id.get(s.get("claimed_by"))
                    is_offline = assigned_agent and assigned_agent.get("status") == "offline"
                    if is_expired or is_offline:
                        zombies.append({
                            "type": "system",
                            "id": s["id"],
                            "slug": s["slug"],
                            "name": s["name"],
                            "claimed_by": s.get("claimed_by"),
                            "lease_until": s.get("lease_until"),
                            "reason": "Offline agent" if is_offline else "Lease expired",
                        })

            # 2. Coverage & Scaffolding Gaps
            unscaffolded = []
            tasks_by_system: Dict[str, List[Dict[str, Any]]] = {}
            for t in tasks:
                if t.get("system_id"):
                    tasks_by_system.setdefault(t["system_id"], []).append(t)

            standard_types = {
                "architecture_map",
                "security_review",
                "performance_review",
                "integration_trace",
                "verification",
            }
            for s in systems:
                sys_tasks = tasks_by_system.get(s["id"], [])
                existing_types = {t["task_type"] for t in sys_tasks}
                missing_types = standard_types - existing_types
                if missing_types:
                    unscaffolded.append({
                        "system_id": s["id"],
                        "slug": s["slug"],
                        "name": s["name"],
                        "missing_types": list(missing_types),
                        "existing_task_count": len(sys_tasks),
                    })

            # 3. Duplicate or Overlapping Findings
            duplicates = []
            seen_pairs = set()
            for i, f1 in enumerate(findings):
                for f2 in findings[i + 1:]:
                    pair_key = (f1["id"], f2["id"])
                    if pair_key in seen_pairs:
                        continue
                    is_same_system = f1.get("system_id") and f1.get("system_id") == f2.get("system_id")
                    is_same_file = f1.get("file_path") and f1.get("file_path") == f2.get("file_path")
                    is_same_lines = f1.get("line_range") and f1.get("line_range") == f2.get("line_range")
                    is_same_title = f1.get("title", "").strip().lower() == f2.get("title", "").strip().lower()

                    if is_same_system and (is_same_title or (is_same_file and is_same_lines)):
                        seen_pairs.add(pair_key)
                        reason = "Identical title on same system" if is_same_title else "Overlapping file and lines"
                        duplicates.append({
                            "finding_a": {"id": f1["id"], "title": f1["title"], "severity": f1["severity"]},
                            "finding_b": {"id": f2["id"], "title": f2["title"], "severity": f2["severity"]},
                            "file": f1.get("file_path") or "-",
                            "reason": reason,
                        })

            # 4. Workforce & Coverage Imbalances
            roster = self.list_roles(pid)
            imbalances = []
            if roster["vacant_roles"]:
                imbalances.append(f"Vacant specialist roles needing agents: {', '.join(roster['vacant_roles'])}.")

            active_claims_by_system: Dict[str, int] = {}
            for t in tasks:
                if t["status"] == "claimed" and t.get("system_id"):
                    active_claims_by_system[t["system_id"]] = active_claims_by_system.get(t["system_id"], 0) + 1

            for sid, count in active_claims_by_system.items():
                if count >= 3:
                    sys_name = next((s["name"] for s in systems if s["id"] == sid), sid)
                    imbalances.append(f"High task concentration: {count} active tasks claimed on '{sys_name}'.")

            # 5. Systems Ready for Milestone Sign-Off
            ready_for_signoff = []
            for s in systems:
                sys_tasks = tasks_by_system.get(s["id"], [])
                has_completed = any(t["status"] == "completed" for t in sys_tasks)
                has_pending = any(t["status"] in ("open", "claimed") for t in sys_tasks)
                sys_findings = [f for f in findings if (f.get("system_id") == s["id"] or f.get("related_system_id") == s["id"]) and f["status"] == "open"]
                has_crit = any(f["severity"] == "critical" for f in sys_findings)

                if has_completed and not has_pending and s["status"] in ("unreviewed", "in_progress"):
                    calibrated_status = "needs_attention" if has_crit else ("healthy" if (s.get("health_score") or 0) >= 85 else "reviewed")
                    ready_for_signoff.append({
                        "system_id": s["id"],
                        "slug": s["slug"],
                        "name": s["name"],
                        "current_status": s["status"],
                        "calibrated_status": calibrated_status,
                        "health_score": s.get("health_score"),
                        "open_findings": len(sys_findings),
                    })

        if auto_fix:
            with self.connect(immediate=True) as conn:
                for z in zombies:
                    if z["type"] == "task":
                        conn.execute(
                            "UPDATE tasks SET status = 'open', claimed_by = NULL, claimed_at = NULL, lease_until = NULL, updated_at = ? WHERE id = ?",
                            (now, z["id"]),
                        )
                        actions_taken.append(f"Reopened stalled task '{z['title']}' ({z['id']})")
                    elif z["type"] == "system":
                        conn.execute(
                            "UPDATE systems SET claimed_by = NULL, claimed_at = NULL, lease_until = NULL, updated_at = ? WHERE id = ?",
                            (now, z["id"]),
                        )
                        actions_taken.append(f"Released stalled claim on system '{z['name']}' ({z['slug']})")

                for s in ready_for_signoff:
                    conn.execute(
                        "UPDATE systems SET status = ?, updated_at = ? WHERE id = ?",
                        (s["calibrated_status"], now, s["system_id"]),
                    )
                    actions_taken.append(f"Signed off system '{s['name']}' ({s['slug']}) -> {s['calibrated_status']}")

                if actions_taken:
                    self._log_event(
                        conn,
                        pid,
                        agent_id or "audit-lead",
                        "sweep.executed",
                        "project",
                        pid,
                        f"Audit sweep executed with {len(actions_taken)} remediation actions.",
                        {"actions": actions_taken},
                    )

            if unscaffolded:
                for entry in unscaffolded:
                    created = self.scaffold_system_tasks(pid, entry["slug"], created_by=agent_id or "audit-lead")
                    if created:
                        actions_taken.append(f"Scaffolded {len(created)} tasks for system '{entry['name']}'")

        return {
            "project": proj_dict,
            "timestamp": now,
            "auto_fix": auto_fix,
            "zombies": zombies,
            "unscaffolded": unscaffolded,
            "duplicates": duplicates,
            "imbalances": imbalances,
            "ready_for_signoff": ready_for_signoff,
            "actions_taken": actions_taken,
        }
