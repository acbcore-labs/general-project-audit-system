"""
Repository mixin for agent registration, heartbeat monitoring, and role taxonomy.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional

from auditos.core.config import ROLE_METADATA, VALID_AGENT_ROLES
from auditos.core.utils import future_utc_iso, short_id, utc_now_iso, validate_identifier


class AgentRepositoryMixin:
    """Manages autonomous agent identities, leases, heartbeats, and roles."""

    def _ensure_agent_in_conn(
        self,
        conn: sqlite3.Connection,
        agent_id: Optional[str],
        project_id: Optional[str] = None,
    ) -> Optional[str]:
        """Validate and ensure an agent ID exists in agents table before foreign-key writes (F-10, RF-03)."""
        if not agent_id:
            return None
        aid = validate_identifier(agent_id, "agent_id")
        now = utc_now_iso()
        agent = conn.execute("SELECT id, project_id FROM agents WHERE id = ?", (aid,)).fetchone()
        if not agent:
            conn.execute(
                """
                INSERT INTO agents (id, project_id, name, role, status, registered_at, last_heartbeat, metadata_json)
                VALUES (?, ?, ?, 'general-auditor', 'active', ?, ?, '{}')
                """,
                (aid, project_id, aid, now, now),
            )
        elif project_id and not agent["project_id"]:
            conn.execute("UPDATE agents SET project_id = ? WHERE id = ?", (project_id, aid))
        return aid

    def register_agent(
        self,
        agent_id: Optional[str] = None,
        name: Optional[str] = None,
        role: str = "general-auditor",
        model: str = "",
        capabilities: str = "",
        status: str = "active",
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        aid = validate_identifier(agent_id, "agent_id") if agent_id else short_id("agent")
        display_name = name.strip() if name else aid
        now = utc_now_iso()
        with self.connect(immediate=True) as conn:
            existing = conn.execute("SELECT * FROM agents WHERE id = ?", (aid,)).fetchone()
            if existing:
                conn.execute(
                    """
                    UPDATE agents
                    SET name = ?, role = ?, model = COALESCE(NULLIF(?, ''), model),
                        capabilities = COALESCE(NULLIF(?, ''), capabilities),
                        project_id = COALESCE(?, project_id),
                        status = ?, last_heartbeat = ?
                    WHERE id = ?
                    """,
                    (display_name, role, model, capabilities, project_id, status, now, aid),
                )
                action = "agent.heartbeat"
                summary = f"Agent '{display_name}' ({aid}) updated identity/heartbeat [role: {role}]"
            else:
                conn.execute(
                    """
                    INSERT INTO agents (id, project_id, name, role, model, status, capabilities, registered_at, last_heartbeat, metadata_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '{}')
                    """,
                    (aid, project_id, display_name, role, model, status, capabilities, now, now),
                )
                action = "agent.registered"
                summary = f"Registered agent '{display_name}' ({aid}) as {role}"

            self._log_event(conn, project_id, aid, action, "agent", aid, summary, {"role": role, "model": model})
            return dict(conn.execute("SELECT * FROM agents WHERE id = ?", (aid,)).fetchone())

    def heartbeat_agent(
        self,
        agent_id: str,
        status: str = "active",
        extend_leases_minutes: int = 30,
    ) -> Dict[str, Any]:
        """Update agent heartbeat; only extend unexpired leases and cleanly release/block when offline (F-23, RF-09, RF-16)."""
        aid = validate_identifier(agent_id, "agent_id")
        now = utc_now_iso()
        new_lease = future_utc_iso(extend_leases_minutes)
        norm_status = (status or "active").strip().lower()
        with self.connect(immediate=True) as conn:
            row = conn.execute("SELECT * FROM agents WHERE id = ?", (aid,)).fetchone()
            if not row:
                raise ValueError(f"Agent '{aid}' is not registered. Run 'agent register' first.")

            if norm_status == "offline":
                # Release or block tasks held by this offline agent (RF-09)
                conn.execute(
                    """
                    UPDATE tasks
                    SET status = CASE WHEN attempt_count >= max_attempts THEN 'blocked' ELSE 'open' END,
                        blocked_reason = CASE
                            WHEN attempt_count >= max_attempts
                            THEN 'Agent went offline after reaching max_attempts (' || max_attempts || ')'
                            ELSE blocked_reason END,
                        claimed_by = NULL,
                        claimed_at = NULL,
                        lease_until = NULL,
                        updated_at = ?
                    WHERE claimed_by = ? AND status = 'claimed'
                    """,
                    (now, aid),
                )
                # Release systems held by this offline agent and reset orphaned 'in_progress' status (RF-16)
                claimed_systems = conn.execute(
                    "SELECT id, status FROM systems WHERE claimed_by = ?", (aid,)
                ).fetchall()
                for srow in claimed_systems:
                    sid = srow["id"]
                    open_crit_high = conn.execute(
                        """
                        SELECT COUNT(*) AS cnt FROM findings
                        WHERE system_id = ? AND severity IN ('critical', 'high') AND status NOT IN ('resolved', 'wont_fix')
                        """,
                        (sid,),
                    ).fetchone()["cnt"]
                    other_claimed_tasks = conn.execute(
                        "SELECT COUNT(*) AS cnt FROM tasks WHERE system_id = ? AND status = 'claimed'",
                        (sid,),
                    ).fetchone()["cnt"]
                    if open_crit_high > 0:
                        next_sys_status = "needs_attention"
                    elif other_claimed_tasks > 0:
                        next_sys_status = "in_progress"
                    elif srow["status"] == "in_progress":
                        next_sys_status = "unreviewed"
                    else:
                        next_sys_status = srow["status"]
                    conn.execute(
                        """
                        UPDATE systems
                        SET claimed_by = NULL, claimed_at = NULL, lease_until = NULL,
                            status = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (next_sys_status, now, sid),
                    )
                conn.execute(
                    """
                    UPDATE agents
                    SET last_heartbeat = ?, status = 'offline', current_task_id = NULL, current_system_id = NULL
                    WHERE id = ?
                    """,
                    (now, aid),
                )
            else:
                conn.execute(
                    "UPDATE agents SET last_heartbeat = ?, status = ? WHERE id = ?",
                    (now, norm_status, aid),
                )
                conn.execute(
                    """
                    UPDATE systems
                    SET lease_until = ?, updated_at = ?
                    WHERE claimed_by = ? AND (lease_until IS NULL OR lease_until >= ?)
                    """,
                    (new_lease, now, aid, now),
                )
                conn.execute(
                    """
                    UPDATE tasks
                    SET lease_until = ?, updated_at = ?
                    WHERE claimed_by = ? AND status = 'claimed' AND (lease_until IS NULL OR lease_until >= ?)
                    """,
                    (new_lease, now, aid, now),
                )
            return dict(conn.execute("SELECT * FROM agents WHERE id = ?", (aid,)).fetchone())

    def list_agents(
        self,
        project_id: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        """List agents with project-scoped metrics so multi-project databases don't bleed counts (F-24)."""
        def _query(c: sqlite3.Connection) -> List[Dict[str, Any]]:
            if project_id:
                rows = c.execute(
                    """
                    SELECT a.*,
                           s.name AS current_system_name,
                           s.slug AS current_system_slug,
                           t.title AS current_task_title,
                           (SELECT COUNT(*) FROM tasks tk WHERE tk.claimed_by = a.id AND tk.project_id = ? AND tk.status = 'completed') AS completed_tasks_count,
                           (SELECT COUNT(*) FROM tasks tk WHERE tk.claimed_by = a.id AND tk.project_id = ? AND tk.status = 'claimed') AS active_tasks_count,
                           (SELECT COUNT(*) FROM findings f WHERE f.agent_id = a.id AND f.project_id = ?) AS findings_count,
                           (SELECT COUNT(*) FROM audit_logs l WHERE l.agent_id = a.id AND l.project_id = ?) AS actions_count
                    FROM agents a
                    LEFT JOIN systems s ON a.current_system_id = s.id AND s.project_id = ?
                    LEFT JOIN tasks t ON a.current_task_id = t.id AND t.project_id = ?
                    WHERE a.project_id = ?
                       OR a.project_id IS NULL
                       OR EXISTS (SELECT 1 FROM audit_logs l2 WHERE l2.agent_id = a.id AND l2.project_id = ?)
                       OR EXISTS (SELECT 1 FROM tasks t2 WHERE t2.claimed_by = a.id AND t2.project_id = ?)
                       OR EXISTS (SELECT 1 FROM findings f2 WHERE f2.agent_id = a.id AND f2.project_id = ?)
                    ORDER BY a.last_heartbeat DESC
                    """,
                    (
                        project_id,
                        project_id,
                        project_id,
                        project_id,
                        project_id,
                        project_id,
                        project_id,
                        project_id,
                        project_id,
                        project_id,
                    ),
                ).fetchall()
            else:
                rows = c.execute(
                    """
                    SELECT a.*,
                           s.name AS current_system_name,
                           s.slug AS current_system_slug,
                           t.title AS current_task_title,
                           (SELECT COUNT(*) FROM tasks tk WHERE tk.claimed_by = a.id AND tk.status = 'completed') AS completed_tasks_count,
                           (SELECT COUNT(*) FROM tasks tk WHERE tk.claimed_by = a.id AND tk.status = 'claimed') AS active_tasks_count,
                           (SELECT COUNT(*) FROM findings f WHERE f.agent_id = a.id) AS findings_count,
                           (SELECT COUNT(*) FROM audit_logs l WHERE l.agent_id = a.id) AS actions_count
                    FROM agents a
                    LEFT JOIN systems s ON a.current_system_id = s.id
                    LEFT JOIN tasks t ON a.current_task_id = t.id
                    ORDER BY a.last_heartbeat DESC
                    """
                ).fetchall()
            return [dict(r) for r in rows]

        if conn is not None:
            return _query(conn)
        with self.connect() as c:
            return _query(c)

    def list_roles(self, project_id: Optional[str] = None) -> Dict[str, Any]:
        """List canonical agent roles, descriptions, target task types, and currently active agents per role."""
        with self.connect() as conn:
            query = "SELECT role, status, id, name FROM agents"
            params: List[Any] = []
            if project_id:
                query += " WHERE project_id = ? OR project_id IS NULL"
                params.append(project_id)
            rows = conn.execute(query, params).fetchall()

        role_occupancy: Dict[str, List[Dict[str, str]]] = {r: [] for r in VALID_AGENT_ROLES}
        custom_roles: Dict[str, List[Dict[str, str]]] = {}
        for r in rows:
            role_name = r["role"]
            agent_item = {"id": r["id"], "name": r["name"], "status": r["status"]}
            if role_name in role_occupancy:
                role_occupancy[role_name].append(agent_item)
            else:
                custom_roles.setdefault(role_name, []).append(agent_item)

        roles_list = []
        for role_slug, meta in ROLE_METADATA.items():
            assigned = role_occupancy.get(role_slug, [])
            active_count = sum(1 for a in assigned if a["status"] == "active")
            roles_list.append({
                "role": role_slug,
                "title": meta["title"],
                "description": meta["description"],
                "task_types": list(meta["task_types"]),
                "capabilities": list(meta["capabilities"]),
                "active_agents": active_count,
                "total_agents": len(assigned),
                "agents": assigned,
                "is_vacant": active_count == 0,
            })

        for custom_slug, assigned in custom_roles.items():
            active_count = sum(1 for a in assigned if a["status"] == "active")
            roles_list.append({
                "role": custom_slug,
                "title": f"Custom Role ({custom_slug})",
                "description": "User-defined or specialized worker role.",
                "task_types": [],
                "capabilities": [],
                "active_agents": active_count,
                "total_agents": len(assigned),
                "agents": assigned,
                "is_vacant": active_count == 0,
            })

        return {
            "canonical_roles": list(VALID_AGENT_ROLES),
            "roles": roles_list,
            "total_active_agents": sum(r["active_agents"] for r in roles_list),
            "vacant_roles": [r["role"] for r in roles_list if r["is_vacant"] and r["role"] in VALID_AGENT_ROLES],
        }
