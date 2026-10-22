"""
Repository mixin for task creation, lifecycle state transitions, and querying.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional

from auditos.core.config import PRIORITY_ORDER_SQL, VALID_PRIORITIES
from auditos.core.utils import future_utc_iso, short_id, utc_now_iso, validate_health_score


class TaskRepositoryMixin:
    """Manages audit tasks, priority queues, state transitions, and deliverable summaries."""

    def create_task(
        self,
        project_id: str,
        title: str,
        system_ref: Optional[str] = None,
        task_type: str = "subsystem_audit",
        priority: str = "medium",
        description: str = "",
        created_by: Optional[str] = None,
        claim_immediately_for: Optional[str] = None,
        max_attempts: int = 3,
    ) -> Dict[str, Any]:
        if not title or not str(title).strip():
            raise ValueError("Task title is required.")
        now = utc_now_iso()
        norm_priority = (priority or "medium").strip().lower()
        if norm_priority not in VALID_PRIORITIES:
            raise ValueError(f"Invalid priority '{priority}'. Must be one of {VALID_PRIORITIES}.")
        with self.connect(immediate=True) as conn:
            creator_id = self._ensure_agent_in_conn(conn, created_by, project_id)
            claimer_id = self._ensure_agent_in_conn(conn, claim_immediately_for, project_id)

            system_id = None
            sys_obj = None
            if system_ref:
                sys_obj = self._resolve_system_in_conn(conn, project_id, system_ref)
                if not sys_obj:
                    raise ValueError(f"System '{system_ref}' not found.")
                system_id = sys_obj["id"]

            if claimer_id and sys_obj:
                holder = sys_obj["claimed_by"]
                lease = sys_obj["lease_until"]
                if holder and holder != claimer_id and lease and lease > now:
                    raise RuntimeError(
                        f"Cannot immediately claim task for '{claimer_id}': target system '{sys_obj['name']}' is leased by '{holder}' until {lease}."
                    )

            tid = short_id("task")
            status = "claimed" if claimer_id else "open"
            claimed_at = now if claimer_id else None
            lease_until = future_utc_iso(30) if claimer_id else None
            attempt_count = 1 if claimer_id else 0

            conn.execute(
                """
                INSERT INTO tasks (
                    id, project_id, system_id, title, task_type, priority, status,
                    description, claimed_by, claimed_at, lease_until,
                    attempt_count, max_attempts, created_by, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tid,
                    project_id,
                    system_id,
                    title.strip(),
                    task_type,
                    norm_priority,
                    status,
                    description,
                    claimer_id,
                    claimed_at,
                    lease_until,
                    attempt_count,
                    int(max_attempts),
                    creator_id,
                    now,
                    now,
                ),
            )
            if claimer_id:
                conn.execute(
                    "UPDATE agents SET current_task_id = ?, current_system_id = COALESCE(?, current_system_id), last_heartbeat = ? WHERE id = ?",
                    (tid, system_id, now, claimer_id),
                )
                if system_id:
                    conn.execute(
                        "UPDATE agents SET current_system_id = NULL WHERE current_system_id = ? AND id != ?",
                        (system_id, claimer_id),
                    )
                    conn.execute(
                        """
                        UPDATE systems
                        SET claimed_by = ?, claimed_at = ?, lease_until = ?,
                            status = CASE WHEN status = 'unreviewed' THEN 'in_progress' ELSE status END,
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (claimer_id, now, lease_until, now, system_id),
                    )

            self._log_event(
                conn,
                project_id,
                creator_id or claimer_id,
                "task.created",
                "task",
                tid,
                f"Created task '{title.strip()}' [{norm_priority} / {task_type}]",
                {"system_id": system_id, "priority": norm_priority, "status": status},
            )
            return self._get_task_in_conn(conn, tid)

    def _get_task_in_conn(self, conn: sqlite3.Connection, task_id: str) -> Dict[str, Any]:
        row = conn.execute(
            """
            SELECT t.*,
                   s.name AS system_name, s.slug AS system_slug, s.system_type AS system_type,
                   a.name AS claimed_by_name, a.role AS claimed_by_role
            FROM tasks t
            LEFT JOIN systems s ON t.system_id = s.id
            LEFT JOIN agents a ON t.claimed_by = a.id
            WHERE t.id = ?
            """,
            (task_id,),
        ).fetchone()
        if not row:
            raise ValueError(f"Task '{task_id}' not found.")
        return dict(row)

    def block_task(
        self,
        task_id: str,
        agent_id: Optional[str] = None,
        reason: str = "Blocked during review",
        force: bool = False,
    ) -> Dict[str, Any]:
        """Mark a task as 'blocked' with ownership validation, completion guards, and lock cleanup (F-33, RF-06)."""
        now = utc_now_iso()
        with self.connect(immediate=True) as conn:
            t = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if not t:
                raise ValueError(f"Task '{task_id}' not found.")
            if t["status"] == "completed" and not force:
                raise RuntimeError(f"Task '{task_id}' is already completed (pass force=True to override).")

            aid = self._ensure_agent_in_conn(conn, agent_id, t["project_id"])
            holder = t["claimed_by"]
            if holder and not force and aid != holder:
                raise RuntimeError(
                    f"Task '{task_id}' is claimed by '{holder}', not '{aid or 'anonymous'}' (pass force=True to override)."
                )

            effective_agent = aid or holder
            conn.execute(
                """
                UPDATE tasks
                SET status = 'blocked',
                    blocked_reason = ?,
                    lease_until = NULL,
                    updated_at = ?
                WHERE id = ?
                """,
                (reason, now, task_id),
            )
            conn.execute(
                "UPDATE agents SET current_task_id = NULL WHERE current_task_id = ?",
                (task_id,),
            )
            if t["system_id"] and holder:
                remaining_on_sys = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM tasks WHERE system_id = ? AND claimed_by = ? AND status = 'claimed' AND id != ?",
                    (t["system_id"], holder, task_id),
                ).fetchone()["cnt"]
                if remaining_on_sys == 0:
                    conn.execute(
                        "UPDATE agents SET current_system_id = NULL WHERE id = ? AND current_system_id = ?",
                        (holder, t["system_id"]),
                    )
                    conn.execute(
                        """
                        UPDATE systems
                        SET claimed_by = NULL, claimed_at = NULL, lease_until = NULL, updated_at = ?
                        WHERE id = ? AND claimed_by = ?
                        """,
                        (now, t["system_id"], holder),
                    )
            self._log_event(
                conn,
                t["project_id"],
                effective_agent,
                "task.blocked",
                "task",
                task_id,
                f"Blocked task '{t['title']}' ({task_id}): {reason}",
                {"reason": reason},
            )
            return self._get_task_in_conn(conn, task_id)

    def complete_task(
        self,
        task_id: str,
        agent_id: Optional[str] = None,
        deliverable_summary: str = "",
        system_status: Optional[str] = None,
        system_health_score: Optional[int] = None,
        force: bool = False,
        summary: Optional[str] = None,
        health: Optional[int] = None,
        health_score: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Complete a claimed task with strict ownership verification, multi-task lock preservation, and vulnerability protection (F-02, RF-01, RF-05, RF-07, RF-08)."""
        if summary is not None and not deliverable_summary:
            deliverable_summary = summary
        effective_health = health if health is not None else health_score
        if effective_health is not None and system_health_score is None:
            system_health_score = effective_health
        validated_health = validate_health_score(system_health_score)
        now = utc_now_iso()
        with self.connect(immediate=True) as conn:
            t = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if not t:
                raise ValueError(f"Task '{task_id}' not found.")

            if t["status"] == "completed" and not force:
                raise RuntimeError(f"Task '{task_id}' is already completed (pass force=True to overwrite).")

            aid = self._ensure_agent_in_conn(conn, agent_id, t["project_id"])
            holder = t["claimed_by"]
            # Strict ownership check: if claimed, caller MUST match holder (even if agent_id is None) unless force=True (RF-05)
            if holder and not force and aid != holder:
                raise RuntimeError(
                    f"Task '{task_id}' is claimed by '{holder}', not '{aid or 'anonymous'}' (pass force=True to override)."
                )

            effective_agent = aid or holder

            conn.execute(
                """
                UPDATE tasks
                SET status = 'completed',
                    claimed_by = COALESCE(?, claimed_by),
                    deliverable_summary = COALESCE(NULLIF(?, ''), deliverable_summary),
                    lease_until = NULL,
                    completed_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (effective_agent, deliverable_summary, now, now, task_id),
            )

            # Clear current_task_id for any agent pointing to this task
            conn.execute(
                "UPDATE agents SET current_task_id = NULL WHERE current_task_id = ?",
                (task_id,),
            )

            # Check if effective_agent still holds other claimed tasks on this system (RF-07)
            remaining_agent_tasks = 0
            if effective_agent and t["system_id"]:
                remaining_agent_tasks = conn.execute(
                    """
                    SELECT COUNT(*) AS cnt FROM tasks
                    WHERE system_id = ? AND claimed_by = ? AND status = 'claimed' AND id != ?
                    """,
                    (t["system_id"], effective_agent, task_id),
                ).fetchone()["cnt"]

            if effective_agent:
                if remaining_agent_tasks == 0:
                    conn.execute(
                        """
                        UPDATE agents
                        SET current_system_id = CASE WHEN current_system_id = ? THEN NULL ELSE current_system_id END,
                            last_heartbeat = ?
                        WHERE id = ?
                        """,
                        (t["system_id"], now, effective_agent),
                    )
                else:
                    conn.execute(
                        "UPDATE agents SET last_heartbeat = ? WHERE id = ?",
                        (now, effective_agent),
                    )

            if t["system_id"]:
                sys_row = conn.execute("SELECT * FROM systems WHERE id = ?", (t["system_id"],)).fetchone()
                if sys_row:
                    computed_status = self._compute_post_audit_system_status(
                        conn, t["system_id"], sys_row["status"], system_status
                    )
                    raw_health = validated_health if validated_health is not None else sys_row["health_score"]
                    new_health = self._calibrate_system_health(conn, t["system_id"], raw_health)
                    should_release_sys = 1 if (effective_agent is not None and remaining_agent_tasks == 0) else 0
                    # Only clear system lease if effective_agent is NOT NULL, owns the system lease, and has 0 remaining tasks on it (RF-07, RF-08)
                    conn.execute(
                        """
                        UPDATE systems
                        SET claimed_by = CASE WHEN ? = 1 AND claimed_by = ? THEN NULL ELSE claimed_by END,
                            claimed_at = CASE WHEN ? = 1 AND claimed_by = ? THEN NULL ELSE claimed_at END,
                            lease_until = CASE WHEN ? = 1 AND claimed_by = ? THEN NULL ELSE lease_until END,
                            status = ?,
                            health_score = ?,
                            last_audited_by = COALESCE(?, last_audited_by),
                            last_audited_at = ?,
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            should_release_sys, effective_agent,
                            should_release_sys, effective_agent,
                            should_release_sys, effective_agent,
                            computed_status,
                            new_health,
                            effective_agent,
                            now,
                            now,
                            t["system_id"],
                        ),
                    )

            self._log_event(
                conn,
                t["project_id"],
                effective_agent,
                "task.completed",
                "task",
                task_id,
                f"Completed task '{t['title']}' ({task_id})",
                {"deliverable_summary": deliverable_summary},
            )
            return self._get_task_in_conn(conn, task_id)

    def list_tasks(
        self,
        project_id: str,
        status: Optional[str] = None,
        agent_id: Optional[str] = None,
        system_ref: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        def _query(c: sqlite3.Connection) -> List[Dict[str, Any]]:
            params: List[Any] = [project_id]
            where = "WHERE t.project_id = ?"
            if status:
                where += " AND t.status = ?"
                params.append(status)
            if agent_id:
                where += " AND t.claimed_by = ?"
                params.append(agent_id)
            if system_ref:
                sys_obj = self._resolve_system_in_conn(c, project_id, system_ref)
                if not sys_obj:
                    raise ValueError(f"System '{system_ref}' not found.")
                where += " AND t.system_id = ?"
                params.append(sys_obj["id"])

            rows = c.execute(
                f"""
                SELECT t.*,
                       s.name AS system_name, s.slug AS system_slug, s.system_type AS system_type,
                       a.name AS claimed_by_name, a.role AS claimed_by_role
                FROM tasks t
                LEFT JOIN systems s ON t.system_id = s.id
                LEFT JOIN agents a ON t.claimed_by = a.id
                {where}
                ORDER BY
                    CASE t.status
                        WHEN 'claimed' THEN 1
                        WHEN 'open' THEN 2
                        WHEN 'blocked' THEN 3
                        WHEN 'completed' THEN 4
                        ELSE 5
                    END,
                    {PRIORITY_ORDER_SQL.replace('priority', 't.priority')},
                    t.updated_at DESC
                """,
                params,
            ).fetchall()
            return [dict(r) for r in rows]

        if conn is not None:
            return _query(conn)
        with self.connect() as c:
            return _query(c)
