"""
Coordination mixin for system/task leases, atomicity, heartbeats, resumption, and reversion.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional

from auditos.core.config import PRIORITY_ORDER_SQL, ROLE_METADATA
from auditos.core.utils import future_utc_iso, utc_now_iso, validate_health_score, validate_identifier


class LeaseCoordinatorMixin:
    """Manages multi-agent lease exclusions, atomic claims, stale lease reclamation, and session resumption."""

    def claim_system(
        self,
        project_id: str,
        system_ref: str,
        agent_id: str,
        lease_minutes: int = 30,
        force: bool = False,
    ) -> Dict[str, Any]:
        now = utc_now_iso()
        lease_until = future_utc_iso(lease_minutes)
        with self.connect(immediate=True) as conn:
            aid = self._ensure_agent_in_conn(conn, agent_id, project_id)
            if not aid:
                raise ValueError("agent_id is required to claim a system.")
            sys_obj = self._resolve_system_in_conn(conn, project_id, system_ref)
            if not sys_obj:
                raise ValueError(f"System '{system_ref}' not found.")

            current_holder = sys_obj["claimed_by"]
            current_lease = sys_obj["lease_until"]
            if (
                current_holder
                and current_holder != aid
                and not force
                and current_lease
                and current_lease > now
            ):
                raise RuntimeError(
                    f"System '{sys_obj['name']}' is currently claimed by agent '{current_holder}' until {current_lease}."
                )

            # Clear stale system pointers on any previous holder (RF-12)
            conn.execute(
                "UPDATE agents SET current_system_id = NULL WHERE current_system_id = ? AND id != ?",
                (sys_obj["id"], aid),
            )

            new_status = "in_progress" if sys_obj["status"] == "unreviewed" else sys_obj["status"]
            conn.execute(
                """
                UPDATE systems
                SET claimed_by = ?, claimed_at = ?, lease_until = ?, status = ?, updated_at = ?
                WHERE id = ?
                """,
                (aid, now, lease_until, new_status, now, sys_obj["id"]),
            )
            conn.execute(
                "UPDATE agents SET current_system_id = ?, last_heartbeat = ?, status = 'active' WHERE id = ?",
                (sys_obj["id"], now, aid),
            )
            self._log_event(
                conn,
                project_id,
                aid,
                "system.claimed",
                "system",
                sys_obj["id"],
                f"Agent '{aid}' claimed {sys_obj['system_type']} '{sys_obj['name']}'",
                {"lease_until": lease_until},
            )
            return self.get_system(project_id, sys_obj["id"], conn=conn)

    def release_system(
        self,
        project_id: str,
        system_ref: str,
        agent_id: Optional[str] = None,
        status: Optional[str] = None,
        health_score: Optional[int] = None,
        details_append: Optional[str] = None,
        force: bool = False,
    ) -> Dict[str, Any]:
        """Release system lock with ownership validation and full agent roster cleanup (F-13, RF-01)."""
        validated_health = validate_health_score(health_score)
        now = utc_now_iso()
        with self.connect(immediate=True) as conn:
            aid = self._ensure_agent_in_conn(conn, agent_id, project_id)
            sys_obj = self._resolve_system_in_conn(conn, project_id, system_ref)
            if not sys_obj:
                raise ValueError(f"System '{system_ref}' not found.")

            holder = sys_obj["claimed_by"]
            lease_until = sys_obj["lease_until"]
            if (
                holder
                and not force
                and lease_until
                and lease_until > now
                and aid != holder
            ):
                raise RuntimeError(
                    f"Cannot release system '{sys_obj['name']}': currently claimed by '{holder}' until {lease_until} (pass force=True to override)."
                )

            new_status = self._compute_post_audit_system_status(
                conn, sys_obj["id"], sys_obj["status"], status
            )
            raw_health = validated_health if validated_health is not None else sys_obj["health_score"]
            new_health = self._calibrate_system_health(conn, sys_obj["id"], raw_health)
            new_details = sys_obj["details"] or ""
            if details_append:
                sep = "\n\n" if new_details else ""
                new_details = f"{new_details}{sep}[{now} by {aid or holder or 'agent'}]: {details_append}"

            conn.execute(
                """
                UPDATE systems
                SET claimed_by = NULL, claimed_at = NULL, lease_until = NULL,
                    status = ?, health_score = ?, details = ?,
                    last_audited_by = COALESCE(?, ?, last_audited_by),
                    last_audited_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (new_status, new_health, new_details, aid, holder, now, now, sys_obj["id"]),
            )
            conn.execute(
                "UPDATE agents SET current_system_id = NULL WHERE current_system_id = ?",
                (sys_obj["id"],),
            )
            self._log_event(
                conn,
                project_id,
                aid or holder,
                "system.released",
                "system",
                sys_obj["id"],
                f"Released system '{sys_obj['name']}' [status: {new_status}]",
                {"status": new_status, "health_score": new_health},
            )
            return self.get_system(project_id, sys_obj["id"], conn=conn)

    def claim_task(
        self,
        task_id: str,
        agent_id: str,
        lease_minutes: int = 30,
        force: bool = False,
    ) -> Dict[str, Any]:
        """Claim a specific task while verifying system lock and preventing poison pills (F-14, F-18, RF-09, RF-12)."""
        now = utc_now_iso()
        lease_until = future_utc_iso(lease_minutes)
        with self.connect(immediate=True) as conn:
            t = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if not t:
                raise ValueError(f"Task '{task_id}' not found.")
            aid = self._ensure_agent_in_conn(conn, agent_id, t["project_id"])
            if not aid:
                raise ValueError("agent_id is required to claim a task.")
            if t["status"] == "completed" and not force:
                raise RuntimeError(f"Task '{task_id}' is already completed (pass force=True to re-open).")

            if t["attempt_count"] >= t["max_attempts"] and not force:
                conn.execute(
                    "UPDATE tasks SET status = 'blocked', blocked_reason = 'Exceeded max_attempts', updated_at = ? WHERE id = ?",
                    (now, task_id),
                )
                raise RuntimeError(
                    f"Task '{task_id}' has reached max_attempts ({t['max_attempts']}) and is now blocked."
                )
            if (
                t["status"] == "claimed"
                and t["claimed_by"]
                and t["claimed_by"] != aid
                and not force
                and t["lease_until"]
                and t["lease_until"] > now
            ):
                raise RuntimeError(
                    f"Task '{task_id}' is already claimed by agent '{t['claimed_by']}' until {t['lease_until']}."
                )

            if t["system_id"]:
                sys_row = conn.execute("SELECT * FROM systems WHERE id = ?", (t["system_id"],)).fetchone()
                if (
                    sys_row
                    and sys_row["claimed_by"]
                    and sys_row["claimed_by"] != aid
                    and not force
                    and sys_row["lease_until"]
                    and sys_row["lease_until"] > now
                ):
                    raise RuntimeError(
                        f"Target system '{sys_row['name']}' is currently leased by agent '{sys_row['claimed_by']}' until {sys_row['lease_until']}."
                    )

            # Clear stale current_task_id on any previous agent holding this task (RF-12)
            conn.execute(
                "UPDATE agents SET current_task_id = NULL WHERE current_task_id = ? AND id != ?",
                (task_id, aid),
            )

            conn.execute(
                """
                UPDATE tasks
                SET status = 'claimed', claimed_by = ?, claimed_at = ?, lease_until = ?,
                    attempt_count = attempt_count + 1, updated_at = ?
                WHERE id = ?
                """,
                (aid, now, lease_until, now, task_id),
            )
            conn.execute(
                """
                UPDATE agents
                SET current_task_id = ?, current_system_id = COALESCE(?, current_system_id),
                    status = 'active', last_heartbeat = ?
                WHERE id = ?
                """,
                (task_id, t["system_id"], now, aid),
            )
            if t["system_id"]:
                # Clear stale current_system_id on previous agent if we are acquiring the system lock (RF-12)
                conn.execute(
                    "UPDATE agents SET current_system_id = NULL WHERE current_system_id = ? AND id != ?",
                    (t["system_id"], aid),
                )
                conn.execute(
                    """
                    UPDATE systems
                    SET claimed_by = CASE
                            WHEN claimed_by IS NULL OR claimed_by = ? OR lease_until IS NULL OR lease_until < ? OR ? = 1
                            THEN ? ELSE claimed_by END,
                        claimed_at = CASE
                            WHEN claimed_by IS NULL OR claimed_by = ? OR lease_until IS NULL OR lease_until < ? OR ? = 1
                            THEN ? ELSE claimed_at END,
                        lease_until = CASE
                            WHEN claimed_by IS NULL OR claimed_by = ? OR lease_until IS NULL OR lease_until < ? OR ? = 1
                            THEN ? ELSE lease_until END,
                        status = CASE WHEN status = 'unreviewed' THEN 'in_progress' ELSE status END,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        aid, now, 1 if force else 0, aid,
                        aid, now, 1 if force else 0, now,
                        aid, now, 1 if force else 0, lease_until,
                        now,
                        t["system_id"],
                    ),
                )

            self._log_event(
                conn,
                t["project_id"],
                aid,
                "task.claimed",
                "task",
                task_id,
                f"Agent '{aid}' claimed task '{t['title']}' ({task_id})",
                {"lease_until": lease_until, "system_id": t["system_id"]},
            )
            return self._get_task_in_conn(conn, task_id)

    def claim_next_task(
        self,
        project_id: str,
        agent_id: str,
        task_type: Optional[str] = None,
        system_ref: Optional[str] = None,
        lease_minutes: int = 30,
    ) -> Optional[Dict[str, Any]]:
        """Atomically claim the highest-priority task without stealing active system leases or wedging poison-pill tasks (F-03, F-18, RF-09, RF-12)."""
        now = utc_now_iso()
        lease_until = future_utc_iso(lease_minutes)
        with self.connect(immediate=True) as conn:
            aid = self._ensure_agent_in_conn(conn, agent_id, project_id)
            if not aid:
                raise ValueError("agent_id is required to claim next task.")

            # Auto-block any open or lease-expired claimed tasks that have reached max_attempts (F-18, RF-09)
            conn.execute(
                """
                UPDATE tasks
                SET status = 'blocked',
                    blocked_reason = 'Exceeded max_attempts (' || max_attempts || ')',
                    lease_until = NULL,
                    updated_at = ?
                WHERE project_id = ?
                  AND status IN ('open', 'claimed')
                  AND attempt_count >= max_attempts
                  AND (status = 'open' OR (lease_until IS NOT NULL AND lease_until < ?))
                """,
                (now, project_id, now),
            )

            params: List[Any] = [project_id, now, aid, now]
            filters = ""
            if task_type:
                filters += " AND t.task_type = ?"
                params.append(task_type)
            elif aid:
                # Role-aware dispatching: if agent has a specialized role, prioritize its matched task types
                agent_row = conn.execute("SELECT role FROM agents WHERE id = ?", (aid,)).fetchone()
                if agent_row and agent_row["role"] in ROLE_METADATA and agent_row["role"] != "general-auditor":
                    target_types = ROLE_METADATA[agent_row["role"]]["task_types"]
                    placeholders = ",".join(["?"] * len(target_types))
                    check_params = [project_id, now, aid, now] + list(target_types)
                    has_role_tasks = conn.execute(
                        f"""
                        SELECT 1
                        FROM tasks t
                        LEFT JOIN systems s ON t.system_id = s.id
                        WHERE t.project_id = ?
                          AND (t.status = 'open' OR (t.status = 'claimed' AND t.lease_until IS NOT NULL AND t.lease_until < ?))
                          AND t.attempt_count < t.max_attempts
                          AND (
                              t.system_id IS NULL
                              OR s.claimed_by IS NULL
                              OR s.claimed_by = ?
                              OR s.lease_until IS NULL
                              OR s.lease_until < ?
                          )
                          AND t.task_type IN ({placeholders})
                        LIMIT 1
                        """,
                        check_params,
                    ).fetchone()
                    if has_role_tasks:
                        filters += f" AND t.task_type IN ({placeholders})"
                        params.extend(target_types)
            if system_ref:
                sys_obj = self._resolve_system_in_conn(conn, project_id, system_ref)
                if not sys_obj:
                    raise ValueError(f"System '{system_ref}' not found.")
                filters += " AND t.system_id = ?"
                params.append(sys_obj["id"])

            candidate = conn.execute(
                f"""
                SELECT t.*
                FROM tasks t
                LEFT JOIN systems s ON t.system_id = s.id
                WHERE t.project_id = ?
                  AND (t.status = 'open' OR (t.status = 'claimed' AND t.lease_until IS NOT NULL AND t.lease_until < ?))
                  AND t.attempt_count < t.max_attempts
                  AND (
                      t.system_id IS NULL
                      OR s.claimed_by IS NULL
                      OR s.claimed_by = ?
                      OR s.lease_until IS NULL
                      OR s.lease_until < ?
                  )
                  {filters}
                ORDER BY {PRIORITY_ORDER_SQL.replace('priority', 't.priority')}, t.created_at ASC
                LIMIT 1
                """,
                params,
            ).fetchone()

            if not candidate:
                return None

            tid = candidate["id"]
            # Clear stale current_task_id on any previous agent whose lease expired (RF-12)
            conn.execute(
                "UPDATE agents SET current_task_id = NULL WHERE current_task_id = ? AND id != ?",
                (tid, aid),
            )

            conn.execute(
                """
                UPDATE tasks
                SET status = 'claimed', claimed_by = ?, claimed_at = ?, lease_until = ?,
                    attempt_count = attempt_count + 1, updated_at = ?
                WHERE id = ?
                """,
                (aid, now, lease_until, now, tid),
            )
            conn.execute(
                """
                UPDATE agents
                SET current_task_id = ?, current_system_id = COALESCE(?, current_system_id),
                    status = 'active', last_heartbeat = ?
                WHERE id = ?
                """,
                (tid, candidate["system_id"], now, aid),
            )
            if candidate["system_id"]:
                conn.execute(
                    "UPDATE agents SET current_system_id = NULL WHERE current_system_id = ? AND id != ?",
                    (candidate["system_id"], aid),
                )
                conn.execute(
                    """
                    UPDATE systems
                    SET claimed_by = ?, claimed_at = ?, lease_until = ?,
                        status = CASE WHEN status = 'unreviewed' THEN 'in_progress' ELSE status END,
                        updated_at = ?
                    WHERE id = ?
                      AND (claimed_by IS NULL OR claimed_by = ? OR lease_until IS NULL OR lease_until < ?)
                    """,
                    (aid, now, lease_until, now, candidate["system_id"], aid, now),
                )

            self._log_event(
                conn,
                project_id,
                aid,
                "task.claimed",
                "task",
                tid,
                f"Agent '{aid}' atomically claimed next task '{candidate['title']}' ({tid})",
                {"priority": candidate["priority"], "task_type": candidate["task_type"]},
            )
            return self._get_task_in_conn(conn, tid)

    def resume_agent(
        self,
        agent_id: str,
        project_id: Optional[str] = None,
        extend_leases_minutes: int = 30,
    ) -> Dict[str, Any]:
        """Resume an agent session, extend unexpired leases, and restore working context."""
        aid = validate_identifier(agent_id, "agent_id")
        now = utc_now_iso()
        with self.connect(immediate=True) as conn:
            agent = conn.execute("SELECT * FROM agents WHERE id = ?", (aid,)).fetchone()
            if not agent:
                raise ValueError(f"Agent '{aid}' is not registered.")
            pid = self.resolve_project_id(project_id or agent["project_id"])

            # Heartbeat & extend active leases
            conn.execute(
                "UPDATE agents SET status = 'active', last_heartbeat = ? WHERE id = ?",
                (now, aid),
            )
            lease_until = future_utc_iso(extend_leases_minutes)
            conn.execute(
                "UPDATE tasks SET lease_until = ?, updated_at = ? WHERE claimed_by = ? AND status = 'claimed' AND (lease_until IS NULL OR lease_until >= ?)",
                (lease_until, now, aid, now),
            )
            conn.execute(
                "UPDATE systems SET lease_until = ?, updated_at = ? WHERE claimed_by = ? AND (lease_until IS NULL OR lease_until >= ?)",
                (lease_until, now, aid, now),
            )

            # Fetch claimed task & system
            current_task = None
            if agent["current_task_id"]:
                task_row = conn.execute("SELECT * FROM tasks WHERE id = ?", (agent["current_task_id"],)).fetchone()
                if task_row and task_row["claimed_by"] == aid and task_row["status"] == "claimed":
                    current_task = dict(task_row)
                    if current_task.get("system_id"):
                        sys_row = conn.execute("SELECT slug, name FROM systems WHERE id = ?", (current_task["system_id"],)).fetchone()
                        if sys_row:
                            current_task["system_slug"] = sys_row["slug"]
                            current_task["system_name"] = sys_row["name"]

            current_system = None
            if agent["current_system_id"]:
                sys_row = conn.execute("SELECT * FROM systems WHERE id = ?", (agent["current_system_id"],)).fetchone()
                if sys_row and sys_row["claimed_by"] == aid:
                    current_system = dict(sys_row)

            # Latest checkpoint
            chk_row = conn.execute(
                "SELECT * FROM agent_checkpoints WHERE agent_id = ? ORDER BY created_at DESC LIMIT 1",
                (aid,),
            ).fetchone()
            latest_checkpoint = dict(chk_row) if chk_row else None

            # Next suggested action
            if current_task:
                next_action = f"Continue working on task {current_task['id']} ('{current_task['title']}'). Lease valid until {current_task.get('lease_until')}."
            elif current_system:
                next_action = f"Continue reviewing system '{current_system['name']}' ({current_system['slug']}). Claimed until {current_system.get('lease_until')}."
            else:
                next_action = f"No active tasks claimed. Run './audit task next --agent {aid}' to claim the next priority task for role '{agent['role']}'."

            return {
                "agent": dict(agent),
                "active_task": current_task,
                "active_system": current_system,
                "latest_checkpoint": latest_checkpoint,
                "lease_extended_minutes": extend_leases_minutes,
                "next_action": next_action,
            }

    def revert_agent(
        self,
        agent_id: str,
        project_id: Optional[str] = None,
        reason: str = "Aborted by agent",
    ) -> Dict[str, Any]:
        """Cleanly release any active tasks and systems claimed by this agent and return them to the queue."""
        aid = validate_identifier(agent_id, "agent_id")
        now = utc_now_iso()
        with self.connect(immediate=True) as conn:
            agent = conn.execute("SELECT * FROM agents WHERE id = ?", (aid,)).fetchone()
            if not agent:
                raise ValueError(f"Agent '{aid}' is not registered.")
            pid = self.resolve_project_id(project_id or agent["project_id"])

            reverted_tasks = []
            claimed_tasks = conn.execute(
                "SELECT id, title FROM tasks WHERE claimed_by = ? AND status = 'claimed'",
                (aid,),
            ).fetchall()
            for ct in claimed_tasks:
                conn.execute(
                    "UPDATE tasks SET status = 'open', claimed_by = NULL, claimed_at = NULL, lease_until = NULL, updated_at = ? WHERE id = ?",
                    (now, ct["id"]),
                )
                reverted_tasks.append(ct["id"])
                self._log_event(
                    conn, pid, aid, "task.reverted", "task", ct["id"],
                    f"Agent '{aid}' reverted task '{ct['title']}' back to open queue ({reason})",
                )

            reverted_systems = []
            claimed_systems = conn.execute(
                "SELECT id, slug, name FROM systems WHERE claimed_by = ?",
                (aid,),
            ).fetchall()
            for cs in claimed_systems:
                conn.execute(
                    "UPDATE systems SET claimed_by = NULL, claimed_at = NULL, lease_until = NULL, updated_at = ? WHERE id = ?",
                    (now, cs["id"]),
                )
                reverted_systems.append(cs["slug"])
                self._log_event(
                    conn, pid, aid, "system.released", "system", cs["id"],
                    f"Agent '{aid}' released claim on '{cs['name']}' ({reason})",
                )

            conn.execute(
                "UPDATE agents SET current_task_id = NULL, current_system_id = NULL, status = 'idle', last_heartbeat = ? WHERE id = ?",
                (now, aid),
            )

            return {
                "agent_id": aid,
                "status": "idle",
                "reverted_tasks": reverted_tasks,
                "reverted_systems": reverted_systems,
                "reason": reason,
            }
