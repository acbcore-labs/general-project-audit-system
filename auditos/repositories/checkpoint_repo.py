"""
Repository mixin for agent checkpoints, scratchpads, and progress state.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from auditos.core.utils import short_id, utc_now_iso, validate_identifier


class CheckpointRepositoryMixin:
    """Manages agent scratchpads, checkpoint snapshots, and context state."""

    def save_checkpoint(
        self,
        project_id: Optional[str] = None,
        agent_id: str = "",
        content: str = "",
        title: str = "",
        state_json: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
        system_id: Optional[str] = None,
        checkpoint_type: str = "scratchpad",
    ) -> Dict[str, Any]:
        """Save intermediate progress, scratch notes, or audit state for an agent session."""
        aid = validate_identifier(agent_id, "agent_id")
        now = utc_now_iso()
        cid = short_id("chk")
        with self.connect(immediate=True) as conn:
            agent = conn.execute("SELECT * FROM agents WHERE id = ?", (aid,)).fetchone()
            if not agent:
                raise ValueError(f"Agent '{aid}' is not registered.")
            pid = self.resolve_project_id(project_id or agent["project_id"])
            tid = task_id or agent["current_task_id"]
            sid = system_id or agent["current_system_id"]
            raw_state = json.dumps(state_json or {})

            conn.execute(
                """
                INSERT INTO agent_checkpoints (
                    id, project_id, agent_id, task_id, system_id,
                    checkpoint_type, title, content, state_json, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (cid, pid, aid, tid, sid, checkpoint_type, title or "Checkpoint", content, raw_state, now, now),
            )
            self._log_event(
                conn, pid, aid, "checkpoint.saved", "agent_checkpoint", cid,
                f"Agent '{aid}' saved checkpoint '{title or 'Checkpoint'}'",
                {"task_id": tid, "system_id": sid, "checkpoint_type": checkpoint_type},
            )
            row = conn.execute("SELECT * FROM agent_checkpoints WHERE id = ?", (cid,)).fetchone()
            return dict(row)

    def get_agent_checkpoint(
        self,
        agent_id: str,
        task_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve the latest checkpoint or scratchpad for an agent."""
        aid = validate_identifier(agent_id, "agent_id")
        with self.connect() as conn:
            if task_id:
                row = conn.execute(
                    "SELECT * FROM agent_checkpoints WHERE agent_id = ? AND task_id = ? ORDER BY created_at DESC LIMIT 1",
                    (aid, task_id),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM agent_checkpoints WHERE agent_id = ? ORDER BY created_at DESC LIMIT 1",
                    (aid,),
                ).fetchone()
            return dict(row) if row else None

    def list_checkpoints(
        self,
        project_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        task_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List checkpoints matching optional filters."""
        params: List[Any] = []
        clauses = []
        if project_id:
            pid = self.resolve_project_id(project_id)
            clauses.append("project_id = ?")
            params.append(pid)
        if agent_id:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if task_id:
            clauses.append("task_id = ?")
            params.append(task_id)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM agent_checkpoints {where} ORDER BY created_at DESC LIMIT {int(limit)}",
                params,
            ).fetchall()
            return [dict(r) for r in rows]
