"""
Repository mixin for audit logs and event history.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, List, Optional

from auditos.core.utils import short_id, utc_now_iso


class LogRepositoryMixin:
    """Manages audit log recording and historical querying."""

    def _log_event(
        self,
        conn: sqlite3.Connection,
        project_id: Optional[str],
        agent_id: Optional[str],
        action: str,
        entity_type: str,
        entity_id: str,
        summary: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        log_id = short_id("log")
        now = utc_now_iso()
        aid = self._ensure_agent_in_conn(conn, agent_id, project_id) if agent_id else None
        if aid:
            conn.execute(
                "UPDATE agents SET last_heartbeat = ?, status = CASE WHEN status = 'offline' THEN 'offline' ELSE 'active' END WHERE id = ?",
                (now, aid),
            )
        conn.execute(
            """
            INSERT INTO audit_logs (id, project_id, agent_id, action, entity_type, entity_id, summary, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                log_id,
                project_id,
                aid,
                action,
                entity_type,
                entity_id,
                summary,
                json.dumps(details or {}),
                now,
            ),
        )
        return log_id

    def list_logs(
        self,
        project_id: Optional[str] = None,
        limit: int = 100,
        conn: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        clamped_limit = max(1, min(int(limit), 500))  # Prevent SQLite LIMIT -1 pagination bypass (RF-15)

        def _query(c: sqlite3.Connection) -> List[Dict[str, Any]]:
            if project_id:
                rows = c.execute(
                    """
                    SELECT l.*, a.name AS agent_name, a.role AS agent_role
                    FROM audit_logs l
                    LEFT JOIN agents a ON l.agent_id = a.id
                    WHERE l.project_id = ? OR l.project_id IS NULL
                    ORDER BY l.created_at DESC
                    LIMIT ?
                    """,
                    (project_id, clamped_limit),
                ).fetchall()
            else:
                rows = c.execute(
                    """
                    SELECT l.*, a.name AS agent_name, a.role AS agent_role
                    FROM audit_logs l
                    LEFT JOIN agents a ON l.agent_id = a.id
                    ORDER BY l.created_at DESC
                    LIMIT ?
                    """,
                    (clamped_limit,),
                ).fetchall()
            return [dict(r) for r in rows]

        if conn is not None:
            return _query(conn)
        with self.connect() as c:
            return _query(c)
