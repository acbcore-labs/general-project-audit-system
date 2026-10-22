"""
Repository mixin for finding creation, evidence provenance, and lifecycle updates.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional

from auditos.core.config import SEVERITY_ORDER_SQL, VALID_SEVERITIES
from auditos.core.utils import compute_span_hash, get_git_commit_sha, short_id, utc_now_iso


class FindingRepositoryMixin:
    """Manages audit findings, bugs, vulnerabilities, and cryptographic evidence provenance."""

    def add_finding(
        self,
        project_id: str,
        title: str,
        severity: str = "medium",
        category: str = "architecture",
        system_ref: Optional[str] = None,
        related_system_ref: Optional[str] = None,
        task_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        description: str = "",
        details: str = "",
        file_path: str = "",
        line_range: str = "",
        commit_sha: str = "",
        span_hash: str = "",
        code_snippet: str = "",
        recommendation: str = "",
        status: str = "open",
    ) -> Dict[str, Any]:
        if not title or not str(title).strip():
            raise ValueError("Finding title is required.")
        now = utc_now_iso()
        norm_sev = (severity or "medium").strip().lower()
        if norm_sev not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{severity}'. Must be one of {VALID_SEVERITIES}.")
        norm_cat = (category or "architecture").strip().lower()
        norm_status = (status or "open").strip().lower()

        with self.connect(immediate=True) as conn:
            aid = self._ensure_agent_in_conn(conn, agent_id, project_id)
            system_id = None
            if system_ref:
                sys_obj = self._resolve_system_in_conn(conn, project_id, system_ref)
                if not sys_obj:
                    raise ValueError(f"System '{system_ref}' not found.")
                system_id = sys_obj["id"]

            related_system_id = None
            if related_system_ref:
                rel_obj = self._resolve_system_in_conn(conn, project_id, related_system_ref)
                if not rel_obj:
                    raise ValueError(f"Related system '{related_system_ref}' not found.")
                related_system_id = rel_obj["id"]

            # Validate task_id before INSERT so non-existent tasks raise clean ValueError instead of IntegrityError (RF-14)
            if task_id:
                trow = conn.execute(
                    "SELECT id FROM tasks WHERE id = ? AND project_id = ?",
                    (task_id, project_id),
                ).fetchone()
                if not trow:
                    raise ValueError(f"Task '{task_id}' not found in project '{project_id}'.")

            # Evidence reconstruction & provenance
            final_commit_sha = (commit_sha or "").strip()
            if not final_commit_sha:
                p_row = conn.execute("SELECT root_path FROM projects WHERE id = ?", (project_id,)).fetchone()
                root_p = p_row["root_path"] if p_row else None
                final_commit_sha = get_git_commit_sha(root_p)

            final_span_hash = (span_hash or "").strip()
            if not final_span_hash and code_snippet:
                final_span_hash = compute_span_hash(code_snippet)

            fid = short_id("find")
            conn.execute(
                """
                INSERT INTO findings (
                    id, project_id, system_id, related_system_id, task_id, agent_id,
                    severity, category, status, title, description, details,
                    file_path, line_range, commit_sha, span_hash, recommendation, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fid,
                    project_id,
                    system_id,
                    related_system_id,
                    task_id,
                    aid,
                    norm_sev,
                    norm_cat,
                    norm_status,
                    title.strip(),
                    description,
                    details,
                    file_path,
                    line_range,
                    final_commit_sha,
                    final_span_hash,
                    recommendation,
                    now,
                    now,
                ),
            )

            if system_id and norm_sev in ("critical", "high") and norm_status not in ("resolved", "wont_fix"):
                cur_health_row = conn.execute("SELECT health_score FROM systems WHERE id = ?", (system_id,)).fetchone()
                cur_health = cur_health_row["health_score"] if cur_health_row else None
                calibrated_health = self._calibrate_system_health(conn, system_id, cur_health)
                conn.execute(
                    """
                    UPDATE systems
                    SET status = 'needs_attention',
                        health_score = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (calibrated_health, now, system_id),
                )

            self._log_event(
                conn,
                project_id,
                aid,
                "finding.logged",
                "finding",
                fid,
                f"Logged [{norm_sev.upper()}] {norm_cat} finding: '{title.strip()}'",
                {"severity": norm_sev, "category": norm_cat, "system_id": system_id, "file_path": file_path},
            )
            row = conn.execute(
                """
                SELECT f.*,
                       s.name AS system_name, s.slug AS system_slug,
                       rs.name AS related_system_name, rs.slug AS related_system_slug,
                       a.name AS agent_name, a.role AS agent_role
                FROM findings f
                LEFT JOIN systems s ON f.system_id = s.id
                LEFT JOIN systems rs ON f.related_system_id = rs.id
                LEFT JOIN agents a ON f.agent_id = a.id
                WHERE f.id = ?
                """,
                (fid,),
            ).fetchone()
            return dict(row)

    def update_finding_status(
        self,
        finding_id: str,
        status: str,
        agent_id: Optional[str] = None,
        recommendation: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = utc_now_iso()
        with self.connect(immediate=True) as conn:
            f = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
            if not f:
                raise ValueError(f"Finding '{finding_id}' not found.")
            aid = self._ensure_agent_in_conn(conn, agent_id, f["project_id"])
            conn.execute(
                """
                UPDATE findings
                SET status = ?,
                    recommendation = COALESCE(NULLIF(?, ''), recommendation),
                    updated_at = ?
                WHERE id = ?
                """,
                (status.lower(), recommendation or "", now, finding_id),
            )
            self._log_event(
                conn,
                f["project_id"],
                aid,
                "finding.updated",
                "finding",
                finding_id,
                f"Updated finding '{f['title']}' status to '{status}'",
                {"status": status},
            )
            row = conn.execute(
                """
                SELECT f.*,
                       s.name AS system_name, s.slug AS system_slug,
                       rs.name AS related_system_name, rs.slug AS related_system_slug,
                       a.name AS agent_name, a.role AS agent_role
                FROM findings f
                LEFT JOIN systems s ON f.system_id = s.id
                LEFT JOIN systems rs ON f.related_system_id = rs.id
                LEFT JOIN agents a ON f.agent_id = a.id
                WHERE f.id = ?
                """,
                (finding_id,),
            ).fetchone()
            return dict(row)

    def list_findings(
        self,
        project_id: str,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        status: Optional[str] = None,
        system_ref: Optional[str] = None,
        agent_id: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        def _query(c: sqlite3.Connection) -> List[Dict[str, Any]]:
            params: List[Any] = [project_id]
            where = "WHERE f.project_id = ?"
            if severity:
                where += " AND f.severity = ?"
                params.append(severity.lower())
            if category:
                where += " AND f.category = ?"
                params.append(category.lower())
            if status:
                where += " AND f.status = ?"
                params.append(status.lower())
            if agent_id:
                where += " AND f.agent_id = ?"
                params.append(agent_id)
            if system_ref:
                sys_obj = self._resolve_system_in_conn(c, project_id, system_ref)
                if not sys_obj:
                    raise ValueError(f"System '{system_ref}' not found.")
                where += " AND (f.system_id = ? OR f.related_system_id = ?)"
                params.extend([sys_obj["id"], sys_obj["id"]])

            rows = c.execute(
                f"""
                SELECT f.*,
                       s.name AS system_name, s.slug AS system_slug, s.system_type AS system_type,
                       rs.name AS related_system_name, rs.slug AS related_system_slug,
                       a.name AS agent_name, a.role AS agent_role
                FROM findings f
                LEFT JOIN systems s ON f.system_id = s.id
                LEFT JOIN systems rs ON f.related_system_id = rs.id
                LEFT JOIN agents a ON f.agent_id = a.id
                {where}
                ORDER BY {SEVERITY_ORDER_SQL.replace('severity', 'f.severity')}, f.created_at DESC
                """,
                params,
            ).fetchall()
            return [dict(r) for r in rows]

        if conn is not None:
            return _query(conn)
        with self.connect() as c:
            return _query(c)
