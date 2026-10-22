"""
Repository mixin for project tenancy, initialization, and resolution.
"""
from __future__ import annotations

import sqlite3
import uuid
from typing import Any, Dict, List, Optional

from auditos.core.utils import short_id, slugify, utc_now_iso, validate_identifier


class ProjectRepositoryMixin:
    """Manages multi-tenant project records and default project resolution."""

    def ensure_default_project(
        self,
        name: str = "Default Project Audit",
        root_path: str = "",
        description: str = "Multi-agent system and subsystem codebase review",
        conn: Optional[sqlite3.Connection] = None,
    ) -> Dict[str, Any]:
        def _impl(c: sqlite3.Connection) -> Dict[str, Any]:
            row = c.execute(
                """
                SELECT * FROM projects
                ORDER BY CASE WHEN slug = 'default-project-audit' THEN 1 ELSE 0 END ASC,
                         updated_at DESC, created_at DESC
                LIMIT 1
                """
            ).fetchone()
            if row:
                return dict(row)
            proj_id = short_id("proj")
            slug = slugify(name)
            now = utc_now_iso()
            c.execute(
                """
                INSERT INTO projects (id, slug, name, root_path, description, details, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (proj_id, slug, name, root_path, description, "", now, now),
            )
            self._log_event(
                c,
                proj_id,
                None,
                "project.created",
                "project",
                proj_id,
                f"Initialized project '{name}' ({proj_id})",
                {"root_path": root_path},
            )
            return dict(c.execute("SELECT * FROM projects WHERE id = ?", (proj_id,)).fetchone())

        if conn is not None:
            return _impl(conn)
        with self.connect(immediate=True) as c:
            return _impl(c)

    def create_project(
        self,
        name: str,
        root_path: str = "",
        description: str = "",
        details: str = "",
        project_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not name or not str(name).strip():
            raise ValueError("Project name is required.")
        pid = validate_identifier(project_id, "project_id") if project_id else short_id("proj")
        with self.connect(immediate=True) as conn:
            base_slug = slugify(name)
            slug = base_slug
            existing = conn.execute("SELECT id FROM projects WHERE slug = ? OR id = ?", (slug, pid)).fetchone()
            if existing:
                slug = f"{base_slug}-{uuid.uuid4().hex[:6]}"
            now = utc_now_iso()
            conn.execute(
                """
                INSERT INTO projects (id, slug, name, root_path, description, details, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (pid, slug, name.strip(), root_path, description, details, now, now),
            )
            self._log_event(
                conn,
                pid,
                agent_id,
                "project.created",
                "project",
                pid,
                f"Created project '{name.strip()}'",
                {"root_path": root_path},
            )
            return dict(conn.execute("SELECT * FROM projects WHERE id = ?", (pid,)).fetchone())

    def list_projects(self, conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
        if conn is not None:
            rows = conn.execute("SELECT * FROM projects ORDER BY updated_at DESC").fetchall()
            return [dict(r) for r in rows]
        with self.connect() as c:
            rows = c.execute("SELECT * FROM projects ORDER BY updated_at DESC").fetchall()
            return [dict(r) for r in rows]

    def has_any_project(self) -> bool:
        with self.connect() as conn:
            row = conn.execute("SELECT id FROM projects LIMIT 1").fetchone()
            return row is not None

    def resolve_project_id(
        self, project_ref: Optional[str] = None, conn: Optional[sqlite3.Connection] = None
    ) -> str:
        """Resolve explicit project ref or select the most recently created/updated non-default project (F-12, RF-18)."""
        def _lookup(c: sqlite3.Connection) -> Optional[str]:
            if project_ref:
                row = c.execute(
                    "SELECT id FROM projects WHERE id = ? OR slug = ? OR lower(name) = lower(?)",
                    (project_ref, project_ref, project_ref),
                ).fetchone()
                if row:
                    return row["id"]
                raise ValueError(f"Project '{project_ref}' not found.")
            row = c.execute(
                """
                SELECT id FROM projects
                ORDER BY CASE WHEN slug = 'default-project-audit' THEN 1 ELSE 0 END ASC,
                         updated_at DESC, created_at DESC
                LIMIT 1
                """
            ).fetchone()
            return row["id"] if row else None

        if conn is not None:
            found = _lookup(conn)
            if found:
                return found
            proj = self.ensure_default_project(conn=conn)
            return proj["id"]

        with self.connect() as c:
            found = _lookup(c)
            if found:
                return found
        proj = self.ensure_default_project()
        return proj["id"]
