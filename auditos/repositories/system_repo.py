"""
Repository mixin for systems, subsystems, and cross-system relations.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional

from auditos.core.config import PRIORITY_ORDER_SQL, SEVERITY_ORDER_SQL
from auditos.core.utils import short_id, slugify, utc_now_iso, validate_health_score, validate_identifier
from auditos.invariants.rules import HealthCalibrator, HierarchyCycleDetector, StatusGovernor


class SystemRepositoryMixin:
    """Manages system hierarchy, subsystem taxonomy, and cross-system relational topology."""

    def _resolve_system_in_conn(
        self, conn: sqlite3.Connection, project_id: str, system_ref: str
    ) -> Optional[Dict[str, Any]]:
        row = conn.execute(
            """
            SELECT * FROM systems
            WHERE project_id = ? AND (id = ? OR slug = ? OR lower(name) = lower(?))
            LIMIT 1
            """,
            (project_id, system_ref, system_ref, system_ref),
        ).fetchone()
        return dict(row) if row else None

    def resolve_system_id(self, project_id: str, system_ref: str) -> str:
        with self.connect() as conn:
            sys_obj = self._resolve_system_in_conn(conn, project_id, system_ref)
            if not sys_obj:
                raise ValueError(f"System or subsystem '{system_ref}' not found in project '{project_id}'.")
            return sys_obj["id"]

    def _compute_post_audit_system_status(
        self,
        conn: sqlite3.Connection,
        system_id: str,
        current_status: str,
        requested_status: Optional[str],
    ) -> str:
        """Prevent systems with open critical/high findings from being marked reviewed, healthy, or unreviewed (F-02, RF-01)."""
        return StatusGovernor.compute_post_audit_system_status(
            conn, system_id, current_status, requested_status
        )

    def _calibrate_system_health(
        self,
        conn: sqlite3.Connection,
        system_id: str,
        asserted_health: Optional[int],
    ) -> Optional[int]:
        """Calibrate and clamp health score against unresolved finding severities."""
        return HealthCalibrator.calibrate_system_health(conn, system_id, asserted_health)

    def upsert_system(
        self,
        project_id: str,
        name: str,
        parent_ref: Optional[str] = None,
        system_type: Optional[str] = None,
        path_scope: Optional[str] = None,
        description: Optional[str] = None,
        details: Optional[str] = None,
        status: Optional[str] = None,
        health_score: Optional[int] = None,
        agent_id: Optional[str] = None,
        slug: Optional[str] = None,
        system_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not name or not str(name).strip():
            raise ValueError("System name is required.")
        validated_health = validate_health_score(health_score)
        if system_id:
            system_id = validate_identifier(system_id, "system_id")
        if slug:
            slug = validate_identifier(slug, "slug")
        now = utc_now_iso()
        with self.connect(immediate=True) as conn:
            aid = self._ensure_agent_in_conn(conn, agent_id, project_id)
            parent_id = None
            if parent_ref:
                parent_obj = self._resolve_system_in_conn(conn, project_id, parent_ref)
                if not parent_obj:
                    raise ValueError(f"Parent system '{parent_ref}' not found.")
                parent_id = parent_obj["id"]

            target_slug = slug or slugify(name)
            existing = None
            if system_id:
                row = conn.execute("SELECT * FROM systems WHERE id = ? AND project_id = ?", (system_id, project_id)).fetchone()
                existing = dict(row) if row else None
            if not existing:
                row = conn.execute(
                    "SELECT * FROM systems WHERE project_id = ? AND slug = ?",
                    (project_id, target_slug),
                ).fetchone()
                existing = dict(row) if row else None

            if existing:
                sid = existing["id"]
                new_parent = parent_id if parent_ref is not None else existing["parent_id"]
                # Reject hierarchy cycles (RF-10)
                HierarchyCycleDetector.validate_no_cycles(conn, sid, new_parent)

                new_type = system_type or existing["system_type"]
                new_path = path_scope if path_scope is not None else existing["path_scope"]
                new_desc = description if description is not None else existing["description"]
                new_details = details if details is not None else existing["details"]
                # Enforce _compute_post_audit_system_status (RF-01)
                new_status = self._compute_post_audit_system_status(
                    conn, sid, existing["status"], status
                )
                raw_health = validated_health if validated_health is not None else existing["health_score"]
                new_health = self._calibrate_system_health(conn, sid, raw_health)
                last_by = aid or existing["last_audited_by"]
                last_at = now if aid else existing["last_audited_at"]

                conn.execute(
                    """
                    UPDATE systems
                    SET name = ?, parent_id = ?, system_type = ?, path_scope = ?,
                        description = ?, details = ?, status = ?, health_score = ?,
                        last_audited_by = ?, last_audited_at = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        name.strip() or existing["name"],
                        new_parent,
                        new_type,
                        new_path,
                        new_desc,
                        new_details,
                        new_status,
                        new_health,
                        last_by,
                        last_at,
                        now,
                        sid,
                    ),
                )
                self._log_event(
                    conn,
                    project_id,
                    aid,
                    "system.updated",
                    "system",
                    sid,
                    f"Updated {new_type} '{name.strip()}' ({target_slug}) [status: {new_status}]",
                    {"status": new_status, "health_score": new_health},
                )
            else:
                sid = system_id or short_id("sys")
                inferred_type = system_type or ("subsystem" if parent_id else "system")
                init_status = status or "unreviewed"
                init_health = self._calibrate_system_health(conn, sid, validated_health)
                conn.execute(
                    """
                    INSERT INTO systems (
                        id, project_id, parent_id, slug, name, system_type, path_scope,
                        description, details, status, health_score,
                        last_audited_by, last_audited_at, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sid,
                        project_id,
                        parent_id,
                        target_slug,
                        name.strip(),
                        inferred_type,
                        path_scope or "",
                        description or "",
                        details or "",
                        init_status,
                        init_health,
                        aid,
                        now if aid else None,
                        now,
                        now,
                    ),
                )
                self._log_event(
                    conn,
                    project_id,
                    aid,
                    "system.created",
                    "system",
                    sid,
                    f"Registered {inferred_type} '{name.strip()}' ({target_slug})",
                    {"parent_id": parent_id, "path_scope": path_scope or ""},
                )

            conn.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (now, project_id))
            return self.get_system(project_id, sid, conn=conn)

    def get_system(
        self,
        project_id: str,
        system_ref: str,
        conn: Optional[sqlite3.Connection] = None,
    ) -> Dict[str, Any]:
        if conn is not None:
            return self._get_system_impl(conn, project_id, system_ref)
        with self.connect() as c:
            return self._get_system_impl(c, project_id, system_ref)

    def _get_system_impl(
        self, conn: sqlite3.Connection, project_id: str, system_ref: str
    ) -> Dict[str, Any]:
        sys_obj = self._resolve_system_in_conn(conn, project_id, system_ref)
        if not sys_obj:
            raise ValueError(f"System '{system_ref}' not found.")
        sid = sys_obj["id"]

        parent = None
        if sys_obj["parent_id"]:
            prow = conn.execute("SELECT id, slug, name, system_type FROM systems WHERE id = ?", (sys_obj["parent_id"],)).fetchone()
            if prow:
                parent = dict(prow)

        subsystems = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM systems WHERE parent_id = ? ORDER BY name ASC", (sid,)
            ).fetchall()
        ]

        outbound = [
            dict(r)
            for r in conn.execute(
                """
                SELECT r.*,
                       s_src.name AS source_name, s_src.slug AS source_slug, s_src.system_type AS source_type,
                       s_tgt.name AS target_name, s_tgt.slug AS target_slug, s_tgt.system_type AS target_type
                FROM system_relations r
                JOIN systems s_src ON r.source_system_id = s_src.id
                JOIN systems s_tgt ON r.target_system_id = s_tgt.id
                WHERE r.source_system_id = ?
                ORDER BY r.updated_at DESC
                """,
                (sid,),
            ).fetchall()
        ]

        inbound = [
            dict(r)
            for r in conn.execute(
                """
                SELECT r.*,
                       s_src.name AS source_name, s_src.slug AS source_slug, s_src.system_type AS source_type,
                       s_tgt.name AS target_name, s_tgt.slug AS target_slug, s_tgt.system_type AS target_type
                FROM system_relations r
                JOIN systems s_src ON r.source_system_id = s_src.id
                JOIN systems s_tgt ON r.target_system_id = s_tgt.id
                WHERE r.target_system_id = ?
                ORDER BY r.updated_at DESC
                """,
                (sid,),
            ).fetchall()
        ]

        findings = [
            dict(r)
            for r in conn.execute(
                f"""
                SELECT f.*, a.name AS agent_name
                FROM findings f
                LEFT JOIN agents a ON f.agent_id = a.id
                WHERE f.system_id = ? OR f.related_system_id = ?
                ORDER BY {SEVERITY_ORDER_SQL}, f.created_at DESC
                """,
                (sid, sid),
            ).fetchall()
        ]

        tasks = [
            dict(r)
            for r in conn.execute(
                f"""
                SELECT t.*, a.name AS claimed_by_name
                FROM tasks t
                LEFT JOIN agents a ON t.claimed_by = a.id
                WHERE t.system_id = ?
                ORDER BY {PRIORITY_ORDER_SQL}, t.created_at DESC
                """,
                (sid,),
            ).fetchall()
        ]

        sys_obj["parent"] = parent
        sys_obj["subsystems"] = subsystems
        sys_obj["outbound_relations"] = outbound
        sys_obj["inbound_relations"] = inbound
        sys_obj["findings"] = findings
        sys_obj["tasks"] = tasks
        return sys_obj

    def list_systems(
        self, project_id: str, conn: Optional[sqlite3.Connection] = None
    ) -> List[Dict[str, Any]]:
        def _query(c: sqlite3.Connection) -> List[Dict[str, Any]]:
            rows = c.execute(
                """
                SELECT s.*,
                       p.name AS parent_name,
                       p.slug AS parent_slug,
                       a.name AS claimed_by_name,
                       (SELECT COUNT(*) FROM systems c WHERE c.parent_id = s.id) AS subsystem_count,
                       (SELECT COUNT(*) FROM system_relations r WHERE r.source_system_id = s.id) AS outbound_count,
                       (SELECT COUNT(*) FROM system_relations r WHERE r.target_system_id = s.id) AS inbound_count,
                       (SELECT COUNT(*) FROM findings f WHERE f.system_id = s.id AND f.status NOT IN ('resolved', 'wont_fix')) AS open_findings_count,
                       (SELECT COUNT(*) FROM findings f WHERE f.system_id = s.id AND f.severity IN ('critical', 'high') AND f.status NOT IN ('resolved', 'wont_fix')) AS high_findings_count,
                       (SELECT COUNT(*) FROM tasks t WHERE t.system_id = s.id AND t.status != 'completed') AS open_tasks_count
                FROM systems s
                LEFT JOIN systems p ON s.parent_id = p.id
                LEFT JOIN agents a ON s.claimed_by = a.id
                WHERE s.project_id = ?
                ORDER BY CASE WHEN s.parent_id IS NULL THEN 0 ELSE 1 END, s.name ASC
                """,
                (project_id,),
            ).fetchall()
            return [dict(r) for r in rows]

        if conn is not None:
            return _query(conn)
        with self.connect() as c:
            return _query(c)

    def add_relation(
        self,
        project_id: str,
        source_ref: str,
        target_ref: str,
        relation_type: str = "depends_on",
        interface_or_protocol: str = "",
        direction: str = "unidirectional",
        criticality: str = "medium",
        description: str = "",
        details: str = "",
        agent_id: Optional[str] = None,
        protocol: Optional[str] = None,
    ) -> Dict[str, Any]:
        if protocol and not interface_or_protocol:
            interface_or_protocol = protocol
        now = utc_now_iso()
        norm_crit = (criticality or "medium").strip().lower()
        with self.connect(immediate=True) as conn:
            aid = self._ensure_agent_in_conn(conn, agent_id, project_id)
            src = self._resolve_system_in_conn(conn, project_id, source_ref)
            if not src:
                raise ValueError(f"Source system '{source_ref}' not found.")
            tgt = self._resolve_system_in_conn(conn, project_id, target_ref)
            if not tgt:
                raise ValueError(f"Target system '{target_ref}' not found.")
            if src["id"] == tgt["id"]:
                raise ValueError(f"Self-referential relation not allowed: '{src['name']}' cannot link to itself (F-38).")

            existing = conn.execute(
                """
                SELECT * FROM system_relations
                WHERE project_id = ? AND source_system_id = ? AND target_system_id = ? AND relation_type = ?
                """,
                (project_id, src["id"], tgt["id"], relation_type),
            ).fetchone()

            if existing:
                rid = existing["id"]
                conn.execute(
                    """
                    UPDATE system_relations
                    SET interface_or_protocol = COALESCE(NULLIF(?, ''), interface_or_protocol),
                        direction = ?, criticality = ?,
                        description = COALESCE(NULLIF(?, ''), description),
                        details = COALESCE(NULLIF(?, ''), details),
                        recorded_by = COALESCE(?, recorded_by),
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        interface_or_protocol,
                        direction,
                        norm_crit,
                        description,
                        details,
                        aid,
                        now,
                        rid,
                    ),
                )
            else:
                rid = short_id("rel")
                conn.execute(
                    """
                    INSERT INTO system_relations (
                        id, project_id, source_system_id, target_system_id,
                        relation_type, interface_or_protocol, direction, criticality,
                        description, details, recorded_by, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        rid,
                        project_id,
                        src["id"],
                        tgt["id"],
                        relation_type,
                        interface_or_protocol,
                        direction,
                        norm_crit,
                        description,
                        details,
                        aid,
                        now,
                        now,
                    ),
                )

            self._log_event(
                conn,
                project_id,
                aid,
                "relation.recorded",
                "relation",
                rid,
                f"Linked '{src['name']}' --[{relation_type}]--> '{tgt['name']}' ({interface_or_protocol or 'direct'})",
                {
                    "source": src["slug"],
                    "target": tgt["slug"],
                    "relation_type": relation_type,
                    "protocol": interface_or_protocol,
                },
            )
            row = conn.execute(
                """
                SELECT r.*,
                       s_src.name AS source_name, s_src.slug AS source_slug, s_src.system_type AS source_type,
                       s_tgt.name AS target_name, s_tgt.slug AS target_slug, s_tgt.system_type AS target_type
                FROM system_relations r
                JOIN systems s_src ON r.source_system_id = s_src.id
                JOIN systems s_tgt ON r.target_system_id = s_tgt.id
                WHERE r.id = ?
                """,
                (rid,),
            ).fetchone()
            return dict(row)

    def list_relations(
        self,
        project_id: str,
        system_ref: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        def _query(c: sqlite3.Connection) -> List[Dict[str, Any]]:
            params: List[Any] = [project_id]
            where_extra = ""
            if system_ref:
                sys_obj = self._resolve_system_in_conn(c, project_id, system_ref)
                if not sys_obj:
                    raise ValueError(f"System '{system_ref}' not found.")
                where_extra = " AND (r.source_system_id = ? OR r.target_system_id = ?)"
                params.extend([sys_obj["id"], sys_obj["id"]])

            rows = c.execute(
                f"""
                SELECT r.*,
                       s_src.name AS source_name, s_src.slug AS source_slug, s_src.system_type AS source_type, s_src.parent_id AS source_parent_id,
                       s_tgt.name AS target_name, s_tgt.slug AS target_slug, s_tgt.system_type AS target_type, s_tgt.parent_id AS target_parent_id,
                       a.name AS recorded_by_name
                FROM system_relations r
                JOIN systems s_src ON r.source_system_id = s_src.id
                JOIN systems s_tgt ON r.target_system_id = s_tgt.id
                LEFT JOIN agents a ON r.recorded_by = a.id
                WHERE r.project_id = ? {where_extra}
                ORDER BY r.updated_at DESC
                """,
                params,
            ).fetchall()
            return [dict(r) for r in rows]

        if conn is not None:
            return _query(conn)
        with self.connect() as c:
            return _query(c)
