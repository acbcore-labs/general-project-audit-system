from __future__ import annotations

import json
import os
import re
import sqlite3
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Generator, List, Optional


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def future_utc_iso(minutes: int = 30) -> str:
    """Return a future UTC timestamp in ISO-8601 format for task/system leases."""
    dt = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


VALID_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def validate_identifier(value: Optional[str], field_name: str = "id") -> Optional[str]:
    """Validate that an identifier or slug contains only safe alphanumeric, underscore, or hyphen characters (RF-03)."""
    if value is None or value == "":
        return None
    val = str(value).strip()
    if not VALID_ID_RE.match(val):
        raise ValueError(
            f"Invalid {field_name} '{val}': must be 1-64 characters matching [a-zA-Z0-9_-]."
        )
    return val


def slugify(value: str) -> str:
    """Create a URL/CLI-friendly slug from a name."""
    s = re.sub(r"[^a-zA-Z0-9\s_-]", "", value.strip().lower())
    s = re.sub(r"[\s_]+", "-", s)
    cleaned = s.strip("-")[:64].strip("-")
    return cleaned or f"item-{uuid.uuid4().hex[:8]}"


def short_id(prefix: str) -> str:
    """Generate a readable unique identifier with 48 bits (12 hex chars) of entropy (F-27)."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def validate_health_score(score: Optional[int]) -> Optional[int]:
    """Validate that health_score is None or an integer between 0 and 100 inclusive (F-25)."""
    if score is None or score == "":
        return None
    val = int(score)
    if val < 0 or val > 100:
        raise ValueError(f"health_score must be between 0 and 100 (got {val}).")
    return val


VALID_PRIORITIES = ("critical", "high", "medium", "low")
VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
VALID_SYSTEM_STATUSES = ("unreviewed", "in_progress", "reviewed", "needs_attention", "healthy")
VALID_TASK_STATUSES = ("open", "claimed", "completed", "blocked")
VALID_AGENT_ROLES = (
    "arch-mapper",
    "security-auditor",
    "performance-reviewer",
    "integration-tracer",
    "verifier",
    "general-auditor",
)

ROLE_METADATA: Dict[str, Dict[str, Any]] = {
    "arch-mapper": {
        "title": "Architecture & Scope Mapper",
        "description": "Maps system/subsystem hierarchy, path scopes, architectural boundaries, and baseline component health.",
        "task_types": ("architecture_map", "subsystem_audit"),
        "capabilities": ("ast", "directory-mapping", "hierarchy", "scoping"),
    },
    "security-auditor": {
        "title": "Security & Invariants Auditor",
        "description": "Audits authentication, RBAC, input validation, cryptographic primitives, secrets, and authorization boundaries.",
        "task_types": ("security_review", "bug_hunt"),
        "capabilities": ("auth", "jwt", "crypto", "sql-injection", "rbac", "secrets"),
    },
    "performance-reviewer": {
        "title": "Performance & Concurrency Reviewer",
        "description": "Audits database queries, N+1 patterns, async bottlenecks, race conditions, memory leaks, and throughput budgets.",
        "task_types": ("performance_review",),
        "capabilities": ("concurrency", "async", "database-queries", "benchmarking", "latency"),
    },
    "integration-tracer": {
        "title": "Cross-System Integration Tracer",
        "description": "Traces relations, protocols (gRPC, REST, Kafka), contract coupling, and cascading failure modes between systems.",
        "task_types": ("integration_trace",),
        "capabilities": ("cross-system", "protocols", "contracts", "events", "grpc", "rest"),
    },
    "verifier": {
        "title": "Quality & Verification Prover",
        "description": "Verifies logged findings, reproduces edge cases, checks test suite quality, and signs off on subsystem health scores.",
        "task_types": ("verification", "bug_hunt"),
        "capabilities": ("verification", "testing", "reproduction", "regression", "mutation"),
    },
    "general-auditor": {
        "title": "General Purpose Auditor",
        "description": "Generalist auditor capable of executing any open audit task across the project.",
        "task_types": (
            "architecture_map",
            "subsystem_audit",
            "integration_trace",
            "security_review",
            "performance_review",
            "bug_hunt",
            "verification",
        ),
        "capabilities": ("general",),
    },
}


SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    root_path TEXT DEFAULT '',
    description TEXT DEFAULT '',
    details TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    project_id TEXT DEFAULT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'general-auditor',
    model TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active', -- active, idle, offline
    capabilities TEXT DEFAULT '',
    current_task_id TEXT DEFAULT NULL,
    current_system_id TEXT DEFAULT NULL,
    registered_at TEXT NOT NULL,
    last_heartbeat TEXT NOT NULL,
    metadata_json TEXT DEFAULT '{}',
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS systems (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    parent_id TEXT DEFAULT NULL,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    system_type TEXT NOT NULL DEFAULT 'system', -- system, subsystem, service, module, pipeline, datastore, external
    path_scope TEXT DEFAULT '',
    description TEXT DEFAULT '',
    details TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'unreviewed', -- unreviewed, in_progress, reviewed, needs_attention, healthy
    health_score INTEGER DEFAULT NULL CHECK (health_score IS NULL OR (health_score >= 0 AND health_score <= 100)),
    claimed_by TEXT DEFAULT NULL,
    claimed_at TEXT DEFAULT NULL,
    lease_until TEXT DEFAULT NULL,
    last_audited_by TEXT DEFAULT NULL,
    last_audited_at TEXT DEFAULT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(project_id, slug),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_id) REFERENCES systems(id) ON DELETE CASCADE,
    FOREIGN KEY (claimed_by) REFERENCES agents(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS system_relations (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    source_system_id TEXT NOT NULL,
    target_system_id TEXT NOT NULL,
    relation_type TEXT NOT NULL DEFAULT 'depends_on', -- depends_on, calls, publishes_to, consumes_from, reads_writes, authenticates_via, orchestrates, syncs_with
    interface_or_protocol TEXT DEFAULT '',
    direction TEXT NOT NULL DEFAULT 'unidirectional', -- unidirectional, bidirectional
    criticality TEXT NOT NULL DEFAULT 'medium', -- critical, high, medium, low
    description TEXT DEFAULT '',
    details TEXT DEFAULT '',
    recorded_by TEXT DEFAULT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (source_system_id != target_system_id),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (source_system_id) REFERENCES systems(id) ON DELETE CASCADE,
    FOREIGN KEY (target_system_id) REFERENCES systems(id) ON DELETE CASCADE,
    FOREIGN KEY (recorded_by) REFERENCES agents(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    system_id TEXT DEFAULT NULL,
    title TEXT NOT NULL,
    task_type TEXT NOT NULL DEFAULT 'subsystem_audit', -- architecture_map, subsystem_audit, integration_trace, security_review, performance_review, bug_hunt, verification
    priority TEXT NOT NULL DEFAULT 'medium', -- critical, high, medium, low
    status TEXT NOT NULL DEFAULT 'open', -- open, claimed, completed, blocked
    description TEXT DEFAULT '',
    deliverable_summary TEXT DEFAULT '',
    claimed_by TEXT DEFAULT NULL,
    claimed_at TEXT DEFAULT NULL,
    lease_until TEXT DEFAULT NULL,
    completed_at TEXT DEFAULT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    blocked_reason TEXT DEFAULT '',
    created_by TEXT DEFAULT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (system_id) REFERENCES systems(id) ON DELETE SET NULL,
    FOREIGN KEY (claimed_by) REFERENCES agents(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    system_id TEXT DEFAULT NULL,
    related_system_id TEXT DEFAULT NULL,
    task_id TEXT DEFAULT NULL,
    agent_id TEXT DEFAULT NULL,
    severity TEXT NOT NULL DEFAULT 'medium', -- critical, high, medium, low, info
    category TEXT NOT NULL DEFAULT 'architecture', -- architecture, security, integration, performance, reliability, maintainability, bug, documentation
    status TEXT NOT NULL DEFAULT 'open', -- open, confirmed, mitigated, resolved, wont_fix
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    details TEXT DEFAULT '',
    file_path TEXT DEFAULT '',
    line_range TEXT DEFAULT '',
    recommendation TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (system_id) REFERENCES systems(id) ON DELETE SET NULL,
    FOREIGN KEY (related_system_id) REFERENCES systems(id) ON DELETE SET NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE SET NULL,
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    project_id TEXT DEFAULT NULL,
    agent_id TEXT DEFAULT NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    summary TEXT NOT NULL,
    details_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_checkpoints (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    task_id TEXT DEFAULT NULL,
    system_id TEXT DEFAULT NULL,
    checkpoint_type TEXT NOT NULL DEFAULT 'scratchpad', -- scratchpad, draft_finding, progress_state, artifact
    title TEXT DEFAULT '',
    content TEXT DEFAULT '',
    state_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE SET NULL,
    FOREIGN KEY (system_id) REFERENCES systems(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_systems_project ON systems(project_id);
CREATE INDEX IF NOT EXISTS idx_systems_parent ON systems(parent_id);
CREATE INDEX IF NOT EXISTS idx_relations_project ON system_relations(project_id);
CREATE INDEX IF NOT EXISTS idx_relations_source ON system_relations(source_system_id);
CREATE INDEX IF NOT EXISTS idx_relations_target ON system_relations(target_system_id);
CREATE INDEX IF NOT EXISTS idx_tasks_project_status ON tasks(project_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_project_severity ON findings(project_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_system ON findings(system_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_project_time ON audit_logs(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_checkpoints_agent ON agent_checkpoints(agent_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_checkpoints_task ON agent_checkpoints(task_id);
CREATE INDEX IF NOT EXISTS idx_checkpoints_system ON agent_checkpoints(system_id);
"""


PRIORITY_ORDER_SQL = """
CASE lower(priority)
    WHEN 'critical' THEN 1
    WHEN 'high' THEN 2
    WHEN 'medium' THEN 3
    WHEN 'low' THEN 4
    ELSE 5
END
"""

SEVERITY_ORDER_SQL = """
CASE lower(severity)
    WHEN 'critical' THEN 1
    WHEN 'high' THEN 2
    WHEN 'medium' THEN 3
    WHEN 'low' THEN 4
    WHEN 'info' THEN 5
    ELSE 6
END
"""


class AuditDB:
    """Thread-safe, multi-process-safe SQLite auditing engine for multi-agent codebase review."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        auto_sync_snapshot: bool = False,
        ui_dir: Optional[str] = None,
    ) -> None:
        self.ui_dir = os.path.abspath(
            ui_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")
        )
        if db_path == ":memory:":
            self.db_path = ":memory:"
            self._shared_mem_uri = f"file:auditos_{uuid.uuid4().hex}?mode=memory&cache=shared"
            self._keepalive_conn = sqlite3.connect(self._shared_mem_uri, uri=True, check_same_thread=False)
            self.auto_sync_snapshot = False
        else:
            default_path = os.environ.get(
                "AUDIT_DB_PATH",
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit.db"),
            )
            self.db_path = os.path.abspath(db_path or default_path)
            self._shared_mem_uri = None
            self._keepalive_conn = None
            self.auto_sync_snapshot = auto_sync_snapshot
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db()

    def _raw_connect(self) -> sqlite3.Connection:
        if self._shared_mem_uri:
            return sqlite3.connect(self._shared_mem_uri, timeout=10.0, isolation_level=None, uri=True, check_same_thread=False)
        return sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None, check_same_thread=False)

    @contextmanager
    def connect(self, immediate: bool = False) -> Generator[sqlite3.Connection, None, None]:
        conn = self._raw_connect()
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        try:
            if immediate:
                conn.execute("BEGIN IMMEDIATE;")
            else:
                conn.execute("BEGIN;")
            yield conn
            if conn.in_transaction:
                conn.execute("COMMIT;")
        except Exception:
            if conn.in_transaction:
                try:
                    conn.execute("ROLLBACK;")
                except sqlite3.Error:
                    pass
            raise
        finally:
            conn.close()
        if immediate and self.auto_sync_snapshot:
            self.sync_static_snapshot()

    def init_db(self) -> None:
        """Initialize schema only when tables are missing to avoid exclusive DDL locks on reads (F-26)."""
        conn = self._raw_connect()
        try:
            conn.execute("PRAGMA busy_timeout = 5000;")
            existing = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='projects'"
            ).fetchone()
            if not existing:
                conn.executescript(SCHEMA_SQL)
                conn.commit()
            else:
                agent_cols = {r[1] for r in conn.execute("PRAGMA table_info(agents)").fetchall()}
                if "project_id" not in agent_cols:
                    conn.execute("ALTER TABLE agents ADD COLUMN project_id TEXT DEFAULT NULL;")
                task_cols = {r[1] for r in conn.execute("PRAGMA table_info(tasks)").fetchall()}
                if "attempt_count" not in task_cols:
                    conn.execute("ALTER TABLE tasks ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0;")
                if "max_attempts" not in task_cols:
                    conn.execute("ALTER TABLE tasks ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 3;")
                if "blocked_reason" not in task_cols:
                    conn.execute("ALTER TABLE tasks ADD COLUMN blocked_reason TEXT DEFAULT '';")
                has_checkpoints = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='agent_checkpoints'"
                ).fetchone()
                if not has_checkpoints:
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS agent_checkpoints (
                            id TEXT PRIMARY KEY,
                            project_id TEXT NOT NULL,
                            agent_id TEXT NOT NULL,
                            task_id TEXT DEFAULT NULL,
                            system_id TEXT DEFAULT NULL,
                            checkpoint_type TEXT NOT NULL DEFAULT 'scratchpad',
                            title TEXT DEFAULT '',
                            content TEXT DEFAULT '',
                            state_json TEXT DEFAULT '{}',
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                            FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
                            FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE SET NULL,
                            FOREIGN KEY (system_id) REFERENCES systems(id) ON DELETE SET NULL
                        );
                        """
                    )
                    conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_checkpoints_agent ON agent_checkpoints(agent_id, updated_at DESC);"
                    )
                    conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_checkpoints_task ON agent_checkpoints(task_id);"
                    )
                    conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_checkpoints_system ON agent_checkpoints(system_id);"
                    )
        finally:
            conn.close()

    def sync_static_snapshot(self, project_ref: Optional[str] = None) -> Optional[str]:
        """Atomically write snapshot.js via temp file + os.replace to prevent 0-byte truncation races (F-07, RF-13)."""
        if self.db_path == ":memory:":
            return None
        if not os.path.isdir(self.ui_dir):
            return None
        snap = self.get_project_snapshot(project_ref)
        snap_path = os.path.join(self.ui_dir, "snapshot.js")
        fd, tmp_path = tempfile.mkstemp(prefix=".snapshot_", suffix=".tmp", dir=self.ui_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("window.__AUDIT_SNAPSHOT__ = ")
                json.dump(snap, f, indent=2)
                f.write(";\n")
                f.flush()
            os.replace(tmp_path, snap_path)
            return snap_path
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise

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

    # -------------------------------------------------------------------------
    # Projects
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # Agents (Workers)
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # Systems & Subsystems
    # -------------------------------------------------------------------------
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
        open_crit_high = conn.execute(
            """
            SELECT COUNT(*) AS cnt FROM findings
            WHERE system_id = ?
              AND severity IN ('critical', 'high')
              AND status NOT IN ('resolved', 'wont_fix')
            """,
            (system_id,),
        ).fetchone()["cnt"]

        if open_crit_high > 0 and requested_status in (None, "reviewed", "healthy", "unreviewed"):
            return "needs_attention"
        if requested_status:
            return requested_status
        active_tasks = conn.execute(
            """
            SELECT COUNT(*) AS cnt FROM tasks
            WHERE system_id = ? AND status IN ('open', 'claimed')
            """,
            (system_id,),
        ).fetchone()["cnt"]
        if active_tasks > 0 and current_status == "in_progress":
            return "in_progress"
        return "reviewed" if current_status == "in_progress" else current_status

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
                # Walk full ancestor chain to reject both direct and transitive hierarchy cycles (RF-10)
                curr_anc = new_parent
                visited_anc = {sid}
                while curr_anc:
                    if curr_anc in visited_anc:
                        raise ValueError(
                            "Hierarchy cycle detected: a system cannot be a direct or transitive parent of itself."
                        )
                    visited_anc.add(curr_anc)
                    prow = conn.execute("SELECT parent_id FROM systems WHERE id = ?", (curr_anc,)).fetchone()
                    curr_anc = prow["parent_id"] if prow else None

                new_type = system_type or existing["system_type"]
                new_path = path_scope if path_scope is not None else existing["path_scope"]
                new_desc = description if description is not None else existing["description"]
                new_details = details if details is not None else existing["details"]
                # Enforce _compute_post_audit_system_status so upsert_system cannot mask open critical/high findings (RF-01)
                new_status = self._compute_post_audit_system_status(
                    conn, sid, existing["status"], status
                )
                new_health = validated_health if validated_health is not None else existing["health_score"]
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
                        validated_health,
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
            new_health = validated_health if validated_health is not None else sys_obj["health_score"]
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
                f"Released {sys_obj['system_type']} '{sys_obj['name']}' [status: {new_status}]",
                {"status": new_status, "health_score": new_health},
            )
            return self.get_system(project_id, sys_obj["id"], conn=conn)

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

    # -------------------------------------------------------------------------
    # Cross-System Relations ("Works With")
    # -------------------------------------------------------------------------
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
    ) -> Dict[str, Any]:
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

    # -------------------------------------------------------------------------
    # Tasks (Multi-Agent Job Queue & Coordination)
    # -------------------------------------------------------------------------
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

    def claim_task(
        self,
        task_id: str,
        agent_id: str,
        lease_minutes: int = 30,
        force: bool = False,
    ) -> Dict[str, Any]:
        """Claim a specific task, enforce max_attempts, and clean up stale agent pointers (F-08, RF-09, RF-12)."""
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
                raise RuntimeError(f"Task '{task_id}' is already completed.")
            if t["status"] == "blocked" and not force:
                raise RuntimeError(f"Task '{task_id}' is blocked ({t['blocked_reason'] or 'max attempts exceeded'}).")
            if t["attempt_count"] >= t["max_attempts"] and not force:
                conn.execute(
                    """
                    UPDATE tasks
                    SET status = 'blocked',
                        blocked_reason = 'Exceeded max_attempts (' || max_attempts || ')',
                        lease_until = NULL,
                        updated_at = ?
                    WHERE id = ?
                    """,
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
    ) -> Dict[str, Any]:
        """Complete a claimed task with strict ownership verification, multi-task lock preservation, and vulnerability protection (F-02, RF-01, RF-05, RF-07, RF-08)."""
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
                    should_release_sys = 1 if (effective_agent is not None and remaining_agent_tasks == 0) else 0
                    # Only clear system lease if effective_agent is NOT NULL, owns the system lease, and has 0 remaining tasks on it (RF-07, RF-08)
                    conn.execute(
                        """
                        UPDATE systems
                        SET claimed_by = CASE WHEN ? = 1 AND claimed_by = ? THEN NULL ELSE claimed_by END,
                            claimed_at = CASE WHEN ? = 1 AND claimed_by = ? THEN NULL ELSE claimed_at END,
                            lease_until = CASE WHEN ? = 1 AND claimed_by = ? THEN NULL ELSE lease_until END,
                            status = ?,
                            health_score = COALESCE(?, health_score),
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
                            validated_health,
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

    # -------------------------------------------------------------------------
    # Findings (Audit Observations, Bugs, Security & Architecture Issues)
    # -------------------------------------------------------------------------
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

            fid = short_id("find")
            conn.execute(
                """
                INSERT INTO findings (
                    id, project_id, system_id, related_system_id, task_id, agent_id,
                    severity, category, status, title, description, details,
                    file_path, line_range, recommendation, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    recommendation,
                    now,
                    now,
                ),
            )

            if system_id and norm_sev in ("critical", "high") and norm_status not in ("resolved", "wont_fix"):
                conn.execute(
                    """
                    UPDATE systems
                    SET status = 'needs_attention',
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (now, system_id),
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

    # -------------------------------------------------------------------------
    # Audit Logs & Point-in-Time Consistent Project Snapshot (F-16, RF-15, RF-18)
    # -------------------------------------------------------------------------
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

    def get_project_snapshot(self, project_ref: Optional[str] = None) -> Dict[str, Any]:
        """Resolve project and assemble the entire snapshot inside a single consistent transaction (F-16, RF-18)."""
        with self.connect() as conn:
            project_id = self.resolve_project_id(project_ref, conn=conn)
            prow = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
            if not prow:
                raise ValueError(f"Project '{project_id}' not found.")
            project = dict(prow)
            projects = self.list_projects(conn=conn)
            systems = self.list_systems(project_id, conn=conn)
            relations = self.list_relations(project_id, conn=conn)
            agents = self.list_agents(project_id=project_id, conn=conn)
            tasks = self.list_tasks(project_id, conn=conn)
            findings = self.list_findings(project_id, conn=conn)
            logs = self.list_logs(project_id, limit=120, conn=conn)

        top_systems = [s for s in systems if not s["parent_id"]]
        subsystems = [s for s in systems if s["parent_id"]]
        scored = [s["health_score"] for s in systems if s["health_score"] is not None]
        avg_health = round(sum(scored) / len(scored), 1) if scored else None

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        open_findings = 0
        for f in findings:
            sev = f["severity"]
            if sev in severity_counts:
                severity_counts[sev] += 1
            if f["status"] not in ("resolved", "wont_fix"):
                open_findings += 1

        task_counts = {"open": 0, "claimed": 0, "completed": 0, "blocked": 0}
        for t in tasks:
            st = t["status"]
            if st in task_counts:
                task_counts[st] += 1

        return {
            "project": project,
            "projects": projects,
            "metrics": {
                "total_systems": len(top_systems),
                "total_subsystems": len(subsystems),
                "total_components": len(systems),
                "reviewed_components": sum(
                    1 for s in systems if s["status"] in ("reviewed", "healthy", "needs_attention")
                ),
                "total_relations": len(relations),
                "active_agents": sum(1 for a in agents if a["status"] == "active"),
                "total_agents": len(agents),
                "avg_health_score": avg_health,
                "open_findings": open_findings,
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "task_counts": task_counts,
            },
            "systems": systems,
            "relations": relations,
            "agents": agents,
            "tasks": tasks,
            "findings": findings,
            "logs": logs,
        }

    def export_markdown_report(self, project_ref: Optional[str] = None) -> str:
        snap = self.get_project_snapshot(project_ref)
        proj = snap["project"]
        m = snap["metrics"]
        systems = snap["systems"]
        relations = snap["relations"]
        agents = snap["agents"]
        tasks = snap["tasks"]
        findings = snap["findings"]

        lines: List[str] = []
        lines.append(f"# System & Subsystem Audit Report: {proj['name']}")
        lines.append("")
        lines.append(f"- **Project ID**: `{proj['id']}` (`{proj['slug']}`)")
        if proj.get("root_path"):
            lines.append(f"- **Root Path**: `{proj['root_path']}`")
        lines.append(f"- **Generated At**: `{utc_now_iso()}`")
        lines.append(
            f"- **Coverage**: {m['reviewed_components']}/{m['total_components']} components reviewed "
            f"({m['total_systems']} top-level systems, {m['total_subsystems']} subsystems)"
        )
        lines.append(
            f"- **Average Health Score**: {m['avg_health_score'] if m['avg_health_score'] is not None else 'N/A'}/100"
        )
        lines.append(
            f"- **Findings Summary**: {m['total_findings']} total ({m['severity_counts']['critical']} Critical, "
            f"{m['severity_counts']['high']} High, {m['severity_counts']['medium']} Medium, "
            f"{m['severity_counts']['low']} Low, {m['severity_counts']['info']} Info)"
        )
        lines.append("")

        if proj.get("description"):
            lines.append("## Executive Overview")
            lines.append(proj["description"])
            lines.append("")

        lines.append("## Multi-Agent Audit Workforce")
        lines.append("")
        if agents:
            lines.append("| Agent ID | Name | Role | Status | Tasks Completed | Findings Logged | Last Heartbeat |")
            lines.append("| :--- | :--- | :--- | :--- | :---: | :---: | :--- |")
            for a in agents:
                lines.append(
                    f"| `{a['id']}` | {a['name']} | `{a['role']}` | `{a['status']}` | "
                    f"{a.get('completed_tasks_count', 0)} | {a.get('findings_count', 0)} | `{a['last_heartbeat']}` |"
                )
        else:
            lines.append("_No agents registered._")
        lines.append("")

        lines.append("## Systems & Subsystems Hierarchy")
        lines.append("")
        by_parent: Dict[Optional[str], List[Dict[str, Any]]] = {}
        for s in systems:
            by_parent.setdefault(s["parent_id"], []).append(s)

        visited_nodes = set()

        def render_sys(sys_item: Dict[str, Any], depth: int = 0) -> None:
            if sys_item["id"] in visited_nodes:
                return
            visited_nodes.add(sys_item["id"])
            indent = "  " * depth
            health = f"{sys_item['health_score']}/100" if sys_item["health_score"] is not None else "Unscored"
            claim_tag = f" | Claimed by `{sys_item['claimed_by']}`" if sys_item.get("claimed_by") else ""
            lines.append(
                f"{indent}- **{sys_item['name']}** (`{sys_item['slug']}` | `{sys_item['system_type']}`) — "
                f"Status: `{sys_item['status']}` | Health: **{health}**{claim_tag}"
            )
            if sys_item.get("path_scope"):
                lines.append(f"{indent}  - **Scope**: `{sys_item['path_scope']}`")
            if sys_item.get("description"):
                lines.append(f"{indent}  - **Description**: {sys_item['description']}")
            if sys_item.get("details"):
                lines.append(f"{indent}  - **Details**: {sys_item['details']}")
            lines.append(
                f"{indent}  - **Timestamps**: Created `{sys_item['created_at']}` | Updated `{sys_item['updated_at']}`"
            )
            for child in by_parent.get(sys_item["id"], []):
                render_sys(child, depth + 1)

        for root_sys in by_parent.get(None, []):
            render_sys(root_sys, 0)
        lines.append("")

        lines.append("## Cross-System Interactions & Dependencies")
        lines.append("")
        if relations:
            lines.append("| Source System | Relation | Target System | Protocol / Interface | Criticality | Description |")
            lines.append("| :--- | :---: | :--- | :--- | :---: | :--- |")
            for r in relations:
                arrow = "<-->" if r["direction"] == "bidirectional" else "-->"
                lines.append(
                    f"| **{r['source_name']}** (`{r['source_slug']}`) | `{r['relation_type']}` {arrow} | "
                    f"**{r['target_name']}** (`{r['target_slug']}`) | `{r['interface_or_protocol'] or 'direct'}` | "
                    f"`{r['criticality']}` | {r['description']} |"
                )
        else:
            lines.append("_No cross-system relations recorded._")
        lines.append("")

        lines.append("## Audit Findings & Recommendations")
        lines.append("")
        if findings:
            for f in findings:
                lines.append(
                    f"### [{f['severity'].upper()}] {f['title']} (`{f['id']}`)"
                )
                lines.append(
                    f"- **Category**: `{f['category']}` | **Status**: `{f['status']}` | "
                    f"**System**: {f.get('system_name') or 'Project-wide'} (`{f.get('system_slug') or 'n/a'}`) | "
                    f"**Logged By**: `{f.get('agent_id') or 'unknown'}` at `{f['created_at']}`"
                )
                if f.get("file_path"):
                    loc = f"{f['file_path']}:{f['line_range']}" if f.get("line_range") else f["file_path"]
                    lines.append(f"- **Location**: `{loc}`")
                if f.get("description"):
                    lines.append(f"- **Summary**: {f['description']}")
                if f.get("details"):
                    lines.append(f"- **Technical Details**: {f['details']}")
                if f.get("recommendation"):
                    lines.append(f"- **Recommendation**: {f['recommendation']}")
                lines.append("")
        else:
            lines.append("_No findings logged._")

        lines.append("## Audit Task Queue")
        lines.append("")
        if tasks:
            lines.append("| Task ID | Priority | Type | Title | System | Status | Agent | Deliverable Summary |")
            lines.append("| :--- | :---: | :--- | :--- | :--- | :---: | :--- | :--- |")
            for t in tasks:
                lines.append(
                    f"| `{t['id']}` | `{t['priority']}` | `{t['task_type']}` | {t['title']} | "
                    f"`{t.get('system_slug') or 'project'}` | `{t['status']}` | `{t.get('claimed_by') or '-'}` | "
                    f"{t.get('deliverable_summary') or '-'} |"
                )
        lines.append("")
        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Reset & Demo Seeding
    # -------------------------------------------------------------------------
    def reset_database(self) -> None:
        with self.connect(immediate=True) as conn:
            conn.execute("DELETE FROM audit_logs;")
            conn.execute("DELETE FROM findings;")
            conn.execute("DELETE FROM tasks;")
            conn.execute("DELETE FROM system_relations;")
            conn.execute("DELETE FROM systems;")
            conn.execute("DELETE FROM agents;")
            conn.execute("DELETE FROM projects;")

    def seed_demo_data(self, reset_first: bool = True) -> Dict[str, Any]:
        prev_sync = self.auto_sync_snapshot
        self.auto_sync_snapshot = False
        pid = "proj-horizon"
        try:
            if reset_first:
                self.reset_database()

            proj = self.create_project(
                name="Horizon Distributed Commerce Engine",
                root_path="/workspace/horizon-commerce",
                description=(
                    "Multi-region microservices and event-driven fulfillment architecture "
                    "audited by a coordinated fleet of specialized AI agents."
                ),
                details="Production codebase with 4 core systems, 8 specialized subsystems, gRPC/Kafka interconnects, and PostgreSQL/Redis stores.",
                project_id=pid,
            )
            pid = proj["id"]

            self.register_agent(
                agent_id="agent-atlas-01",
                name="Atlas (Architecture Mapper)",
                role="architecture-mapper",
                model="gemini-2.5-pro",
                capabilities="system-topology, dependency-graphing, boundary-analysis",
                project_id=pid,
            )
            self.register_agent(
                agent_id="agent-sentinel-02",
                name="Sentinel (Security Auditor)",
                role="security-auditor",
                model="claude-3.7-sonnet",
                capabilities="auth-flows, token-validation, injection-analysis, secrets-review",
                project_id=pid,
            )
            self.register_agent(
                agent_id="agent-pulse-03",
                name="Pulse (Performance & Reliability)",
                role="performance-reviewer",
                model="gpt-4.1",
                capabilities="concurrency, db-queries, backpressure, retry-storms",
                project_id=pid,
            )
            self.register_agent(
                agent_id="agent-veritas-04",
                name="Veritas (Integration & QA Verifier)",
                role="integration-verifier",
                model="gemini-2.5-flash",
                capabilities="schema-contracts, idempotency, dead-letter-queues",
                project_id=pid,
            )

            edge = self.upsert_system(
                project_id=pid,
                name="Edge API Gateway",
                slug="edge-gateway",
                system_type="system",
                path_scope="services/edge-gateway/**",
                description="Public-facing ingress router handling TLS termination, rate limiting, and request routing.",
                details="Written in Go (Envoy + custom middleware). Handles 45k req/sec peak traffic across 3 availability zones.",
                status="reviewed",
                health_score=88,
                agent_id="agent-atlas-01",
            )
            iam = self.upsert_system(
                project_id=pid,
                name="Identity & Access Engine",
                slug="identity-engine",
                system_type="system",
                path_scope="services/identity/**",
                description="Authentication, OAuth2/OIDC token issuance, RBAC policy evaluation, and session revocation.",
                details="Rust service backed by PostgreSQL and Redis cluster for sub-2ms token introspection.",
                status="needs_attention",
                health_score=72,
                agent_id="agent-sentinel-02",
            )
            orders = self.upsert_system(
                project_id=pid,
                name="Order & Fulfillment Core",
                slug="order-core",
                system_type="system",
                path_scope="services/order-core/**",
                description="Orchestrates cart checkout, inventory reservation, payment capture, and fulfillment state machines.",
                details="TypeScript/Node.js + Temporal workflows with transactional outbox pattern publishing to Kafka.",
                status="in_progress",
                health_score=79,
                agent_id="agent-pulse-03",
            )
            telemetry = self.upsert_system(
                project_id=pid,
                name="Telemetry & Audit Pipeline",
                slug="telemetry-pipeline",
                system_type="system",
                path_scope="platform/telemetry/**",
                description="High-throughput ingestion pipeline for distributed traces, structured logs, and compliance events.",
                details="OpenTelemetry collectors streaming into ClickHouse and S3 parquet archives.",
                status="healthy",
                health_score=94,
                agent_id="agent-veritas-04",
            )

            self.upsert_system(
                project_id=pid,
                name="Rate Limiter & WAF Filter",
                slug="edge-rate-limiter",
                parent_ref=edge["id"],
                system_type="subsystem",
                path_scope="services/edge-gateway/middleware/ratelimit/**",
                description="Token-bucket distributed rate limiter using Redis Lua scripts.",
                details="Enforces per-IP and per-API-key quotas; falls back to local in-memory window if Redis latency > 15ms.",
                status="healthy",
                health_score=92,
                agent_id="agent-atlas-01",
            )
            self.upsert_system(
                project_id=pid,
                name="GraphQL & REST Aggregator",
                slug="edge-aggregator",
                parent_ref=edge["id"],
                system_type="subsystem",
                path_scope="services/edge-gateway/aggregator/**",
                description="Federates downstream gRPC calls into unified client payloads.",
                details="Uses dataloader batching but lacks strict depth limits on nested GraphQL fragments.",
                status="reviewed",
                health_score=82,
                agent_id="agent-sentinel-02",
            )

            self.upsert_system(
                project_id=pid,
                name="JWT & Refresh Token Issuer",
                slug="iam-token-issuer",
                parent_ref=iam["id"],
                system_type="subsystem",
                path_scope="services/identity/src/tokens/**",
                description="EdDSA key rotation, short-lived access JWT minting, and refresh token family tracking.",
                details="Rotates signing keys every 24h; refresh token reuse detection revokes entire session family.",
                status="needs_attention",
                health_score=65,
                agent_id="agent-sentinel-02",
            )
            self.upsert_system(
                project_id=pid,
                name="RBAC Policy Evaluator",
                slug="iam-rbac-evaluator",
                parent_ref=iam["id"],
                system_type="subsystem",
                path_scope="services/identity/src/rbac/**",
                description="Fine-grained permission resolver evaluating tenant roles and resource policies.",
                details="Caches compiled policy ASTs in local LRU cache with 60-second TTL.",
                status="reviewed",
                health_score=81,
                agent_id="agent-sentinel-02",
            )

            self.upsert_system(
                project_id=pid,
                name="Checkout Saga Orchestrator",
                slug="order-checkout-saga",
                parent_ref=orders["id"],
                system_type="subsystem",
                path_scope="services/order-core/src/sagas/checkout/**",
                description="Coordinates multi-step checkout across inventory lock, fraud check, and payment capture.",
                details="Executes compensating transactions on payment decline or inventory contention.",
                status="in_progress",
                health_score=76,
                agent_id="agent-pulse-03",
            )
            self.upsert_system(
                project_id=pid,
                name="Payment Gateway Adapter",
                slug="order-payment-adapter",
                parent_ref=orders["id"],
                system_type="subsystem",
                path_scope="services/order-core/src/adapters/payment/**",
                description="Idempotent wrapper around external Stripe/Adyen payment processors.",
                details="Stores idempotency keys in PostgreSQL `payment_attempts` table before outbound HTTP call.",
                status="reviewed",
                health_score=84,
                agent_id="agent-veritas-04",
            )
            self.upsert_system(
                project_id=pid,
                name="Inventory Reservation Ledger",
                slug="order-inventory-ledger",
                parent_ref=orders["id"],
                system_type="subsystem",
                path_scope="services/order-core/src/inventory/**",
                description="Tracks SKU stock holds, warehouse allocation, and TTL expiration for abandoned carts.",
                details="Uses optimistic locking (`version` column) on high-contention flash-sale SKUs.",
                status="needs_attention",
                health_score=68,
                agent_id="agent-pulse-03",
            )

            self.upsert_system(
                project_id=pid,
                name="Kafka Event Stream Consumer",
                slug="telemetry-kafka-consumer",
                parent_ref=telemetry["id"],
                system_type="subsystem",
                path_scope="platform/telemetry/consumers/**",
                description="Consumes domain events from `orders.*` and `identity.*` topics for compliance archiving.",
                details="Batch-inserts 5,000 events per flush into ClickHouse with dead-letter routing.",
                status="healthy",
                health_score=95,
                agent_id="agent-veritas-04",
            )

            self.add_relation(
                project_id=pid,
                source_ref="edge-gateway",
                target_ref="identity-engine",
                relation_type="authenticates_via",
                interface_or_protocol="gRPC (IdentityService.VerifyToken)",
                direction="unidirectional",
                criticality="critical",
                description="Validates bearer tokens and enriches upstream headers with tenant claims.",
                details="P99 latency budget is 4ms; circuit breaker trips after 5 consecutive timeouts.",
                agent_id="agent-atlas-01",
            )
            self.add_relation(
                project_id=pid,
                source_ref="edge-aggregator",
                target_ref="order-core",
                relation_type="calls",
                interface_or_protocol="gRPC / Protobuf v3 (OrderService)",
                direction="unidirectional",
                criticality="critical",
                description="Routes client checkout and order history mutations to Order & Fulfillment Core.",
                details="Propagates W3C traceparent and X-Idempotency-Key headers.",
                agent_id="agent-atlas-01",
            )
            self.add_relation(
                project_id=pid,
                source_ref="order-checkout-saga",
                target_ref="order-inventory-ledger",
                relation_type="orchestrates",
                interface_or_protocol="Internal Domain Service / SQL Transaction",
                direction="bidirectional",
                criticality="critical",
                description="Reserves SKU stock during checkout initialization and commits/releases on payment outcome.",
                details="Saga step 1 acquires 10-minute reservation lock before calling Payment Gateway Adapter.",
                agent_id="agent-pulse-03",
            )
            self.add_relation(
                project_id=pid,
                source_ref="order-checkout-saga",
                target_ref="order-payment-adapter",
                relation_type="calls",
                interface_or_protocol="Temporal Activity RPC",
                direction="unidirectional",
                criticality="critical",
                description="Triggers asynchronous payment authorization and capture with automatic retry policy.",
                details="Retries up to 3 times with exponential backoff on 5xx provider errors.",
                agent_id="agent-pulse-03",
            )
            self.add_relation(
                project_id=pid,
                source_ref="order-core",
                target_ref="telemetry-kafka-consumer",
                relation_type="publishes_to",
                interface_or_protocol="Kafka Topic: orders.lifecycle.v2 (Avro)",
                direction="unidirectional",
                criticality="high",
                description="Streams order state transitions via transactional outbox relay.",
                details="Guaranteed at-least-once delivery; consumers must deduplicate by `event_id`.",
                agent_id="agent-veritas-04",
            )
            self.add_relation(
                project_id=pid,
                source_ref="iam-token-issuer",
                target_ref="telemetry-kafka-consumer",
                relation_type="publishes_to",
                interface_or_protocol="Kafka Topic: identity.security.audit",
                direction="unidirectional",
                criticality="high",
                description="Emits login, token rotation, and anomalous revocation events.",
                details="Used for SIEM anomaly detection and compliance audit trails.",
                agent_id="agent-sentinel-02",
            )
            self.add_relation(
                project_id=pid,
                source_ref="order-core",
                target_ref="iam-rbac-evaluator",
                relation_type="depends_on",
                interface_or_protocol="gRPC (PolicyService.CheckPermission)",
                direction="unidirectional",
                criticality="high",
                description="Verifies merchant admin privileges for bulk order refunds and overrides.",
                details="Called synchronously on administrative endpoints.",
                agent_id="agent-sentinel-02",
            )

            t1 = self.create_task(
                project_id=pid,
                title="Map top-level systems, subsystem boundaries, and gRPC/Kafka contracts",
                system_ref="edge-gateway",
                task_type="architecture_map",
                priority="critical",
                description="Identify all ingress routes, downstream service dependencies, and failure blast radii.",
                created_by="agent-atlas-01",
                claim_immediately_for="agent-atlas-01",
            )
            self.complete_task(
                t1["id"],
                agent_id="agent-atlas-01",
                deliverable_summary="Mapped 4 core systems, 8 subsystems, and 7 primary cross-system interaction channels.",
            )

            self.create_task(
                project_id=pid,
                title="Audit JWT refresh token rotation & revocation race conditions",
                system_ref="iam-token-issuer",
                task_type="security_review",
                priority="critical",
                description="Verify atomic rotation of refresh tokens under concurrent mobile/web requests and inspect Redis revocation propagation.",
                created_by="agent-atlas-01",
                claim_immediately_for="agent-sentinel-02",
            )

            self.create_task(
                project_id=pid,
                title="Analyze Checkout Saga lock contention & retry backpressure under flash sales",
                system_ref="order-checkout-saga",
                task_type="performance_review",
                priority="high",
                description="Inspect database lock acquisition order between checkout saga and inventory reservation ledger.",
                created_by="agent-atlas-01",
                claim_immediately_for="agent-pulse-03",
            )

            self.create_task(
                project_id=pid,
                title="Verify Avro schema backward compatibility on orders.lifecycle.v2",
                system_ref="telemetry-kafka-consumer",
                task_type="integration_trace",
                priority="medium",
                description="Confirm outbox producer in Order Core and ClickHouse consumer handle nullable v2 fields cleanly.",
                created_by="agent-veritas-04",
            )

            self.create_task(
                project_id=pid,
                title="Enforce query depth & complexity ceiling in GraphQL Aggregator",
                system_ref="edge-aggregator",
                task_type="security_review",
                priority="high",
                description="Prevent deeply nested fragment amplification attacks from exhausting downstream Order Core gRPC pools.",
                created_by="agent-sentinel-02",
            )

            self.create_task(
                project_id=pid,
                title="Audit expired cart reservation reaper job for deadlocks",
                system_ref="order-inventory-ledger",
                task_type="bug_hunt",
                priority="high",
                description="Review cron worker that releases expired SKU holds to ensure consistent row locking order.",
                created_by="agent-pulse-03",
            )

            self.add_finding(
                project_id=pid,
                title="Race window in Refresh Token Rotation allows parallel token minting before family revocation",
                severity="critical",
                category="security",
                system_ref="iam-token-issuer",
                related_system_ref="edge-gateway",
                agent_id="agent-sentinel-02",
                file_path="services/identity/src/tokens/refresh_store.rs",
                line_range="142-189",
                description="Non-atomic SELECT followed by UPDATE on `refresh_tokens` table permits two concurrent requests with the same token to both succeed within a 4ms window.",
                details=(
                    "When two requests arrive simultaneously at Edge Gateway with an identical refresh token, "
                    "both pass `is_revoked == false` before either transaction commits. Recommend using "
                    "`UPDATE refresh_tokens SET consumed_at = NOW() WHERE token_hash = $1 AND consumed_at IS NULL RETURNING *`."
                ),
                recommendation="Replace read-then-write check with a single atomic `UPDATE ... WHERE consumed_at IS NULL RETURNING` query.",
                status="open",
            )

            self.add_finding(
                project_id=pid,
                title="Unbounded retries in Checkout Saga can trigger cascading thread pool exhaustion on Inventory Ledger",
                severity="high",
                category="performance",
                system_ref="order-checkout-saga",
                related_system_ref="order-inventory-ledger",
                agent_id="agent-pulse-03",
                file_path="services/order-core/src/sagas/checkout/reserve_step.ts",
                line_range="64-112",
                description="Optimistic lock failures during high-contention SKU drops trigger immediate tight-loop retries without jitter.",
                details=(
                    "When `version` mismatch occurs in `order-inventory-ledger`, `reserve_step.ts` retries up to 15 times "
                    "with a fixed 10ms delay, saturating the PostgreSQL connection pool during flash sales."
                ),
                recommendation="Add full jitter exponential backoff and cap synchronous retries at 4 attempts with circuit-breaker shedding.",
                status="open",
            )

            self.add_finding(
                project_id=pid,
                title="GraphQL Aggregator lacks AST query depth limit on nested Order -> LineItems -> Product resolver",
                severity="high",
                category="security",
                system_ref="edge-aggregator",
                related_system_ref="order-core",
                agent_id="agent-sentinel-02",
                file_path="services/edge-gateway/aggregator/graphql_server.go",
                line_range="205-238",
                description="Clients can submit deeply nested GraphQL queries that fan out into N+1 gRPC calls against Order Core.",
                details="While dataloader batches single-level IDs, recursive cyclic fragments bypass batching limits.",
                recommendation="Configure max query depth = 7 and max complexity score = 500 in `graphql_server.go`.",
                status="confirmed",
            )

            self.add_finding(
                project_id=pid,
                title="RBAC policy cache TTL (60s) delays immediate privilege revocation across Order Core admin endpoints",
                severity="medium",
                category="architecture",
                system_ref="iam-rbac-evaluator",
                related_system_ref="order-core",
                agent_id="agent-sentinel-02",
                file_path="services/identity/src/rbac/evaluator.rs",
                line_range="88-115",
                description="Local LRU policy cache does not subscribe to Redis pub/sub invalidation events when an admin role is revoked.",
                details="Revoked merchant admins retain refund execution privileges for up to 60 seconds until cache expiry.",
                recommendation="Subscribe `iam-rbac-evaluator` instances to `iam:policy:invalidate` pub/sub channel for sub-second eviction.",
                status="open",
            )

            self.add_finding(
                project_id=pid,
                title="Outbox relay lacks dead-letter metric alert when Kafka broker acks time out",
                severity="low",
                category="reliability",
                system_ref="telemetry-kafka-consumer",
                related_system_ref="order-core",
                agent_id="agent-veritas-04",
                file_path="platform/telemetry/consumers/order_stream.py",
                line_range="310-342",
                description="Poison pill Avro payloads are routed to DLQ topic but do not increment Prometheus counter `telemetry_dlq_messages_total`.",
                details="Verified DLQ routing works as designed, but metric label `topic` was omitted in error handler.",
                recommendation="Emit `telemetry_dlq_messages_total{topic, reason}` counter before committing consumer offset.",
                status="open",
            )

            return self.get_project_snapshot(pid)
        finally:
            self.auto_sync_snapshot = prev_sync
            if self.auto_sync_snapshot:
                self.sync_static_snapshot(pid)

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

    def scaffold_system_tasks(
        self,
        project_id: str,
        system_ref: str,
        created_by: Optional[str] = None,
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
