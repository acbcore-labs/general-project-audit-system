"""
SQLite database engine, connection lifecycle, and versioned schema migrations for AuditOS.
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from contextlib import contextmanager
from typing import Generator, Optional

from auditos.core.config import SCHEMA_SQL


class DatabaseEngine:
    """Manages SQLite connections, WAL concurrency, and versioned schema migrations."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        auto_sync_snapshot: bool = False,
        ui_dir: Optional[str] = None,
    ) -> None:
        self.ui_dir = os.path.abspath(
            ui_dir
            or os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                "ui",
            )
        )
        if db_path == ":memory:":
            self.db_path = ":memory:"
            self._shared_mem_uri = f"file:auditos_{uuid.uuid4().hex}?mode=memory&cache=shared"
            self._keepalive_conn = sqlite3.connect(
                self._shared_mem_uri, uri=True, check_same_thread=False
            )
            self.auto_sync_snapshot = False
        else:
            default_path = os.environ.get(
                "AUDIT_DB_PATH",
                os.path.join(
                    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                    "audit.db",
                ),
            )
            self.db_path = os.path.abspath(db_path or default_path)
            self._shared_mem_uri = None
            self._keepalive_conn = None
            self.auto_sync_snapshot = auto_sync_snapshot
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db()

    def _raw_connect(self) -> sqlite3.Connection:
        if self._shared_mem_uri:
            return sqlite3.connect(
                self._shared_mem_uri,
                timeout=10.0,
                isolation_level=None,
                uri=True,
                check_same_thread=False,
            )
        return sqlite3.connect(
            self.db_path,
            timeout=10.0,
            isolation_level=None,
            check_same_thread=False,
        )

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

        if immediate and getattr(self, "auto_sync_snapshot", False):
            sync_fn = getattr(self, "sync_static_snapshot", None)
            if callable(sync_fn):
                sync_fn()

    def init_db(self) -> None:
        """Initialize schema and execute versioned migrations under PRAGMA user_version."""
        conn = self._raw_connect()
        try:
            conn.execute("PRAGMA busy_timeout = 5000;")
            existing = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='projects'"
            ).fetchone()
            if not existing:
                conn.executescript(SCHEMA_SQL)
                conn.execute("PRAGMA user_version = 2;")
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
                finding_cols = {r[1] for r in conn.execute("PRAGMA table_info(findings)").fetchall()}
                if "commit_sha" not in finding_cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN commit_sha TEXT DEFAULT '';")
                if "span_hash" not in finding_cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN span_hash TEXT DEFAULT '';")
                conn.execute("PRAGMA user_version = 2;")
        finally:
            conn.close()
