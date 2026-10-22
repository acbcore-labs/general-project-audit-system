"""
Core constants, role taxonomy, SQL schemas, and ordering rules for AuditOS.
"""
from __future__ import annotations

import re
from typing import Any, Dict

VALID_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

VALID_PRIORITIES = ("critical", "high", "medium", "low")
VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
VALID_SYSTEM_STATUSES = ("unreviewed", "in_progress", "reviewed", "needs_attention", "healthy")
VALID_TASK_STATUSES = ("open", "claimed", "completed", "blocked")
VALID_AGENT_ROLES = (
    "audit-lead",
    "arch-mapper",
    "security-auditor",
    "performance-reviewer",
    "integration-tracer",
    "verifier",
    "general-auditor",
)

ROLE_METADATA: Dict[str, Dict[str, Any]] = {
    "audit-lead": {
        "title": "Audit Lead & Synthesis Orchestrator",
        "description": "Conducts macro-level sweeps, resolves coverage imbalances, de-duplicates findings, reaps zombie leases, and signs off on subsystem health scores.",
        "task_types": (
            "architecture_map",
            "subsystem_audit",
            "integration_trace",
            "security_review",
            "performance_review",
            "bug_hunt",
            "verification",
        ),
        "capabilities": ("orchestration", "synthesis", "scaffolding", "triage", "de-duplication", "sign-off"),
    },
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
    commit_sha TEXT DEFAULT '',
    span_hash TEXT DEFAULT '',
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
