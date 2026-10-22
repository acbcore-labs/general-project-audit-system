"""
AuditOS - Multi-Agent Codebase Auditing & Coordination Kernel.
"""
from auditos.core.config import (
    PRIORITY_ORDER_SQL,
    ROLE_METADATA,
    SCHEMA_SQL,
    SEVERITY_ORDER_SQL,
    VALID_AGENT_ROLES,
    VALID_PRIORITIES,
    VALID_SEVERITIES,
)
from auditos.core.database import DatabaseEngine
from auditos.core.utils import (
    compute_span_hash,
    future_utc_iso,
    get_git_commit_sha,
    short_id,
    slugify,
    utc_now_iso,
    validate_health_score,
    validate_identifier,
)
from auditos.engine import AuditDB
from auditos.invariants.rules import HealthCalibrator, HierarchyCycleDetector, StatusGovernor

__version__ = "1.0.0"

__all__ = [
    "AuditDB",
    "DatabaseEngine",
    "StatusGovernor",
    "HealthCalibrator",
    "HierarchyCycleDetector",
    "VALID_PRIORITIES",
    "VALID_SEVERITIES",
    "VALID_AGENT_ROLES",
    "ROLE_METADATA",
    "SCHEMA_SQL",
    "PRIORITY_ORDER_SQL",
    "SEVERITY_ORDER_SQL",
    "utc_now_iso",
    "future_utc_iso",
    "validate_identifier",
    "slugify",
    "short_id",
    "validate_health_score",
    "get_git_commit_sha",
    "compute_span_hash",
]
