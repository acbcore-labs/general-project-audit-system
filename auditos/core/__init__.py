"""
Core infrastructure for AuditOS.
"""
from auditos.core.config import (
    PRIORITY_ORDER_SQL,
    ROLE_METADATA,
    SCHEMA_SQL,
    SEVERITY_ORDER_SQL,
    VALID_AGENT_ROLES,
    VALID_ID_RE,
    VALID_PRIORITIES,
    VALID_SEVERITIES,
    VALID_SYSTEM_STATUSES,
    VALID_TASK_STATUSES,
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

__all__ = [
    "DatabaseEngine",
    "VALID_ID_RE",
    "VALID_PRIORITIES",
    "VALID_SEVERITIES",
    "VALID_SYSTEM_STATUSES",
    "VALID_TASK_STATUSES",
    "VALID_AGENT_ROLES",
    "ROLE_METADATA",
    "PRIORITY_ORDER_SQL",
    "SEVERITY_ORDER_SQL",
    "SCHEMA_SQL",
    "utc_now_iso",
    "future_utc_iso",
    "validate_identifier",
    "slugify",
    "short_id",
    "validate_health_score",
    "get_git_commit_sha",
    "compute_span_hash",
]
