"""
AuditOS - Multi-Agent Codebase Auditing & Coordination Kernel.

This module acts as the public entrypoint and backwards-compatible facade,
re-exporting AuditDB and all domain constants, utilities, and rules from the
SOLID-architected `auditos` package.
"""
from __future__ import annotations

import os
import sys

# Ensure this directory is importable
_pkg_dir = os.path.dirname(os.path.abspath(__file__))
if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)

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
from auditos.engine import AuditDB
from auditos.invariants.rules import HealthCalibrator, HierarchyCycleDetector, StatusGovernor

__all__ = [
    "AuditDB",
    "DatabaseEngine",
    "StatusGovernor",
    "HealthCalibrator",
    "HierarchyCycleDetector",
    "VALID_ID_RE",
    "VALID_PRIORITIES",
    "VALID_SEVERITIES",
    "VALID_SYSTEM_STATUSES",
    "VALID_TASK_STATUSES",
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
